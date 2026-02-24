import {
  App,
  FuzzySuggestModal,
  ItemView,
  MarkdownRenderer,
  Modal,
  Notice,
  Plugin,
  PluginSettingTab,
  Setting,
  TFile,
  WorkspaceLeaf,
} from "obsidian";

// ─── Settings ────────────────────────────────────────────────────────

type StreamItem = { type: "tool"; label: string; url?: string; textPos?: number } | { type: "text"; text: string };

interface OpenClawSettings {
  gatewayUrl: string;
  token: string;
  sessionKey: string;
  onboardingComplete: boolean;
  deviceId?: string;
  devicePublicKey?: string;
  devicePrivateKey?: string;
  /** Persisted stream items (tool calls + intermediary text) keyed by assistant message index */
  streamItemsMap?: Record<string, StreamItem[]>;
}

const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: "ws://127.0.0.1:18789",
  token: "",
  sessionKey: "main",
  onboardingComplete: false,
};

// ─── Device Identity (Ed25519) ───────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data.buffer);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

interface DeviceIdentity {
  deviceId: string;
  publicKey: string;
  privateKey: string;
  cryptoKey: CryptoKey;
}

async function getOrCreateDeviceIdentity(
  loadData: () => Promise<any>,
  saveData: (data: any) => Promise<void>
): Promise<DeviceIdentity> {
  const data = await loadData();
  if (data?.deviceId && data?.devicePublicKey && data?.devicePrivateKey) {
    // Restore existing identity
    const privBytes = fromBase64Url(data.devicePrivateKey);
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privBytes,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    return {
      deviceId: data.deviceId,
      publicKey: data.devicePublicKey,
      privateKey: data.devicePrivateKey,
      cryptoKey,
    };
  }

  // Generate new Ed25519 keypair
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const deviceId = await sha256Hex(pubRaw);
  const publicKey = toBase64Url(pubRaw);
  const privateKey = toBase64Url(privPkcs8);

  // Save to plugin data
  const existing = (await loadData()) || {};
  existing.deviceId = deviceId;
  existing.devicePublicKey = publicKey;
  existing.devicePrivateKey = privateKey;
  await saveData(existing);

  return { deviceId, publicKey, privateKey, cryptoKey: keyPair.privateKey };
}

async function signDevicePayload(identity: DeviceIdentity, payload: string): Promise<string> {
  const encoded = new TextEncoder().encode(payload);
  let cryptoKey = identity.cryptoKey;
  // If cryptoKey doesn't have sign usage, re-import
  if (!cryptoKey) {
    const privBytes = fromBase64Url(identity.privateKey);
    cryptoKey = await crypto.subtle.importKey("pkcs8", privBytes, { name: "Ed25519" }, false, ["sign"]);
  }
  const sig = await crypto.subtle.sign("Ed25519", cryptoKey, encoded);
  return toBase64Url(new Uint8Array(sig));
}

function buildSignaturePayload(params: {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token: string | null;
  nonce: string | null;
}): string {
  const version = params.nonce ? "v2" : "v1";
  const parts = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    params.scopes.join(","),
    String(params.signedAtMs),
    params.token ?? "",
  ];
  if (version === "v2") parts.push(params.nonce ?? "");
  return parts.join("|");
}

// ─── Gateway Client ──────────────────────────────────────────────────

type GatewayEventHandler = (event: { event: string; payload: any; seq?: number }) => void;
type GatewayHelloHandler = (payload: any) => void;
type GatewayCloseHandler = (info: { code: number; reason: string }) => void;

interface GatewayClientOpts {
  url: string;
  token?: string;
  deviceIdentity?: DeviceIdentity;
  onEvent?: GatewayEventHandler;
  onHello?: GatewayHelloHandler;
  onClose?: GatewayCloseHandler;
}

function generateId(): string {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

class GatewayClient {
  private ws: WebSocket | null = null;
  private pending = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  private closed = false;
  private connectSent = false;
  private connectNonce: string | null = null;
  private backoffMs = 800;
  private opts: GatewayClientOpts;
  private connectTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingTimeouts = new Map<string, ReturnType<typeof setTimeout>>();

  constructor(opts: GatewayClientOpts) {
    this.opts = opts;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  start(): void {
    this.closed = false;
    this.doConnect();
  }

  stop(): void {
    this.closed = true;
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
    for (const [, t] of this.pendingTimeouts) clearTimeout(t);
    this.pendingTimeouts.clear();
    this.ws?.close();
    this.ws = null;
    this.flushPending(new Error("client stopped"));
  }

  async request(method: string, params?: any): Promise<any> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("not connected");
    }
    const id = generateId();
    const msg = { type: "req", id, method, params };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      // Timeout requests after 30s
      const t = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error("request timeout"));
        }
      }, 30000);
      this.pendingTimeouts.set(id, t);
      this.ws!.send(JSON.stringify(msg));
    });
  }

  private doConnect(): void {
    if (this.closed) return;

    // Validate URL before connecting
    const url = this.opts.url;
    if (!url.startsWith("ws://") && !url.startsWith("wss://")) {
      console.error("[ObsidianClaw] Invalid gateway URL: must start with ws:// or wss://");
      return;
    }

    this.ws = new WebSocket(url);
    this.ws.addEventListener("open", () => this.queueConnect());
    this.ws.addEventListener("message", (e) => this.handleMessage(String(e.data ?? "")));
    this.ws.addEventListener("close", (e) => {
      this.ws = null;
      this.flushPending(new Error(`closed (${e.code})`));
      this.opts.onClose?.({ code: e.code, reason: e.reason || "" });
      this.scheduleReconnect();
    });
    this.ws.addEventListener("error", () => {});
  }

  private scheduleReconnect(): void {
    if (this.closed) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 1.7, 15000);
    setTimeout(() => this.doConnect(), delay);
  }

  private flushPending(err: Error): void {
    for (const [id, p] of this.pending) {
      const t = this.pendingTimeouts.get(id);
      if (t) clearTimeout(t);
      p.reject(err);
    }
    this.pending.clear();
    this.pendingTimeouts.clear();
  }

  private queueConnect(): void {
    this.connectNonce = null;
    this.connectSent = false;
    if (this.connectTimer !== null) clearTimeout(this.connectTimer);
    this.connectTimer = setTimeout(() => this.sendConnect(), 750);
  }

  private async sendConnect(): Promise<void> {
    if (this.connectSent) return;
    this.connectSent = true;
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }

    const CLIENT_ID = "gateway-client";
    const CLIENT_MODE = "ui";
    const ROLE = "operator";
    const SCOPES = ["operator.admin", "operator.write", "operator.read"];

    const auth = this.opts.token ? { token: this.opts.token } : undefined;

    // Build device fingerprint if identity is available
    let device: any = undefined;
    const identity = this.opts.deviceIdentity;
    if (identity) {
      try {
        const signedAtMs = Date.now();
        const nonce = this.connectNonce ?? null;
        const payload = buildSignaturePayload({
          deviceId: identity.deviceId,
          clientId: CLIENT_ID,
          clientMode: CLIENT_MODE,
          role: ROLE,
          scopes: SCOPES,
          signedAtMs,
          token: this.opts.token ?? null,
          nonce,
        });
        const signature = await signDevicePayload(identity, payload);
        device = {
          id: identity.deviceId,
          publicKey: identity.publicKey,
          signature,
          signedAt: signedAtMs,
          nonce: nonce ?? undefined,
        };
      } catch (e) {
        console.error("[ObsidianClaw] Device signing failed:", e);
      }
    }

    const params = {
      minProtocol: 3,
      maxProtocol: 3,
      client: {
        id: CLIENT_ID,
        version: "0.1.0",
        platform: "obsidian",
        mode: CLIENT_MODE,
      },
      role: ROLE,
      scopes: SCOPES,
      auth,
      device,
      caps: ["tool-events"],
    };

    this.request("connect", params)
      .then((payload) => {
        this.backoffMs = 800;
        this.opts.onHello?.(payload);
      })
      .catch(() => {
        this.ws?.close(4008, "connect failed");
      });
  }

  private handleMessage(raw: string): void {
    let msg: any;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === "event") {
      if (msg.event === "connect.challenge") {
        const nonce = msg.payload?.nonce;
        if (typeof nonce === "string") {
          this.connectNonce = nonce;
          this.sendConnect();
        }
        return;
      }
      this.opts.onEvent?.(msg);
      return;
    }

    if (msg.type === "res") {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      const t = this.pendingTimeouts.get(msg.id);
      if (t) {
        clearTimeout(t);
        this.pendingTimeouts.delete(msg.id);
      }
      if (msg.ok) {
        p.resolve(msg.payload);
      } else {
        p.reject(new Error(msg.error?.message ?? "request failed"));
      }
    }
  }
}

// ─── Chat Message Types ──────────────────────────────────────────────

interface ChatMessage {
  role: "user" | "assistant";
  text: string;
  images: string[]; // data URIs or URLs
  timestamp: number;
  contentBlocks?: any[]; // raw content array from history (preserves tool_use interleaving)
}

// ─── Onboarding Modal ────────────────────────────────────────────────

class OnboardingModal extends Modal {
  plugin: OpenClawPlugin;
  private step = 0;
  private urlInput: HTMLInputElement | null = null;
  private tokenInput: HTMLInputElement | null = null;
  private statusEl: HTMLElement | null = null;

  constructor(app: App, plugin: OpenClawPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("openclaw-onboarding");
    this.renderStep();
  }

  onClose(): void {
    // If they close without finishing, that's ok — they can reopen from settings
  }

  private renderStep(): void {
    const { contentEl } = this;
    contentEl.empty();

    if (this.step === 0) this.renderWelcome(contentEl);
    else if (this.step === 1) this.renderConnect(contentEl);
    else if (this.step === 2) this.renderDone(contentEl);
  }

  private renderWelcome(el: HTMLElement): void {
    el.createEl("h2", { text: "Welcome to OpenClaw" });
    el.createEl("p", {
      text: "This plugin connects Obsidian to your OpenClaw AI agent via Tailscale. Your vault becomes the agent's workspace — it can read your notes, create new ones, and search across everything.",
      cls: "openclaw-onboard-desc",
    });

    el.createEl("h3", { text: "Before you start" });
    const list = el.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", {
      text: "OpenClaw must be running on a machine with Tailscale",
    });
    list.createEl("li", {
      text: "This device must be on the same Tailscale network",
    });
    list.createEl("li", {
      text: "Have your gateway auth token ready (from ~/.openclaw/openclaw.json)",
    });

    const info = el.createDiv("openclaw-onboard-info");
    info.createEl("strong", { text: "Need help? " });
    info.createEl("span", {
      text: "Visit botsetupguide.com for the full setup guide.",
    });

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const nextBtn = btnRow.createEl("button", { text: "Connect to gateway →", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      this.step = 1;
      this.renderStep();
    });
  }

  private renderConnect(el: HTMLElement): void {
    el.createEl("h2", { text: "Connect to your gateway" });
    el.createEl("p", {
      text: "Enter your Tailscale gateway address and auth token. Find both on your gateway machine.",
      cls: "openclaw-onboard-desc",
    });

    // URL input
    const urlGroup = el.createDiv("openclaw-onboard-field");
    urlGroup.createEl("label", { text: "Gateway URL (Tailscale)" });
    this.urlInput = urlGroup.createEl("input", {
      type: "text",
      value: this.plugin.settings.gatewayUrl || "",
      placeholder: "ws://100.x.x.x:18789",
      cls: "openclaw-onboard-input",
    });

    const urlHint = urlGroup.createDiv("openclaw-onboard-hint");
    urlHint.innerHTML = "Run <code>tailscale ip -4</code> on your gateway machine to get the IP";

    // Token input
    const tokenGroup = el.createDiv("openclaw-onboard-field");
    tokenGroup.createEl("label", { text: "Auth Token" });
    this.tokenInput = tokenGroup.createEl("input", {
      type: "password",
      value: this.plugin.settings.token,
      placeholder: "From ~/.openclaw/openclaw.json → gateway.auth.token",
      cls: "openclaw-onboard-input",
    });

    const tokenHint = tokenGroup.createDiv("openclaw-onboard-hint");
    tokenHint.innerHTML = "On your gateway machine: <code>cat ~/.openclaw/openclaw.json | grep token</code>";

    // Security note
    const secNote = el.createDiv("openclaw-onboard-security");
    secNote.createEl("strong", { text: "🔒 Security" });
    secNote.createEl("p", {
      text: "After connecting, this device will generate a unique keypair for device pairing. You'll need to approve the pairing on your gateway machine. Your token and keys are stored locally and never leave your Tailscale network.",
    });

    // Status
    this.statusEl = el.createDiv("openclaw-onboard-status");

    // Buttons
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const backBtn = btnRow.createEl("button", { text: "← Back" });
    backBtn.addEventListener("click", () => {
      this.step = 0;
      this.renderStep();
    });
    const testBtn = btnRow.createEl("button", { text: "Test connection", cls: "mod-cta" });
    testBtn.addEventListener("click", () => this.testConnection(testBtn));
  }

  private async testConnection(btn: HTMLButtonElement): Promise<void> {
    if (!this.urlInput || !this.statusEl) return;

    const url = this.urlInput.value.trim();
    if (!url) {
      this.showStatus("Enter a gateway URL", "error");
      return;
    }
    if (!url.startsWith("ws://") && !url.startsWith("wss://")) {
      this.showStatus("URL must start with ws:// or wss://", "error");
      return;
    }

    btn.disabled = true;
    btn.textContent = "Connecting...";
    this.showStatus("Connecting to gateway...", "info");

    const token = this.tokenInput?.value.trim() || "";

    // Save settings
    this.plugin.settings.gatewayUrl = url;
    this.plugin.settings.token = token;
    await this.plugin.saveSettings();

    // Try to connect with a timeout
    const testResult = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => {
        testClient.stop();
        resolve(false);
      }, 8000);

      const testClient = new GatewayClient({
        url,
        token: token || undefined,
        onHello: () => {
          clearTimeout(timeout);
          testClient.stop();
          resolve(true);
        },
        onClose: () => {
          // Don't resolve here — let timeout handle failure
        },
      });
      testClient.start();
    });

    btn.disabled = false;
    btn.textContent = "Test connection";

    if (testResult) {
      this.showStatus("✓ Connected successfully!", "success");
      // Auto-advance after a moment
      setTimeout(() => {
        this.step = 2;
        this.renderStep();
      }, 1000);
    } else {
      this.showStatus("Could not connect. Check that OpenClaw is running and the URL is correct.", "error");
    }
  }

  private renderDone(el: HTMLElement): void {
    el.createEl("h2", { text: "Connected!" });
    el.createEl("p", {
      text: "OpenClaw is connected. If this is a new device, you'll need to approve the device pairing on your gateway machine (check the OpenClaw dashboard or CLI).",
      cls: "openclaw-onboard-desc",
    });

    const tips = el.createDiv("openclaw-onboard-tips");
    tips.createEl("h3", { text: "Quick tips" });
    const list = tips.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", { text: "Use Cmd/Ctrl+P → \"Ask about current note\" to send any note as context" });
    list.createEl("li", { text: "The agent can read and edit files in your vault directly" });
    list.createEl("li", { text: "Tool calls are shown inline — click file paths to open them" });
    list.createEl("li", { text: "Change settings anytime in Settings → OpenClaw" });

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const doneBtn = btnRow.createEl("button", { text: "Start chatting", cls: "mod-cta" });
    doneBtn.addEventListener("click", async () => {
      this.plugin.settings.onboardingComplete = true;
      await this.plugin.saveSettings();
      this.close();
      this.plugin.connectGateway();
      this.plugin.activateView();
    });
  }

  private showStatus(text: string, type: "info" | "success" | "error"): void {
    if (!this.statusEl) return;
    this.statusEl.empty();
    this.statusEl.className = `openclaw-onboard-status openclaw-onboard-status-${type}`;
    this.statusEl.textContent = text;
  }
}

// ─── Chat View ───────────────────────────────────────────────────────

const VIEW_TYPE = "openclaw-chat";

class OpenClawChatView extends ItemView {
  plugin: OpenClawPlugin;
  private messagesEl!: HTMLElement;
  private inputEl!: HTMLTextAreaElement;
  private sendBtn!: HTMLButtonElement;
  private reconnectBtn!: HTMLButtonElement;
  private abortBtn!: HTMLButtonElement;
  private statusEl!: HTMLElement;
  private messages: ChatMessage[] = [];
  private streamText: string | null = null;
  private streamRunId: string | null = null;
  private compactTimer: ReturnType<typeof setTimeout> | null = null;
  private lastDeltaTime: number = 0;
  private workingTimer: ReturnType<typeof setTimeout> | null = null;
  private currentToolCalls: string[] = [];
  /** Ordered list of stream items (tool calls) for re-rendering after loadHistory */
  private streamItems: StreamItem[] = [];
  private streamSplitPoints: number[] = []; // character positions where tool calls interrupted text
  private streamEl: HTMLElement | null = null;
  private typingEl!: HTMLElement;
  private attachPreviewEl!: HTMLElement;
  private fileInputEl!: HTMLInputElement;
  private pendingAttachments: { name: string; content: string; vaultPath?: string; base64?: string; mimeType?: string }[] = [];
  private sending = false;
  private bannerEl!: HTMLElement;

  constructor(leaf: WorkspaceLeaf, plugin: OpenClawPlugin) {
    super(leaf);
    this.plugin = plugin;
  }

  getViewType(): string {
    return VIEW_TYPE;
  }

  getDisplayText(): string {
    return "OpenClaw";
  }

  getIcon(): string {
    return "message-square";
  }

  async onOpen(): Promise<void> {
    const container = this.containerEl.children[1] as HTMLElement;
    container.empty();
    container.addClass("openclaw-chat-container");

    // Header (hidden, status dot moved to input row)
    const header = container.createDiv("openclaw-chat-header");
    header.createSpan({ text: "OpenClaw", cls: "openclaw-header-title" });

    // Status banner (compaction, etc.) — hidden by default
    this.bannerEl = container.createDiv("openclaw-banner");
    this.bannerEl.style.display = "none";

    // Messages area
    this.messagesEl = container.createDiv("openclaw-messages");

    // Typing indicator (hidden by default)
    this.typingEl = container.createDiv("openclaw-typing");
    this.typingEl.style.display = "none";
    const typingDots = this.typingEl.createDiv("openclaw-typing-inner");
    typingDots.createSpan({ text: "Thinking", cls: "openclaw-typing-text" });
    const dotsEl = typingDots.createSpan("openclaw-typing-dots");
    dotsEl.createSpan("openclaw-dot");
    dotsEl.createSpan("openclaw-dot");
    dotsEl.createSpan("openclaw-dot");

    // Input area
    const inputArea = container.createDiv("openclaw-input-area");
    const inputRow = inputArea.createDiv("openclaw-input-row");
    // Status dot overlays the send button as a badge
    // Attach button + hidden file input
    const attachBtn = inputRow.createEl("button", { cls: "openclaw-attach-btn", attr: { "aria-label": "Attach file" } });
    attachBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>`;
    this.fileInputEl = inputArea.createEl("input", {
      cls: "openclaw-file-input",
      attr: { type: "file", accept: "image/*,.md,.txt,.json,.csv,.pdf,.yaml,.yml,.js,.ts,.py,.html,.css", multiple: "true" },
    });
    this.fileInputEl.style.display = "none";
    this.fileInputEl.addEventListener("change", () => this.handleFileSelect());
    attachBtn.addEventListener("click", () => this.fileInputEl.click());
    this.inputEl = inputRow.createEl("textarea", {
      cls: "openclaw-input",
      attr: { placeholder: "Message...", rows: "1" },
    });
    // Attachment preview (hidden by default)
    this.attachPreviewEl = inputArea.createDiv("openclaw-attach-preview");
    this.attachPreviewEl.style.display = "none";
    this.abortBtn = inputRow.createEl("button", { cls: "openclaw-abort-btn", attr: { "aria-label": "Stop" } });
    this.abortBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>`;
    this.abortBtn.style.display = "none";
    const sendWrapper = inputRow.createDiv("openclaw-send-wrapper");
    this.sendBtn = sendWrapper.createEl("button", { cls: "openclaw-send-btn", attr: { "aria-label": "Send" } });
    this.sendBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`;
    this.reconnectBtn = sendWrapper.createEl("button", { cls: "openclaw-reconnect-btn", attr: { "aria-label": "Reconnect" } });
    this.reconnectBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 00-2 2v.18a2 2 0 01-1 1.73l-.43.25a2 2 0 01-2 0l-.15-.08a2 2 0 00-2.73.73l-.22.38a2 2 0 00.73 2.73l.15.1a2 2 0 011 1.72v.51a2 2 0 01-1 1.74l-.15.09a2 2 0 00-.73 2.73l.22.38a2 2 0 002.73.73l.15-.08a2 2 0 012 0l.43.25a2 2 0 011 1.73V20a2 2 0 002 2h.44a2 2 0 002-2v-.18a2 2 0 011-1.73l.43-.25a2 2 0 012 0l.15.08a2 2 0 002.73-.73l.22-.39a2 2 0 00-.73-2.73l-.15-.08a2 2 0 01-1-1.74v-.5a2 2 0 011-1.74l.15-.09a2 2 0 00.73-2.73l-.22-.38a2 2 0 00-2.73-.73l-.15.08a2 2 0 01-2 0l-.43-.25a2 2 0 01-1-1.73V4a2 2 0 00-2-2z"/><circle cx="12" cy="12" r="3"/></svg>`;
    this.reconnectBtn.style.display = "none";
    this.reconnectBtn.addEventListener("click", () => {
      // Open plugin settings
      (this.app as any).setting?.open?.();
      (this.app as any).setting?.openTabById?.("openclaw");
    });
    this.statusEl = sendWrapper.createSpan("openclaw-status-dot");

    // Events
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // Mobile: Enter always creates new line (use send button to send)
        // Desktop: Enter sends, Shift+Enter creates new line
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) ||
          (navigator.maxTouchPoints > 0 && window.innerWidth < 768);
        if (isMobile) {
          // Let Enter create a new line naturally
          return;
        }
        if (!e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      }
    });
    this.inputEl.addEventListener("input", () => this.autoResize());
    this.inputEl.addEventListener("focus", () => {
      setTimeout(() => {
        this.inputEl.scrollIntoView({ block: "end", behavior: "smooth" });
      }, 300);
    });
    // Clipboard paste: capture images from clipboard
    this.inputEl.addEventListener("paste", (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (const item of Array.from(items)) {
        if (item.type.startsWith("image/")) {
          e.preventDefault();
          const file = item.getAsFile();
          if (file) this.handlePastedFile(file);
          return;
        }
      }
    });
    this.sendBtn.addEventListener("click", () => this.sendMessage());
    this.abortBtn.addEventListener("click", () => this.abortMessage());

    // Initial state
    this.updateStatus();
    this.plugin.chatView = this;
    if (this.plugin.gatewayConnected) {
      await this.loadHistory();
    }
  }

  async onClose(): Promise<void> {
    if (this.plugin.chatView === this) {
      this.plugin.chatView = null;
    }
  }

  updateStatus(): void {
    if (!this.statusEl) return;
    this.statusEl.removeClass("connected", "disconnected");
    const connected = this.plugin.gatewayConnected;
    this.statusEl.addClass(connected ? "connected" : "disconnected");

    // Swap send button for reconnect when disconnected
    if (connected) {
      this.sendBtn.style.display = "";
      if (this.reconnectBtn) this.reconnectBtn.style.display = "none";
      this.inputEl.disabled = false;
      this.inputEl.placeholder = "Message...";
    } else {
      this.sendBtn.style.display = "none";
      if (this.reconnectBtn) this.reconnectBtn.style.display = "";
      this.inputEl.disabled = true;
      this.inputEl.placeholder = "Disconnected";
    }
  }

  async loadHistory(): Promise<void> {
    if (!this.plugin.gateway?.connected) return;
    try {
      const result = await this.plugin.gateway.request("chat.history", {
        sessionKey: this.plugin.settings.sessionKey,
        limit: 200,
      });
      if (result?.messages && Array.isArray(result.messages)) {
        this.messages = result.messages
          .filter((m: any) => m.role === "user" || m.role === "assistant")
          .map((m: any) => {
            const { text, images } = this.extractContent(m.content);
            return {
              role: m.role as "user" | "assistant",
              text,
              images,
              timestamp: m.timestamp ?? Date.now(),
              contentBlocks: Array.isArray(m.content) ? m.content : undefined,
            };
          })
          .filter((m: ChatMessage) => (m.text.trim() || m.images.length > 0) && !m.text.startsWith("HEARTBEAT"));
        await this.renderMessages();
      }
    } catch (e) {
      console.error("[ObsidianClaw] Failed to load history:", e);
    }
  }

  private extractContent(content: any): { text: string; images: string[] } {
    let text = "";
    const images: string[] = [];

    if (typeof content === "string") {
      text = content;
    } else if (Array.isArray(content)) {
      for (const c of content) {
        if (c.type === "text") {
          text += (text ? "\n" : "") + c.text;
        } else if (c.type === "image_url" && c.image_url?.url) {
          images.push(c.image_url.url);
        }
      }
    }

    // Extract vault image paths from "File saved at:" lines
    const savedAtRegex = /File saved at:\s*(.+?openclaw-attachments\/[^\s\n]+)/g;
    let match;
    while ((match = savedAtRegex.exec(text)) !== null) {
      // Try to resolve as vault-relative path
      const fullPath = match[1].trim();
      const vaultRelative = fullPath.includes("openclaw-attachments/")
        ? "openclaw-attachments/" + fullPath.split("openclaw-attachments/")[1]
        : null;
      if (vaultRelative) {
        try {
          const resourcePath = this.app.vault.adapter.getResourcePath(vaultRelative);
          if (resourcePath) images.push(resourcePath);
        } catch { /* ignore */ }
      }
    }

    // Extract inline data URIs from text (legacy)
    const dataUriRegex = /(?:^|\n)data:(image\/[^;]+);base64,[A-Za-z0-9+/=\n]+/g;
    while ((match = dataUriRegex.exec(text)) !== null) {
      images.push(match[0].replace(/^\n/, "").trim());
    }
    // Remove data URIs from text display
    text = text.replace(/\n?data:image\/[^;]+;base64,[A-Za-z0-9+/=\n]+/g, "").trim();
    // Strip [Attached image: ...] and "File saved at:" lines
    text = text.replace(/^\[Attached image:.*?\]\s*/gm, "").trim();
    text = text.replace(/^File saved at:.*$/gm, "").trim();

    // Strip gateway metadata blocks (Conversation info + JSON code block)
    text = text.replace(/Conversation info \(untrusted metadata\):\s*```json[\s\S]*?```\s*/g, "").trim();
    // Strip any remaining standalone metadata JSON blocks
    text = text.replace(/^```json\s*\{\s*"message_id"[\s\S]*?```\s*/gm, "").trim();
    // Strip timestamp prefixes like "[Sun 2026-02-22 21:58 GMT+7] "
    text = text.replace(/^\[.*?GMT[+-]\d+\]\s*/gm, "").trim();
    // Strip media attachment lines
    text = text.replace(/^\[media attached:.*?\]\s*/gm, "").trim();
    // Strip "To send an image back..." instruction lines
    text = text.replace(/^To send an image back.*$/gm, "").trim();
    // Strip "NO_REPLY" responses
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK") text = "";
    return { text, images };
  }

  async sendMessage(): Promise<void> {
    let text = this.inputEl.value.trim();
    if (!text && this.pendingAttachments.length === 0) return;
    if (this.sending) return;
    if (!this.plugin.gateway?.connected) {
      new Notice("Not connected to OpenClaw gateway");
      return;
    }

    this.sending = true;
    this.sendBtn.disabled = true;
    this.inputEl.value = "";
    this.autoResize();

    // Build attachments for gateway
    let fullMessage = text;
    const displayText = text;
    const userImages: string[] = [];
    const gatewayAttachments: { type: string; mimeType: string; content: string }[] = [];
    if (this.pendingAttachments.length > 0) {
      for (const att of this.pendingAttachments) {
        if (att.base64 && att.mimeType) {
          // Image: send via attachments field (gateway saves to disk)
          gatewayAttachments.push({ type: "image", mimeType: att.mimeType, content: att.base64 });
        } else {
          // Text files: append to message as before
          fullMessage = (fullMessage ? fullMessage + "\n\n" : "") + att.content;
        }
      }
      if (!text) text = `📎 ${this.pendingAttachments.map(a => a.name).join(", ")}`;
      this.pendingAttachments = [];
      this.attachPreviewEl.style.display = "none";
    }

    this.messages.push({ role: "user", text: displayText || text, images: userImages, timestamp: Date.now() });
    await this.renderMessages();

    const runId = generateId();
    this.streamRunId = runId;
    this.streamText = "";
    this.abortBtn.style.display = "";
    this.typingEl.style.display = "";
    // Update thinking text and show immediately
    const thinkText = this.typingEl.querySelector(".openclaw-typing-text");
    if (thinkText) thinkText.textContent = "Thinking";
    this.scrollToBottom();

    // Fallback: if no events at all after 15s, show generic status
    this.compactTimer = setTimeout(() => {
      if (this.streamRunId === runId && !this.streamText) {
        const tt = this.typingEl.querySelector(".openclaw-typing-text");
        if (tt && tt.textContent === "Thinking") tt.textContent = "Still thinking";
      }
    }, 15000);

    try {
      const sendParams: any = {
        sessionKey: this.plugin.settings.sessionKey,
        message: fullMessage,
        deliver: false,
        idempotencyKey: runId,
      };
      if (gatewayAttachments.length > 0) {
        sendParams.attachments = gatewayAttachments;
      }
      await this.plugin.gateway.request("chat.send", sendParams);
    } catch (e) {
      if (this.compactTimer) clearTimeout(this.compactTimer);
      this.messages.push({ role: "assistant", text: `Error: ${e}`, images: [], timestamp: Date.now() });
      this.streamRunId = null;
      this.streamText = null;
      this.abortBtn.style.display = "none";
      await this.renderMessages();
    } finally {
      this.sending = false;
      this.sendBtn.disabled = false;
    }
  }

  async abortMessage(): Promise<void> {
    if (!this.plugin.gateway?.connected || !this.streamRunId) return;
    try {
      await this.plugin.gateway.request("chat.abort", {
        sessionKey: this.plugin.settings.sessionKey,
        runId: this.streamRunId,
      });
    } catch {
      // ignore
    }
  }

  async handleFileSelect(): Promise<void> {
    const files = this.fileInputEl.files;
    if (!files || files.length === 0) return;

    for (const file of Array.from(files)) {
      try {
        const isImage = file.type.startsWith("image/");
        const isText = file.type.startsWith("text/") ||
          ["application/json", "application/yaml", "application/xml", "application/javascript"].includes(file.type) ||
          /\.(md|txt|json|csv|yaml|yml|js|ts|py|html|css|xml|toml|ini|sh|log)$/i.test(file.name);

        if (isImage) {
          const resized = await this.resizeImage(file, 2048, 0.85);
          this.pendingAttachments.push({
            name: file.name,
            content: `[Attached image: ${file.name}]`,
            base64: resized.base64,
            mimeType: resized.mimeType,
          });
        } else if (isText) {
          const content = await file.text();
          const truncated = content.length > 10000 ? content.slice(0, 10000) + "\n...(truncated)" : content;
          this.pendingAttachments.push({
            name: file.name,
            content: `File: ${file.name}\n\`\`\`\n${truncated}\n\`\`\``,
          });
        } else {
          this.pendingAttachments.push({
            name: file.name,
            content: `[Attached file: ${file.name} (${file.type || "unknown type"}, ${Math.round(file.size/1024)}KB)]`,
          });
        }
      } catch (e) {
        new Notice(`Failed to attach ${file.name}: ${e}`);
      }
    }

    // Update preview
    this.renderAttachPreview();
    this.fileInputEl.value = "";
  }

  async handlePastedFile(file: File): Promise<void> {
    try {
      const ext = file.type.split("/")[1] || "png";
      const resized = await this.resizeImage(file, 2048, 0.85);
      this.pendingAttachments.push({
        name: `clipboard.${ext}`,
        content: `[Attached image: clipboard.${ext}]`,
        base64: resized.base64,
        mimeType: resized.mimeType,
      });
      this.renderAttachPreview();
    } catch (e) {
      new Notice(`Failed to paste image: ${e}`);
    }
  }

  private async resizeImage(file: File, maxSide: number, quality: number): Promise<{ base64: string; mimeType: string }> {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(url);
        let { width, height } = img;
        if (width > maxSide || height > maxSide) {
          const scale = maxSide / Math.max(width, height);
          width = Math.round(width * scale);
          height = Math.round(height * scale);
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        if (!ctx) { reject(new Error("No canvas context")); return; }
        ctx.drawImage(img, 0, 0, width, height);
        const dataUrl = canvas.toDataURL("image/jpeg", quality);
        const base64 = dataUrl.split(",")[1];
        resolve({ base64, mimeType: "image/jpeg" });
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("Failed to load image")); };
      img.src = url;
    });
  }

  private renderAttachPreview(): void {
    this.attachPreviewEl.empty();
    if (this.pendingAttachments.length === 0) {
      this.attachPreviewEl.style.display = "none";
      return;
    }
    this.attachPreviewEl.style.display = "flex";

    for (let i = 0; i < this.pendingAttachments.length; i++) {
      const att = this.pendingAttachments[i];
      const chip = this.attachPreviewEl.createDiv("openclaw-attach-chip");

      // Show thumbnail for images
      if (att.base64 && att.mimeType) {
        const src = `data:${att.mimeType};base64,${att.base64}`;
        chip.createEl("img", { cls: "openclaw-attach-thumb", attr: { src } });
      } else if (att.vaultPath) {
        try {
          const src = this.app.vault.adapter.getResourcePath(att.vaultPath);
          if (src) chip.createEl("img", { cls: "openclaw-attach-thumb", attr: { src } });
        } catch { /* ignore */ }
      }

      chip.createSpan({ text: att.name, cls: "openclaw-attach-name" });
      const removeBtn = chip.createEl("button", { text: "✕", cls: "openclaw-attach-remove" });
      const idx = i;
      removeBtn.addEventListener("click", () => {
        this.pendingAttachments.splice(idx, 1);
        this.renderAttachPreview();
      });
    }
  }

  private buildToolLabel(toolName: string, args: any): { label: string; url?: string } {
    const a = args || {};
    switch (toolName) {
      case "exec": {
        const cmd = a.command || "";
        const short = cmd.length > 60 ? cmd.slice(0, 60) + "…" : cmd;
        return { label: `🔧 ${short || "Running command"}` };
      }
      case "read": case "Read": {
        const p = a.path || a.file_path || "";
        const name = p.split("/").pop() || "file";
        return { label: `📄 Reading ${name}` };
      }
      case "write": case "Write": {
        const p = a.path || a.file_path || "";
        const name = p.split("/").pop() || "file";
        return { label: `✏️ Writing ${name}` };
      }
      case "edit": case "Edit": {
        const p = a.path || a.file_path || "";
        const name = p.split("/").pop() || "file";
        return { label: `✏️ Editing ${name}` };
      }
      case "web_search": {
        const q = a.query || "";
        return { label: `🔍 Searching "${q.length > 40 ? q.slice(0, 40) + "…" : q}"` };
      }
      case "web_fetch": {
        const rawUrl = a.url || "";
        try {
          const domain = new URL(rawUrl).hostname;
          return { label: `🌐 Fetching ${domain}`, url: rawUrl };
        } catch {
          return { label: `🌐 Fetching page`, url: rawUrl || undefined };
        }
      }
      case "browser":
        return { label: "🌐 Using browser" };
      case "image":
        return { label: "👁️ Viewing image" };
      case "memory_search": {
        const q = a.query || "";
        return { label: `🧠 Searching "${q.length > 40 ? q.slice(0, 40) + "…" : q}"` };
      }
      case "memory_get": {
        const p = a.path || "";
        const name = p.split("/").pop() || "memory";
        return { label: `🧠 Reading ${name}` };
      }
      case "message":
        return { label: "💬 Sending message" };
      case "tts":
        return { label: "🔊 Speaking" };
      case "sessions_spawn":
        return { label: "🤖 Spawning sub-agent" };
      default:
        return { label: toolName ? `⚡ ${toolName}` : "Working" };
    }
  }

  private appendToolCall(label: string, url?: string, active = false): void {
    const el = document.createElement("div");
    el.className = "openclaw-tool-item" + (active ? " openclaw-tool-active" : "");
    if (url) {
      const link = document.createElement("a");
      link.href = url;
      link.textContent = label;
      link.className = "openclaw-tool-link";
      link.addEventListener("click", (e) => {
        e.preventDefault();
        window.open(url, "_blank");
      });
      el.appendChild(link);
    } else {
      const span = document.createElement("span");
      span.textContent = label;
      el.appendChild(span);
    }
    if (active) {
      const dots = document.createElement("span");
      dots.className = "openclaw-tool-dots";
      dots.innerHTML = '<span class="openclaw-dot"></span><span class="openclaw-dot"></span><span class="openclaw-dot"></span>';
      el.appendChild(dots);
    }
    this.messagesEl.appendChild(el);
    this.scrollToBottom();
  }

  private deactivateLastToolItem(): void {
    const items = this.messagesEl.querySelectorAll(".openclaw-tool-active");
    const last = items[items.length - 1];
    if (last) {
      last.removeClass("openclaw-tool-active");
      const dots = last.querySelector(".openclaw-tool-dots");
      if (dots) dots.remove();
    }
  }

  private showBanner(text: string): void {
    if (!this.bannerEl) return;
    this.bannerEl.textContent = text;
    this.bannerEl.style.display = "";
  }

  private hideBanner(): void {
    if (!this.bannerEl) return;
    this.bannerEl.style.display = "none";
  }

  handleStreamEvent(payload: any): void {
    const stream = payload.stream || "";
    const state = payload.state || "";

    // Compaction can arrive without an active stream (before user message gets processed)
    if (!this.streamRunId) {
      if (stream === "compaction" || state === "compacting") {
        this.showBanner("Compacting context...");
      }
      return;
    }

    const typingText = this.typingEl.querySelector(".openclaw-typing-text");
    if (!typingText) return;

    // Agent "assistant" events = agent is actively working
    if (state === "assistant") {
      const timeSinceDelta = Date.now() - this.lastDeltaTime;
      if (this.streamText && timeSinceDelta > 1500 && this.typingEl.style.display === "none") {
        if (!this.workingTimer) {
          this.workingTimer = setTimeout(() => {
            if (this.streamRunId && this.typingEl.style.display === "none") {
              typingText.textContent = "Working";
              this.typingEl.style.display = "";
            }
            this.workingTimer = null;
          }, 500);
        }
      } else if (!this.streamText && !this.lastDeltaTime) {
        this.typingEl.style.display = "";
      }
    } else if (state === "lifecycle") {
      if (!this.streamText) {
        typingText.textContent = "Thinking";
        this.typingEl.style.display = "";
      }
    }

    // Handle explicit tool events (persistent in chat + typing indicator)
    const toolName = payload.data?.name || payload.data?.toolName || payload.toolName || payload.name || "";
    const phase = payload.data?.phase || payload.phase || "";

    if ((stream === "tool" || toolName) && (phase === "start" || state === "tool_use")) {
      if (this.compactTimer) { clearTimeout(this.compactTimer); this.compactTimer = null; }
      if (this.workingTimer) { clearTimeout(this.workingTimer); this.workingTimer = null; }
      // Record where in the text this tool call happened
      if (this.streamText) {
        this.streamSplitPoints.push(this.streamText.length);
      }
      // Freeze the current streaming bubble in place (don't delete it)
      if (this.streamEl) {
        this.streamEl.removeClass("openclaw-streaming");
        this.streamEl = null; // Next text delta will create a new bubble below the tool item
      }
      const { label, url } = this.buildToolLabel(toolName, payload.data?.args || payload.args);
      this.currentToolCalls.push(label);
      this.streamItems.push({ type: "tool", label, url } as StreamItem);
      this.appendToolCall(label, url, true); // true = active (animated)
      this.typingEl.style.display = "none";
    } else if ((stream === "tool" || toolName) && phase === "result") {
      // Tool finished — remove animated dots from last tool item
      this.deactivateLastToolItem();
      typingText.textContent = "Thinking";
      this.typingEl.style.display = "";
      this.scrollToBottom();
    } else if (stream === "compaction" || state === "compacting") {
      this.currentToolCalls.push("Compacting memory");
      this.streamItems.push({ type: "tool", label: "Compacting memory" });
      this.appendToolCall("Compacting memory");
      this.typingEl.style.display = "none";
      this.showBanner("Compacting context...");
    }
  }

  handleChatEvent(payload: any): void {
    // Session key "main" resolves to "agent:main:main" on the gateway
    const sk = this.plugin.settings.sessionKey;
    const payloadSk = payload.sessionKey ?? "";
    if (payloadSk !== sk && payloadSk !== `agent:main:${sk}` && !payloadSk.endsWith(`:${sk}`)) return;

    // No active stream (passive device): still refresh history and inject any locally collected stream items
    if (!this.streamRunId && (payload.state === "final" || payload.state === "aborted" || payload.state === "error")) {
      const items = [...this.streamItems];
      this.streamItems = [];
      this.currentToolCalls = [];
      // Passive device: refresh history on final
      this.loadHistory().then(() => {
        if (items.length > 0) {
          // Persist on passive device too
          const lastAssistant = [...this.messages].reverse().find(m => m.role === "assistant");
          if (lastAssistant) {
            const key = String(lastAssistant.timestamp);
            if (!this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
            this.plugin.settings.streamItemsMap[key] = items;
            this.plugin.saveSettings();
          }
          this.insertStreamItemsBeforeLastAssistant(items);
        }
      });
      return;
    }

    if (payload.state === "delta") {
      // Clear timers, hide typing indicator once we have text to show
      if (this.compactTimer) { clearTimeout(this.compactTimer); this.compactTimer = null; }
      if (this.workingTimer) { clearTimeout(this.workingTimer); this.workingTimer = null; }
      this.lastDeltaTime = Date.now();
      this.typingEl.style.display = "none";
      this.hideBanner();
      // Extract text from delta - could be string or content blocks
      const text = this.extractDeltaText(payload.message);
      if (text) {
        this.streamText = text;
        this.updateStreamBubble();
      }
    } else if (payload.state === "final") {
      // Use the final message text (authoritative)
      const finalText = this.extractDeltaText(payload.message) || this.streamText || "";
      const toolItems = this.streamItems.filter(i => i.type === "tool");
      
      // Only persist tool items (text comes from history — no duplication risk)
      this.streamItems = toolItems;
      const items = [...this.streamItems];
      this.finishStream();

      // Load history and re-render with interleaved items
      this.loadHistory(true).then(async () => {
        if (items.length > 0) {
          const lastAssistant = [...this.messages].reverse().find(m => m.role === "assistant");
          if (lastAssistant) {
            const key = String(lastAssistant.timestamp);
            if (!this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
            this.plugin.settings.streamItemsMap[key] = items;
            const keys = Object.keys(this.plugin.settings.streamItemsMap);
            if (keys.length > 100) {
              keys.sort().slice(0, keys.length - 100).forEach(k => delete this.plugin.settings.streamItemsMap![k]);
            }
            await this.plugin.saveSettings();
          }
        }
        // Re-render with interleaved items now that data is saved
        await this.renderMessages();
      });
    } else if (payload.state === "aborted") {
      if (this.streamText) {
        this.messages.push({ role: "assistant", text: this.streamText, images: [], timestamp: Date.now() });
      }
      this.finishStream();
      this.renderMessages();
    } else if (payload.state === "error") {
      this.messages.push({
        role: "assistant",
        text: `Error: ${payload.errorMessage ?? "unknown error"}`,
        images: [],
        timestamp: Date.now(),
      });
      this.finishStream();
      this.renderMessages();
    }
  }

  private finishStream(): void {
    if (this.compactTimer) { clearTimeout(this.compactTimer); this.compactTimer = null; }
    if (this.workingTimer) { clearTimeout(this.workingTimer); this.workingTimer = null; }
    this.hideBanner();
    this.streamRunId = null;
    this.streamText = null;
    this.lastDeltaTime = 0;
    this.currentToolCalls = [];
    this.streamItems = [];
    this.streamSplitPoints = [];
    this.streamEl = null;
    this.abortBtn.style.display = "none";
    this.typingEl.style.display = "none";
    const typingText = this.typingEl.querySelector(".openclaw-typing-text");
    if (typingText) typingText.textContent = "Thinking";
  }

  private insertStreamItemsBeforeLastAssistant(items: StreamItem[]): void {
    if (items.length === 0) return;
    const bubbles = this.messagesEl.querySelectorAll(".openclaw-msg-assistant");
    const lastBubble = bubbles[bubbles.length - 1];
    if (!lastBubble) return;

    for (const item of items) {
      const el = this.createStreamItemEl(item);
      lastBubble.parentElement?.insertBefore(el, lastBubble);
    }
    this.scrollToBottom();
  }

  private createStreamItemEl(item: StreamItem): HTMLElement {
    if (item.type === "tool") {
      const el = document.createElement("div");
      el.className = "openclaw-tool-item";
      if (item.url) {
        const link = document.createElement("a");
        link.href = item.url;
        link.textContent = item.label;
        link.className = "openclaw-tool-link";
        link.addEventListener("click", (e) => { e.preventDefault(); window.open(item.url!, "_blank"); });
        el.appendChild(link);
      } else {
        el.textContent = item.label;
      }
      return el;
    } else {
      const details = document.createElement("details");
      details.className = "openclaw-intermediary";
      const summary = document.createElement("summary");
      summary.className = "openclaw-intermediary-summary";
      const preview = item.text.length > 60 ? item.text.slice(0, 60) + "..." : item.text;
      summary.textContent = preview;
      details.appendChild(summary);
      const content = document.createElement("div");
      content.className = "openclaw-intermediary-content";
      content.textContent = item.text;
      details.appendChild(content);
      return details;
    }
  }

  private cleanText(text: string): string {
    text = text.replace(/Conversation info \(untrusted metadata\):\s*```json[\s\S]*?```\s*/g, "").trim();
    text = text.replace(/^```json\s*\{\s*"message_id"[\s\S]*?```\s*/gm, "").trim();
    text = text.replace(/^\[.*?GMT[+-]\d+\]\s*/gm, "").trim();
    text = text.replace(/^\[media attached:.*?\]\s*/gm, "").trim();
    text = text.replace(/^To send an image back.*$/gm, "").trim();
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK") return "";
    return text;
  }

  private extractDeltaText(msg: any): string {
    if (typeof msg === "string") return msg;
    // Gateway sends {role, content, timestamp} where content is [{type:"text", text:"..."}]
    const content = msg?.content ?? msg;
    if (Array.isArray(content)) {
      let text = "";
      for (const block of content) {
        if (typeof block === "string") { text += block; }
        else if (block?.text) { text += (text ? "\n" : "") + block.text; }
      }
      return text;
    }
    if (typeof content === "string") return content;
    return msg?.text ?? "";
  }

  private updateStreamBubble(): void {
    if (!this.streamText) return;
    const visibleText = this.streamText;
    if (!visibleText) return;
    if (!this.streamEl) {
      this.streamEl = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant openclaw-streaming");
      this.scrollToBottom(); // Scroll once when bubble first appears
    }
    this.streamEl.empty();
    this.streamEl.createDiv({ text: visibleText, cls: "openclaw-msg-text" });
    // Don't auto-scroll during text streaming — let user read from the top
  }

  async renderMessages(): Promise<void> {
    this.messagesEl.empty();
    const itemsMap = this.plugin.settings.streamItemsMap || {};
    for (const msg of this.messages) {
      if (msg.role === "assistant") {
        // Check if content blocks have tool_use (gateway may include them)
        const hasContentTools = msg.contentBlocks?.some((b: any) => b.type === "tool_use") || false;
        // Check if we have persisted stream items with tools
        const key = String(msg.timestamp);
        const stored = itemsMap[key];
        const storedTools = stored?.filter((s: StreamItem) => s.type === "tool") || [];

        if (hasContentTools && msg.contentBlocks) {
          // Best case: content blocks have tools interleaved — use them directly
          for (const block of msg.contentBlocks) {
            if (block.type === "text" && block.text?.trim()) {
              const cleaned = this.cleanText(block.text);
              if (!cleaned) continue;
              const bubble = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant");
              try {
                await MarkdownRenderer.render(this.app, cleaned, bubble, "", this.plugin);
              } catch {
                bubble.createDiv({ text: cleaned, cls: "openclaw-msg-text" });
              }
            } else if (block.type === "tool_use") {
              const { label, url } = this.buildToolLabel(block.name || "", block.input || {});
              const el = this.createStreamItemEl({ type: "tool", label, url } as StreamItem);
              this.messagesEl.appendChild(el);
            }
          }
          continue;
        }

        if (storedTools.length > 0) {
          // Render stored tool items before the text bubble
          for (const item of storedTools) {
            this.messagesEl.appendChild(this.createStreamItemEl(item));
          }
          // Fall through to render the text bubble normally
        }
      }
      const cls = msg.role === "user" ? "openclaw-msg-user" : "openclaw-msg-assistant";
      const bubble = this.messagesEl.createDiv(`openclaw-msg ${cls}`);
      // Render images
      if (msg.images && msg.images.length > 0) {
        const imgContainer = bubble.createDiv("openclaw-msg-images");
        for (const src of msg.images) {
          const img = imgContainer.createEl("img", {
            cls: "openclaw-msg-img",
            attr: { src, loading: "lazy" },
          });
          img.addEventListener("click", () => {
            // Open full-size in a modal-like overlay
            const overlay = document.body.createDiv("openclaw-img-overlay");
            const fullImg = overlay.createEl("img", { attr: { src } });
            overlay.addEventListener("click", () => overlay.remove());
          });
        }
      }
      // Render text
      if (msg.text) {
        if (msg.role === "assistant") {
          try {
            await MarkdownRenderer.render(this.app, msg.text, bubble, "", this.plugin);
          } catch {
            bubble.createDiv({ text: msg.text, cls: "openclaw-msg-text" });
          }
        } else {
          bubble.createDiv({ text: msg.text, cls: "openclaw-msg-text" });
        }
      }
    }
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    if (this.messagesEl) {
      // Use requestAnimationFrame to ensure DOM has updated
      requestAnimationFrame(() => {
        this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
      });
    }
  }

  private autoResize(): void {
    this.inputEl.style.height = "auto";
    this.inputEl.style.height = Math.min(this.inputEl.scrollHeight, 150) + "px";
  }
}

// ─── Main Plugin ─────────────────────────────────────────────────────

export default class OpenClawPlugin extends Plugin {
  settings: OpenClawSettings = DEFAULT_SETTINGS;
  gateway: GatewayClient | null = null;
  gatewayConnected = false;
  chatView: OpenClawChatView | null = null;

  async onload(): Promise<void> {
    await this.loadSettings();

    this.registerView(VIEW_TYPE, (leaf) => new OpenClawChatView(leaf, this));

    // Ribbon icon
    this.addRibbonIcon("message-square", "OpenClaw Chat", () => {
      this.activateView();
    });

    // Commands
    this.addCommand({
      id: "toggle-chat",
      name: "Toggle chat sidebar",
      callback: () => this.activateView(),
    });

    this.addCommand({
      id: "ask-about-note",
      name: "Ask about current note",
      callback: () => this.askAboutNote(),
    });

    this.addCommand({
      id: "reconnect",
      name: "Reconnect to gateway",
      callback: () => this.connectGateway(),
    });

    this.addCommand({
      id: "setup",
      name: "Run setup wizard",
      callback: () => new OnboardingModal(this.app, this).open(),
    });

    this.addSettingTab(new OpenClawSettingTab(this.app, this));

    // Show onboarding on first run, otherwise auto-connect and open chat
    if (!this.settings.onboardingComplete) {
      // Small delay so Obsidian finishes loading
      setTimeout(() => new OnboardingModal(this.app, this).open(), 500);
    } else {
      this.connectGateway();
      // Auto-open chat sidebar after workspace is ready
      this.app.workspace.onLayoutReady(() => {
        this.activateView();
      });
    }
  }

  onunload(): void {
    this.gateway?.stop();
    this.gateway = null;
    this.gatewayConnected = false;
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  async connectGateway(): Promise<void> {
    this.gateway?.stop();
    this.gatewayConnected = false;
    this.chatView?.updateStatus();

    const url = this.settings.gatewayUrl.trim();
    if (!url) return;

    // Security: validate URL scheme
    if (!url.startsWith("ws://") && !url.startsWith("wss://")) {
      new Notice("OpenClaw: Invalid gateway URL (must be ws:// or wss://)");
      return;
    }

    // Get or create device identity for scope authorization
    let deviceIdentity: DeviceIdentity | undefined;
    try {
      deviceIdentity = await getOrCreateDeviceIdentity(
        () => this.loadData(),
        (data) => this.saveData(data)
      );
    } catch (e) {
      console.warn("[ObsidianClaw] Device identity creation failed, connecting without scopes:", e);
    }

    this.gateway = new GatewayClient({
      url,
      token: this.settings.token.trim() || undefined,
      deviceIdentity,
      onHello: () => {
        this.gatewayConnected = true;
        this.chatView?.updateStatus();
        this.chatView?.loadHistory();
      },
      onClose: (info) => {
        this.gatewayConnected = false;
        this.chatView?.updateStatus();
        // Show pairing instructions if needed
        if (info.reason.includes("pairing required") || info.reason.includes("device identity required")) {
          new Notice("OpenClaw: Device pairing required. Run 'openclaw devices approve' on your gateway machine.", 10000);
        }
      },
      onEvent: (evt) => {
        if (evt.event === "chat") {
          this.chatView?.handleChatEvent(evt.payload);
        } else if (evt.event === "stream" || evt.event === "agent") {
          this.chatView?.handleStreamEvent(evt.payload);
        }
      },
    });

    this.gateway.start();
  }

  async activateView(): Promise<void> {
    const existing = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    if (existing.length > 0) {
      this.app.workspace.revealLeaf(existing[0]);
      return;
    }
    const leaf = this.app.workspace.getRightLeaf(false);
    if (leaf) {
      await leaf.setViewState({ type: VIEW_TYPE, active: true });
      this.app.workspace.revealLeaf(leaf);
    }
  }

  async askAboutNote(): Promise<void> {
    const file = this.app.workspace.getActiveFile();
    if (!file) {
      new Notice("No active note");
      return;
    }

    const content = await this.app.vault.read(file);
    if (!content.trim()) {
      new Notice("Note is empty");
      return;
    }

    await this.activateView();

    if (!this.chatView || !this.gateway?.connected) {
      new Notice("Not connected to OpenClaw");
      return;
    }

    const message = `Here is my current note "${file.basename}":\n\n${content}\n\nWhat can you tell me about this?`;
    const inputEl = this.chatView.containerEl.querySelector(".openclaw-input") as HTMLTextAreaElement;
    if (inputEl) {
      inputEl.value = message;
      inputEl.focus();
    }
  }
}

// ─── Attachment Picker ───────────────────────────────────────────────

class AttachmentModal extends FuzzySuggestModal<TFile> {
  private files: TFile[];
  private onChoose: (file: TFile) => void;

  constructor(app: App, files: TFile[], onChoose: (file: TFile) => void) {
    super(app);
    this.files = files;
    this.onChoose = onChoose;
    this.setPlaceholder("Search files to attach...");
  }

  getItems(): TFile[] {
    return this.files;
  }

  getItemText(file: TFile): string {
    return file.path;
  }

  onChooseItem(file: TFile): void {
    this.onChoose(file);
  }
}

// ─── Settings Tab ────────────────────────────────────────────────────

class OpenClawSettingTab extends PluginSettingTab {
  plugin: OpenClawPlugin;

  constructor(app: App, plugin: OpenClawPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "OpenClaw" });

    new Setting(containerEl)
      .setName("Gateway URL")
      .setDesc("WebSocket URL (e.g., ws://127.0.0.1:18789 or ws://100.x.x.x:18789 via Tailscale)")
      .addText((text) =>
        text
          .setPlaceholder("ws://127.0.0.1:18789")
          .setValue(this.plugin.settings.gatewayUrl)
          .onChange(async (value) => {
            this.plugin.settings.gatewayUrl = value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Auth Token")
      .setDesc("Gateway auth token (leave empty if no auth)")
      .addText((text) => {
        text.inputEl.type = "password";
        return text
          .setPlaceholder("Token")
          .setValue(this.plugin.settings.token)
          .onChange(async (value) => {
            this.plugin.settings.token = value;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Session Key")
      .setDesc("Which session to chat in")
      .addText((text) =>
        text
          .setPlaceholder("main")
          .setValue(this.plugin.settings.sessionKey)
          .onChange(async (value) => {
            this.plugin.settings.sessionKey = value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Reconnect")
      .setDesc("Re-establish the gateway connection")
      .addButton((btn) =>
        btn.setButtonText("Reconnect").onClick(() => {
          this.plugin.connectGateway();
          new Notice("OpenClaw: Reconnecting...");
        })
      );

    new Setting(containerEl)
      .setName("Run setup wizard")
      .setDesc("Re-run the onboarding flow")
      .addButton((btn) =>
        btn.setButtonText("Setup").onClick(() => {
          new OnboardingModal(this.app, this.plugin).open();
        })
      );
  }
}
