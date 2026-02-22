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

interface OpenClawSettings {
  gatewayUrl: string;
  token: string;
  sessionKey: string;
  onboardingComplete: boolean;
  deviceId?: string;
  devicePublicKey?: string;
  devicePrivateKey?: string;
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
      caps: [],
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
  timestamp: number;
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
      text: "This plugin connects Obsidian to your OpenClaw AI agent. Your vault becomes the agent's workspace — it can read your notes, create new ones, and search across everything.",
      cls: "openclaw-onboard-desc",
    });

    el.createEl("h3", { text: "Before you start" });
    const list = el.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", {
      text: "OpenClaw must be running on your machine (or reachable via Tailscale)",
    });
    list.createEl("li", {
      text: "Your Obsidian vault should be the OpenClaw workspace (~/.openclaw/workspace)",
    });
    list.createEl("li", {
      text: "If your gateway requires auth, have your token ready",
    });

    const info = el.createDiv("openclaw-onboard-info");
    info.createEl("strong", { text: "Don't have OpenClaw yet? " });
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
      text: "Enter your OpenClaw gateway address. If it's running on this machine, the default should work.",
      cls: "openclaw-onboard-desc",
    });

    // URL input
    const urlGroup = el.createDiv("openclaw-onboard-field");
    urlGroup.createEl("label", { text: "Gateway URL" });
    this.urlInput = urlGroup.createEl("input", {
      type: "text",
      value: this.plugin.settings.gatewayUrl,
      placeholder: "ws://127.0.0.1:18789",
      cls: "openclaw-onboard-input",
    });

    const urlHint = urlGroup.createDiv("openclaw-onboard-hint");
    urlHint.innerHTML = "<strong>Local:</strong> ws://127.0.0.1:18789 &nbsp;|&nbsp; <strong>Tailscale:</strong> ws://100.x.x.x:18789";

    // Token input
    const tokenGroup = el.createDiv("openclaw-onboard-field");
    tokenGroup.createEl("label", { text: "Auth Token (optional)" });
    this.tokenInput = tokenGroup.createEl("input", {
      type: "password",
      value: this.plugin.settings.token,
      placeholder: "Leave empty if no auth configured",
      cls: "openclaw-onboard-input",
    });

    // Security note
    const secNote = el.createDiv("openclaw-onboard-security");
    secNote.createEl("strong", { text: "🔒 Security" });
    secNote.createEl("p", {
      text: "Your token is stored locally in this vault's plugin data and never sent anywhere except your own gateway. All communication stays between Obsidian and your OpenClaw instance.",
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
    el.createEl("h2", { text: "You're all set!" });
    el.createEl("p", {
      text: "OpenClaw is connected. Click the chat icon (💬) in the left ribbon to open the sidebar and start chatting with your AI.",
      cls: "openclaw-onboard-desc",
    });

    const tips = el.createDiv("openclaw-onboard-tips");
    tips.createEl("h3", { text: "Quick tips" });
    const list = tips.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", { text: "Use Cmd/Ctrl+P → \"Ask about current note\" to send any note as context" });
    list.createEl("li", { text: "The agent can read and edit files in your vault directly" });
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
  private abortBtn!: HTMLButtonElement;
  private statusEl!: HTMLElement;
  private messages: ChatMessage[] = [];
  private streamText: string | null = null;
  private streamRunId: string | null = null;
  private streamEl: HTMLElement | null = null;
  private typingEl!: HTMLElement;
  private attachPreviewEl!: HTMLElement;
  private fileInputEl!: HTMLInputElement;
  private pendingAttachment: { name: string; content: string } | null = null;
  private sending = false;

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
      attr: { type: "file", accept: "image/*,.md,.txt,.json,.csv,.pdf,.yaml,.yml,.js,.ts,.py,.html,.css" },
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
    this.statusEl.addClass(this.plugin.gatewayConnected ? "connected" : "disconnected");
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
          .map((m: any) => ({
            role: m.role as "user" | "assistant",
            text: this.extractText(m.content),
            timestamp: m.timestamp ?? Date.now(),
          }))
          .filter((m: ChatMessage) => m.text.trim() && !m.text.startsWith("HEARTBEAT"));
        await this.renderMessages();
      }
    } catch (e) {
      console.error("[ObsidianClaw] Failed to load history:", e);
    }
  }

  private extractText(content: any): string {
    let text = "";
    if (typeof content === "string") {
      text = content;
    } else if (Array.isArray(content)) {
      text = content
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text)
        .join("\n");
    }
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
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK") return "";
    return text;
  }

  async sendMessage(): Promise<void> {
    let text = this.inputEl.value.trim();
    if (!text && !this.pendingAttachment) return;
    if (this.sending) return;
    if (!this.plugin.gateway?.connected) {
      new Notice("Not connected to OpenClaw gateway");
      return;
    }

    this.sending = true;
    this.sendBtn.disabled = true;
    this.inputEl.value = "";
    this.autoResize();

    // Append attachment content to message
    let fullMessage = text;
    const displayText = text;
    if (this.pendingAttachment) {
      fullMessage = (text ? text + "\n\n" : "") + this.pendingAttachment.content;
      if (!text) text = `📎 ${this.pendingAttachment.name}`;
      this.pendingAttachment = null;
      this.attachPreviewEl.style.display = "none";
    }

    this.messages.push({ role: "user", text: displayText || text, timestamp: Date.now() });
    await this.renderMessages();

    const runId = generateId();
    this.streamRunId = runId;
    this.streamText = "";
    this.abortBtn.style.display = "";
    this.typingEl.style.display = "";
    this.scrollToBottom();

    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: fullMessage,
        deliver: false,
        idempotencyKey: runId,
      });
    } catch (e) {
      this.messages.push({ role: "assistant", text: `Error: ${e}`, timestamp: Date.now() });
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
    const file = this.fileInputEl.files?.[0];
    if (!file) return;

    try {
      const isImage = file.type.startsWith("image/");
      const isText = file.type.startsWith("text/") ||
        ["application/json", "application/yaml", "application/xml", "application/javascript"].includes(file.type) ||
        /\.(md|txt|json|csv|yaml|yml|js|ts|py|html|css|xml|toml|ini|sh|log)$/i.test(file.name);

      if (isImage) {
        // Read as base64, send inline (don't save to vault)
        const arrayBuf = await file.arrayBuffer();
        const bytes = new Uint8Array(arrayBuf);
        let binary = "";
        for (const b of bytes) binary += String.fromCharCode(b);
        const b64 = btoa(binary);
        this.pendingAttachment = {
          name: file.name,
          content: `[Attached image: ${file.name} (${file.type}, ${Math.round(file.size/1024)}KB)]\ndata:${file.type};base64,${b64}`,
        };
      } else if (isText) {
        const content = await file.text();
        const truncated = content.length > 10000 ? content.slice(0, 10000) + "\n...(truncated)" : content;
        this.pendingAttachment = {
          name: file.name,
          content: `File: ${file.name}\n\`\`\`\n${truncated}\n\`\`\``,
        };
      } else {
        // Binary: describe it, can't meaningfully send
        this.pendingAttachment = {
          name: file.name,
          content: `[Attached file: ${file.name} (${file.type || "unknown type"}, ${Math.round(file.size/1024)}KB)]`,
        };
      }

      // Show preview
      this.attachPreviewEl.empty();
      this.attachPreviewEl.style.display = "flex";
      this.attachPreviewEl.createSpan({ text: `📎 ${file.name}`, cls: "openclaw-attach-name" });
      const removeBtn = this.attachPreviewEl.createEl("button", { text: "✕", cls: "openclaw-attach-remove" });
      removeBtn.addEventListener("click", () => {
        this.pendingAttachment = null;
        this.attachPreviewEl.style.display = "none";
      });
    } catch (e) {
      new Notice(`Failed to attach file: ${e}`);
    }

    // Reset input so the same file can be re-selected
    this.fileInputEl.value = "";
  }

  handleChatEvent(payload: any): void {
    // Session key "main" resolves to "agent:main:main" on the gateway
    const sk = this.plugin.settings.sessionKey;
    const payloadSk = payload.sessionKey ?? "";
    if (payloadSk !== sk && payloadSk !== `agent:main:${sk}` && !payloadSk.endsWith(`:${sk}`)) return;

    if (payload.state === "delta") {
      // Switch from "Thinking" to "Typing" once streaming begins
      const typingText = this.typingEl.querySelector(".openclaw-typing-text");
      if (typingText) typingText.textContent = "Typing";
      const text = this.extractText(payload.message);
      if (typeof text === "string") {
        this.streamText = text;
        this.updateStreamBubble();
      }
    } else if (payload.state === "final") {
      this.finishStream();
      this.loadHistory();
    } else if (payload.state === "aborted") {
      if (this.streamText) {
        this.messages.push({ role: "assistant", text: this.streamText, timestamp: Date.now() });
      }
      this.finishStream();
      this.renderMessages();
    } else if (payload.state === "error") {
      this.messages.push({
        role: "assistant",
        text: `Error: ${payload.errorMessage ?? "unknown error"}`,
        timestamp: Date.now(),
      });
      this.finishStream();
      this.renderMessages();
    }
  }

  private finishStream(): void {
    this.streamRunId = null;
    this.streamText = null;
    this.streamEl = null;
    this.abortBtn.style.display = "none";
    this.typingEl.style.display = "none";
    // Reset for next message
    const typingText = this.typingEl.querySelector(".openclaw-typing-text");
    if (typingText) typingText.textContent = "Thinking";
  }

  private updateStreamBubble(): void {
    if (!this.streamText) return;
    if (!this.streamEl) {
      this.streamEl = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant openclaw-streaming");
      this.scrollToBottom();
    }
    this.streamEl.empty();
    this.streamEl.createDiv({ text: this.streamText, cls: "openclaw-msg-text" });
    this.scrollToBottom();
  }

  async renderMessages(): Promise<void> {
    this.messagesEl.empty();
    for (const msg of this.messages) {
      const cls = msg.role === "user" ? "openclaw-msg-user" : "openclaw-msg-assistant";
      const bubble = this.messagesEl.createDiv(`openclaw-msg ${cls}`);
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
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    if (this.messagesEl) {
      this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
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

    // Show onboarding on first run, otherwise auto-connect
    if (!this.settings.onboardingComplete) {
      // Small delay so Obsidian finishes loading
      setTimeout(() => new OnboardingModal(this.app, this).open(), 500);
    } else {
      this.connectGateway();
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
