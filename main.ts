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
  currentModel?: string;  // persisted model selection (provider/model format)
  onboardingComplete: boolean;
  deviceId?: string;
  devicePublicKey?: string;
  devicePrivateKey?: string;
  /** Persisted stream items (tool calls + intermediary text) keyed by assistant message index */
  streamItemsMap?: Record<string, StreamItem[]>;
}

const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: "",
  token: "",
  sessionKey: "main",
  onboardingComplete: false,
};

// ─── Device Identity (Ed25519) ───────────────────────────────────────

/** Normalize a gateway URL: accepts ws://, wss://, http://, https:// and returns ws:// or wss://. Returns null if invalid. */
function normalizeGatewayUrl(raw: string): string | null {
  let url = raw.trim();
  if (url.startsWith("https://")) url = "wss://" + url.slice(8);
  else if (url.startsWith("http://")) url = "ws://" + url.slice(7);
  if (!url.startsWith("ws://") && !url.startsWith("wss://")) return null;
  // Strip trailing slash for consistency
  return url.replace(/\/+$/, "");
}

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

    // Normalize and validate URL
    const url = normalizeGatewayUrl(this.opts.url);
    if (!url) {
      console.error("[ObsidianClaw] Invalid gateway URL: must be a valid ws://, wss://, http://, or https:// URL");
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
  voiceRefs?: string[]; // VOICE:filename.b64 refs for audio playback via gateway
}

// ─── Onboarding Modal ────────────────────────────────────────────────

class OnboardingModal extends Modal {
  plugin: OpenClawPlugin;
  private step = 0;
  private statusEl: HTMLElement | null = null;
  private pairingPollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(app: App, plugin: OpenClawPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("openclaw-onboarding");
    this.renderStep();
  }

  onClose(): void {
    if (this.pairingPollTimer) { clearInterval(this.pairingPollTimer); this.pairingPollTimer = null; }
  }

  private renderStep(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.statusEl = null;

    // Step indicator
    const steps = ["Install", "Network", "Gateway", "Connect", "Pair", "Done"];
    const indicator = contentEl.createDiv("openclaw-onboard-steps");
    steps.forEach((label, i) => {
      const dot = indicator.createSpan("openclaw-step-dot" + (i === this.step ? " active" : i < this.step ? " done" : ""));
      dot.textContent = i < this.step ? "✓" : String(i + 1);
      if (i < steps.length - 1) indicator.createSpan("openclaw-step-line" + (i < this.step ? " done" : ""));
    });

    if (this.step === 0) this.renderInstall(contentEl);
    else if (this.step === 1) this.renderNetwork(contentEl);
    else if (this.step === 2) this.renderGateway(contentEl);
    else if (this.step === 3) this.renderConnect(contentEl);
    else if (this.step === 4) this.renderPairing(contentEl);
    else if (this.step === 5) this.renderDone(contentEl);
  }

  // ─── Step 0: Install ─────────────────────────────────────────────

  private renderInstall(el: HTMLElement): void {
    el.createEl("h2", { text: "Welcome to OpenClaw" });
    el.createEl("p", {
      text: "This plugin connects Obsidian to your OpenClaw AI agent. Your vault becomes the agent's workspace — it reads your notes, creates new ones, and works alongside you.",
      cls: "openclaw-onboard-desc",
    });

    el.createEl("h3", { text: "Before we start" });
    el.createEl("p", {
      text: "You need OpenClaw running on a computer that stays on (a Mac, PC, or VPS). This is your \"gateway\" — the brain that runs your AI agent.",
      cls: "openclaw-onboard-desc",
    });

    const list = el.createEl("ul", { cls: "openclaw-onboard-list" });
    const li = list.createEl("li");
    li.innerHTML = "Don't have OpenClaw yet? Follow the <a href='https://botsetupguide.com'>setup guide</a> first, then come back here.";
    list.createEl("li", { text: "Already have OpenClaw running? Click next." });

    this.statusEl = el.createDiv("openclaw-onboard-status");

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const nextBtn = btnRow.createEl("button", { text: "I have OpenClaw running →", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => { this.step = 1; this.renderStep(); });
  }

  // ─── Step 1: Network (Tailscale) ─────────────────────────────────

  private renderNetwork(el: HTMLElement): void {
    el.createEl("h2", { text: "Set up your private network" });
    el.createEl("p", {
      text: "Tailscale creates an encrypted private network between your devices. It's how this device talks to your gateway securely — no ports to open, no VPN to configure.",
      cls: "openclaw-onboard-desc",
    });

    el.createEl("h3", { text: "Install Tailscale on both devices" });

    const steps = el.createEl("ol", { cls: "openclaw-onboard-list" });
    const s1 = steps.createEl("li");
    s1.innerHTML = "Install on your <strong>gateway machine</strong> (where OpenClaw runs): <a href='https://tailscale.com/download'>tailscale.com/download</a>";
    const s2 = steps.createEl("li");
    s2.innerHTML = "Install on <strong>this device</strong> (where you're reading this): <a href='https://tailscale.com/download'>tailscale.com/download</a>";
    steps.createEl("li", { text: "Sign in to the same Tailscale account on both devices." });

    el.createEl("p", {
      text: "Both devices will appear on your private tailnet. You can verify by running this on your gateway machine:",
      cls: "openclaw-onboard-hint",
    });
    this.makeCopyBox(el, "tailscale status");

    const checkInfo = el.createDiv("openclaw-onboard-info");
    checkInfo.createEl("span", { text: "You should see both devices listed. If this device doesn't appear, make sure Tailscale is connected (check the system tray / menu bar icon)." });

    this.statusEl = el.createDiv("openclaw-onboard-status");

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "← Back" }).addEventListener("click", () => { this.step = 0; this.renderStep(); });
    const nextBtn = btnRow.createEl("button", { text: "Both devices are on Tailscale →", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => { this.step = 2; this.renderStep(); });
  }

  // ─── Step 2: Gateway (Tailscale Serve) ────────────────────────────

  private renderGateway(el: HTMLElement): void {
    el.createEl("h2", { text: "Expose your gateway securely" });
    el.createEl("p", {
      text: "Tailscale Serve makes your gateway reachable from all your Tailscale devices with automatic HTTPS. Run these commands on your gateway machine (in Terminal):",
      cls: "openclaw-onboard-desc",
    });

    const steps = el.createDiv("openclaw-onboard-numbered");

    // Step 1: Enable Tailscale Serve
    const s1 = steps.createDiv("openclaw-onboard-numbered-item");
    s1.createEl("strong", { text: "1. Start Tailscale Serve" });
    s1.createEl("p", { text: "This tells Tailscale to securely proxy traffic to your gateway:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(s1, "tailscale serve --bg http://127.0.0.1:18789");

    // Step 2: Verify it's working
    const s2 = steps.createDiv("openclaw-onboard-numbered-item");
    s2.createEl("strong", { text: "2. Verify it's running" });
    s2.createEl("p", { text: "You should see your gateway URL in the output:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(s2, "tailscale serve status");

    // Step 3: Note the URL
    const s3 = steps.createDiv("openclaw-onboard-numbered-item");
    s3.createEl("strong", { text: "3. Copy your gateway URL" });
    const s3hint = s3.createEl("p", { cls: "openclaw-onboard-hint" });
    s3hint.innerHTML = "The output will show something like:<br><code>https://your-machine.tail1234.ts.net</code><br>Copy that URL — you'll paste it in the next step.";

    // Step 4: Get the auth token
    const s4 = steps.createDiv("openclaw-onboard-numbered-item");
    s4.createEl("strong", { text: "4. Copy your auth token" });
    s4.createEl("p", { text: "Run this to find your gateway auth token:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(s4, "cat ~/.openclaw/openclaw.json | grep token");
    const s4hint = s4.createEl("p", { cls: "openclaw-onboard-hint" });
    s4hint.innerHTML = "Copy the token value (the long string after <code>\"token\":</code>).";

    // Troubleshooting
    const trouble = el.createDiv("openclaw-onboard-info");
    trouble.createEl("strong", { text: "💡 Not working? " });
    trouble.createEl("span", { text: "Run this first to fix common issues:" });
    this.makeCopyBox(trouble, "openclaw doctor --fix && openclaw gateway restart");

    this.statusEl = el.createDiv("openclaw-onboard-status");

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "← Back" }).addEventListener("click", () => { this.step = 1; this.renderStep(); });
    const nextBtn = btnRow.createEl("button", { text: "I have the URL and token →", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => { this.step = 3; this.renderStep(); });
  }

  // ─── Step 3: Connect ─────────────────────────────────────────────

  private renderConnect(el: HTMLElement): void {
    el.createEl("h2", { text: "Connect to your gateway" });
    el.createEl("p", {
      text: "Paste the URL and token from the previous step.",
      cls: "openclaw-onboard-desc",
    });

    // URL input
    const urlGroup = el.createDiv("openclaw-onboard-field");
    urlGroup.createEl("label", { text: "Gateway URL" });
    const urlInput = urlGroup.createEl("input", {
      type: "text",
      value: this.plugin.settings.gatewayUrl || "",
      placeholder: "https://your-machine.tail1234.ts.net",
      cls: "openclaw-onboard-input",
    });
    const urlHint = urlGroup.createDiv("openclaw-onboard-hint");
    urlHint.innerHTML = "The URL from <code>tailscale serve status</code>. You can paste <code>https://</code> or <code>wss://</code> — both work.";

    // Token input
    const tokenGroup = el.createDiv("openclaw-onboard-field");
    tokenGroup.createEl("label", { text: "Auth Token" });
    const tokenInput = tokenGroup.createEl("input", {
      type: "password",
      value: this.plugin.settings.token || "",
      placeholder: "Paste your gateway auth token",
      cls: "openclaw-onboard-input",
    });

    this.statusEl = el.createDiv("openclaw-onboard-status");

    // Troubleshooting (hidden until failure)
    const troubleshoot = el.createDiv("openclaw-onboard-troubleshoot");
    troubleshoot.style.display = "none";
    troubleshoot.createEl("h3", { text: "Troubleshooting" });

    const checks = troubleshoot.createEl("ol", { cls: "openclaw-onboard-list" });

    const li1 = checks.createEl("li");
    li1.innerHTML = "<strong>Is Tailscale connected on this device?</strong> Check the Tailscale icon in your system tray / menu bar. If it's off, turn it on.";

    const li2 = checks.createEl("li");
    li2.innerHTML = "<strong>DNS not resolving? (most common on macOS)</strong> Open the <strong>Tailscale app</strong> from your menu bar, toggle it <strong>OFF</strong>, wait 5 seconds, toggle it <strong>ON</strong>. This resets MagicDNS, which macOS sometimes loses track of.";

    const li3 = checks.createEl("li");
    li3.innerHTML = "Is the gateway running? On the gateway machine, run:";
    this.makeCopyBox(troubleshoot, "openclaw doctor --fix && openclaw gateway restart");

    const li4 = checks.createEl("li");
    li4.innerHTML = "Is Tailscale Serve active? On the gateway machine, run:";
    this.makeCopyBox(troubleshoot, "tailscale serve status");
    const tsHint = troubleshoot.createDiv("openclaw-onboard-hint");
    tsHint.innerHTML = "If Tailscale Serve shows nothing, set it up:";
    this.makeCopyBox(troubleshoot, "tailscale serve --bg http://127.0.0.1:18789");

    const li5 = checks.createEl("li");
    li5.innerHTML = "<strong>Gateway config broken?</strong> If <code>openclaw doctor</code> shows \"Invalid config\" errors, your gateway config file may have been corrupted. To reset to the recommended setup, run these on the gateway machine:";
    this.makeCopyBox(troubleshoot, `cat ~/.openclaw/openclaw.json | python3 -c "
import json, sys
c = json.load(sys.stdin)
c.setdefault('gateway', {})['bind'] = 'loopback'
c['gateway'].setdefault('tailscale', {})['mode'] = 'serve'
c['gateway']['tailscale']['resetOnExit'] = False
json.dump(c, open(sys.argv[1], 'w'), indent=2)
print('Config fixed: bind=loopback, tailscale.mode=serve')
" ~/.openclaw/openclaw.json`);
    const li5hint = troubleshoot.createDiv("openclaw-onboard-hint");
    li5hint.innerHTML = "Then restart the gateway and re-enable Tailscale Serve:";
    this.makeCopyBox(troubleshoot, "openclaw gateway restart && tailscale serve --bg http://127.0.0.1:18789");

    const li6 = checks.createEl("li");
    li6.innerHTML = "<strong>Still stuck?</strong> Try restarting the Tailscale app entirely, or reboot this device. macOS DNS can get stuck and needs a fresh start.";

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "← Back" }).addEventListener("click", () => { this.step = 2; this.renderStep(); });

    const testBtn = btnRow.createEl("button", { text: "Test connection", cls: "mod-cta" });
    testBtn.addEventListener("click", async () => {
      const url = urlInput.value.trim();
      const token = tokenInput.value.trim();

      if (!url) { this.showStatus("Paste your gateway URL from the previous step", "error"); return; }
      const normalizedUrl = normalizeGatewayUrl(url);
      if (!normalizedUrl) {
        this.showStatus("That doesn't look right. Paste the URL from `tailscale serve status` (e.g. https://your-machine.tail1234.ts.net)", "error"); return;
      }
      if (!token) { this.showStatus("Paste your auth token", "error"); return; }

      testBtn.disabled = true;
      testBtn.textContent = "Connecting...";
      troubleshoot.style.display = "none";
      this.showStatus("Testing connection...", "info");

      // Always reset to "main" session to ensure clean connection
      urlInput.value = normalizedUrl;
      this.plugin.settings.gatewayUrl = normalizedUrl;
      this.plugin.settings.token = token;
      this.plugin.settings.sessionKey = "main";
      await this.plugin.saveSettings();

      const ok = await new Promise<boolean>((resolve) => {
        const timeout = setTimeout(() => { tc.stop(); resolve(false); }, 8000);
        const tc = new GatewayClient({
          url: normalizedUrl, token,
          onHello: () => { clearTimeout(timeout); tc.stop(); resolve(true); },
          onClose: () => {},
        });
        tc.start();
      });

      testBtn.disabled = false;
      testBtn.textContent = "Test connection";

      if (ok) {
        this.showStatus("✓ Connected!", "success");
        setTimeout(() => { this.step = 4; this.renderStep(); }, 800);
      } else {
        this.showStatus("Could not connect. Check the troubleshooting steps below.", "error");
        troubleshoot.style.display = "";
      }
    });
  }

  private makeCopyBox(parent: HTMLElement, command: string): HTMLElement {
    const box = parent.createDiv("openclaw-copy-box");
    box.createEl("code", { text: command });
    const btn = box.createSpan("openclaw-copy-btn");
    btn.textContent = "copy";
    box.addEventListener("click", () => {
      navigator.clipboard.writeText(command).then(() => {
        btn.textContent = "✓";
        setTimeout(() => btn.textContent = "copy", 1500);
      });
    });
    return box;
  }

  // ─── Step 4: Device Pairing ──────────────────────────────────────

  private renderPairing(el: HTMLElement): void {
    el.createEl("h2", { text: "Pair this device" });
    el.createEl("p", {
      text: "For security, each device needs one-time approval from the gateway. This creates a unique keypair for this device so the gateway knows it's you.",
      cls: "openclaw-onboard-desc",
    });

    const hasKeys = this.plugin.settings.deviceId && this.plugin.settings.devicePublicKey;

    if (hasKeys) {
      const info = el.createDiv("openclaw-onboard-info");
      info.createEl("p", { text: "This device already has a keypair." });
      info.createEl("p").innerHTML = `Device ID: <code>${this.plugin.settings.deviceId?.slice(0, 12)}...</code>`;
    }

    this.statusEl = el.createDiv("openclaw-onboard-status");

    // Approval instructions (always visible)
    const approvalInfo = el.createDiv("openclaw-onboard-numbered");
    const a1 = approvalInfo.createDiv("openclaw-onboard-numbered-item");
    a1.createEl("strong", { text: "How approval works" });
    a1.createEl("p", { text: "Click the button below to send a pairing request. Then, on your gateway machine, run:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(a1, "openclaw devices list");
    a1.createEl("p", { text: "You'll see your pending request. Approve it with:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(a1, "openclaw devices approve <requestId>");
    const a1hint = a1.createEl("p", { cls: "openclaw-onboard-hint" });
    a1hint.innerHTML = "Replace <code>&lt;requestId&gt;</code> with the ID shown in the pending list. You can also approve from the OpenClaw Control UI dashboard.";

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "← Back" }).addEventListener("click", () => { this.step = 3; this.renderStep(); });

    const pairBtn = btnRow.createEl("button", {
      text: hasKeys ? "Check pairing status" : "Send pairing request",
      cls: "mod-cta",
    });
    pairBtn.addEventListener("click", async () => {
      pairBtn.disabled = true;
      this.showStatus("Connecting to gateway...", "info");

      try {
        // Ensure we have a real connection to test pairing
        await this.plugin.connectGateway();

        // Wait a moment for connection to establish
        await new Promise(r => setTimeout(r, 2000));

        if (!this.plugin.gatewayConnected) {
          this.showStatus("Could not connect to gateway. Go back and check your settings.", "error");
          pairBtn.disabled = false;
          return;
        }

        // Try a simple request to verify pairing
        try {
          const result = await this.plugin.gateway!.request("sessions.list", {});
          if (result?.sessions) {
            this.showStatus("✓ Device is paired and authorized!", "success");
            setTimeout(() => { this.step = 5; this.renderStep(); }, 1000);
            return;
          }
        } catch (e: any) {
          // If we get an auth error, device needs approval
          const msg = String(e);
          if (msg.includes("scope") || msg.includes("auth") || msg.includes("pair")) {
            this.showStatus("⏳ Pairing request sent! Now approve it on your gateway machine using the commands above.\n\nWaiting for approval...", "info");
            this.startPairingPoll(pairBtn);
            return;
          }
        }

        // If we got here, connection works — might already be paired
        this.showStatus("✓ Connection working! Proceeding...", "success");
        setTimeout(() => { this.step = 5; this.renderStep(); }, 1000);
      } catch (e) {
        this.showStatus(`Error: ${e}`, "error");
        pairBtn.disabled = false;
      }
    });

    const skipBtn = btnRow.createEl("button", { text: "Skip for now" });
    skipBtn.addEventListener("click", () => { this.step = 5; this.renderStep(); });
  }

  private startPairingPoll(btn: HTMLButtonElement): void {
    let attempts = 0;
    this.pairingPollTimer = setInterval(async () => {
      attempts++;
      if (attempts > 60) { // 2 minutes
        if (this.pairingPollTimer) clearInterval(this.pairingPollTimer);
        this.showStatus("Timed out waiting for approval. You can approve later and re-run the setup wizard from settings.", "error");
        btn.disabled = false;
        return;
      }
      try {
        const result = await this.plugin.gateway?.request("sessions.list", {});
        if (result?.sessions) {
          if (this.pairingPollTimer) clearInterval(this.pairingPollTimer);
          this.showStatus("✓ Device approved!", "success");
          setTimeout(() => { this.step = 5; this.renderStep(); }, 1000);
        }
      } catch { /* still waiting */ }
    }, 2000);
  }

  // ─── Step 5: Done ────────────────────────────────────────────────

  private renderDone(el: HTMLElement): void {
    el.createEl("h2", { text: "You're all set! 🎉" });
    el.createEl("p", {
      text: "OpenClaw is connected and ready. Your vault is now the agent's workspace.",
      cls: "openclaw-onboard-desc",
    });

    const tips = el.createDiv("openclaw-onboard-tips");
    tips.createEl("h3", { text: "What you can do" });
    const list = tips.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", { text: "Chat with your AI agent in the sidebar" });
    list.createEl("li", { text: "Use Cmd/Ctrl+P → \"Ask about current note\" to discuss any note" });
    list.createEl("li", { text: "The agent can read, create, and edit files in your vault" });
    list.createEl("li", { text: "Tool calls appear inline — click file paths to open them" });

    const syncTip = el.createDiv("openclaw-onboard-info");
    syncTip.createEl("strong", { text: "💡 Sync tip: " });
    syncTip.createEl("span", {
      text: "Enable Obsidian Sync to access your agent from multiple devices. Your chat settings and device keys sync automatically — set up once, works everywhere.",
    });

    const controlTip = el.createDiv("openclaw-onboard-info");
    controlTip.createEl("strong", { text: "🖥️ Control UI: " });
    const ctrlSpan = controlTip.createEl("span");
    ctrlSpan.innerHTML = "You can also manage your gateway from any browser on your Tailscale network. Just open your gateway URL in a browser.";

    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const doneBtn = btnRow.createEl("button", { text: "Start chatting →", cls: "mod-cta" });
    doneBtn.addEventListener("click", async () => {
      this.plugin.settings.onboardingComplete = true;
      // Always reset to "main" session to ensure clean connection
      this.plugin.settings.sessionKey = "main";
      await this.plugin.saveSettings();
      this.close();
      if (!this.plugin.gatewayConnected) this.plugin.connectGateway();
      this.plugin.activateView();
    });
  }

  private showStatus(text: string, type: "info" | "success" | "error"): void {
    if (!this.statusEl) return;
    this.statusEl.empty();
    this.statusEl.className = `openclaw-onboard-status openclaw-onboard-status-${type}`;
    // Support multiline with \n
    for (const line of text.split("\n")) {
      if (this.statusEl.childNodes.length > 0) this.statusEl.createEl("br");
      this.statusEl.appendText(line);
    }
  }
}

// ─── Chat View ───────────────────────────────────────────────────────

const VIEW_TYPE = "openclaw-chat";

class OpenClawChatView extends ItemView {
  plugin: OpenClawPlugin;
  private messagesEl!: HTMLElement;
  private tabBarEl!: HTMLElement;
  private tabSessions: { key: string; label: string; pct: number }[] = [];
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
  private contextMeterEl!: HTMLElement;
  private contextFillEl!: HTMLElement;
  private contextLabelEl!: HTMLElement;
  modelLabelEl!: HTMLElement;
  private sessionPillEl!: HTMLElement;
  currentModel: string = "";
  currentModelSetAt: number = 0; // timestamp to prevent stale overwrites
  cachedSessionDisplayName: string = "";
  private typingEl!: HTMLElement;
  private attachPreviewEl!: HTMLElement;
  private fileInputEl!: HTMLInputElement;
  private pendingAttachments: { name: string; content: string; vaultPath?: string; base64?: string; mimeType?: string }[] = [];
  private sending = false;
  private recording = false;
  private mediaRecorder: MediaRecorder | null = null;
  private recordedChunks: Blob[] = [];

  private readonly micSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z"/><path d="M19 10v2a7 7 0 01-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>`;
  private readonly sendSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`;
  private readonly stopSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="red" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>`;
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

    // Tab bar (browser-like tabs)
    this.tabBarEl = container.createDiv("openclaw-tab-bar");
    this.tabBarEl.addEventListener("wheel", (e) => { e.preventDefault(); this.tabBarEl.scrollLeft += e.deltaY; }, { passive: false });

    // Reset button (right side of tab bar)
    const resetBtn = container.createEl("button", { cls: "openclaw-tab-reset" });
    resetBtn.textContent = "↻";
    resetBtn.title = "Reset current tab (clear conversation)";
    resetBtn.addEventListener("click", () => this.resetCurrentTab());

    // We'll render tabs after loading sessions
    this.renderTabs();

    // Hidden elements for compatibility
    this.sessionPillEl = createDiv();
    this.contextMeterEl = createDiv();
    this.contextFillEl = createDiv();
    this.contextLabelEl = document.createElement("span");
    this.modelLabelEl = createDiv();

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
    // Brain button (model picker)
    const brainBtn = inputRow.createEl("button", { cls: "openclaw-brain-btn", attr: { "aria-label": "Switch model" } });
    brainBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.5 4.5L18 9l-4.5 1.5L12 15l-1.5-4.5L6 9l4.5-1.5L12 3z"/><path d="M19 14l.9 2.7L22.6 17.6l-2.7.9L19 21.2l-.9-2.7-2.7-.9 2.7-.9z"/><path d="M6 17l.6 1.8L8.4 19.4l-1.8.6L6 21.8l-.6-1.8-1.8-.6 1.8-.6z"/></svg>`;
    brainBtn.addEventListener("click", () => this.openModelPicker());
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
    this.sendBtn.innerHTML = this.sendSvg;
    this.sendBtn.style.opacity = "0.3";
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
    this.inputEl.addEventListener("input", () => {
      this.autoResize();
      this.updateSendButton();
    });
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
    this.sendBtn.addEventListener("click", () => {
      if (this.inputEl.value.trim() || this.pendingAttachments.length > 0) {
        this.sendMessage();
      }
      // Voice recording disabled — base64 in message text bloats context
    });
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

        // No post-processing needed: VOICE: refs are in the assistant message text itself

        await this.renderMessages();
        this.updateContextMeter();
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
        } else if (c.type === "tool_result") {
          // Extract text from tool_result content (e.g., TTS MEDIA: paths)
          const trContent = c.content;
          if (typeof trContent === "string") {
            text += (text ? "\n" : "") + trContent;
          } else if (Array.isArray(trContent)) {
            for (const tc of trContent) {
              if (tc?.type === "text" && tc.text) text += (text ? "\n" : "") + tc.text;
            }
          }
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

  private updateSendButton(): void {
    if (this.inputEl.value.trim() || this.pendingAttachments.length > 0) {
      this.sendBtn.innerHTML = this.sendSvg;
      this.sendBtn.setAttribute("aria-label", "Send");
      this.sendBtn.style.opacity = "1";
    } else {
      this.sendBtn.innerHTML = this.sendSvg;
      this.sendBtn.setAttribute("aria-label", "Send");
      this.sendBtn.style.opacity = "0.3";
    }
  }

  private async startRecording(): Promise<void> {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.recordedChunks = [];

      // Try opus first, fall back to default
      const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
        ? "audio/webm;codecs=opus"
        : MediaRecorder.isTypeSupported("audio/webm")
        ? "audio/webm"
        : "";

      this.mediaRecorder = new MediaRecorder(stream, mimeType ? { mimeType } : {});
      this.mediaRecorder.addEventListener("dataavailable", (e) => {
        if (e.data.size > 0) this.recordedChunks.push(e.data);
      });
      this.mediaRecorder.addEventListener("stop", () => {
        stream.getTracks().forEach(t => t.stop());
        this.finishRecording();
      });

      this.mediaRecorder.start();
      this.recording = true;
      this.updateSendButton();
      this.inputEl.placeholder = "Recording... tap ■ to stop";
    } catch (e) {
      console.error("[ObsidianClaw] Mic access failed:", e);
      new Notice("Microphone access denied");
    }
  }

  private stopRecording(): void {
    if (this.mediaRecorder && this.mediaRecorder.state !== "inactive") {
      this.mediaRecorder.stop();
    }
    this.recording = false;
    this.updateSendButton();
    this.inputEl.placeholder = "Message...";
  }

  private async finishRecording(): Promise<void> {
    if (this.recordedChunks.length === 0) return;
    const blob = new Blob(this.recordedChunks, { type: this.mediaRecorder?.mimeType || "audio/webm" });
    this.recordedChunks = [];

    // Convert to base64
    const arrayBuf = await blob.arrayBuffer();
    const bytes = new Uint8Array(arrayBuf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    const mime = blob.type || "audio/webm";

    // Upload to gateway static dir via the agent (exec), and send VOICE: ref
    // For now: send as AUDIO_DATA in message text, agent handles transcription
    const marker = `AUDIO_DATA:${mime};base64,${b64}`;

    // Show voice message in local UI
    this.messages.push({ role: "user", text: "🎤 Voice message", images: [], timestamp: Date.now() });
    await this.renderMessages();

    // Send to gateway
    const runId = generateId();
    this.streamRunId = runId;
    this.streamText = "";
    this.abortBtn.style.display = "";
    this.typingEl.style.display = "";
    const thinkText = this.typingEl.querySelector(".openclaw-typing-text");
    if (thinkText) thinkText.textContent = "Thinking";
    this.scrollToBottom();

    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: marker,
        deliver: false,
        idempotencyKey: runId,
      });
    } catch (e) {
      this.messages.push({ role: "assistant", text: `Error: ${e}`, images: [], timestamp: Date.now() });
      this.streamRunId = null;
      this.streamText = null;
      this.abortBtn.style.display = "none";
      await this.renderMessages();
    }
  }

  async sendMessage(): Promise<void> {
    let text = this.inputEl.value.trim();
    const hasAttachments = this.pendingAttachments.length > 0;
    if (!text && !hasAttachments) return;
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
          // Show preview in chat history
          userImages.push(`data:${att.mimeType};base64,${att.base64}`);
        } else {
          // Text files: append to message as before
          fullMessage = (fullMessage ? fullMessage + "\n\n" : "") + att.content;
        }
      }
      if (!text) {
        text = `📎 ${this.pendingAttachments.map(a => a.name).join(", ")}`;
        fullMessage = text;
      }
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

  async updateContextMeter(): Promise<void> {
    if (!this.plugin.gateway?.connected) return;
    try {
      const result = await this.plugin.gateway.request("sessions.list", {});
      const sessions = result?.sessions || [];
      // Find session matching current sessionKey (try exact match, then with agent prefix)
      const sk = this.plugin.settings.sessionKey || "main";
      const session = sessions.find((s: any) => s.key === sk) ||
        sessions.find((s: any) => s.key === `agent:main:${sk}`) ||
        sessions.find((s: any) => s.key.endsWith(`:${sk}`));
      if (!session) return;
      const used = session.totalTokens || 0;
      const max = session.contextTokens || 200000;
      const pct = Math.min(100, Math.round((used / max) * 100));
      this.contextFillEl.style.width = pct + "%";
      this.contextFillEl.className = "openclaw-context-fill" + (pct > 80 ? " openclaw-context-high" : pct > 60 ? " openclaw-context-mid" : "");
      this.contextLabelEl.textContent = `${pct}%`;
      // Update active tab circle
      const activeTab = this.tabBarEl?.querySelector(".openclaw-tab.active .openclaw-tab-circle") as HTMLCanvasElement;
      if (activeTab) this.drawContextCircle(activeTab, pct);
      // Update model label from session data (but don't overwrite a recent manual switch)
      const fullModel = session.model || "";
      const modelCooldown = Date.now() - this.currentModelSetAt < 15000;
      if (fullModel && fullModel !== this.currentModel && !modelCooldown) {
        this.currentModel = fullModel;
        this.updateModelPill();
      }
      // Update session display name from gateway
      if (session.displayName && session.displayName !== this.cachedSessionDisplayName) {
        this.cachedSessionDisplayName = session.displayName;
        this.updateSessionPill();
      }
    } catch { /* ignore */ }
  }

  updateSessionPill(): void {
    if (!this.sessionPillEl) return;
    // Prefer cached gateway displayName, fall back to local logic
    let display = this.cachedSessionDisplayName || "";
    if (!display) {
      const sessionKey = this.plugin.settings.sessionKey || "main";
      if (sessionKey === "main") display = "Main";
      else if (sessionKey.startsWith("telegram:")) display = "Telegram";
      else if (sessionKey.startsWith("discord:")) display = "Discord";
      else if (sessionKey.startsWith("whatsapp:")) display = "WhatsApp";
      else display = sessionKey;
    }
    this.sessionPillEl.empty();
    this.sessionPillEl.createSpan({ text: display, cls: "openclaw-ctx-pill-text" });
    this.sessionPillEl.createSpan({ text: " ▾", cls: "openclaw-ctx-pill-arrow" });
  }

  updateModelPill(): void {
    if (!this.modelLabelEl) return;
    const model = this.currentModel ? this.shortModelName(this.currentModel) : "model";
    this.modelLabelEl.empty();
    this.modelLabelEl.createSpan({ text: model, cls: "openclaw-ctx-pill-text" });
    this.modelLabelEl.createSpan({ text: " ▾", cls: "openclaw-ctx-pill-arrow" });
  }

  // Alias for external callers
  updateContextPill(): void { this.updateSessionPill(); this.updateModelPill(); }

  openSessionPicker(): void {
    new SessionPickerModal(this.app, this.plugin, this).open();
  }

  async renderTabs(): Promise<void> {
    if (!this.tabBarEl) return;
    this.tabBarEl.empty();
    const currentKey = this.plugin.settings.sessionKey || "main";

    // Fetch sessions from gateway
    let sessions: any[] = [];
    if (this.plugin.gateway?.connected) {
      try {
        const result = await this.plugin.gateway.request("sessions.list", {});
        sessions = result?.sessions || [];
      } catch { /* use empty */ }
    }

    // Filter to direct conversations only
    const channelPfx = ["telegram:", "discord:", "whatsapp:", "signal:", "webchat:", "slack:", "irc:", "subag"];
    const agentPrefix = "agent:main:";
    const convSessions = sessions.filter(s => {
      if (!s.key.startsWith(agentPrefix) || s.key.includes(":cron:")) return false;
      const sk = s.key.slice(agentPrefix.length);
      return !channelPfx.some(p => sk.startsWith(p));
    });

    // Build tab list — ensure "main" is always first
    this.tabSessions = [];
    const mainSession = convSessions.find(s => s.key === "agent:main:main");
    if (mainSession) {
      const used = mainSession.totalTokens || 0;
      const max = mainSession.contextTokens || 200000;
      this.tabSessions.push({ key: "main", label: "Main", pct: Math.min(100, Math.round((used / max) * 100)) });
    } else {
      this.tabSessions.push({ key: "main", label: "Main", pct: 0 });
    }

    // Add other sessions numbered 1, 2, 3...
    let num = 1;
    for (const s of convSessions) {
      const sk = s.key.slice(agentPrefix.length);
      if (sk === "main") continue;
      const used = s.totalTokens || 0;
      const max = s.contextTokens || 200000;
      const pct = Math.min(100, Math.round((used / max) * 100));
      const label = s.label || s.displayName || String(num);
      this.tabSessions.push({ key: sk, label, pct });
      num++;
    }

    // Render each tab
    for (const tab of this.tabSessions) {
      const isCurrent = tab.key === currentKey;
      const tabEl = this.tabBarEl.createDiv({ cls: `openclaw-tab${isCurrent ? " active" : ""}` });

      // Context circle indicator
      const circle = tabEl.createEl("canvas", { cls: "openclaw-tab-circle" });
      circle.width = 16;
      circle.height = 16;
      this.drawContextCircle(circle, tab.pct);

      // Label
      tabEl.createSpan({ text: tab.label, cls: "openclaw-tab-label" });

      // Close button (not for main)
      if (tab.key !== "main") {
        const closeBtn = tabEl.createSpan({ text: "×", cls: "openclaw-tab-close" });
        closeBtn.addEventListener("click", async (e) => {
          e.stopPropagation();
          try {
            await this.plugin.gateway?.request("sessions.delete", { key: `agent:main:${tab.key}`, deleteTranscript: true });
            new Notice(`Closed: ${tab.label}`);
          } catch (err: any) {
            new Notice(`Close failed: ${err?.message || err}`);
          }
          // Switch to main if we closed the active tab
          if (tab.key === currentKey) {
            this.plugin.settings.sessionKey = "main";
            await this.plugin.saveSettings();
            this.messages = [];
            this.messagesEl.empty();
            await this.loadHistory();
          }
          await this.renderTabs();
          await this.updateContextMeter();
        });
      }

      // Click to switch
      if (!isCurrent) {
        tabEl.addEventListener("click", async () => {
          this.plugin.settings.sessionKey = tab.key;
          await this.plugin.saveSettings();
          this.messages = [];
          this.messagesEl.empty();
          this.cachedSessionDisplayName = tab.label;
          await this.loadHistory();
          await this.updateContextMeter();
          this.renderTabs();
        });
      }
    }

    // + button to add new tab
    const addBtn = this.tabBarEl.createDiv({ cls: "openclaw-tab openclaw-tab-add" });
    addBtn.createSpan({ text: "+", cls: "openclaw-tab-label" });
    addBtn.addEventListener("click", async () => {
      // Auto-name: find next number
      const nums = this.tabSessions.map(t => parseInt(t.label)).filter(n => !isNaN(n));
      const nextNum = nums.length > 0 ? Math.max(...nums) + 1 : 1;
      const sessionKey = `tab-${nextNum}`;
      try {
        await this.plugin.gateway?.request("chat.send", {
          sessionKey: sessionKey,
          message: "/new",
          deliver: false,
          idempotencyKey: "newtab-" + Date.now(),
        });
        await new Promise(r => setTimeout(r, 500));
        try {
          await this.plugin.gateway?.request("sessions.patch", {
            key: `agent:main:${sessionKey}`,
            label: String(nextNum),
          });
        } catch { /* label optional */ }
        // Switch to it
        this.plugin.settings.sessionKey = sessionKey;
        this.messages = [];
        if (this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
        await this.plugin.saveSettings();
        this.messagesEl.empty();
        await this.renderTabs();
        await this.updateContextMeter();
        new Notice(`New tab: ${nextNum}`);
      } catch (err: any) {
        new Notice(`Failed to create tab: ${err?.message || err}`);
      }
    });
  }

  private drawContextCircle(canvas: HTMLCanvasElement, pct: number): void {
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const size = 16;
    const center = size / 2;
    const radius = 5;
    const lineWidth = 2;

    ctx.clearRect(0, 0, size, size);

    // Background circle
    ctx.beginPath();
    ctx.arc(center, center, radius, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(128,128,128,0.2)";
    ctx.lineWidth = lineWidth;
    ctx.stroke();

    // Fill arc
    if (pct > 0) {
      ctx.beginPath();
      const start = -Math.PI / 2;
      const end = start + (Math.PI * 2 * pct / 100);
      ctx.arc(center, center, radius, start, end);
      ctx.strokeStyle = pct > 80 ? "#c44" : pct > 60 ? "#d4a843" : "var(--interactive-accent)";
      ctx.lineWidth = lineWidth;
      ctx.stroke();
    }
  }

  async resetCurrentTab(): Promise<void> {
    if (!this.plugin.gateway?.connected) return;
    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/reset",
        deliver: false,
        idempotencyKey: "reset-" + Date.now(),
      });
      this.messages = [];
      if (this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
      await this.plugin.saveSettings();
      this.messagesEl.empty();
      await this.updateContextMeter();
      await this.renderTabs();
      new Notice("Tab reset");
    } catch (e) {
      new Notice(`Reset failed: ${e}`);
    }
  }

  openModelPicker(): void {
    new ModelPickerModal(this.app, this.plugin, this).open();
  }

  async compactSession(): Promise<void> {
    if (!this.plugin.gateway?.connected) return;
    try {
      this.showBanner("Compacting context...");
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/compact",
        deliver: false,
        idempotencyKey: "compact-" + Date.now(),
      });
      // Poll context meter to animate the decrease
      const pollInterval = setInterval(async () => {
        await this.updateContextMeter();
      }, 2000);
      setTimeout(async () => {
        clearInterval(pollInterval);
        this.hideBanner();
        await this.loadHistory();
        await this.updateContextMeter();
      }, 12000);
    } catch (e) {
      this.hideBanner();
      new Notice(`Compact failed: ${e}`);
    }
  }

  async newSession(): Promise<void> {
    if (!this.plugin.gateway?.connected) return;
    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/new",
        deliver: false,
        idempotencyKey: "new-" + Date.now(),
      });
      this.messages = [];
      if (this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
      await this.plugin.saveSettings();
      this.messagesEl.empty();
      await this.updateContextMeter();
      new Notice("New session started");
    } catch (e) {
      new Notice(`New session failed: ${e}`);
    }
  }

  shortModelName(fullId: string): string {
    // "anthropic/claude-opus-4-6" -> "opus-4-6" (selected display)
    // Strip provider prefix, strip "claude-" prefix for brevity
    const model = fullId.includes("/") ? fullId.split("/")[1] : fullId;
    return model.replace(/^claude-/, "");
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

  private async playTTSAudio(audioPath: string): Promise<void> {
    try {
      // Works in Electron/Obsidian (same machine as gateway)
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      const buffer = fs.readFileSync(audioPath);
      const ext = audioPath.split(".").pop()?.toLowerCase() || "opus";
      const mimeMap: Record<string, string> = {
        opus: "audio/ogg; codecs=opus",
        mp3: "audio/mpeg",
        mp4: "audio/mp4",
        wav: "audio/wav",
        ogg: "audio/ogg",
      };
      const mime = mimeMap[ext] || "audio/ogg; codecs=opus";
      const blob = new Blob([buffer], { type: mime });
      const url = URL.createObjectURL(blob);
      const audio = new Audio(url);
      audio.onended = () => URL.revokeObjectURL(url);
      await audio.play();
    } catch {
      // Silently ignore — remote devices don't have local file access
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
        const cPhase = payload.data?.phase || "";
        if (cPhase === "end") {
          setTimeout(() => this.hideBanner(), 2000);
        } else {
          this.showBanner("Compacting context...");
        }
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
      // Record position for interleaving
      if (this.streamText) {
        this.streamSplitPoints.push(this.streamText.length);
      }
      // Show tool call in chat + typing indicator
      const { label, url } = this.buildToolLabel(toolName, payload.data?.args || payload.args);
      this.currentToolCalls.push(label);
      this.streamItems.push({ type: "tool", label, url } as StreamItem);
      this.appendToolCall(label, url, true);
      typingText.textContent = label;
      this.typingEl.style.display = "";
    } else if ((stream === "tool" || toolName) && phase === "result") {
      // Tool finished — remove animated dots from last tool item
      this.deactivateLastToolItem();
      typingText.textContent = "Thinking";
      this.typingEl.style.display = "";

      this.scrollToBottom();
    } else if (stream === "compaction" || state === "compacting") {
      if (phase === "end") {
        // Compaction finished — keep banner briefly then hide
        setTimeout(() => this.hideBanner(), 2000);
      } else {
        // phase=start or unknown — show compacting indicator
        this.currentToolCalls.push("Compacting memory");
        this.streamItems.push({ type: "tool", label: "Compacting memory" });
        this.appendToolCall("Compacting memory");
        this.typingEl.style.display = "none";
        this.showBanner("Compacting context...");
      }
    }
  }

  handleChatEvent(payload: any): void {
    // Session key "main" resolves to "agent:main:main" on the gateway
    const sk = this.plugin.settings.sessionKey;
    const payloadSk = payload.sessionKey ?? "";
    if (payloadSk !== sk && payloadSk !== `agent:main:${sk}` && !payloadSk.endsWith(`:${sk}`)) return;

    // No active stream (passive device): still refresh history and inject any locally collected stream items
    if (!this.streamRunId && (payload.state === "final" || payload.state === "aborted" || payload.state === "error")) {
      this.hideBanner();
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
      this.finishStream();

      // Reload history — contentBlocks from gateway have proper tool interleaving
      this.loadHistory().then(async () => {
        await this.renderMessages();
        this.updateContextMeter();
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
    // Strip TTS directives and MEDIA: paths (rendered as audio players separately)
    text = text.replace(/^\[\[audio_as_voice\]\]\s*/gm, "").trim();
    text = text.replace(/^MEDIA:\/[^\n]+$/gm, "").trim();
    text = text.replace(/^VOICE:[^\s\n]+$/gm, "").trim();
    // Strip inbound voice data (shown as "🎤 Voice message" in UI)
    text = text.replace(/^AUDIO_DATA:[^\n]+$/gm, "").trim();
    if (text === "🎤 Voice message") text = "🎤 Voice message"; // keep the label
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK") return "";
    return text;
  }

  /** Extract VOICE:path references from message text */
  private extractVoiceRefs(text: string): string[] {
    const refs: string[] = [];
    const re = /^VOICE:([^\s\n]+\.(?:mp3|opus|ogg|wav|m4a|mp4))$/gm;
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      refs.push(match[1].trim());
    }
    return refs;
  }

  /** Build HTTP URL for a voice file served by the gateway */
  private buildVoiceUrl(voicePath: string): string {
    // Gateway URL is ws:// or wss:// — convert to http:// or https://
    const gwUrl = this.plugin.settings.gatewayUrl || "";
    const httpUrl = gwUrl.replace(/^ws(s?):\/\//, "http$1://");
    return `${httpUrl}/${voicePath}`;
  }

  /** Render an inline audio player that fetches audio via gateway HTTP */
  private renderAudioPlayer(container: HTMLElement, voiceRef: string): void {
    const playerEl = container.createDiv("openclaw-audio-player");
    const playBtn = playerEl.createEl("button", { cls: "openclaw-audio-play-btn", text: "▶ Voice message" });
    const progressEl = playerEl.createDiv("openclaw-audio-progress");
    const barEl = progressEl.createDiv("openclaw-audio-bar");

    let audio: HTMLAudioElement | null = null;

    playBtn.addEventListener("click", async () => {
      if (audio && !audio.paused) {
        audio.pause();
        playBtn.textContent = "▶ Voice message";
        return;
      }

      if (!audio) {
        playBtn.textContent = "⏳ Loading...";
        try {
          const url = this.buildVoiceUrl(voiceRef);
          console.log("[ObsidianClaw] Loading audio from:", url);
          audio = new Audio(url);

          await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("timeout")), 10000);
            audio!.addEventListener("canplaythrough", () => { clearTimeout(timer); resolve(); }, { once: true });
            audio!.addEventListener("error", () => { clearTimeout(timer); reject(new Error("load error")); }, { once: true });
            audio!.load();
          });

          audio.addEventListener("timeupdate", () => {
            if (audio && audio.duration) barEl.style.width = `${(audio.currentTime / audio.duration) * 100}%`;
          });
          audio.addEventListener("ended", () => {
            playBtn.textContent = "▶ Voice message";
            barEl.style.width = "0%";
          });
        } catch (e) {
          console.error("[ObsidianClaw] Audio load failed:", e);
          playBtn.textContent = "⚠ Audio unavailable";
          playBtn.disabled = true;
          return;
        }
      }

      playBtn.textContent = "⏸ Playing...";
      audio.play().catch(() => { playBtn.textContent = "⚠ Audio unavailable"; playBtn.disabled = true; });
    });
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
    for (const msg of this.messages) {
      if (msg.role === "assistant") {
        const hasContentTools = msg.contentBlocks?.some((b: any) => b.type === "tool_use" || b.type === "toolCall") || false;

        if (hasContentTools && msg.contentBlocks) {
          // Render interleaved text + tool blocks directly
          for (const block of msg.contentBlocks) {
            if (block.type === "text" && block.text?.trim()) {
              const blockAudio = this.extractVoiceRefs(block.text);
              const cleaned = this.cleanText(block.text);
              // Render text bubble if there's visible text
              if (cleaned) {
                const bubble = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant");
                try {
                  await MarkdownRenderer.render(this.app, cleaned, bubble, "", this.plugin);
                } catch {
                  bubble.createDiv({ text: cleaned, cls: "openclaw-msg-text" });
                }
                // Audio players inside text bubble
                for (const ap of blockAudio) {
                  this.renderAudioPlayer(bubble, ap);
                }
              } else if (blockAudio.length > 0) {
                // No visible text but has audio — create a bubble just for the player
                const bubble = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant");
                for (const ap of blockAudio) {
                  this.renderAudioPlayer(bubble, ap);
                }
              }
            } else if (block.type === "tool_use" || block.type === "toolCall") {
              const { label, url } = this.buildToolLabel(block.name || "", block.input || block.arguments || {});
              const el = this.createStreamItemEl({ type: "tool", label, url } as StreamItem);
              this.messagesEl.appendChild(el);
            }
          }
          continue;
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
      // Combine audio paths from message metadata + text content
      const allAudio = msg.text ? this.extractVoiceRefs(msg.text) : [];

      // Render text
      if (msg.text) {
        const displayText = msg.role === "assistant" ? this.cleanText(msg.text) : msg.text;
        if (displayText) {
          if (msg.role === "assistant") {
            try {
              await MarkdownRenderer.render(this.app, displayText, bubble, "", this.plugin);
            } catch {
              bubble.createDiv({ text: displayText, cls: "openclaw-msg-text" });
            }
          } else {
            bubble.createDiv({ text: displayText, cls: "openclaw-msg-text" });
          }
        }
      }

      // Render audio players for voice messages
      for (const ap of allAudio) {
        this.renderAudioPlayer(bubble, ap);
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

    const rawUrl = this.settings.gatewayUrl.trim();
    if (!rawUrl) return;

    // Normalize URL (accept https:// and http:// as well)
    const url = normalizeGatewayUrl(rawUrl);
    if (!url) {
      new Notice("OpenClaw: Invalid gateway URL. Use your Tailscale Serve URL (e.g. wss://your-machine.tail1234.ts.net)");
      return;
    }

    // Persist the normalized form if it changed
    if (url !== rawUrl) {
      this.settings.gatewayUrl = url;
      await this.saveSettings();
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
        this.chatView?.renderTabs();
        // Restore persisted model selection
        if (this.settings.currentModel && this.chatView) {
          this.chatView.currentModel = this.settings.currentModel;
          this.chatView.updateModelPill();
        }
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

// ─── Confirm Modal ──────────────────────────────────────────────────

// ─── Chat Picker Modal (was: Session Picker) ────────────────────────

class SessionPickerModal extends Modal {
  plugin: OpenClawPlugin;
  chatView: OpenClawChatView;
  private sessions: any[] = [];
  private bots: { id: string; isCurrent: boolean }[] = [];
  private selectedBot: string = "main";

  constructor(app: App, plugin: OpenClawPlugin, chatView: OpenClawChatView) {
    super(app);
    this.plugin = plugin;
    this.chatView = chatView;
  }

  async onOpen(): Promise<void> {
    this.modalEl.addClass("openclaw-picker");
    this.contentEl.createDiv("openclaw-picker-loading").textContent = "Loading...";

    try {
      const result = await this.plugin.gateway?.request("sessions.list", {});
      this.sessions = result?.sessions || [];
    } catch { this.sessions = []; }

    // Detect bots from session keys (agent:{botId}:...)
    const botIds = new Set<string>();
    for (const s of this.sessions) {
      const match = s.key.match(/^agent:([^:]+):/);
      if (match) botIds.add(match[1]);
    }
    if (botIds.size === 0) botIds.add("main");
    this.selectedBot = "main";
    this.bots = [...botIds].map(id => ({ id, isCurrent: id === "main" }));

    // Always show bot selection first
    this.renderBots();
  }

  onClose(): void { this.contentEl.empty(); }

  /** Turn a raw session key into a friendly display name */
  private friendlyName(shortKey: string, session: any): string {
    // Main is always "Main" regardless of gateway metadata
    if (shortKey === "main") return "Main";
    if (session.label && session.label.length < 40) return session.label;
    if (session.displayName && session.displayName.length < 40) return session.displayName;
    if (shortKey.startsWith("telegram:")) return "Telegram";
    if (shortKey.startsWith("discord:")) return "Discord";
    if (shortKey.startsWith("whatsapp:")) return "WhatsApp";
    if (shortKey.startsWith("signal:")) return "Signal";
    if (shortKey.startsWith("webchat:")) return "WebChat";
    return shortKey.replace(/:/g, " / ");
  }

  // ─── Bot selection (only shown if multiple bots) ──────────────
  private renderBots(): void {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h3", { text: "Choose your bot", cls: "openclaw-picker-title" });
    const hint = contentEl.createDiv("openclaw-picker-hint");
    hint.innerHTML = "Each bot is a separate AI agent. <a href='https://docs.openclaw.ai/concepts/multi-agent'>Add more on your gateway.</a>";

    const list = contentEl.createDiv("openclaw-picker-list");
    for (const bot of this.bots) {
      const row = list.createDiv({ cls: `openclaw-picker-row${bot.id === this.selectedBot ? " active" : ""}` });
      const left = row.createDiv("openclaw-picker-row-left");
      if (bot.id === this.selectedBot) left.createSpan({ text: "● ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: bot.id });
      const right = row.createDiv("openclaw-picker-row-right");
      const channelPfx = ["telegram:", "discord:", "whatsapp:", "signal:", "webchat:", "slack:", "irc:", "subag"];
      const prefix = `agent:${bot.id}:`;
      const convCount = this.sessions.filter(s => {
        if (!s.key.startsWith(prefix) || s.key.includes(":cron:")) return false;
        const sk = s.key.slice(prefix.length);
        return !channelPfx.some(p => sk.startsWith(p));
      }).length;
      right.createSpan({ text: `${convCount} conversation${convCount !== 1 ? "s" : ""} →`, cls: "openclaw-picker-meta" });
      row.addEventListener("click", () => {
        this.selectedBot = bot.id;
        this.renderConversations();
      });
    }
  }

  // ─── Conversation list ────────────────────────────────────────
  private renderConversations(): void {
    const { contentEl } = this;
    contentEl.empty();

    const currentSessionKey = this.plugin.settings.sessionKey || "main";
    const agentPrefix = `agent:${this.selectedBot}:`;

    // Header with back button if multiple bots
    if (this.bots.length > 1) {
      const header = contentEl.createDiv("openclaw-picker-header");
      const backBtn = header.createEl("button", { cls: "openclaw-picker-back", text: "← " + this.selectedBot });
      backBtn.addEventListener("click", () => this.renderBots());
    }

    contentEl.createEl("h3", { text: "Conversations", cls: "openclaw-picker-title" });
    const hint = contentEl.createDiv("openclaw-picker-hint");
    hint.textContent = "There's always a Main conversation. You can add more for separate topics.";

    // Settings cog
    const cogRow = contentEl.createDiv("openclaw-picker-header-right");
    const cogBtn = cogRow.createEl("button", { cls: "openclaw-picker-cog", text: "⚙" });
    cogBtn.title = "Plugin settings";
    cogBtn.addEventListener("click", () => {
      this.close();
      (this.app as any).setting?.open?.();
      (this.app as any).setting?.openTabById?.("openclaw");
    });

    const channelPrefixes = ["telegram:", "discord:", "whatsapp:", "signal:", "webchat:", "slack:", "irc:", "subag"];
    const conversations = this.sessions.filter((s: any) => {
      if (!s.key.startsWith(agentPrefix)) return false;
      if (s.key.includes(":cron:")) return false;
      const shortKey = s.key.slice(agentPrefix.length);
      // Exclude channel-wrapped sessions (e.g. agent:main:telegram:slash:123)
      if (channelPrefixes.some(p => shortKey.startsWith(p))) return false;
      return true;
    });

    const list = contentEl.createDiv("openclaw-picker-list");

    for (const session of conversations) {
      const shortKey = session.key.slice(agentPrefix.length);
      const isCurrent = shortKey === currentSessionKey;
      const used = session.totalTokens || 0;
      const max = session.contextTokens || 200000;
      const pct = Math.min(100, Math.round((used / max) * 100));
      const name = this.friendlyName(shortKey, session);
      const isMain = shortKey === "main";

      const row = list.createDiv({ cls: `openclaw-picker-row${isCurrent ? " active" : ""}` });

      const left = row.createDiv("openclaw-picker-row-left");
      if (isCurrent) left.createSpan({ text: "● ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: name });

      const right = row.createDiv("openclaw-picker-row-right");

      // Context meter
      const meter = right.createDiv("openclaw-picker-meter");
      const fill = meter.createDiv("openclaw-picker-fill");
      fill.style.width = pct + "%";
      if (pct > 80) fill.addClass("high");
      else if (pct > 60) fill.addClass("mid");
      right.createSpan({ text: `${pct}%`, cls: "openclaw-picker-pct" });

      // Rename button (not for main)
      if (!isMain) {
        const renameBtn = right.createEl("button", { text: "✎", cls: "openclaw-picker-del" });
        renameBtn.title = "Rename";
        renameBtn.addEventListener("click", async (e) => {
          e.stopPropagation();
          new TextInputModal(this.app, {
            title: "Rename conversation",
            placeholder: "New name",
            confirmText: "Rename",
            initialValue: name,
            onConfirm: async (newName: string) => {
              if (!newName.trim()) return;
              try {
                await this.plugin.gateway?.request("sessions.patch", { key: session.key, label: newName.trim() });
                session.label = newName.trim();
                if (isCurrent) {
                  this.chatView.cachedSessionDisplayName = newName.trim();
                  this.chatView.updateSessionPill();
                }
                this.renderConversations();
                new Notice(`Renamed to: ${newName.trim()}`);
              } catch (err: any) {
                new Notice(`Rename failed: ${err?.message || err}`);
              }
            },
          }).open();
        });
      }

      // Delete button (not for main, not for current)
      if (!isMain && !isCurrent) {
        const delBtn = right.createEl("button", { text: "✕", cls: "openclaw-picker-del" });
        delBtn.title = "Delete conversation";
        delBtn.addEventListener("click", async (e) => {
          e.stopPropagation();
          delBtn.textContent = "…";
          delBtn.disabled = true;
          try {
            await this.plugin.gateway?.request("sessions.delete", { key: session.key, deleteTranscript: true });
            new Notice(`Deleted: ${name}`);
          } catch (err: any) {
            new Notice(`Delete failed: ${err?.message || err}`);
          }
          // Small delay to let gateway process, then re-fetch to confirm
          await new Promise(r => setTimeout(r, 500));
          try {
            const result = await this.plugin.gateway?.request("sessions.list", {});
            this.sessions = result?.sessions || [];
          } catch { /* keep current */ }
          this.renderConversations();
        });
      }

      if (!isCurrent) {
        row.addEventListener("click", async () => {
          this.plugin.settings.sessionKey = shortKey;
          await this.plugin.saveSettings();
          this.close();
          this.chatView.cachedSessionDisplayName = name;
          this.chatView.updateSessionPill();
          this.chatView.messages = [];
          this.chatView.messagesEl.empty();
          await this.chatView.loadHistory();
          await this.chatView.updateContextMeter();
          new Notice(`Switched to: ${name}`);
        });
      }
    }

    // + New conversation
    const newRow = list.createDiv("openclaw-picker-row openclaw-picker-add");
    newRow.createSpan({ text: "+ New conversation" });
    newRow.addEventListener("click", () => {
      this.close();
      new TextInputModal(this.app, {
        title: "New conversation",
        placeholder: "Name (e.g. 'Work', 'Personal', 'Research')",
        confirmText: "Create",
        onConfirm: async (name: string) => {
          if (!name.trim()) {
            new Notice("Name cannot be empty");
            return;
          }
          const sessionKey = name.trim().toLowerCase().replace(/[^a-z0-9-]/g, "-");

          // Create session on gateway by sending /new to that key
          try {
            await this.plugin.gateway?.request("chat.send", {
              sessionKey: sessionKey,
              message: "/new",
              deliver: false,
              idempotencyKey: "create-" + Date.now(),
            });
            // Label the session
            await new Promise(r => setTimeout(r, 500));
            try {
              await this.plugin.gateway?.request("sessions.patch", {
                key: `agent:main:${sessionKey}`,
                label: name.trim(),
              });
            } catch { /* label is optional */ }
          } catch (err: any) {
            new Notice(`Create failed: ${err?.message || err}`);
            return;
          }

          // Switch to the new session
          this.plugin.settings.sessionKey = sessionKey;
          this.chatView.messages = [];
          if (this.plugin.settings.streamItemsMap) this.plugin.settings.streamItemsMap = {};
          await this.plugin.saveSettings();
          this.chatView.messagesEl.empty();
          this.chatView.cachedSessionDisplayName = name.trim();
          this.chatView.updateSessionPill();
          this.chatView.updateContextMeter();
          new Notice(`Created: ${name.trim()}`);
        },
      }).open();
    });

    // Footer
    const footer = contentEl.createDiv("openclaw-picker-hint");
    footer.style.marginTop = "8px";
    footer.style.fontSize = "11px";
    footer.textContent = "Main can't be deleted. New conversations are created when you send your first message.";
  }
}

// ─── Model Picker Modal ─────────────────────────────────────────────

class ModelPickerModal extends Modal {
  plugin: OpenClawPlugin;
  chatView: OpenClawChatView;
  private models: any[] = [];
  private currentModel: string = "";
  private selectedProvider: string | null = null;

  constructor(app: App, plugin: OpenClawPlugin, chatView: OpenClawChatView) {
    super(app);
    this.plugin = plugin;
    this.chatView = chatView;
  }

  async onOpen(): Promise<void> {
    this.modalEl.addClass("openclaw-picker");
    this.contentEl.createDiv("openclaw-picker-loading").textContent = "Loading models...";

    try {
      const result = await this.plugin.gateway?.request("models.list", {});
      this.models = result?.models || [];
    } catch { this.models = []; }

    // Normalize currentModel to always be provider/id format
    this.currentModel = this.chatView.currentModel || "";
    if (this.currentModel && !this.currentModel.includes("/")) {
      const match = this.models.find((m: any) => m.id === this.currentModel);
      if (match) this.currentModel = `${match.provider}/${match.id}`;
    }

    // Auto-select provider of current model
    if (this.currentModel.includes("/")) {
      this.selectedProvider = this.currentModel.split("/")[0];
    }

    this.renderProviders();
  }

  onClose(): void { this.contentEl.empty(); }

  private renderProviders(): void {
    const { contentEl } = this;
    contentEl.empty();

    // Group models by provider
    const providerMap = new Map<string, any[]>();
    for (const m of this.models) {
      const p = m.provider || "unknown";
      if (!providerMap.has(p)) providerMap.set(p, []);
      providerMap.get(p)!.push(m);
    }

    // Current provider from currentModel
    const currentProvider = this.currentModel.includes("/") ? this.currentModel.split("/")[0] : "";

    const list = contentEl.createDiv("openclaw-picker-list");

    for (const [provider, models] of providerMap) {
      const isCurrent = provider === currentProvider;
      const row = list.createDiv({ cls: `openclaw-picker-row${isCurrent ? " active" : ""}` });

      const left = row.createDiv("openclaw-picker-row-left");
      if (isCurrent) left.createSpan({ text: "● ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: provider, cls: "openclaw-picker-provider-name" });

      const right = row.createDiv("openclaw-picker-row-right");
      right.createSpan({ text: `${models.length} model${models.length !== 1 ? "s" : ""}`, cls: "openclaw-picker-meta" });
      right.createSpan({ text: " →", cls: "openclaw-picker-arrow" });

      row.addEventListener("click", () => {
        this.selectedProvider = provider;
        this.renderModels(provider);
      });
    }

    // Footer
    const footer = contentEl.createDiv("openclaw-picker-hint openclaw-picker-footer");
    footer.innerHTML = "Want more models? <a href='https://docs.openclaw.ai/gateway/configuration#choose-and-configure-models'>Add them in your gateway config.</a>";
  }

  private renderModels(provider: string): void {
    const { contentEl } = this;
    contentEl.empty();

    // Back button
    const header = contentEl.createDiv("openclaw-picker-header");
    const backBtn = header.createEl("button", { cls: "openclaw-picker-back", text: "← " + provider });
    backBtn.addEventListener("click", () => this.renderProviders());

    const models = this.models.filter((m: any) => m.provider === provider);
    const list = contentEl.createDiv("openclaw-picker-list openclaw-picker-model-list");

    for (const m of models) {
      const fullId = `${m.provider}/${m.id}`;
      const isCurrent = fullId === this.currentModel;
      const row = list.createDiv({ cls: `openclaw-picker-row${isCurrent ? " active" : ""}` });

      const left = row.createDiv("openclaw-picker-row-left");
      if (isCurrent) left.createSpan({ text: "● ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: m.name || m.id });

      // Always clickable - even the current model (user might want to re-select it)
      row.addEventListener("click", async () => {
        if (!this.plugin.gateway?.connected) return;
        row.addClass("openclaw-picker-selecting");
        row.textContent = "Switching...";
        try {
          await this.plugin.gateway.request("chat.send", {
            sessionKey: this.plugin.settings.sessionKey,
            message: `/model ${fullId}`,
            deliver: false,
            idempotencyKey: "model-" + Date.now(),
          });
          this.chatView.currentModel = fullId;
          this.chatView.currentModelSetAt = Date.now();
          this.plugin.settings.currentModel = fullId;
          await this.plugin.saveSettings();
          this.chatView.updateModelPill();
          new Notice(`Model: ${m.name || m.id}`);
          this.close();
        } catch (e) {
          new Notice(`Failed: ${e}`);
          this.renderModels(provider);
        }
      });
    }
  }
}

// ─── Confirm Modal ───────────────────────────────────────────────────

class ConfirmModal extends Modal {
  private config: { title: string; message: string; confirmText: string; onConfirm: () => void };

  constructor(app: App, config: { title: string; message: string; confirmText: string; onConfirm: () => void }) {
    super(app);
    this.config = config;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.addClass("openclaw-confirm-modal");
    contentEl.createEl("h3", { text: this.config.title, cls: "openclaw-confirm-title" });
    contentEl.createEl("p", { text: this.config.message, cls: "openclaw-confirm-message" });
    const btnRow = contentEl.createDiv("openclaw-confirm-buttons");
    const cancelBtn = btnRow.createEl("button", { text: "Cancel", cls: "openclaw-confirm-cancel" });
    cancelBtn.addEventListener("click", () => this.close());
    const confirmBtn = btnRow.createEl("button", { text: this.config.confirmText, cls: "openclaw-confirm-ok" });
    confirmBtn.addEventListener("click", () => {
      this.close();
      this.config.onConfirm();
    });
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

// ─── Text Input Modal ────────────────────────────────────────────────

class TextInputModal extends Modal {
  private config: { title: string; placeholder: string; confirmText: string; initialValue?: string; onConfirm: (value: string) => void };
  private inputEl!: HTMLInputElement;

  constructor(app: App, config: { title: string; placeholder: string; confirmText: string; initialValue?: string; onConfirm: (value: string) => void }) {
    super(app);
    this.config = config;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.addClass("openclaw-confirm-modal");
    contentEl.createEl("h3", { text: this.config.title, cls: "openclaw-confirm-title" });
    this.inputEl = contentEl.createEl("input", {
      type: "text",
      placeholder: this.config.placeholder,
      cls: "openclaw-text-input",
    });
    if (this.config.initialValue) this.inputEl.value = this.config.initialValue;
    this.inputEl.focus();
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        this.submit();
      }
    });
    const btnRow = contentEl.createDiv("openclaw-confirm-buttons");
    const cancelBtn = btnRow.createEl("button", { text: "Cancel", cls: "openclaw-confirm-cancel" });
    cancelBtn.addEventListener("click", () => this.close());
    const confirmBtn = btnRow.createEl("button", { text: this.config.confirmText, cls: "openclaw-confirm-ok" });
    confirmBtn.addEventListener("click", () => this.submit());
  }

  private submit(): void {
    const value = this.inputEl.value.trim();
    if (!value) return;
    this.close();
    this.config.onConfirm(value);
  }

  onClose(): void {
    this.contentEl.empty();
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

    // ─── Setup Wizard (top, most prominent) ───────────────────────
    const wizardSection = containerEl.createDiv("openclaw-settings-wizard");
    const wizardDesc = wizardSection.createDiv("openclaw-settings-wizard-desc");
    wizardDesc.createEl("strong", { text: "Setup wizard" });
    wizardDesc.createEl("p", {
      text: "The easiest way to connect. Walks you through Tailscale, gateway setup, and device pairing step by step.",
      cls: "setting-item-description",
    });
    const wizardBtn = wizardSection.createEl("button", { text: "Run setup wizard", cls: "mod-cta openclaw-settings-wizard-btn" });
    wizardBtn.addEventListener("click", () => {
      new OnboardingModal(this.app, this.plugin).open();
    });

    // ─── Status ──────────────────────────────────────────────────
    const statusSection = containerEl.createDiv("openclaw-settings-status");
    const connected = this.plugin.gatewayConnected;
    const statusDot = statusSection.createSpan({ cls: `openclaw-settings-dot ${connected ? "connected" : "disconnected"}` });
    statusSection.createSpan({ text: connected ? "Connected" : "Disconnected", cls: "openclaw-settings-status-text" });
    if (this.plugin.settings.gatewayUrl) {
      statusSection.createSpan({
        text: ` — ${this.plugin.settings.gatewayUrl.replace(/^wss?:\/\//, "")}`,
        cls: "openclaw-settings-status-url",
      });
    }

    // ─── Session ──────────────────────────────────────────────────
    containerEl.createEl("h3", { text: "Session" });

    new Setting(containerEl)
      .setName("Conversation")
      .setDesc("Current conversation key. Use \"main\" for the default session.")
      .addText((text) =>
        text
          .setPlaceholder("main")
          .setValue(this.plugin.settings.sessionKey)
          .onChange(async (value) => {
            this.plugin.settings.sessionKey = value || "main";
            await this.plugin.saveSettings();
          })
      )
      .addButton((btn) =>
        btn
          .setButtonText("Reset to Main")
          .onClick(async () => {
            this.plugin.settings.sessionKey = "main";
            await this.plugin.saveSettings();
            this.display(); // refresh the settings UI
            await this.plugin.connectGateway();
            new Notice("Reset to Main conversation");
          })
      );

    // ─── Connection (Advanced) ────────────────────────────────────
    const advancedHeader = containerEl.createEl("h3", { text: "Connection", cls: "openclaw-settings-advanced-header" });
    const advancedHint = containerEl.createEl("p", {
      text: "These are set automatically by the setup wizard. Edit manually only if you know what you're doing.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Gateway URL")
      .setDesc("Tailscale Serve URL (e.g. wss://your-machine.tail1234.ts.net)")
      .addText((text) =>
        text
          .setPlaceholder("wss://your-machine.tail1234.ts.net")
          .setValue(this.plugin.settings.gatewayUrl)
          .onChange(async (value) => {
            const normalized = normalizeGatewayUrl(value);
            this.plugin.settings.gatewayUrl = normalized || value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Auth token")
      .setDesc("Gateway auth token")
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
      .setName("Reconnect")
      .setDesc("Re-establish the gateway connection")
      .addButton((btn) =>
        btn.setButtonText("Reconnect").onClick(() => {
          this.plugin.connectGateway();
          new Notice("OpenClaw: Reconnecting...");
        })
      );
  }
}
