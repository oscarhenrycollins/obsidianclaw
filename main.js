var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// main.ts
var main_exports = {};
__export(main_exports, {
  default: () => OpenClawPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");
function str(v, fallback = "") {
  return typeof v === "string" ? v : fallback;
}
var DEFAULT_SETTINGS = {
  gatewayUrl: "",
  token: "",
  sessionKey: "main",
  onboardingComplete: false
};
function normalizeGatewayUrl(raw) {
  let url = raw.trim();
  if (url.startsWith("https://"))
    url = "wss://" + url.slice(8);
  else if (url.startsWith("http://"))
    url = "ws://" + url.slice(7);
  if (!url.startsWith("ws://") && !url.startsWith("wss://"))
    return null;
  return url.replace(/\/+$/, "");
}
function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes)
    binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", data.buffer);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}
async function getOrCreateDeviceIdentity(loadData, saveData) {
  var _a;
  const data = await loadData();
  const deviceId = typeof (data == null ? void 0 : data.deviceId) === "string" ? data.deviceId : null;
  const devicePublicKey = typeof (data == null ? void 0 : data.devicePublicKey) === "string" ? data.devicePublicKey : null;
  const devicePrivateKey = typeof (data == null ? void 0 : data.devicePrivateKey) === "string" ? data.devicePrivateKey : null;
  if (deviceId && devicePublicKey && devicePrivateKey) {
    const privBytes = fromBase64Url(devicePrivateKey);
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privBytes,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    return {
      deviceId,
      publicKey: devicePublicKey,
      privateKey: devicePrivateKey,
      cryptoKey
    };
  }
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const newDeviceId = await sha256Hex(pubRaw);
  const publicKey = toBase64Url(pubRaw);
  const privateKey = toBase64Url(privPkcs8);
  const existing = (_a = await loadData()) != null ? _a : {};
  existing.deviceId = newDeviceId;
  existing.devicePublicKey = publicKey;
  existing.devicePrivateKey = privateKey;
  await saveData(existing);
  return { deviceId: newDeviceId, publicKey, privateKey, cryptoKey: keyPair.privateKey };
}
async function signDevicePayload(identity, payload) {
  const encoded = new TextEncoder().encode(payload);
  let cryptoKey = identity.cryptoKey;
  if (!cryptoKey) {
    const privBytes = fromBase64Url(identity.privateKey);
    cryptoKey = await crypto.subtle.importKey("pkcs8", privBytes, { name: "Ed25519" }, false, ["sign"]);
  }
  const sig = await crypto.subtle.sign("Ed25519", cryptoKey, encoded);
  return toBase64Url(new Uint8Array(sig));
}
function buildSignaturePayload(params) {
  var _a, _b;
  const version = params.nonce ? "v2" : "v1";
  const parts = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    params.scopes.join(","),
    String(params.signedAtMs),
    (_a = params.token) != null ? _a : ""
  ];
  if (version === "v2")
    parts.push((_b = params.nonce) != null ? _b : "");
  return parts.join("|");
}
function generateId() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}
async function deleteSessionWithFallback(gateway, key, deleteTranscript = true) {
  const result = await gateway.request("sessions.delete", { key, deleteTranscript });
  if (result == null ? void 0 : result.deleted)
    return true;
  const match = key.match(/^agent:[^:]+:(.+)$/);
  if (match) {
    const rawKey = match[1];
    const retry = await gateway.request("sessions.delete", { key: rawKey, deleteTranscript });
    return !!(retry == null ? void 0 : retry.deleted);
  }
  return false;
}
var GatewayClient = class {
  constructor(opts) {
    this.ws = null;
    this.pending = /* @__PURE__ */ new Map();
    this.closed = false;
    this.connectSent = false;
    this.connectNonce = null;
    this.backoffMs = 800;
    this.connectTimer = null;
    this.pendingTimeouts = /* @__PURE__ */ new Map();
    this.opts = opts;
  }
  get connected() {
    var _a;
    return ((_a = this.ws) == null ? void 0 : _a.readyState) === WebSocket.OPEN;
  }
  start() {
    this.closed = false;
    this.doConnect();
  }
  stop() {
    var _a;
    this.closed = true;
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
    for (const [, t] of this.pendingTimeouts)
      clearTimeout(t);
    this.pendingTimeouts.clear();
    (_a = this.ws) == null ? void 0 : _a.close();
    this.ws = null;
    this.flushPending(new Error("client stopped"));
  }
  async request(method, params) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("not connected");
    }
    const id = generateId();
    const msg = { type: "req", id, method, params };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const t = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error("request timeout"));
        }
      }, 3e4);
      this.pendingTimeouts.set(id, t);
      this.ws.send(JSON.stringify(msg));
    });
  }
  doConnect() {
    if (this.closed)
      return;
    const url = normalizeGatewayUrl(this.opts.url);
    if (!url) {
      console.error("[ObsidianClaw] Invalid gateway URL: must be a valid ws://, wss://, http://, or https:// URL");
      return;
    }
    this.ws = new WebSocket(url);
    this.ws.addEventListener("open", () => this.queueConnect());
    this.ws.addEventListener("message", (e) => this.handleMessage(str(e.data)));
    this.ws.addEventListener("close", (e) => {
      var _a, _b;
      this.ws = null;
      this.flushPending(new Error(`closed (${e.code})`));
      (_b = (_a = this.opts).onClose) == null ? void 0 : _b.call(_a, { code: e.code, reason: e.reason || "" });
      this.scheduleReconnect();
    });
    this.ws.addEventListener("error", () => {
    });
  }
  scheduleReconnect() {
    if (this.closed)
      return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 1.7, 15e3);
    setTimeout(() => this.doConnect(), delay);
  }
  flushPending(err) {
    for (const [id, p] of this.pending) {
      const t = this.pendingTimeouts.get(id);
      if (t)
        clearTimeout(t);
      p.reject(err);
    }
    this.pending.clear();
    this.pendingTimeouts.clear();
  }
  queueConnect() {
    this.connectNonce = null;
    this.connectSent = false;
    if (this.connectTimer !== null)
      clearTimeout(this.connectTimer);
    this.connectTimer = setTimeout(() => void this.sendConnect(), 750);
  }
  async sendConnect() {
    var _a, _b;
    if (this.connectSent)
      return;
    this.connectSent = true;
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
    const CLIENT_ID = "gateway-client";
    const CLIENT_MODE = "ui";
    const ROLE = "operator";
    const SCOPES = ["operator.admin", "operator.write", "operator.read"];
    const auth = this.opts.token ? { token: this.opts.token } : void 0;
    let device = void 0;
    const identity = this.opts.deviceIdentity;
    if (identity) {
      try {
        const signedAtMs = Date.now();
        const nonce = (_a = this.connectNonce) != null ? _a : null;
        const payload = buildSignaturePayload({
          deviceId: identity.deviceId,
          clientId: CLIENT_ID,
          clientMode: CLIENT_MODE,
          role: ROLE,
          scopes: SCOPES,
          signedAtMs,
          token: (_b = this.opts.token) != null ? _b : null,
          nonce
        });
        const signature = await signDevicePayload(identity, payload);
        device = {
          id: identity.deviceId,
          publicKey: identity.publicKey,
          signature,
          signedAt: signedAtMs,
          nonce: nonce != null ? nonce : void 0
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
        mode: CLIENT_MODE
      },
      role: ROLE,
      scopes: SCOPES,
      auth,
      device,
      caps: ["tool-events"]
    };
    void this.request("connect", params).then((payload) => {
      var _a2, _b2;
      this.backoffMs = 800;
      (_b2 = (_a2 = this.opts).onHello) == null ? void 0 : _b2.call(_a2, payload);
    }).catch(() => {
      var _a2;
      (_a2 = this.ws) == null ? void 0 : _a2.close(4008, "connect failed");
    });
  }
  handleMessage(raw) {
    var _a, _b, _c, _d, _e;
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch (e) {
      return;
    }
    if (msg.type === "event") {
      if (msg.event === "connect.challenge") {
        const nonce = (_a = msg.payload) == null ? void 0 : _a.nonce;
        if (typeof nonce === "string") {
          this.connectNonce = nonce;
          void this.sendConnect();
        }
        return;
      }
      (_c = (_b = this.opts).onEvent) == null ? void 0 : _c.call(_b, msg);
      return;
    }
    if (msg.type === "res") {
      const p = this.pending.get(msg.id);
      if (!p)
        return;
      this.pending.delete(msg.id);
      const t = this.pendingTimeouts.get(msg.id);
      if (t) {
        clearTimeout(t);
        this.pendingTimeouts.delete(msg.id);
      }
      if (msg.ok) {
        p.resolve(msg.payload);
      } else {
        p.reject(new Error((_e = (_d = msg.error) == null ? void 0 : _d.message) != null ? _e : "request failed"));
      }
    }
  }
};
var _OnboardingModal = class _OnboardingModal extends import_obsidian.Modal {
  constructor(app, plugin) {
    super(app);
    this.step = 0;
    this.path = null;
    this.statusEl = null;
    this.pairingPollTimer = null;
    // Setup state for fresh install path
    this.setupKeys = { claude1: "", claude2: "", googleai: "", brave: "", elevenlabs: "" };
    this.setupBots = [{ name: "Assistant", model: "anthropic/claude-sonnet-4-6" }];
    this.plugin = plugin;
  }
  onOpen() {
    this.modalEl.addClass("openclaw-onboarding");
    this.renderStep();
  }
  onClose() {
    if (this.pairingPollTimer) {
      clearInterval(this.pairingPollTimer);
      this.pairingPollTimer = null;
    }
  }
  /** Safely render simple HTML (text, <a>, <code>, <strong>) into an element using DOM API */
  setRichText(el, html) {
    var _a, _b, _c, _d, _e, _f;
    el.empty();
    const parser = new DOMParser();
    const doc = parser.parseFromString(`<span>${html}</span>`, "text/html");
    const source = doc.body.firstElementChild;
    if (!source) {
      el.setText(html);
      return;
    }
    for (const node of Array.from(source.childNodes)) {
      if (node.nodeType === Node.TEXT_NODE) {
        el.appendText((_a = node.textContent) != null ? _a : "");
      } else if (node instanceof HTMLElement) {
        const tag = node.tagName.toLowerCase();
        if (tag === "a") {
          el.createEl("a", { text: (_b = node.textContent) != null ? _b : "", href: (_c = node.getAttribute("href")) != null ? _c : "" });
        } else if (tag === "code") {
          el.createEl("code", { text: (_d = node.textContent) != null ? _d : "" });
        } else if (tag === "strong") {
          el.createEl("strong", { text: (_e = node.textContent) != null ? _e : "" });
        } else {
          el.appendText((_f = node.textContent) != null ? _f : "");
        }
      }
    }
  }
  renderStep() {
    const { contentEl } = this;
    contentEl.empty();
    this.statusEl = null;
    const stepLabels = this.path === "fresh" ? ["Start", "Keys", "Bots", "Install", "Connect", "Pair", "Done"] : this.path === "existing" ? ["Start", "Network", "Gateway", "Connect", "Pair", "Done"] : ["Start"];
    const indicator = contentEl.createDiv("openclaw-onboard-steps");
    stepLabels.forEach((label, i) => {
      const dot = indicator.createSpan("openclaw-step-dot" + (i === this.step ? " active" : i < this.step ? " done" : ""));
      dot.textContent = i < this.step ? "\u2713" : String(i + 1);
      if (i < stepLabels.length - 1)
        indicator.createSpan("openclaw-step-line" + (i < this.step ? " done" : ""));
    });
    if (this.step === 0)
      return this.renderWelcome(contentEl);
    if (this.path === "fresh") {
      if (this.step === 1)
        return this.renderKeys(contentEl);
      if (this.step === 2)
        return this.renderBots(contentEl);
      if (this.step === 3)
        return this.renderInstallCmd(contentEl);
      if (this.step === 4)
        return this.renderConnect(contentEl);
      if (this.step === 5)
        return this.renderPairing(contentEl);
      if (this.step === 6)
        return this.renderDone(contentEl);
    } else {
      if (this.step === 1)
        return this.renderNetwork(contentEl);
      if (this.step === 2)
        return this.renderGateway(contentEl);
      if (this.step === 3)
        return this.renderConnect(contentEl);
      if (this.step === 4)
        return this.renderPairing(contentEl);
      if (this.step === 5)
        return this.renderDone(contentEl);
    }
  }
  // ─── Step 0: Welcome (branching) ─────────────────────────────────
  renderWelcome(el) {
    el.createEl("h2", { text: "Welcome to OpenClaw" });
    el.createEl("p", {
      text: "This plugin connects Obsidian to your OpenClaw AI agent. Your vault becomes the agent's workspace.",
      cls: "openclaw-onboard-desc"
    });
    const btnRow = el.createDiv("openclaw-onboard-buttons openclaw-onboard-buttons-vertical");
    const freshBtn = btnRow.createEl("button", { text: "I need to install OpenClaw", cls: "mod-cta openclaw-full-width" });
    freshBtn.addEventListener("click", () => {
      this.path = "fresh";
      this.step = 1;
      this.renderStep();
    });
    const existBtn = btnRow.createEl("button", { text: "OpenClaw is already running", cls: "openclaw-full-width" });
    existBtn.addEventListener("click", () => {
      this.path = "existing";
      this.step = 1;
      this.renderStep();
    });
  }
  // ─── Fresh path: Step 1 — API Keys ───────────────────────────────
  renderKeys(el) {
    el.createEl("h2", { text: "Your API keys" });
    el.createEl("p", {
      text: "Your bot needs AI model access. Paste your keys below \u2014 they'll be included in the install command. Nothing leaves your device.",
      cls: "openclaw-onboard-desc"
    });
    const fields = [
      { key: "claude1", label: "Claude token", required: true, placeholder: "sk-ant-...", help: "From <a href='https://console.anthropic.com/settings/keys'>console.anthropic.com</a> or Claude Max OAuth" },
      { key: "claude2", label: "Claude token #2 (parallel requests)", placeholder: "sk-ant-...", help: "Optional \u2014 enables concurrent requests" },
      { key: "googleai", label: "Google AI API key", placeholder: "AIza...", help: "Free at <a href='https://aistudio.google.com/apikey'>aistudio.google.com</a> \u2014 enables Gemini models" },
      { key: "brave", label: "Brave Search API key", placeholder: "BSA...", help: "Free at <a href='https://brave.com/search/api/'>brave.com/search/api</a> \u2014 web search" },
      { key: "elevenlabs", label: "ElevenLabs API key", placeholder: "sk_...", help: "Free at <a href='https://elevenlabs.io'>elevenlabs.io</a> \u2014 voice/TTS" }
    ];
    for (const f of fields) {
      const group = el.createDiv("openclaw-onboard-field");
      const label = group.createEl("label", { text: f.label });
      if (f.required) {
        const req = label.createSpan({ cls: "oc-req-label" });
        req.textContent = " (required)";
      }
      const input = group.createEl("input", {
        type: "password",
        value: this.setupKeys[f.key],
        placeholder: f.placeholder,
        cls: "openclaw-onboard-input"
      });
      input.addEventListener("input", () => {
        this.setupKeys[f.key] = input.value.trim();
      });
      const help = group.createDiv("openclaw-onboard-hint");
      this.setRichText(help, f.help);
    }
    const note = el.createDiv("openclaw-onboard-info");
    note.setText("\u{1F512} Keys stay on your device. The install command runs entirely on your server.");
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 0;
      this.path = null;
      this.renderStep();
    });
    const nextBtn = btnRow.createEl("button", { text: "Next \u2192", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      if (!this.setupKeys.claude1) {
        this.showStatus("Claude token is required", "error");
        return;
      }
      this.step = 2;
      this.renderStep();
    });
  }
  // ─── Fresh path: Step 2 — Bot config ─────────────────────────────
  renderBots(el) {
    el.createEl("h2", { text: "Configure your bots" });
    el.createEl("p", {
      text: "Each bot gets its own personality, memory, and workspace folder.",
      cls: "openclaw-onboard-desc"
    });
    const listEl = el.createDiv();
    this.setupBots.forEach((bot, i) => {
      const card = listEl.createDiv("openclaw-onboard-bot-card");
      const row = card.createDiv("openclaw-onboard-bot-row");
      const nameInput = row.createEl("input", { type: "text", value: bot.name, placeholder: "Bot name", cls: "openclaw-onboard-input oc-name-input" });
      nameInput.addEventListener("input", () => {
        bot.name = nameInput.value;
      });
      const select = row.createEl("select", { cls: "openclaw-onboard-input oc-select-inline" });
      for (const m of _OnboardingModal.MODELS) {
        const opt = select.createEl("option", { text: m.label, value: m.id });
        if (m.id === bot.model)
          opt.selected = true;
      }
      select.addEventListener("change", () => {
        bot.model = select.value;
      });
      if (this.setupBots.length > 1) {
        const removeBtn = row.createEl("span", { text: "\xD7", cls: "oc-remove-btn" });
        removeBtn.addEventListener("click", () => {
          this.setupBots.splice(i, 1);
          this.renderStep();
        });
      }
    });
    const addBtn = el.createEl("button", { text: "+ add another bot", cls: "oc-add-bot-btn" });
    addBtn.addEventListener("click", () => {
      this.setupBots.push({ name: "", model: "anthropic/claude-sonnet-4-6" });
      this.renderStep();
    });
    const note = el.createDiv("openclaw-onboard-hint oc-margin-top");
    note.createEl("span", { text: "Each bot gets a folder like " });
    note.createEl("code", { text: "AGENT-YOURBOT/" });
    note.createEl("span", { text: " in your vault." });
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 1;
      this.renderStep();
    });
    const nextBtn = btnRow.createEl("button", { text: "Generate install command \u2192", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      this.step = 3;
      this.renderStep();
    });
  }
  // ─── Fresh path: Step 3 — Install command ────────────────────────
  renderInstallCmd(el) {
    el.createEl("h2", { text: "Install OpenClaw" });
    el.createEl("p", {
      text: "Open a terminal on your server (Mac: Cmd+Space \u2192 Terminal, cloud: ssh in). Run this command:",
      cls: "openclaw-onboard-desc"
    });
    const config = this.generateConfig();
    const configJson = JSON.stringify(config, null, 2);
    const configB64 = btoa(Array.from(new TextEncoder().encode(configJson), (b) => String.fromCharCode(b)).join(""));
    const installCmd = `curl -fsSL https://openclaw.ai/install.sh | bash && echo '${configB64}' | base64 -d > ~/.openclaw/openclaw.json && openclaw gateway restart`;
    this.makeCopyBox(el, installCmd);
    el.createEl("p", { text: "This installs OpenClaw, writes your config with all API keys and bot settings, configures Tailscale Serve, and starts the gateway.", cls: "openclaw-onboard-hint" });
    const details = el.createEl("details", { cls: "oc-margin-top" });
    details.createEl("summary", { text: "Preview config", cls: "oc-details-summary" });
    const pre = details.createEl("pre", { cls: "oc-install-pre" });
    pre.textContent = JSON.stringify(config, null, 2);
    el.createEl("p", { text: "After it finishes, install Tailscale if you haven't:", cls: "openclaw-onboard-desc" });
    this.makeCopyBox(el, "# Mac:\nbrew install --cask tailscale\n\n# Linux:\ncurl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up");
    el.createEl("p", { text: "Then install Tailscale on this device too, using the same account.", cls: "openclaw-onboard-hint" });
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 2;
      this.renderStep();
    });
    const nextBtn = btnRow.createEl("button", { text: "OpenClaw is running \u2192", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      this.step = 4;
      this.renderStep();
    });
  }
  generateConfig() {
    var _a, _b;
    const config = {
      auth: { profiles: {} },
      agents: { defaults: { model: { primary: ((_a = this.setupBots[0]) == null ? void 0 : _a.model) || "anthropic/claude-sonnet-4-6" } } },
      gateway: { port: 18789, bind: "loopback", tailscale: { mode: "serve" }, auth: { mode: "token", allowTailscale: true } }
    };
    if (this.setupKeys.claude1)
      config.auth.profiles["anthropic:default"] = { provider: "anthropic", mode: "token" };
    if (this.setupKeys.claude2)
      config.auth.profiles["anthropic:secondary"] = { provider: "anthropic", mode: "token" };
    if (this.setupKeys.googleai)
      config.auth.profiles["google:default"] = { provider: "google", mode: "api_key" };
    if (this.setupKeys.brave)
      config.tools = { web: { search: { apiKey: this.setupKeys.brave } } };
    if (this.setupKeys.elevenlabs)
      config.messages = { tts: { provider: "elevenlabs", elevenlabs: { apiKey: this.setupKeys.elevenlabs } } };
    if (this.setupBots.length > 1) {
      config.agents.list = this.setupBots.map((bot, i) => {
        const id = i === 0 ? "main" : bot.name.toLowerCase().replace(/[^a-z0-9]/g, "-") || `bot-${i}`;
        const folder = "AGENT-" + (bot.name || "BOT").toUpperCase().replace(/[^A-Z0-9]/g, "-");
        return { id, name: bot.name || `Bot ${i + 1}`, workspace: `~/.openclaw/workspace/${folder}` };
      });
    } else if ((_b = this.setupBots[0]) == null ? void 0 : _b.name) {
      const folder = "AGENT-" + this.setupBots[0].name.toUpperCase().replace(/[^A-Z0-9]/g, "-");
      config.agents.defaults.workspace = `~/.openclaw/workspace/${folder}`;
    }
    return config;
  }
  // ─── Existing path: Step 1 — Network (Tailscale) ─────────────────
  renderNetwork(el) {
    el.createEl("h2", { text: "Set up your private network" });
    el.createEl("p", {
      text: "Tailscale creates an encrypted private network between your devices. No ports to open, no VPN to configure.",
      cls: "openclaw-onboard-desc"
    });
    el.createEl("h3", { text: "Install Tailscale on both devices" });
    const steps = el.createEl("ol", { cls: "openclaw-onboard-list" });
    const s1 = steps.createEl("li");
    s1.appendText("Install on your ");
    s1.createEl("strong", { text: "gateway machine" });
    s1.appendText(": ");
    s1.createEl("a", { text: "tailscale.com/download", href: "https://tailscale.com/download" });
    const s2 = steps.createEl("li");
    s2.appendText("Install on ");
    s2.createEl("strong", { text: "this device" });
    s2.appendText(": ");
    s2.createEl("a", { text: "tailscale.com/download", href: "https://tailscale.com/download" });
    steps.createEl("li", { text: "Sign in to the same Tailscale account on both." });
    el.createEl("p", { text: "Verify by running this on the gateway:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(el, "tailscale status");
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 0;
      this.path = null;
      this.renderStep();
    });
    const nextBtn = btnRow.createEl("button", { text: "Both on Tailscale \u2192", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      this.step = 2;
      this.renderStep();
    });
  }
  // ─── Existing path: Step 2 — Gateway (Tailscale Serve) ───────────
  renderGateway(el) {
    el.createEl("h2", { text: "Expose your gateway" });
    el.createEl("p", {
      text: "Tailscale Serve gives your gateway a private HTTPS address. Run on the gateway machine:",
      cls: "openclaw-onboard-desc"
    });
    el.createEl("strong", { text: "1. Configure OpenClaw" });
    this.makeCopyBox(el, "openclaw config set gateway.bind loopback\nopenclaw config set gateway.tailscale.mode serve\nopenclaw gateway restart");
    el.createEl("strong", { text: "2. Start Tailscale serve" });
    this.makeCopyBox(el, "tailscale serve --bg http://127.0.0.1:18789");
    el.createEl("strong", { text: "3. Get your URL and token" });
    this.makeCopyBox(el, "tailscale serve status");
    this.makeCopyBox(el, "cat ~/.openclaw/openclaw.json | grep token");
    const hint = el.createDiv("openclaw-onboard-hint");
    hint.appendText("Copy the ");
    hint.createEl("code", { text: "https://your-machine.tailXXXX.ts.net" });
    hint.appendText(" URL and the auth token for the next step.");
    const trouble = el.createDiv("openclaw-onboard-info");
    trouble.appendText("\u{1F4A1} ");
    trouble.createEl("strong", { text: "Not working?" });
    trouble.appendText(" Run: ");
    this.makeCopyBox(trouble, "openclaw doctor --fix && openclaw gateway restart");
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 1;
      this.renderStep();
    });
    const nextBtn = btnRow.createEl("button", { text: "I have the URL and token \u2192", cls: "mod-cta" });
    nextBtn.addEventListener("click", () => {
      this.step = 3;
      this.renderStep();
    });
  }
  // ─── Step 3: Connect ─────────────────────────────────────────────
  renderConnect(el) {
    el.createEl("h2", { text: "Connect to your gateway" });
    el.createEl("p", {
      text: "Paste the URL and token from the previous step.",
      cls: "openclaw-onboard-desc"
    });
    const urlGroup = el.createDiv("openclaw-onboard-field");
    urlGroup.createEl("label", { text: "Gateway URL" });
    const urlInput = urlGroup.createEl("input", {
      type: "text",
      value: this.plugin.settings.gatewayUrl || "",
      placeholder: "https://your-machine.tail1234.ts.net",
      cls: "openclaw-onboard-input"
    });
    const urlHint = urlGroup.createDiv("openclaw-onboard-hint");
    urlHint.appendText("The URL from ");
    urlHint.createEl("code", { text: "tailscale serve status" });
    urlHint.appendText(". You can paste ");
    urlHint.createEl("code", { text: "https://" });
    urlHint.appendText(" or ");
    urlHint.createEl("code", { text: "wss://" });
    urlHint.appendText(" \u2014 both work.");
    const tokenGroup = el.createDiv("openclaw-onboard-field");
    tokenGroup.createEl("label", { text: "Auth token" });
    const tokenInput = tokenGroup.createEl("input", {
      type: "password",
      value: this.plugin.settings.token || "",
      placeholder: "Paste your gateway auth token",
      cls: "openclaw-onboard-input"
    });
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const troubleshoot = el.createDiv("openclaw-onboard-troubleshoot");
    troubleshoot.addClass("oc-hidden");
    troubleshoot.createEl("h3", { text: "Troubleshooting" });
    const checks = troubleshoot.createEl("ol", { cls: "openclaw-onboard-list" });
    const li1 = checks.createEl("li");
    li1.createEl("strong", { text: "Is Tailscale connected on this device?" });
    li1.appendText(" Check the Tailscale icon in your system tray / menu bar. If it's off, turn it on.");
    const li2 = checks.createEl("li");
    li2.createEl("strong", { text: "DNS not resolving? (most common on macOS)" });
    li2.appendText(" Open the ");
    li2.createEl("strong", { text: "Tailscale app" });
    li2.appendText(" from your menu bar, toggle it ");
    li2.createEl("strong", { text: "OFF" });
    li2.appendText(", wait 5 seconds, toggle it ");
    li2.createEl("strong", { text: "ON" });
    li2.appendText(". This resets MagicDNS, which macOS sometimes loses track of.");
    const li3 = checks.createEl("li");
    li3.setText("Is the gateway running? On the gateway machine, run:");
    this.makeCopyBox(troubleshoot, "openclaw doctor --fix && openclaw gateway restart");
    const li4 = checks.createEl("li");
    li4.setText("Is Tailscale Serve active? On the gateway machine, run:");
    this.makeCopyBox(troubleshoot, "tailscale serve status");
    const tsHint = troubleshoot.createDiv("openclaw-onboard-hint");
    tsHint.setText("If Tailscale Serve shows nothing, set it up:");
    this.makeCopyBox(troubleshoot, "tailscale serve --bg http://127.0.0.1:18789");
    const li5 = checks.createEl("li");
    li5.createEl("strong", { text: "Gateway config broken?" });
    li5.appendText(" If ");
    li5.createEl("code", { text: "openclaw doctor" });
    li5.appendText(' shows "Invalid config" errors, your gateway config file may have been corrupted. To reset to the recommended setup, run these on the gateway machine:');
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
    li5hint.setText("Then restart the gateway and re-enable Tailscale Serve:");
    this.makeCopyBox(troubleshoot, "openclaw gateway restart && tailscale serve --bg http://127.0.0.1:18789");
    const li6 = checks.createEl("li");
    li6.createEl("strong", { text: "Still stuck?" });
    li6.appendText(" Try restarting the Tailscale app entirely, or reboot this device. macOS DNS can get stuck and needs a fresh start.");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 2;
      this.renderStep();
    });
    const testBtn = btnRow.createEl("button", { text: "Test connection", cls: "mod-cta" });
    testBtn.addEventListener("click", () => void (async () => {
      const url = urlInput.value.trim();
      const token = tokenInput.value.trim();
      if (!url) {
        this.showStatus("Paste your gateway URL from the previous step", "error");
        return;
      }
      const normalizedUrl = normalizeGatewayUrl(url);
      if (!normalizedUrl) {
        this.showStatus("That doesn't look right. Paste the URL from `tailscale serve status` (e.g. https://your-machine.tail1234.ts.net)", "error");
        return;
      }
      if (!token) {
        this.showStatus("Paste your auth token", "error");
        return;
      }
      testBtn.disabled = true;
      testBtn.textContent = "Connecting...";
      troubleshoot.addClass("oc-hidden");
      this.showStatus("Testing connection...", "info");
      urlInput.value = normalizedUrl;
      this.plugin.settings.gatewayUrl = normalizedUrl;
      this.plugin.settings.token = token;
      this.plugin.settings.sessionKey = "main";
      await this.plugin.saveSettings();
      const ok = await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          tc.stop();
          resolve(false);
        }, 8e3);
        const tc = new GatewayClient({
          url: normalizedUrl,
          token,
          onHello: () => {
            clearTimeout(timeout);
            tc.stop();
            resolve(true);
          },
          onClose: () => {
          }
        });
        tc.start();
      });
      testBtn.disabled = false;
      testBtn.textContent = "Test connection";
      if (ok) {
        this.showStatus("\u2713 Connected!", "success");
        setTimeout(() => {
          this.step = 4;
          this.renderStep();
        }, 800);
      } else {
        this.showStatus("Could not connect. Check the troubleshooting steps below.", "error");
        troubleshoot.removeClass("oc-hidden");
      }
    })());
  }
  makeCopyBox(parent, command) {
    const box = parent.createDiv("openclaw-copy-box");
    box.createEl("code", { text: command });
    const btn = box.createSpan("openclaw-copy-btn");
    btn.textContent = "Copy";
    box.addEventListener("click", () => {
      void navigator.clipboard.writeText(command).then(() => {
        btn.textContent = "\u2713";
        setTimeout(() => btn.textContent = "Copy", 1500);
      });
    });
    return box;
  }
  // ─── Step 4: Device Pairing ──────────────────────────────────────
  renderPairing(el) {
    var _a, _b;
    el.createEl("h2", { text: "Pair this device" });
    el.createEl("p", {
      text: "For security, each device needs one-time approval from the gateway. This creates a unique keypair for this device so the gateway knows it's you.",
      cls: "openclaw-onboard-desc"
    });
    const hasKeys = this.plugin.settings.deviceId && this.plugin.settings.devicePublicKey;
    if (hasKeys) {
      const info = el.createDiv("openclaw-onboard-info");
      info.createEl("p", { text: "This device already has a keypair." });
      const deviceP = info.createEl("p");
      deviceP.appendText("Device ID: ");
      deviceP.createEl("code", { text: ((_b = (_a = this.plugin.settings.deviceId) == null ? void 0 : _a.slice(0, 12)) != null ? _b : "") + "..." });
    }
    this.statusEl = el.createDiv("openclaw-onboard-status");
    const approvalInfo = el.createDiv("openclaw-onboard-numbered");
    const a1 = approvalInfo.createDiv("openclaw-onboard-numbered-item");
    a1.createEl("strong", { text: "How approval works" });
    a1.createEl("p", { text: "Click the button below to send a pairing request. Then, on your gateway machine, run:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(a1, "openclaw devices list");
    a1.createEl("p", { text: "You'll see your pending request. Approve it with:", cls: "openclaw-onboard-hint" });
    this.makeCopyBox(a1, "openclaw devices approve <requestId>");
    const a1hint = a1.createEl("p", { cls: "openclaw-onboard-hint" });
    a1hint.appendText("Replace ");
    a1hint.createEl("code", { text: "<requestId>" });
    a1hint.appendText(" with the ID shown in the pending list. You can also approve from the OpenClaw Control UI dashboard.");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    btnRow.createEl("button", { text: "\u2190 back" }).addEventListener("click", () => {
      this.step = 3;
      this.renderStep();
    });
    const pairBtn = btnRow.createEl("button", {
      text: hasKeys ? "Check pairing status" : "Send pairing request",
      cls: "mod-cta"
    });
    pairBtn.addEventListener("click", () => void (async () => {
      pairBtn.disabled = true;
      this.showStatus("Connecting to gateway...", "info");
      try {
        await this.plugin.connectGateway();
        await new Promise((r) => setTimeout(r, 2e3));
        if (!this.plugin.gatewayConnected) {
          this.showStatus("Could not connect to gateway. Go back and check your settings.", "error");
          pairBtn.disabled = false;
          return;
        }
        try {
          const result = await this.plugin.gateway.request("sessions.list", {});
          if (result == null ? void 0 : result.sessions) {
            this.showStatus("\u2713 Device is paired and authorized!", "success");
            setTimeout(() => {
              this.step = 5;
              this.renderStep();
            }, 1e3);
            return;
          }
        } catch (e) {
          const msg = String(e);
          if (msg.includes("scope") || msg.includes("auth") || msg.includes("pair")) {
            this.showStatus("\u23F3 Pairing request sent! Now approve it on your gateway machine using the commands above.\n\nWaiting for approval...", "info");
            this.startPairingPoll(pairBtn);
            return;
          }
        }
        this.showStatus("\u2713 Connection working! Proceeding...", "success");
        setTimeout(() => {
          this.step = 5;
          this.renderStep();
        }, 1e3);
      } catch (e) {
        this.showStatus(`Error: ${e}`, "error");
        pairBtn.disabled = false;
      }
    })());
    const skipBtn = btnRow.createEl("button", { text: "Skip for now" });
    skipBtn.addEventListener("click", () => {
      this.step = 5;
      this.renderStep();
    });
  }
  startPairingPoll(btn) {
    let attempts = 0;
    this.pairingPollTimer = setInterval(() => void (async () => {
      var _a;
      attempts++;
      if (attempts > 60) {
        if (this.pairingPollTimer)
          clearInterval(this.pairingPollTimer);
        this.showStatus("Timed out waiting for approval. You can approve later and re-run the setup wizard from settings.", "error");
        btn.disabled = false;
        return;
      }
      try {
        const result = await ((_a = this.plugin.gateway) == null ? void 0 : _a.request("sessions.list", {}));
        if (result == null ? void 0 : result.sessions) {
          if (this.pairingPollTimer)
            clearInterval(this.pairingPollTimer);
          this.showStatus("\u2713 Device approved!", "success");
          setTimeout(() => {
            this.step = 5;
            this.renderStep();
          }, 1e3);
        }
      } catch (e) {
      }
    })(), 2e3);
  }
  // ─── Step 5: Done ────────────────────────────────────────────────
  renderDone(el) {
    el.createEl("h2", { text: "You're all set! \u{1F389}" });
    el.createEl("p", {
      text: "OpenClaw is connected and ready. Your vault is now the agent's workspace.",
      cls: "openclaw-onboard-desc"
    });
    const tips = el.createDiv("openclaw-onboard-tips");
    tips.createEl("h3", { text: "What you can do" });
    const list = tips.createEl("ul", { cls: "openclaw-onboard-list" });
    list.createEl("li", { text: "Chat with your AI agent in the sidebar" });
    list.createEl("li", { text: 'Use Cmd/Ctrl+P \u2192 "Ask about current note" to discuss any note' });
    list.createEl("li", { text: "The agent can read, create, and edit files in your vault" });
    list.createEl("li", { text: "Tool calls appear inline \u2014 click file paths to open them" });
    const syncTip = el.createDiv("openclaw-onboard-info");
    syncTip.createEl("strong", { text: "\u{1F4A1} sync tip: " });
    syncTip.createEl("span", {
      text: "Enable Obsidian Sync to access your agent from multiple devices. Your chat settings and device keys sync automatically \u2014 set up once, works everywhere."
    });
    const controlTip = el.createDiv("openclaw-onboard-info");
    controlTip.createEl("strong", { text: "\u{1F5A5}\uFE0F control UI: " });
    const ctrlSpan = controlTip.createEl("span");
    ctrlSpan.setText("You can also manage your gateway from any browser on your Tailscale network. Just open your gateway URL in a browser.");
    const btnRow = el.createDiv("openclaw-onboard-buttons");
    const doneBtn = btnRow.createEl("button", { text: "Start chatting \u2192", cls: "mod-cta" });
    doneBtn.addEventListener("click", () => void (async () => {
      this.plugin.settings.onboardingComplete = true;
      this.plugin.settings.sessionKey = "main";
      await this.plugin.saveSettings();
      this.close();
      if (!this.plugin.gatewayConnected)
        void this.plugin.connectGateway();
      void this.plugin.activateView();
    })());
  }
  showStatus(text, type) {
    if (!this.statusEl)
      return;
    this.statusEl.empty();
    this.statusEl.className = `openclaw-onboard-status openclaw-onboard-status-${type}`;
    for (const line of text.split("\n")) {
      if (this.statusEl.childNodes.length > 0)
        this.statusEl.createEl("br");
      this.statusEl.appendText(line);
    }
  }
};
_OnboardingModal.MODELS = [
  { id: "anthropic/claude-opus-4-6", label: "Claude Opus 4" },
  { id: "anthropic/claude-sonnet-4-6", label: "Claude Sonnet 4" },
  { id: "anthropic/claude-sonnet-4-5", label: "Claude Sonnet 4.5" },
  { id: "google/gemini-2.5-pro", label: "Gemini 2.5 Pro" },
  { id: "google/gemini-2.5-flash", label: "Gemini 2.5 Flash" }
];
var OnboardingModal = _OnboardingModal;
var VIEW_TYPE = "openclaw-chat";
var OpenClawChatView = class extends import_obsidian.ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.tabSessions = [];
    this.renderingTabs = false;
    this.tabDeleteInProgress = false;
    this.messages = [];
    // ─── Per-session stream state ──────────────────────────────────────
    this.streams = /* @__PURE__ */ new Map();
    /** Map runId -> sessionKey so we can route stream events that lack sessionKey */
    this.runToSession = /* @__PURE__ */ new Map();
    this.streamEl = null;
    this.currentModel = "";
    this.currentModelSetAt = 0;
    // timestamp to prevent stale overwrites
    this.cachedSessionDisplayName = "";
    // Agent switcher state
    this.agents = [];
    this.activeAgent = { id: "main", name: "Agent", emoji: "\u{1F916}", creature: "" };
    this.profileBtnEl = null;
    this.profileDropdownEl = null;
    this.pendingAttachments = [];
    this.sending = false;
    this.recording = false;
    this.mediaRecorder = null;
    this.recordedChunks = [];
    this.micSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z"/><path d="M19 10v2a7 7 0 01-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>`;
    this.sendSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`;
    this.stopSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="red" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>`;
    this.plugin = plugin;
  }
  /** Get current active session key */
  get activeSessionKey() {
    return this.plugin.settings.sessionKey || "main";
  }
  /** Get stream state for active tab (if any) */
  get activeStream() {
    var _a;
    return (_a = this.streams.get(this.activeSessionKey)) != null ? _a : null;
  }
  /** Get the session key prefix for the active agent */
  get agentPrefix() {
    return `agent:${this.activeAgent.id}:`;
  }
  getViewType() {
    return VIEW_TYPE;
  }
  getDisplayText() {
    return "OpenClaw";
  }
  getIcon() {
    return "message-square";
  }
  async onOpen() {
    const container = this.containerEl.children[1];
    container.empty();
    container.addClass("openclaw-chat-container");
    const topBar = container.createDiv("openclaw-top-bar");
    this.tabBarEl = topBar.createDiv("openclaw-tab-bar");
    this.tabBarEl.addEventListener("wheel", (e) => {
      e.preventDefault();
      this.tabBarEl.scrollLeft += e.deltaY;
    }, { passive: false });
    this.profileBtnEl = topBar.createDiv("openclaw-agent-btn");
    this.profileBtnEl.setAttribute("aria-label", "Switch agent");
    this.updateAgentButton();
    this.profileBtnEl.addEventListener("click", (e) => {
      e.stopPropagation();
      this.toggleAgentSwitcher();
    });
    this.profileDropdownEl = container.createDiv("openclaw-agent-dropdown");
    this.profileDropdownEl.addClass("oc-hidden");
    document.addEventListener("click", () => {
      if (this.profileDropdownEl)
        this.profileDropdownEl.addClass("oc-hidden");
    });
    void this.renderTabs();
    this.contextMeterEl = createDiv();
    this.contextFillEl = createDiv();
    this.contextLabelEl = document.createElement("span");
    this.modelLabelEl = createDiv();
    this.bannerEl = container.createDiv("openclaw-banner");
    this.bannerEl.addClass("oc-hidden");
    this.messagesEl = container.createDiv("openclaw-messages");
    this.typingEl = container.createDiv("openclaw-typing");
    this.typingEl.addClass("oc-hidden");
    const typingDots = this.typingEl.createDiv("openclaw-typing-inner");
    typingDots.createSpan({ text: "Thinking", cls: "openclaw-typing-text" });
    const dotsEl = typingDots.createSpan("openclaw-typing-dots");
    dotsEl.createSpan("openclaw-dot");
    dotsEl.createSpan("openclaw-dot");
    dotsEl.createSpan("openclaw-dot");
    const inputArea = container.createDiv("openclaw-input-area");
    const inputRow = inputArea.createDiv("openclaw-input-row");
    const brainBtn = inputRow.createEl("button", { cls: "openclaw-brain-btn", attr: { "aria-label": "Switch model" } });
    (0, import_obsidian.setIcon)(brainBtn, "sparkles");
    brainBtn.addEventListener("click", () => this.openModelPicker());
    const attachBtn = inputRow.createEl("button", { cls: "openclaw-attach-btn", attr: { "aria-label": "Attach file" } });
    (0, import_obsidian.setIcon)(attachBtn, "paperclip");
    this.fileInputEl = inputArea.createEl("input", {
      cls: "openclaw-file-input",
      attr: { type: "file", accept: "image/*,.md,.txt,.json,.csv,.pdf,.yaml,.yml,.js,.ts,.py,.html,.css", multiple: "true" }
    });
    this.fileInputEl.addClass("oc-hidden");
    this.fileInputEl.addEventListener("change", () => void this.handleFileSelect());
    attachBtn.addEventListener("click", () => this.fileInputEl.click());
    this.inputEl = inputRow.createEl("textarea", {
      cls: "openclaw-input",
      attr: { placeholder: "Message...", rows: "1" }
    });
    this.attachPreviewEl = inputArea.createDiv("openclaw-attach-preview");
    this.attachPreviewEl.addClass("oc-hidden");
    this.abortBtn = inputRow.createEl("button", { cls: "openclaw-abort-btn", attr: { "aria-label": "Stop" } });
    (0, import_obsidian.setIcon)(this.abortBtn, "square");
    this.abortBtn.addClass("oc-hidden");
    const sendWrapper = inputRow.createDiv("openclaw-send-wrapper");
    this.sendBtn = sendWrapper.createEl("button", { cls: "openclaw-send-btn", attr: { "aria-label": "Send" } });
    (0, import_obsidian.setIcon)(this.sendBtn, "send");
    this.sendBtn.addClass("oc-opacity-low");
    this.reconnectBtn = sendWrapper.createEl("button", { cls: "openclaw-reconnect-btn", attr: { "aria-label": "Reconnect" } });
    (0, import_obsidian.setIcon)(this.reconnectBtn, "refresh-cw");
    this.reconnectBtn.addClass("oc-hidden");
    this.reconnectBtn.addEventListener("click", () => {
      void this.plugin.connectGateway();
    });
    this.statusEl = sendWrapper.createSpan("openclaw-status-dot");
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        if (import_obsidian.Platform.isMobile) {
          return;
        }
        if (!e.shiftKey) {
          e.preventDefault();
          void this.sendMessage();
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
    this.inputEl.addEventListener("paste", (e) => {
      var _a;
      const items = (_a = e.clipboardData) == null ? void 0 : _a.items;
      if (!items)
        return;
      for (const item of Array.from(items)) {
        if (item.type.startsWith("image/")) {
          e.preventDefault();
          const file = item.getAsFile();
          if (file)
            void this.handlePastedFile(file);
          return;
        }
      }
    });
    this.sendBtn.addEventListener("click", () => {
      if (this.inputEl.value.trim() || this.pendingAttachments.length > 0) {
        void this.sendMessage();
      }
    });
    this.abortBtn.addEventListener("click", () => void this.abortMessage());
    this.updateStatus();
    this.plugin.chatView = this;
    this.initTouchGestures();
    if (this.plugin.gatewayConnected) {
      await this.loadHistory();
      void this.loadAgents();
    }
  }
  onClose() {
    if (this.plugin.chatView === this) {
      this.plugin.chatView = null;
    }
  }
  updateStatus() {
    if (!this.statusEl)
      return;
    this.statusEl.removeClass("connected", "disconnected");
    const connected = this.plugin.gatewayConnected;
    this.statusEl.addClass(connected ? "connected" : "disconnected");
    if (connected) {
      this.sendBtn.removeClass("oc-hidden");
      if (this.reconnectBtn)
        this.reconnectBtn.addClass("oc-hidden");
      this.inputEl.disabled = false;
      this.inputEl.placeholder = "Message...";
    } else {
      this.sendBtn.addClass("oc-hidden");
      if (this.reconnectBtn)
        this.reconnectBtn.removeClass("oc-hidden");
      this.inputEl.disabled = true;
      this.inputEl.placeholder = "Disconnected";
    }
  }
  /** Fetch all agents from the gateway and load their identities */
  async loadAgents() {
    var _a;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      const result = await this.plugin.gateway.request("agents.list", {});
      const agentList = (result == null ? void 0 : result.agents) || [];
      if (agentList.length === 0) {
        agentList.push({ id: "main" });
      }
      const agents = [];
      for (const a of agentList) {
        agents.push({
          id: a.id || "main",
          name: a.name || a.id || "Agent",
          emoji: "\u{1F916}",
          creature: ""
        });
      }
      this.agents = agents;
      const savedId = this.plugin.settings.activeAgentId;
      const active = agents.find((a) => a.id === savedId) || agents[0];
      if (active) {
        this.activeAgent = active;
        if (this.plugin.settings.activeAgentId !== active.id) {
          this.plugin.settings.activeAgentId = active.id;
          await this.plugin.saveSettings();
        }
      }
      this.updateAgentButton();
    } catch (e) {
      console.warn("[ObsidianClaw] Failed to load agents:", e);
    }
  }
  /** Update the agent button — hidden for single agent, visible for multi */
  updateAgentButton() {
    if (!this.profileBtnEl)
      return;
    if (this.agents.length <= 1) {
      this.profileBtnEl.addClass("oc-hidden");
      return;
    }
    this.profileBtnEl.removeClass("oc-hidden");
    const emoji = this.activeAgent.emoji || "\u{1F916}";
    this.profileBtnEl.empty();
    this.profileBtnEl.createSpan({ text: emoji, cls: "openclaw-agent-emoji" });
  }
  /** Switch to a different agent */
  async switchAgent(agent) {
    if (agent.id === this.activeAgent.id)
      return;
    this.activeAgent = agent;
    this.plugin.settings.activeAgentId = agent.id;
    this.plugin.settings.sessionKey = "main";
    await this.plugin.saveSettings();
    this.updateAgentButton();
    await this.loadHistory();
    await this.renderTabs();
  }
  /** Toggle the agent switcher dropdown */
  toggleAgentSwitcher() {
    if (!this.profileDropdownEl)
      return;
    const visible = !this.profileDropdownEl.hasClass("oc-hidden");
    if (visible) {
      this.profileDropdownEl.addClass("oc-hidden");
      return;
    }
    this.profileDropdownEl.empty();
    for (const agent of this.agents) {
      const isActive = agent.id === this.activeAgent.id;
      const item = this.profileDropdownEl.createDiv({ cls: `openclaw-agent-item${isActive ? " active" : ""}` });
      item.createSpan({ text: agent.emoji || "\u{1F916}", cls: "openclaw-agent-item-emoji" });
      const info = item.createDiv("openclaw-agent-item-info");
      info.createDiv({ text: agent.name, cls: "openclaw-agent-item-name" });
      if (agent.creature) {
        info.createDiv({ text: agent.creature, cls: "openclaw-agent-item-sub" });
      }
      if (!isActive) {
        item.addEventListener("click", () => {
          this.profileDropdownEl.addClass("oc-hidden");
          void this.switchAgent(agent);
        });
      }
    }
    this.profileDropdownEl.removeClass("oc-hidden");
  }
  async loadHistory() {
    var _a;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      const result = await this.plugin.gateway.request("chat.history", {
        sessionKey: this.plugin.settings.sessionKey,
        limit: 200
      });
      if ((result == null ? void 0 : result.messages) && Array.isArray(result.messages)) {
        this.messages = result.messages.filter((m) => m.role === "user" || m.role === "assistant").map((m) => {
          var _a2;
          const { text, images } = this.extractContent(m.content);
          return {
            role: m.role,
            text,
            images,
            timestamp: (_a2 = m.timestamp) != null ? _a2 : Date.now(),
            contentBlocks: Array.isArray(m.content) ? m.content : void 0
          };
        }).filter((m) => (m.text.trim() || m.images.length > 0) && !m.text.startsWith("HEARTBEAT"));
        if (this.messages.length > 0 && this.messages[0].role === "user") {
          this.messages = this.messages.slice(1);
        }
        await this.renderMessages();
        void this.updateContextMeter();
      }
    } catch (e) {
      console.error("[ObsidianClaw] Failed to load history:", e);
    }
  }
  extractContent(content) {
    var _a;
    let text = "";
    const images = [];
    if (typeof content === "string") {
      text = content;
    } else if (Array.isArray(content)) {
      for (const c of content) {
        if (c.type === "text") {
          text += (text ? "\n" : "") + c.text;
        } else if (c.type === "tool_result") {
          const trContent = c.content;
          if (typeof trContent === "string") {
            text += (text ? "\n" : "") + trContent;
          } else if (Array.isArray(trContent)) {
            for (const tc of trContent) {
              if ((tc == null ? void 0 : tc.type) === "text" && tc.text)
                text += (text ? "\n" : "") + tc.text;
            }
          }
        } else if (c.type === "image_url" && ((_a = c.image_url) == null ? void 0 : _a.url)) {
          images.push(c.image_url.url);
        }
      }
    }
    const savedAtRegex = /File saved at:\s*(.+?openclaw-attachments\/[^\s\n]+)/g;
    let match;
    while ((match = savedAtRegex.exec(text)) !== null) {
      const fullPath = match[1].trim();
      const vaultRelative = fullPath.includes("openclaw-attachments/") ? "openclaw-attachments/" + fullPath.split("openclaw-attachments/")[1] : null;
      if (vaultRelative) {
        try {
          const resourcePath = this.app.vault.adapter.getResourcePath(vaultRelative);
          if (resourcePath)
            images.push(resourcePath);
        } catch (e) {
        }
      }
    }
    const dataUriRegex = /(?:^|\n)data:(image\/[^;]+);base64,[A-Za-z0-9+/=\n]+/g;
    while ((match = dataUriRegex.exec(text)) !== null) {
      images.push(match[0].replace(/^\n/, "").trim());
    }
    text = text.replace(/\n?data:image\/[^;]+;base64,[A-Za-z0-9+/=\n]+/g, "").trim();
    text = text.replace(/^\[Attached image:.*?\]\s*/gm, "").trim();
    text = text.replace(/^File saved at:.*$/gm, "").trim();
    text = text.replace(/Conversation info \(untrusted metadata\):\s*```json[\s\S]*?```\s*/g, "").trim();
    text = text.replace(/^```json\s*\{\s*"message_id"[\s\S]*?```\s*/gm, "").trim();
    text = text.replace(/^\[.*?GMT[+-]\d+\]\s*/gm, "").trim();
    text = text.replace(/^\[media attached:.*?\]\s*/gm, "").trim();
    text = text.replace(/^To send an image back.*$/gm, "").trim();
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK")
      text = "";
    return { text, images };
  }
  updateSendButton() {
    if (this.inputEl.value.trim() || this.pendingAttachments.length > 0) {
      this.sendBtn.setAttribute("aria-label", "Send");
      this.sendBtn.removeClass("oc-opacity-low");
    } else {
      this.sendBtn.setAttribute("aria-label", "Send");
      this.sendBtn.addClass("oc-opacity-low");
    }
  }
  async startRecording() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.recordedChunks = [];
      const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus") ? "audio/webm;codecs=opus" : MediaRecorder.isTypeSupported("audio/webm") ? "audio/webm" : "";
      this.mediaRecorder = new MediaRecorder(stream, mimeType ? { mimeType } : {});
      this.mediaRecorder.addEventListener("dataavailable", (e) => {
        if (e.data.size > 0)
          this.recordedChunks.push(e.data);
      });
      this.mediaRecorder.addEventListener("stop", () => {
        stream.getTracks().forEach((t) => t.stop());
        void this.finishRecording();
      });
      this.mediaRecorder.start();
      this.recording = true;
      this.updateSendButton();
      this.inputEl.placeholder = "Recording... tap \u25A0 to stop";
    } catch (e) {
      console.error("[ObsidianClaw] Mic access failed:", e);
      new import_obsidian.Notice("Microphone access denied");
    }
  }
  stopRecording() {
    if (this.mediaRecorder && this.mediaRecorder.state !== "inactive") {
      this.mediaRecorder.stop();
    }
    this.recording = false;
    this.updateSendButton();
    this.inputEl.placeholder = "Message...";
  }
  async finishRecording() {
    var _a;
    if (this.recordedChunks.length === 0)
      return;
    const blob = new Blob(this.recordedChunks, { type: ((_a = this.mediaRecorder) == null ? void 0 : _a.mimeType) || "audio/webm" });
    this.recordedChunks = [];
    const arrayBuf = await blob.arrayBuffer();
    const bytes = new Uint8Array(arrayBuf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++)
      binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    const mime = blob.type || "audio/webm";
    const marker = `AUDIO_DATA:${mime};base64,${b64}`;
    this.messages.push({ role: "user", text: "\u{1F3A4} Voice message", images: [], timestamp: Date.now() });
    await this.renderMessages();
    const runId = generateId();
    const sendSessionKey = this.activeSessionKey;
    const ss = {
      runId,
      text: "",
      toolCalls: [],
      items: [],
      splitPoints: [],
      lastDeltaTime: 0,
      compactTimer: null,
      workingTimer: null
    };
    this.streams.set(sendSessionKey, ss);
    this.runToSession.set(runId, sendSessionKey);
    this.abortBtn.removeClass("oc-hidden");
    this.typingEl.removeClass("oc-hidden");
    const thinkText = this.typingEl.querySelector(".openclaw-typing-text");
    if (thinkText)
      thinkText.textContent = "Thinking";
    this.scrollToBottom();
    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: sendSessionKey,
        message: marker,
        deliver: false,
        idempotencyKey: runId
      });
    } catch (e) {
      this.messages.push({ role: "assistant", text: `Error: ${e}`, images: [], timestamp: Date.now() });
      this.streams.delete(sendSessionKey);
      this.runToSession.delete(runId);
      this.abortBtn.addClass("oc-hidden");
      await this.renderMessages();
    }
  }
  async sendMessage() {
    var _a;
    let text = this.inputEl.value.trim();
    const hasAttachments = this.pendingAttachments.length > 0;
    if (!text && !hasAttachments)
      return;
    if (this.sending)
      return;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected)) {
      new import_obsidian.Notice("Not connected to OpenClaw gateway");
      return;
    }
    this.sending = true;
    this.sendBtn.disabled = true;
    this.inputEl.value = "";
    this.autoResize();
    let fullMessage = text;
    const displayText = text;
    const userImages = [];
    const gatewayAttachments = [];
    if (this.pendingAttachments.length > 0) {
      for (const att of this.pendingAttachments) {
        if (att.base64 && att.mimeType) {
          gatewayAttachments.push({ type: "image", mimeType: att.mimeType, content: att.base64 });
          userImages.push(`data:${att.mimeType};base64,${att.base64}`);
        } else {
          fullMessage = (fullMessage ? fullMessage + "\n\n" : "") + att.content;
        }
      }
      if (!text) {
        text = `\u{1F4CE} ${this.pendingAttachments.map((a) => a.name).join(", ")}`;
        fullMessage = text;
      }
      this.pendingAttachments = [];
      this.attachPreviewEl.addClass("oc-hidden");
    }
    this.messages.push({ role: "user", text: displayText || text, images: userImages, timestamp: Date.now() });
    await this.renderMessages();
    const runId = generateId();
    const sendSessionKey = this.activeSessionKey;
    const ss = {
      runId,
      text: "",
      toolCalls: [],
      items: [],
      splitPoints: [],
      lastDeltaTime: 0,
      compactTimer: null,
      workingTimer: null
    };
    this.streams.set(sendSessionKey, ss);
    this.runToSession.set(runId, sendSessionKey);
    this.abortBtn.removeClass("oc-hidden");
    this.typingEl.removeClass("oc-hidden");
    const thinkText = this.typingEl.querySelector(".openclaw-typing-text");
    if (thinkText)
      thinkText.textContent = "Thinking";
    this.scrollToBottom();
    ss.compactTimer = setTimeout(() => {
      const current = this.streams.get(sendSessionKey);
      if ((current == null ? void 0 : current.runId) === runId && !current.text) {
        if (this.activeSessionKey === sendSessionKey) {
          const tt = this.typingEl.querySelector(".openclaw-typing-text");
          if (tt && tt.textContent === "Thinking")
            tt.textContent = "Still thinking";
        }
      }
    }, 15e3);
    try {
      const sendParams = {
        sessionKey: sendSessionKey,
        message: fullMessage,
        deliver: false,
        idempotencyKey: runId
      };
      if (gatewayAttachments.length > 0) {
        sendParams.attachments = gatewayAttachments;
      }
      await this.plugin.gateway.request("chat.send", sendParams);
    } catch (e) {
      if (ss.compactTimer)
        clearTimeout(ss.compactTimer);
      this.messages.push({ role: "assistant", text: `Error: ${e}`, images: [], timestamp: Date.now() });
      this.streams.delete(sendSessionKey);
      this.runToSession.delete(runId);
      this.abortBtn.addClass("oc-hidden");
      await this.renderMessages();
    } finally {
      this.sending = false;
      this.sendBtn.disabled = false;
    }
  }
  async abortMessage() {
    var _a;
    const ss = this.activeStream;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected) || !ss)
      return;
    try {
      await this.plugin.gateway.request("chat.abort", {
        sessionKey: this.activeSessionKey,
        runId: ss.runId
      });
    } catch (e) {
    }
  }
  async updateContextMeter() {
    var _a, _b;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      const result = await this.plugin.gateway.request("sessions.list", {});
      const sessions = (result == null ? void 0 : result.sessions) || [];
      const sk = this.plugin.settings.sessionKey || "main";
      const session = sessions.find((s) => s.key === sk) || sessions.find((s) => s.key === `${this.agentPrefix}${sk}`) || sessions.find((s) => s.key.endsWith(`:${sk}`));
      if (!session)
        return;
      const used = session.totalTokens || 0;
      const max = session.contextTokens || 2e5;
      const pct = Math.min(100, Math.round(used / max * 100));
      this.contextFillEl.setCssStyles({ width: pct + "%" });
      this.contextFillEl.className = "openclaw-context-fill" + (pct > 80 ? " openclaw-context-high" : pct > 60 ? " openclaw-context-mid" : "");
      this.contextLabelEl.textContent = `${pct}%`;
      const activeFill = (_b = this.tabBarEl) == null ? void 0 : _b.querySelector(".openclaw-tab.active .openclaw-tab-meter-fill");
      if (activeFill)
        activeFill.setCssStyles({ width: pct + "%" });
      const fullModel = session.model || "";
      const modelCooldown = Date.now() - this.currentModelSetAt < 15e3;
      if (fullModel && fullModel !== this.currentModel && !modelCooldown) {
        this.currentModel = fullModel;
        this.updateModelPill();
      }
      if (session.displayName && session.displayName !== this.cachedSessionDisplayName) {
        this.cachedSessionDisplayName = session.displayName;
      }
      const agentPrefix = this.agentPrefix;
      const currentSessionKeys = new Set(
        sessions.filter((s) => s.key.startsWith(agentPrefix) && !s.key.includes(":cron:") && !s.key.includes(":subagent:")).map((s) => s.key)
      );
      const trackedKeys = new Set(this.tabSessions.map((t) => `${agentPrefix}${t.key}`));
      const added = [...currentSessionKeys].some((k) => !trackedKeys.has(k));
      const removed = [...trackedKeys].some((k) => !currentSessionKeys.has(k));
      if ((added || removed) && !this.tabDeleteInProgress) {
        if (removed && !currentSessionKeys.has(`${agentPrefix}${sk}`)) {
          this.plugin.settings.sessionKey = "main";
          await this.plugin.saveSettings();
          this.messages = [];
          this.messagesEl.empty();
          await this.loadHistory();
          this.updateStatus();
        }
        await this.renderTabs();
      }
    } catch (e) {
    }
  }
  updateModelPill() {
    if (!this.modelLabelEl)
      return;
    const model = this.currentModel ? this.shortModelName(this.currentModel) : "model";
    this.modelLabelEl.empty();
    this.modelLabelEl.createSpan({ text: model, cls: "openclaw-ctx-pill-text" });
    this.modelLabelEl.createSpan({ text: " \u25BE", cls: "openclaw-ctx-pill-arrow" });
  }
  async renderTabs() {
    if (!this.tabBarEl || this.renderingTabs)
      return;
    this.renderingTabs = true;
    try {
      await this._renderTabsInner();
    } finally {
      this.renderingTabs = false;
    }
  }
  async _renderTabsInner() {
    var _a;
    this.tabBarEl.empty();
    const currentKey = this.plugin.settings.sessionKey || "main";
    let sessions = [];
    if ((_a = this.plugin.gateway) == null ? void 0 : _a.connected) {
      try {
        const result = await this.plugin.gateway.request("sessions.list", {});
        sessions = (result == null ? void 0 : result.sessions) || [];
      } catch (e) {
      }
    }
    const agentPrefix = this.agentPrefix;
    const convSessions = sessions.filter((s) => {
      if (!s.key.startsWith(agentPrefix))
        return false;
      if (s.key.includes(":cron:"))
        return false;
      if (s.key.includes(":subagent:"))
        return false;
      return true;
    });
    this.tabSessions = [];
    const mainSession = convSessions.find((s) => s.key === `${this.agentPrefix}main`);
    if (mainSession) {
      const used = mainSession.totalTokens || 0;
      const max = mainSession.contextTokens || 2e5;
      this.tabSessions.push({ key: "main", label: "Main", pct: Math.min(100, Math.round(used / max * 100)) });
    } else {
      this.tabSessions.push({ key: "main", label: "Main", pct: 0 });
    }
    const others = convSessions.filter((s) => s.key.slice(agentPrefix.length) !== "main").sort((a, b) => (a.createdAt || a.updatedAt || 0) - (b.createdAt || b.updatedAt || 0));
    let num = 1;
    for (const s of others) {
      const sk = s.key.slice(agentPrefix.length);
      const used = s.totalTokens || 0;
      const max = s.contextTokens || 2e5;
      const pct = Math.min(100, Math.round(used / max * 100));
      const label = s.label || s.displayName || String(num);
      this.tabSessions.push({ key: sk, label, pct });
      num++;
    }
    for (const tab of this.tabSessions) {
      const isCurrent = tab.key === currentKey;
      const tabCls = `openclaw-tab${isCurrent ? " active" : ""}`;
      const tabEl = this.tabBarEl.createDiv({ cls: tabCls });
      const row = tabEl.createDiv({ cls: "openclaw-tab-row" });
      const labelSpan = row.createSpan({ text: tab.label, cls: "openclaw-tab-label" });
      if (tab.key !== "main") {
        labelSpan.title = "Double-click to rename";
        labelSpan.addEventListener("dblclick", (e) => {
          e.stopPropagation();
          const input = createEl("input", { cls: "openclaw-tab-label-input" });
          input.value = tab.label;
          input.maxLength = 30;
          labelSpan.replaceWith(input);
          input.focus();
          input.select();
          const finish = async (save) => {
            var _a2;
            const newName = input.value.trim();
            if (save && newName && newName !== tab.label) {
              try {
                await ((_a2 = this.plugin.gateway) == null ? void 0 : _a2.request("sessions.patch", {
                  key: `${this.agentPrefix}${tab.key}`,
                  label: newName
                }));
                tab.label = newName;
              } catch (e2) {
              }
            }
            input.replaceWith(labelSpan);
            labelSpan.textContent = tab.label;
            void this.renderTabs();
          };
          input.addEventListener("keydown", (ev) => {
            if (ev.key === "Enter") {
              ev.preventDefault();
              void finish(true);
            }
            if (ev.key === "Escape") {
              ev.preventDefault();
              void finish(false);
            }
          });
          input.addEventListener("blur", () => void finish(true));
        });
      }
      const isResetOnly = tab.key === "main";
      const closeBtn = row.createSpan({ text: "\xD7", cls: "openclaw-tab-close" });
      if (isResetOnly) {
        closeBtn.title = "Reset conversation";
        closeBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          void (async () => {
            var _a2;
            if (!((_a2 = this.plugin.gateway) == null ? void 0 : _a2.connected))
              return;
            if (!this.isCloseConfirmDisabled()) {
              const confirmed = await this.confirmTabClose("Reset main tab?", "This will clear the conversation.");
              if (!confirmed)
                return;
            }
            try {
              await this.plugin.gateway.request("chat.send", {
                sessionKey: tab.key,
                message: "/reset",
                deliver: false,
                idempotencyKey: "reset-" + Date.now()
              });
              new import_obsidian.Notice(`Reset: ${tab.label}`);
              if (tab.key === currentKey) {
                this.messages = [];
                this.messagesEl.empty();
              }
              await this.updateContextMeter();
              await this.renderTabs();
            } catch (err) {
              new import_obsidian.Notice(`Reset failed: ${err instanceof Error ? err.message : String(err)}`);
            }
          })();
        });
      } else {
        closeBtn.title = "Close tab";
        closeBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          void (async () => {
            var _a2;
            if (!((_a2 = this.plugin.gateway) == null ? void 0 : _a2.connected) || this.tabDeleteInProgress)
              return;
            if (!this.isCloseConfirmDisabled()) {
              const confirmed = await this.confirmTabClose("Close tab?", `Close "${tab.label}"? Chat history will be lost.`);
              if (!confirmed)
                return;
            }
            this.tabDeleteInProgress = true;
            try {
              const deleted = await deleteSessionWithFallback(this.plugin.gateway, `${this.agentPrefix}${tab.key}`);
              new import_obsidian.Notice(deleted ? `Closed: ${tab.label}` : `Could not delete: ${tab.label}`);
            } catch (err) {
              new import_obsidian.Notice(`Close failed: ${err instanceof Error ? err.message : String(err)}`);
            }
            this.finishStream(tab.key);
            if (tab.key === currentKey) {
              this.plugin.settings.sessionKey = "main";
              await this.plugin.saveSettings();
              this.messages = [];
              this.messagesEl.empty();
              await this.loadHistory();
              this.restoreStreamUI();
            }
            this.tabDeleteInProgress = false;
            await this.renderTabs();
            await this.updateContextMeter();
          })();
        });
      }
      const meter = tabEl.createDiv({ cls: "openclaw-tab-meter" });
      const fill = meter.createDiv({ cls: "openclaw-tab-meter-fill" });
      fill.setCssStyles({ width: tab.pct + "%" });
      if (!isCurrent) {
        tabEl.addEventListener("click", () => void (async () => {
          this.streamEl = null;
          this.typingEl.addClass("oc-hidden");
          this.abortBtn.addClass("oc-hidden");
          this.hideBanner();
          this.plugin.settings.sessionKey = tab.key;
          await this.plugin.saveSettings();
          this.messages = [];
          this.messagesEl.empty();
          this.cachedSessionDisplayName = tab.label;
          await this.loadHistory();
          this.restoreStreamUI();
          await this.updateContextMeter();
          void this.renderTabs();
          this.updateStatus();
        })());
      }
    }
    const addBtn = this.tabBarEl.createDiv({ cls: "openclaw-tab openclaw-tab-add" });
    addBtn.createSpan({ text: "+", cls: "openclaw-tab-label" });
    addBtn.addEventListener("click", () => void (async () => {
      var _a2, _b;
      const nums = this.tabSessions.map((t) => parseInt(t.label)).filter((n) => !isNaN(n));
      const nextNum = nums.length > 0 ? Math.max(...nums) + 1 : 1;
      const sessionKey = `tab-${nextNum}`;
      try {
        await ((_a2 = this.plugin.gateway) == null ? void 0 : _a2.request("chat.send", {
          sessionKey,
          message: "/new",
          deliver: false,
          idempotencyKey: "newtab-" + Date.now()
        }));
        await new Promise((r) => setTimeout(r, 500));
        try {
          await ((_b = this.plugin.gateway) == null ? void 0 : _b.request("sessions.patch", {
            key: `${this.agentPrefix}${sessionKey}`,
            label: String(nextNum)
          }));
        } catch (e) {
        }
        this.streamEl = null;
        this.typingEl.addClass("oc-hidden");
        this.abortBtn.addClass("oc-hidden");
        this.hideBanner();
        this.plugin.settings.sessionKey = sessionKey;
        this.messages = [];
        if (this.plugin.settings.streamItemsMap)
          this.plugin.settings.streamItemsMap = {};
        await this.plugin.saveSettings();
        this.messagesEl.empty();
        await this.renderTabs();
        await this.updateContextMeter();
        new import_obsidian.Notice(`New tab: ${nextNum}`);
      } catch (err) {
        new import_obsidian.Notice(`Failed to create tab: ${err instanceof Error ? err.message : String(err)}`);
      }
    })());
  }
  // ─── Confirm close dialog ──────────────────────────────────────────
  isCloseConfirmDisabled() {
    return localStorage.getItem("openclaw-confirm-close-disabled") === "true";
  }
  confirmTabClose(title, msg) {
    return new Promise((resolve) => {
      const modal = new ConfirmCloseModal(this.app, title, msg, (result, dontAsk) => {
        if (result && dontAsk) {
          localStorage.setItem("openclaw-confirm-close-disabled", "true");
        }
        resolve(result);
      });
      modal.open();
    });
  }
  // ─── Touch gestures ──────────────────────────────────────────────
  initTouchGestures() {
    let touchStartX = 0;
    let touchStartY = 0;
    let pulling = false;
    this.messagesEl.addEventListener("touchstart", (e) => {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
      pulling = false;
    }, { passive: true });
    this.messagesEl.addEventListener("touchmove", (e) => {
      const deltaY = e.touches[0].clientY - touchStartY;
      if (this.messagesEl.scrollTop <= 0 && deltaY > 60) {
        pulling = true;
      }
    }, { passive: true });
    this.messagesEl.addEventListener("touchend", (e) => {
      const deltaX = e.changedTouches[0].clientX - touchStartX;
      const deltaY = e.changedTouches[0].clientY - touchStartY;
      if (pulling) {
        pulling = false;
        this.messages = [];
        this.messagesEl.empty();
        void this.loadHistory().then(() => this.updateContextMeter());
        new import_obsidian.Notice("Refreshed");
        return;
      }
      if (Math.abs(deltaX) > 80 && Math.abs(deltaX) > Math.abs(deltaY) * 1.5) {
        const currentIdx = this.tabSessions.findIndex((t) => t.key === this.activeSessionKey);
        if (currentIdx < 0)
          return;
        const nextIdx = deltaX < 0 ? currentIdx + 1 : currentIdx - 1;
        if (nextIdx >= 0 && nextIdx < this.tabSessions.length) {
          const tab = this.tabSessions[nextIdx];
          this.streamEl = null;
          this.typingEl.addClass("oc-hidden");
          this.abortBtn.addClass("oc-hidden");
          this.hideBanner();
          this.plugin.settings.sessionKey = tab.key;
          void this.plugin.saveSettings();
          this.messages = [];
          this.messagesEl.empty();
          this.cachedSessionDisplayName = tab.label;
          void this.loadHistory();
          void this.updateContextMeter();
          void this.renderTabs();
          this.updateStatus();
        }
      }
    }, { passive: true });
  }
  contextColor(pct) {
    if (pct > 80)
      return "#c44";
    if (pct > 60)
      return "#d4a843";
    if (pct > 30)
      return "#7a7";
    return "#5a5";
  }
  async resetCurrentTab() {
    var _a;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/reset",
        deliver: false,
        idempotencyKey: "reset-" + Date.now()
      });
      this.messages = [];
      if (this.plugin.settings.streamItemsMap)
        this.plugin.settings.streamItemsMap = {};
      await this.plugin.saveSettings();
      this.messagesEl.empty();
      await this.updateContextMeter();
      await this.renderTabs();
      new import_obsidian.Notice("Tab reset");
    } catch (e) {
      new import_obsidian.Notice(`Reset failed: ${e}`);
    }
  }
  openModelPicker() {
    new ModelPickerModal(this.app, this.plugin, this).open();
  }
  async compactSession() {
    var _a;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      this.showBanner("Compacting context...");
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/compact",
        deliver: false,
        idempotencyKey: "compact-" + Date.now()
      });
      const pollInterval = setInterval(() => void (async () => {
        await this.updateContextMeter();
      })(), 2e3);
      setTimeout(() => void (async () => {
        clearInterval(pollInterval);
        this.hideBanner();
        await this.loadHistory();
        await this.updateContextMeter();
      })(), 12e3);
    } catch (e) {
      this.hideBanner();
      new import_obsidian.Notice(`Compact failed: ${e}`);
    }
  }
  async newSession() {
    var _a;
    if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
      return;
    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: "/new",
        deliver: false,
        idempotencyKey: "new-" + Date.now()
      });
      this.messages = [];
      if (this.plugin.settings.streamItemsMap)
        this.plugin.settings.streamItemsMap = {};
      await this.plugin.saveSettings();
      this.messagesEl.empty();
      await this.updateContextMeter();
      new import_obsidian.Notice("New session started");
    } catch (e) {
      new import_obsidian.Notice(`New session failed: ${e}`);
    }
  }
  shortModelName(fullId) {
    const model = fullId.includes("/") ? fullId.split("/")[1] : fullId;
    return model.replace(/^claude-/, "");
  }
  async handleFileSelect() {
    const files = this.fileInputEl.files;
    if (!files || files.length === 0)
      return;
    for (const file of Array.from(files)) {
      try {
        const isImage = file.type.startsWith("image/");
        const isText = file.type.startsWith("text/") || ["application/json", "application/yaml", "application/xml", "application/javascript"].includes(file.type) || /\.(md|txt|json|csv|yaml|yml|js|ts|py|html|css|xml|toml|ini|sh|log)$/i.test(file.name);
        if (isImage) {
          const resized = await this.resizeImage(file, 2048, 0.85);
          this.pendingAttachments.push({
            name: file.name,
            content: `[Attached image: ${file.name}]`,
            base64: resized.base64,
            mimeType: resized.mimeType
          });
        } else if (isText) {
          const content = await file.text();
          const truncated = content.length > 1e4 ? content.slice(0, 1e4) + "\n...(truncated)" : content;
          this.pendingAttachments.push({
            name: file.name,
            content: `File: ${file.name}
\`\`\`
${truncated}
\`\`\``
          });
        } else {
          this.pendingAttachments.push({
            name: file.name,
            content: `[Attached file: ${file.name} (${file.type || "unknown type"}, ${Math.round(file.size / 1024)}KB)]`
          });
        }
      } catch (e) {
        new import_obsidian.Notice(`Failed to attach ${file.name}: ${e}`);
      }
    }
    this.renderAttachPreview();
    this.fileInputEl.value = "";
  }
  async handlePastedFile(file) {
    try {
      const ext = file.type.split("/")[1] || "png";
      const resized = await this.resizeImage(file, 2048, 0.85);
      this.pendingAttachments.push({
        name: `clipboard.${ext}`,
        content: `[Attached image: clipboard.${ext}]`,
        base64: resized.base64,
        mimeType: resized.mimeType
      });
      this.renderAttachPreview();
    } catch (e) {
      new import_obsidian.Notice(`Failed to paste image: ${e}`);
    }
  }
  async resizeImage(file, maxSide, quality) {
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
        if (!ctx) {
          reject(new Error("No canvas context"));
          return;
        }
        ctx.drawImage(img, 0, 0, width, height);
        const dataUrl = canvas.toDataURL("image/jpeg", quality);
        const base64 = dataUrl.split(",")[1];
        resolve({ base64, mimeType: "image/jpeg" });
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Failed to load image"));
      };
      img.src = url;
    });
  }
  renderAttachPreview() {
    this.attachPreviewEl.empty();
    if (this.pendingAttachments.length === 0) {
      this.attachPreviewEl.addClass("oc-hidden");
      return;
    }
    this.attachPreviewEl.removeClass("oc-hidden");
    for (let i = 0; i < this.pendingAttachments.length; i++) {
      const att = this.pendingAttachments[i];
      const chip = this.attachPreviewEl.createDiv("openclaw-attach-chip");
      if (att.base64 && att.mimeType) {
        const src = `data:${att.mimeType};base64,${att.base64}`;
        chip.createEl("img", { cls: "openclaw-attach-thumb", attr: { src } });
      } else if (att.vaultPath) {
        try {
          const src = this.app.vault.adapter.getResourcePath(att.vaultPath);
          if (src)
            chip.createEl("img", { cls: "openclaw-attach-thumb", attr: { src } });
        } catch (e) {
        }
      }
      chip.createSpan({ text: att.name, cls: "openclaw-attach-name" });
      const removeBtn = chip.createEl("button", { text: "\u2715", cls: "openclaw-attach-remove" });
      const idx = i;
      removeBtn.addEventListener("click", () => {
        this.pendingAttachments.splice(idx, 1);
        this.renderAttachPreview();
      });
    }
  }
  buildToolLabel(toolName, args) {
    const a = args != null ? args : {};
    switch (toolName) {
      case "exec": {
        const cmd = str(a == null ? void 0 : a.command);
        const short = cmd.length > 60 ? cmd.slice(0, 60) + "\u2026" : cmd;
        return { label: `\u{1F527} ${short || "Running command"}` };
      }
      case "read":
      case "Read": {
        const p = str(a == null ? void 0 : a.path, str(a == null ? void 0 : a.file_path));
        const name = p.split("/").pop() || "file";
        return { label: `\u{1F4C4} Reading ${name}` };
      }
      case "write":
      case "Write": {
        const p = str(a == null ? void 0 : a.path, str(a == null ? void 0 : a.file_path));
        const name = p.split("/").pop() || "file";
        return { label: `\u270F\uFE0F Writing ${name}` };
      }
      case "edit":
      case "Edit": {
        const p = str(a == null ? void 0 : a.path, str(a == null ? void 0 : a.file_path));
        const name = p.split("/").pop() || "file";
        return { label: `\u270F\uFE0F Editing ${name}` };
      }
      case "web_search": {
        const q = str(a == null ? void 0 : a.query);
        return { label: `\u{1F50D} Searching "${q.length > 40 ? q.slice(0, 40) + "\u2026" : q}"` };
      }
      case "web_fetch": {
        const rawUrl = str(a == null ? void 0 : a.url);
        try {
          const domain = new URL(rawUrl).hostname;
          return { label: `\u{1F310} Fetching ${domain}`, url: rawUrl };
        } catch (e) {
          return { label: `\u{1F310} Fetching page`, url: rawUrl || void 0 };
        }
      }
      case "browser":
        return { label: "\u{1F310} Using browser" };
      case "image":
        return { label: "\u{1F441}\uFE0F Viewing image" };
      case "memory_search": {
        const q = str(a == null ? void 0 : a.query);
        return { label: `\u{1F9E0} Searching "${q.length > 40 ? q.slice(0, 40) + "\u2026" : q}"` };
      }
      case "memory_get": {
        const p = str(a == null ? void 0 : a.path);
        const name = p.split("/").pop() || "memory";
        return { label: `\u{1F9E0} Reading ${name}` };
      }
      case "message":
        return { label: "\u{1F4AC} Sending message" };
      case "tts":
        return { label: "\u{1F50A} Speaking" };
      case "sessions_spawn":
        return { label: "\u{1F916} Spawning sub-agent" };
      default:
        return { label: toolName ? `\u26A1 ${toolName}` : "Working" };
    }
  }
  appendToolCall(label, url, active = false) {
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
      dots.createSpan("openclaw-dot");
      dots.createSpan("openclaw-dot");
      dots.createSpan("openclaw-dot");
      el.appendChild(dots);
    }
    this.messagesEl.appendChild(el);
    this.scrollToBottom();
  }
  deactivateLastToolItem() {
    const items = this.messagesEl.querySelectorAll(".openclaw-tool-active");
    const last = items[items.length - 1];
    if (last) {
      last.removeClass("openclaw-tool-active");
      const dots = last.querySelector(".openclaw-tool-dots");
      if (dots)
        dots.remove();
    }
  }
  async playTTSAudio(_audioPath) {
  }
  showBanner(text) {
    if (!this.bannerEl)
      return;
    this.bannerEl.textContent = text;
    this.bannerEl.removeClass("oc-hidden");
  }
  hideBanner() {
    if (!this.bannerEl)
      return;
    this.bannerEl.addClass("oc-hidden");
  }
  /** Resolve which session a stream/agent event belongs to */
  resolveStreamSession(payload) {
    const sk = str(payload.sessionKey);
    if (sk) {
      const prefix = this.agentPrefix;
      const normalized = sk.startsWith(prefix) ? sk.slice(prefix.length) : sk;
      if (this.streams.has(normalized))
        return normalized;
    }
    const data = payload.data;
    const runId = str(payload.runId, str(data == null ? void 0 : data.runId));
    if (runId && this.runToSession.has(runId))
      return this.runToSession.get(runId);
    if (this.streams.size === 1)
      return this.streams.keys().next().value;
    return null;
  }
  handleStreamEvent(payload) {
    const stream = str(payload.stream);
    const state = str(payload.state);
    const payloadData = payload.data;
    const sessionKey = this.resolveStreamSession(payload);
    const isActiveTab = sessionKey === this.activeSessionKey;
    if (!sessionKey || !this.streams.has(sessionKey)) {
      if (stream === "compaction" || state === "compacting") {
        const cPhase = str(payloadData == null ? void 0 : payloadData.phase);
        if (isActiveTab || !sessionKey) {
          if (cPhase === "end") {
            setTimeout(() => this.hideBanner(), 2e3);
          } else {
            this.showBanner("Compacting context...");
          }
        }
      }
      return;
    }
    const ss = this.streams.get(sessionKey);
    const typingText = this.typingEl.querySelector(".openclaw-typing-text");
    if (state === "assistant") {
      const timeSinceDelta = Date.now() - ss.lastDeltaTime;
      if (ss.text && timeSinceDelta > 1500) {
        if (!ss.workingTimer) {
          ss.workingTimer = setTimeout(() => {
            if (this.streams.has(sessionKey)) {
              if (isActiveTab && this.typingEl.hasClass("oc-hidden")) {
                if (typingText)
                  typingText.textContent = "Working";
                this.typingEl.removeClass("oc-hidden");
              }
            }
            ss.workingTimer = null;
          }, 500);
        }
      } else if (!ss.text && !ss.lastDeltaTime && isActiveTab) {
        this.typingEl.removeClass("oc-hidden");
      }
    } else if (state === "lifecycle") {
      if (!ss.text && isActiveTab && typingText) {
        typingText.textContent = "Thinking";
        this.typingEl.removeClass("oc-hidden");
      }
    }
    const toolName = str(payloadData == null ? void 0 : payloadData.name, str(payloadData == null ? void 0 : payloadData.toolName, str(payload.toolName, str(payload.name))));
    const phase = str(payloadData == null ? void 0 : payloadData.phase, str(payload.phase));
    if ((stream === "tool" || toolName) && (phase === "start" || state === "tool_use")) {
      if (ss.compactTimer) {
        clearTimeout(ss.compactTimer);
        ss.compactTimer = null;
      }
      if (ss.workingTimer) {
        clearTimeout(ss.workingTimer);
        ss.workingTimer = null;
      }
      if (ss.text) {
        ss.splitPoints.push(ss.text.length);
      }
      const { label, url } = this.buildToolLabel(toolName, (payloadData == null ? void 0 : payloadData.args) || payload.args);
      ss.toolCalls.push(label);
      ss.items.push({ type: "tool", label, url });
      if (isActiveTab) {
        this.appendToolCall(label, url, true);
        if (typingText)
          typingText.textContent = label;
        this.typingEl.removeClass("oc-hidden");
      }
    } else if ((stream === "tool" || toolName) && phase === "result") {
      if (isActiveTab) {
        this.deactivateLastToolItem();
        if (typingText)
          typingText.textContent = "Thinking";
        this.typingEl.removeClass("oc-hidden");
        this.scrollToBottom();
      }
    } else if (stream === "compaction" || state === "compacting") {
      if (phase === "end") {
        if (isActiveTab)
          setTimeout(() => this.hideBanner(), 2e3);
      } else {
        ss.toolCalls.push("Compacting memory");
        ss.items.push({ type: "tool", label: "Compacting memory" });
        if (isActiveTab) {
          this.appendToolCall("Compacting memory");
          this.typingEl.addClass("oc-hidden");
          this.showBanner("Compacting context...");
        }
      }
    }
  }
  handleChatEvent(payload) {
    const payloadSk = str(payload.sessionKey);
    const prefix = this.agentPrefix;
    let eventSessionKey = null;
    for (const sk of [...this.streams.keys(), this.activeSessionKey]) {
      if (payloadSk === sk || payloadSk === `${prefix}${sk}` || payloadSk.endsWith(`:${sk}`)) {
        eventSessionKey = sk;
        break;
      }
    }
    if (!eventSessionKey) {
      const active = this.activeSessionKey;
      if (payloadSk === active || payloadSk === `${prefix}${active}` || payloadSk.endsWith(`:${active}`)) {
        eventSessionKey = active;
      } else {
        return;
      }
    }
    const ss = this.streams.get(eventSessionKey);
    const isActiveTab = eventSessionKey === this.activeSessionKey;
    const chatState = str(payload.state);
    if (!ss && (chatState === "final" || chatState === "aborted" || chatState === "error")) {
      if (isActiveTab) {
        this.hideBanner();
        void this.loadHistory();
      }
      return;
    }
    if (chatState === "delta" && ss) {
      if (ss.compactTimer) {
        clearTimeout(ss.compactTimer);
        ss.compactTimer = null;
      }
      if (ss.workingTimer) {
        clearTimeout(ss.workingTimer);
        ss.workingTimer = null;
      }
      ss.lastDeltaTime = Date.now();
      const text = this.extractDeltaText(payload.message);
      if (text) {
        ss.text = text;
        if (isActiveTab) {
          this.typingEl.addClass("oc-hidden");
          this.hideBanner();
          this.updateStreamBubble();
        }
      }
    } else if (chatState === "final") {
      const items = ss ? [...ss.items] : [];
      this.finishStream(eventSessionKey);
      if (isActiveTab) {
        void this.loadHistory().then(async () => {
          await this.renderMessages();
          void this.updateContextMeter();
          if (items.length > 0) {
            const lastAssistant = [...this.messages].reverse().find((m) => m.role === "assistant");
            if (lastAssistant) {
              const key = String(lastAssistant.timestamp);
              if (!this.plugin.settings.streamItemsMap)
                this.plugin.settings.streamItemsMap = {};
              this.plugin.settings.streamItemsMap[key] = items;
              void this.plugin.saveSettings();
            }
          }
        });
      } else {
      }
    } else if (chatState === "aborted") {
      if (isActiveTab && (ss == null ? void 0 : ss.text)) {
        this.messages.push({ role: "assistant", text: ss.text, images: [], timestamp: Date.now() });
      }
      this.finishStream(eventSessionKey);
      if (isActiveTab)
        void this.renderMessages();
    } else if (chatState === "error") {
      if (isActiveTab) {
        this.messages.push({
          role: "assistant",
          text: `Error: ${str(payload.errorMessage, "unknown error")}`,
          images: [],
          timestamp: Date.now()
        });
      }
      this.finishStream(eventSessionKey);
      if (isActiveTab)
        void this.renderMessages();
    }
  }
  finishStream(sessionKey) {
    const sk = sessionKey != null ? sessionKey : this.activeSessionKey;
    const ss = this.streams.get(sk);
    if (ss) {
      if (ss.compactTimer)
        clearTimeout(ss.compactTimer);
      if (ss.workingTimer)
        clearTimeout(ss.workingTimer);
      this.runToSession.delete(ss.runId);
      this.streams.delete(sk);
    }
    if (sk === this.activeSessionKey) {
      this.hideBanner();
      this.streamEl = null;
      this.abortBtn.addClass("oc-hidden");
      this.typingEl.addClass("oc-hidden");
      const typingText = this.typingEl.querySelector(".openclaw-typing-text");
      if (typingText)
        typingText.textContent = "Thinking";
    }
  }
  /** Restore stream UI (typing, tool calls, stream bubble) for the active tab after a tab switch */
  restoreStreamUI() {
    const ss = this.activeStream;
    if (!ss)
      return;
    this.abortBtn.removeClass("oc-hidden");
    for (const item of ss.items) {
      if (item.type === "tool") {
        this.appendToolCall(item.label, item.url);
      }
    }
    if (ss.text) {
      this.updateStreamBubble();
      const typingText = this.typingEl.querySelector(".openclaw-typing-text");
      if (typingText)
        typingText.textContent = "Working";
      this.typingEl.removeClass("oc-hidden");
    } else {
      const typingText = this.typingEl.querySelector(".openclaw-typing-text");
      if (typingText)
        typingText.textContent = "Thinking";
      this.typingEl.removeClass("oc-hidden");
    }
    this.scrollToBottom();
  }
  insertStreamItemsBeforeLastAssistant(items) {
    var _a;
    if (items.length === 0)
      return;
    const bubbles = this.messagesEl.querySelectorAll(".openclaw-msg-assistant");
    const lastBubble = bubbles[bubbles.length - 1];
    if (!lastBubble)
      return;
    for (const item of items) {
      const el = this.createStreamItemEl(item);
      (_a = lastBubble.parentElement) == null ? void 0 : _a.insertBefore(el, lastBubble);
    }
    this.scrollToBottom();
  }
  createStreamItemEl(item) {
    if (item.type === "tool") {
      const el = document.createElement("div");
      el.className = "openclaw-tool-item";
      if (item.url) {
        const link = document.createElement("a");
        link.href = item.url;
        link.textContent = item.label;
        link.className = "openclaw-tool-link";
        link.addEventListener("click", (e) => {
          e.preventDefault();
          window.open(item.url, "_blank");
        });
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
  cleanText(text) {
    text = text.replace(/Conversation info \(untrusted metadata\):\s*```json[\s\S]*?```\s*/g, "").trim();
    text = text.replace(/^```json\s*\{\s*"message_id"[\s\S]*?```\s*/gm, "").trim();
    text = text.replace(/^\[.*?GMT[+-]\d+\]\s*/gm, "").trim();
    text = text.replace(/^\[media attached:.*?\]\s*/gm, "").trim();
    text = text.replace(/^To send an image back.*$/gm, "").trim();
    text = text.replace(/^\[\[audio_as_voice\]\]\s*/gm, "").trim();
    text = text.replace(/^MEDIA:\/[^\n]+$/gm, "").trim();
    text = text.replace(/^VOICE:[^\s\n]+$/gm, "").trim();
    text = text.replace(/^AUDIO_DATA:[^\n]+$/gm, "").trim();
    if (text === "\u{1F3A4} Voice message")
      text = "\u{1F3A4} Voice message";
    if (text === "NO_REPLY" || text === "HEARTBEAT_OK")
      return "";
    return text;
  }
  /** Extract VOICE:path references from message text */
  extractVoiceRefs(text) {
    const refs = [];
    const re = /^VOICE:([^\s\n]+\.(?:mp3|opus|ogg|wav|m4a|mp4))$/gm;
    let match;
    while ((match = re.exec(text)) !== null) {
      refs.push(match[1].trim());
    }
    return refs;
  }
  /** Build HTTP URL for a voice file served by the gateway */
  buildVoiceUrl(voicePath) {
    const gwUrl = this.plugin.settings.gatewayUrl || "";
    const httpUrl = gwUrl.replace(/^ws(s?):\/\//, "http$1://");
    return `${httpUrl}/${voicePath}`;
  }
  /** Render an inline audio player that fetches audio via gateway HTTP */
  renderAudioPlayer(container, voiceRef) {
    const playerEl = container.createDiv("openclaw-audio-player");
    const playBtn = playerEl.createEl("button", { cls: "openclaw-audio-play-btn", text: "\u25B6 voice message" });
    const progressEl = playerEl.createDiv("openclaw-audio-progress");
    const barEl = progressEl.createDiv("openclaw-audio-bar");
    let audio = null;
    playBtn.addEventListener("click", () => void (async () => {
      if (audio && !audio.paused) {
        audio.pause();
        playBtn.textContent = "\u25B6 voice message";
        return;
      }
      if (!audio) {
        playBtn.textContent = "\u23F3 loading...";
        try {
          const url = this.buildVoiceUrl(voiceRef);
          console.debug("[ObsidianClaw] Loading audio from:", url);
          audio = new Audio(url);
          await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("timeout")), 1e4);
            audio.addEventListener("canplaythrough", () => {
              clearTimeout(timer);
              resolve();
            }, { once: true });
            audio.addEventListener("error", () => {
              clearTimeout(timer);
              reject(new Error("load error"));
            }, { once: true });
            audio.load();
          });
          audio.addEventListener("timeupdate", () => {
            if (audio && audio.duration)
              barEl.setCssStyles({ width: `${audio.currentTime / audio.duration * 100}%` });
          });
          audio.addEventListener("ended", () => {
            playBtn.textContent = "\u25B6 voice message";
            barEl.setCssStyles({ width: "0%" });
          });
        } catch (e) {
          console.error("[ObsidianClaw] Audio load failed:", e);
          playBtn.textContent = "\u26A0 audio unavailable";
          playBtn.disabled = true;
          return;
        }
      }
      playBtn.textContent = "\u23F8 playing...";
      audio.play().catch(() => {
        playBtn.textContent = "\u26A0 audio unavailable";
        playBtn.disabled = true;
      });
    })());
  }
  extractDeltaText(msg) {
    var _a;
    if (typeof msg === "string")
      return msg;
    if (!msg)
      return "";
    const content = (_a = msg.content) != null ? _a : msg;
    if (Array.isArray(content)) {
      let text = "";
      for (const block of content) {
        if (typeof block === "string") {
          text += block;
        } else if (block && typeof block === "object" && "text" in block) {
          text += (text ? "\n" : "") + String(block.text);
        }
      }
      return text;
    }
    if (typeof content === "string")
      return content;
    return str(msg.text);
  }
  updateStreamBubble() {
    const ss = this.activeStream;
    const visibleText = ss == null ? void 0 : ss.text;
    if (!visibleText)
      return;
    if (!this.streamEl) {
      this.streamEl = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant openclaw-streaming");
      this.scrollToBottom();
    }
    this.streamEl.empty();
    this.streamEl.createDiv({ text: visibleText, cls: "openclaw-msg-text" });
  }
  async renderMessages() {
    var _a, _b;
    this.messagesEl.empty();
    for (const msg of this.messages) {
      if (msg.role === "assistant") {
        const hasContentTools = ((_a = msg.contentBlocks) == null ? void 0 : _a.some((b) => b.type === "tool_use" || b.type === "toolCall")) || false;
        if (hasContentTools && msg.contentBlocks) {
          for (const block of msg.contentBlocks) {
            if (block.type === "text" && ((_b = block.text) == null ? void 0 : _b.trim())) {
              const blockAudio = this.extractVoiceRefs(block.text);
              const cleaned = this.cleanText(block.text);
              if (cleaned) {
                const bubble2 = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant");
                try {
                  await import_obsidian.MarkdownRenderer.render(this.app, cleaned, bubble2, "", this);
                } catch (e) {
                  bubble2.createDiv({ text: cleaned, cls: "openclaw-msg-text" });
                }
                for (const ap of blockAudio) {
                  this.renderAudioPlayer(bubble2, ap);
                }
              } else if (blockAudio.length > 0) {
                const bubble2 = this.messagesEl.createDiv("openclaw-msg openclaw-msg-assistant");
                for (const ap of blockAudio) {
                  this.renderAudioPlayer(bubble2, ap);
                }
              }
            } else if (block.type === "tool_use" || block.type === "toolCall") {
              const { label, url } = this.buildToolLabel(block.name || "", block.input || block.arguments || {});
              const el = this.createStreamItemEl({ type: "tool", label, url });
              this.messagesEl.appendChild(el);
            }
          }
          continue;
        }
      }
      const cls = msg.role === "user" ? "openclaw-msg-user" : "openclaw-msg-assistant";
      const bubble = this.messagesEl.createDiv(`openclaw-msg ${cls}`);
      if (msg.images && msg.images.length > 0) {
        const imgContainer = bubble.createDiv("openclaw-msg-images");
        for (const src of msg.images) {
          const img = imgContainer.createEl("img", {
            cls: "openclaw-msg-img",
            attr: { src, loading: "lazy" }
          });
          img.addEventListener("click", () => {
            const overlay = document.body.createDiv("openclaw-img-overlay");
            overlay.createEl("img", { attr: { src } });
            overlay.addEventListener("click", () => overlay.remove());
          });
        }
      }
      const allAudio = msg.text ? this.extractVoiceRefs(msg.text) : [];
      if (msg.text) {
        const displayText = msg.role === "assistant" ? this.cleanText(msg.text) : msg.text;
        if (displayText) {
          if (msg.role === "assistant") {
            try {
              await import_obsidian.MarkdownRenderer.render(this.app, displayText, bubble, "", this);
            } catch (e) {
              bubble.createDiv({ text: displayText, cls: "openclaw-msg-text" });
            }
          } else {
            bubble.createDiv({ text: displayText, cls: "openclaw-msg-text" });
          }
        }
      }
      for (const ap of allAudio) {
        this.renderAudioPlayer(bubble, ap);
      }
    }
    this.scrollToBottom();
  }
  scrollToBottom() {
    if (this.messagesEl) {
      requestAnimationFrame(() => {
        this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
      });
    }
  }
  autoResize() {
    this.inputEl.setCssStyles({ height: "auto" });
    this.inputEl.setCssStyles({ height: Math.min(this.inputEl.scrollHeight, 150) + "px" });
  }
};
var OpenClawPlugin = class extends import_obsidian.Plugin {
  constructor() {
    super(...arguments);
    this.settings = DEFAULT_SETTINGS;
    this.gateway = null;
    this.gatewayConnected = false;
    this.chatView = null;
  }
  async onload() {
    await this.loadSettings();
    this.registerView(VIEW_TYPE, (leaf) => new OpenClawChatView(leaf, this));
    this.addRibbonIcon("message-square", "OpenClaw chat", () => {
      void this.activateView();
    });
    this.addCommand({
      id: "toggle-chat",
      name: "Toggle chat sidebar",
      callback: () => void this.activateView()
    });
    this.addCommand({
      id: "ask-about-note",
      name: "Ask about current note",
      callback: () => void this.askAboutNote()
    });
    this.addCommand({
      id: "reconnect",
      name: "Reconnect to gateway",
      callback: () => void this.connectGateway()
    });
    this.addCommand({
      id: "setup",
      name: "Run setup wizard",
      callback: () => new OnboardingModal(this.app, this).open()
    });
    this.addSettingTab(new OpenClawSettingTab(this.app, this));
    if (!this.settings.onboardingComplete) {
      setTimeout(() => new OnboardingModal(this.app, this).open(), 500);
    } else {
      void this.connectGateway();
      this.app.workspace.onLayoutReady(() => {
        void this.activateView();
      });
    }
  }
  onunload() {
    var _a;
    (_a = this.gateway) == null ? void 0 : _a.stop();
    this.gateway = null;
    this.gatewayConnected = false;
  }
  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }
  async saveSettings() {
    await this.saveData(this.settings);
  }
  async connectGateway() {
    var _a, _b;
    (_a = this.gateway) == null ? void 0 : _a.stop();
    this.gatewayConnected = false;
    (_b = this.chatView) == null ? void 0 : _b.updateStatus();
    const rawUrl = this.settings.gatewayUrl.trim();
    if (!rawUrl)
      return;
    const url = normalizeGatewayUrl(rawUrl);
    if (!url) {
      new import_obsidian.Notice("OpenClaw: Invalid gateway URL. Use your Tailscale Serve URL (e.g. wss://your-machine.tail1234.ts.net)");
      return;
    }
    if (url !== rawUrl) {
      this.settings.gatewayUrl = url;
      await this.saveSettings();
    }
    let deviceIdentity;
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
      token: this.settings.token.trim() || void 0,
      deviceIdentity,
      onHello: () => {
        var _a2, _b2, _c, _d;
        this.gatewayConnected = true;
        (_a2 = this.chatView) == null ? void 0 : _a2.updateStatus();
        void ((_b2 = this.chatView) == null ? void 0 : _b2.loadHistory());
        void ((_c = this.chatView) == null ? void 0 : _c.renderTabs());
        void ((_d = this.chatView) == null ? void 0 : _d.loadAgents());
        if (this.settings.currentModel && this.chatView) {
          this.chatView.currentModel = this.settings.currentModel;
          this.chatView.updateModelPill();
        }
      },
      onClose: (info) => {
        var _a2;
        this.gatewayConnected = false;
        (_a2 = this.chatView) == null ? void 0 : _a2.updateStatus();
        if (info.reason.includes("pairing required") || info.reason.includes("device identity required")) {
          new import_obsidian.Notice("OpenClaw: Device pairing required. Run 'openclaw devices approve' on your gateway machine.", 1e4);
        }
      },
      onEvent: (evt) => {
        var _a2, _b2;
        if (evt.event === "chat") {
          (_a2 = this.chatView) == null ? void 0 : _a2.handleChatEvent(evt.payload);
        } else if (evt.event === "stream" || evt.event === "agent") {
          (_b2 = this.chatView) == null ? void 0 : _b2.handleStreamEvent(evt.payload);
        }
      }
    });
    this.gateway.start();
  }
  async activateView() {
    const existing = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    if (existing.length > 0) {
      void this.app.workspace.revealLeaf(existing[0]);
      return;
    }
    const leaf = this.app.workspace.getRightLeaf(false);
    if (leaf) {
      await leaf.setViewState({ type: VIEW_TYPE, active: true });
      void this.app.workspace.revealLeaf(leaf);
    }
  }
  async askAboutNote() {
    var _a;
    const file = this.app.workspace.getActiveFile();
    if (!file) {
      new import_obsidian.Notice("No active note");
      return;
    }
    const content = await this.app.vault.read(file);
    if (!content.trim()) {
      new import_obsidian.Notice("Note is empty");
      return;
    }
    await this.activateView();
    if (!this.chatView || !((_a = this.gateway) == null ? void 0 : _a.connected)) {
      new import_obsidian.Notice("Not connected to OpenClaw");
      return;
    }
    const message = `Here is my current note "${file.basename}":

${content}

What can you tell me about this?`;
    const inputEl = this.chatView.containerEl.querySelector(".openclaw-input");
    if (inputEl) {
      inputEl.value = message;
      inputEl.focus();
    }
  }
};
var ModelPickerModal = class extends import_obsidian.Modal {
  constructor(app, plugin, chatView) {
    super(app);
    this.models = [];
    this.currentModel = "";
    this.selectedProvider = null;
    this.plugin = plugin;
    this.chatView = chatView;
  }
  async onOpen() {
    var _a;
    this.modalEl.addClass("openclaw-picker");
    this.contentEl.createDiv("openclaw-picker-loading").textContent = "Loading models...";
    try {
      const result = await ((_a = this.plugin.gateway) == null ? void 0 : _a.request("models.list", {}));
      this.models = (result == null ? void 0 : result.models) || [];
    } catch (e) {
      this.models = [];
    }
    this.currentModel = this.chatView.currentModel || "";
    if (this.currentModel && !this.currentModel.includes("/")) {
      const match = this.models.find((m) => m.id === this.currentModel);
      if (match)
        this.currentModel = `${match.provider}/${match.id}`;
    }
    if (this.currentModel.includes("/")) {
      this.selectedProvider = this.currentModel.split("/")[0];
    }
    const providers = new Set(this.models.map((m) => m.provider));
    if (providers.size === 1) {
      this.renderModels([...providers][0]);
    } else {
      this.renderProviders();
    }
  }
  onClose() {
    this.contentEl.empty();
  }
  renderProviders() {
    const { contentEl } = this;
    contentEl.empty();
    const providerMap = /* @__PURE__ */ new Map();
    for (const m of this.models) {
      const p = m.provider || "unknown";
      if (!providerMap.has(p))
        providerMap.set(p, []);
      providerMap.get(p).push(m);
    }
    const currentProvider = this.currentModel.includes("/") ? this.currentModel.split("/")[0] : "";
    const list = contentEl.createDiv("openclaw-picker-list");
    for (const [provider, models] of providerMap) {
      const isCurrent = provider === currentProvider;
      const row = list.createDiv({ cls: `openclaw-picker-row${isCurrent ? " active" : ""}` });
      const left = row.createDiv("openclaw-picker-row-left");
      if (isCurrent)
        left.createSpan({ text: "\u25CF ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: provider, cls: "openclaw-picker-provider-name" });
      const right = row.createDiv("openclaw-picker-row-right");
      right.createSpan({ text: `${models.length} model${models.length !== 1 ? "s" : ""}`, cls: "openclaw-picker-meta" });
      right.createSpan({ text: " \u2192", cls: "openclaw-picker-arrow" });
      row.addEventListener("click", () => {
        this.selectedProvider = provider;
        this.renderModels(provider);
      });
    }
    const footer = contentEl.createDiv("openclaw-picker-hint openclaw-picker-footer");
    footer.appendText("Want more models? ");
    footer.createEl("a", { text: "Add them in your gateway config.", href: "https://docs.openclaw.ai/gateway/configuration#choose-and-configure-models" });
  }
  renderModels(provider) {
    const { contentEl } = this;
    contentEl.empty();
    const providers = new Set(this.models.map((m) => m.provider));
    if (providers.size > 1) {
      const header = contentEl.createDiv("openclaw-picker-header");
      const backBtn = header.createEl("button", { cls: "openclaw-picker-back", text: "\u2190 " + provider });
      backBtn.addEventListener("click", () => this.renderProviders());
    }
    const models = this.models.filter((m) => m.provider === provider);
    const list = contentEl.createDiv("openclaw-picker-list openclaw-picker-model-list");
    for (const m of models) {
      const fullId = `${m.provider}/${m.id}`;
      const isCurrent = fullId === this.currentModel;
      const row = list.createDiv({ cls: `openclaw-picker-row${isCurrent ? " active" : ""}` });
      const left = row.createDiv("openclaw-picker-row-left");
      if (isCurrent)
        left.createSpan({ text: "\u25CF ", cls: "openclaw-picker-dot" });
      left.createSpan({ text: m.name || m.id });
      row.addEventListener("click", () => void (async () => {
        var _a;
        if (!((_a = this.plugin.gateway) == null ? void 0 : _a.connected))
          return;
        row.addClass("openclaw-picker-selecting");
        row.textContent = "Switching...";
        try {
          await this.plugin.gateway.request("chat.send", {
            sessionKey: this.plugin.settings.sessionKey,
            message: `/model ${fullId}`,
            deliver: false,
            idempotencyKey: "model-" + Date.now()
          });
          this.chatView.currentModel = fullId;
          this.chatView.currentModelSetAt = Date.now();
          this.plugin.settings.currentModel = fullId;
          await this.plugin.saveSettings();
          this.chatView.updateModelPill();
          new import_obsidian.Notice(`Model: ${m.name || m.id}`);
          this.close();
        } catch (e) {
          new import_obsidian.Notice(`Failed: ${e}`);
          this.renderModels(provider);
        }
      })());
    }
  }
};
var ConfirmCloseModal = class extends import_obsidian.Modal {
  constructor(app, title, message, callback) {
    super(app);
    this.title = title;
    this.message = message;
    this.callback = callback;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.addClass("openclaw-confirm-modal");
    contentEl.createEl("h3", { text: this.title, cls: "openclaw-confirm-title" });
    contentEl.createEl("p", { text: this.message, cls: "openclaw-confirm-message" });
    const checkRow = contentEl.createDiv("openclaw-confirm-check");
    this.checkboxEl = checkRow.createEl("input", { type: "checkbox" });
    this.checkboxEl.id = "confirm-dont-ask";
    checkRow.createEl("label", { text: "Don't ask me again", attr: { for: "confirm-dont-ask" } });
    const btnRow = contentEl.createDiv("openclaw-confirm-buttons");
    const cancelBtn = btnRow.createEl("button", { text: "Cancel", cls: "openclaw-confirm-cancel" });
    cancelBtn.addEventListener("click", () => {
      this.callback(false, false);
      this.close();
    });
    const confirmBtn = btnRow.createEl("button", { text: this.title.startsWith("Reset") ? "Reset" : "Close", cls: "openclaw-confirm-ok" });
    confirmBtn.addEventListener("click", () => {
      this.callback(true, this.checkboxEl.checked);
      this.close();
    });
  }
  onClose() {
    this.contentEl.empty();
  }
};
var OpenClawSettingTab = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    new import_obsidian.Setting(containerEl).setName("OpenClaw").setHeading();
    const wizardSection = containerEl.createDiv("openclaw-settings-wizard");
    const wizardDesc = wizardSection.createDiv("openclaw-settings-wizard-desc");
    wizardDesc.createEl("strong", { text: "Setup wizard" });
    wizardDesc.createEl("p", {
      text: "The easiest way to connect. Walks you through Tailscale, gateway setup, and device pairing step by step.",
      cls: "setting-item-description"
    });
    const wizardBtn = wizardSection.createEl("button", { text: "Run setup wizard", cls: "mod-cta openclaw-settings-wizard-btn" });
    wizardBtn.addEventListener("click", () => {
      new OnboardingModal(this.app, this.plugin).open();
    });
    const statusSection = containerEl.createDiv("openclaw-settings-status");
    const connected = this.plugin.gatewayConnected;
    statusSection.createSpan({ cls: `openclaw-settings-dot ${connected ? "connected" : "disconnected"}` });
    statusSection.createSpan({ text: connected ? "Connected" : "Disconnected", cls: "openclaw-settings-status-text" });
    if (this.plugin.settings.gatewayUrl) {
      statusSection.createSpan({
        text: ` \u2014 ${this.plugin.settings.gatewayUrl.replace(/^wss?:\/\//, "")}`,
        cls: "openclaw-settings-status-url"
      });
    }
    new import_obsidian.Setting(containerEl).setName("Session").setHeading();
    new import_obsidian.Setting(containerEl).setName("Conversation").setDesc('Current conversation key. Use "main" for the default session.').addText(
      (text) => text.setPlaceholder("Main").setValue(this.plugin.settings.sessionKey).onChange(async (value) => {
        this.plugin.settings.sessionKey = value || "main";
        await this.plugin.saveSettings();
      })
    ).addButton(
      (btn) => btn.setButtonText("Reset to main").onClick(async () => {
        this.plugin.settings.sessionKey = "main";
        await this.plugin.saveSettings();
        this.display();
        await this.plugin.connectGateway();
        new import_obsidian.Notice("Reset to main conversation");
      })
    );
    new import_obsidian.Setting(containerEl).setName("Confirm before closing tabs").setDesc("Show a confirmation dialog before closing or resetting tabs").addToggle(
      (toggle) => toggle.setValue(localStorage.getItem("openclaw-confirm-close-disabled") !== "true").onChange((value) => {
        localStorage.setItem("openclaw-confirm-close-disabled", value ? "false" : "true");
      })
    );
    new import_obsidian.Setting(containerEl).setName("Connection").setDesc("These are set automatically by the setup wizard. Edit manually only if you know what you're doing.").setHeading();
    new import_obsidian.Setting(containerEl).setName("Gateway URL").setDesc("Tailscale Serve URL (e.g. wss://your-machine.tail1234.ts.net)").addText(
      (text) => text.setPlaceholder("wss://your-machine.tail1234.ts.net").setValue(this.plugin.settings.gatewayUrl).onChange(async (value) => {
        const normalized = normalizeGatewayUrl(value);
        this.plugin.settings.gatewayUrl = normalized || value;
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian.Setting(containerEl).setName("Auth token").setDesc("Gateway auth token").addText((text) => {
      text.inputEl.type = "password";
      return text.setPlaceholder("Token").setValue(this.plugin.settings.token).onChange(async (value) => {
        this.plugin.settings.token = value;
        await this.plugin.saveSettings();
      });
    });
    new import_obsidian.Setting(containerEl).setName("Reconnect").setDesc("Re-establish the gateway connection").addButton(
      (btn) => btn.setButtonText("Reconnect").onClick(() => {
        void this.plugin.connectGateway();
        new import_obsidian.Notice("OpenClaw: Reconnecting...");
      })
    );
  }
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsibWFpbi50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHtcbiAgQXBwLFxuICBGdXp6eVN1Z2dlc3RNb2RhbCxcbiAgSXRlbVZpZXcsXG4gIE1hcmtkb3duUmVuZGVyZXIsXG4gIE1vZGFsLFxuICBOb3RpY2UsXG4gIFBsYXRmb3JtLFxuICBQbHVnaW4sXG4gIFBsdWdpblNldHRpbmdUYWIsXG4gIFNldHRpbmcsXG4gIFRGaWxlLFxuICBXb3Jrc3BhY2VMZWFmLFxuICBzZXRJY29uLFxufSBmcm9tIFwib2JzaWRpYW5cIjtcblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFNldHRpbmdzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG50eXBlIFN0cmVhbUl0ZW0gPSB7IHR5cGU6IFwidG9vbFwiOyBsYWJlbDogc3RyaW5nOyB1cmw/OiBzdHJpbmc7IHRleHRQb3M/OiBudW1iZXIgfSB8IHsgdHlwZTogXCJ0ZXh0XCI7IHRleHQ6IHN0cmluZyB9O1xuXG4vKiogU2FmZWx5IGV4dHJhY3QgYSBzdHJpbmcgZnJvbSBhbiB1bmtub3duIHZhbHVlIChhdm9pZHMgW29iamVjdCBPYmplY3RdIGNvZXJjaW9uKS4gKi9cbmZ1bmN0aW9uIHN0cih2OiB1bmtub3duLCBmYWxsYmFjayA9IFwiXCIpOiBzdHJpbmcge1xuICByZXR1cm4gdHlwZW9mIHYgPT09IFwic3RyaW5nXCIgPyB2IDogZmFsbGJhY2s7XG59XG5cbmludGVyZmFjZSBBZ2VudEluZm8ge1xuICBpZDogc3RyaW5nO1xuICBuYW1lOiBzdHJpbmc7XG4gIGVtb2ppOiBzdHJpbmc7XG4gIGNyZWF0dXJlOiBzdHJpbmc7XG59XG5cbmludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICB0b2tlbjogc3RyaW5nO1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIGFjdGl2ZUFnZW50SWQ/OiBzdHJpbmc7ICAvLyBjdXJyZW50bHkgc2VsZWN0ZWQgYWdlbnQgaWRcbiAgY3VycmVudE1vZGVsPzogc3RyaW5nOyAgLy8gcGVyc2lzdGVkIG1vZGVsIHNlbGVjdGlvbiAocHJvdmlkZXIvbW9kZWwgZm9ybWF0KVxuICBvbmJvYXJkaW5nQ29tcGxldGU6IGJvb2xlYW47XG4gIGRldmljZUlkPzogc3RyaW5nO1xuICBkZXZpY2VQdWJsaWNLZXk/OiBzdHJpbmc7XG4gIGRldmljZVByaXZhdGVLZXk/OiBzdHJpbmc7XG4gIC8qKiBQZXJzaXN0ZWQgc3RyZWFtIGl0ZW1zICh0b29sIGNhbGxzICsgaW50ZXJtZWRpYXJ5IHRleHQpIGtleWVkIGJ5IGFzc2lzdGFudCBtZXNzYWdlIGluZGV4ICovXG4gIHN0cmVhbUl0ZW1zTWFwPzogUmVjb3JkPHN0cmluZywgU3RyZWFtSXRlbVtdPjtcbn1cblxuY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogXCJcIixcbiAgdG9rZW46IFwiXCIsXG4gIHNlc3Npb25LZXk6IFwibWFpblwiLFxuICBvbmJvYXJkaW5nQ29tcGxldGU6IGZhbHNlLFxufTtcblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIERldmljZSBJZGVudGl0eSAoRWQyNTUxOSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbi8qKiBOb3JtYWxpemUgYSBnYXRld2F5IFVSTDogYWNjZXB0cyB3czovLywgd3NzOi8vLCBodHRwOi8vLCBodHRwczovLyBhbmQgcmV0dXJucyB3czovLyBvciB3c3M6Ly8uIFJldHVybnMgbnVsbCBpZiBpbnZhbGlkLiAqL1xuZnVuY3Rpb24gbm9ybWFsaXplR2F0ZXdheVVybChyYXc6IHN0cmluZyk6IHN0cmluZyB8IG51bGwge1xuICBsZXQgdXJsID0gcmF3LnRyaW0oKTtcbiAgaWYgKHVybC5zdGFydHNXaXRoKFwiaHR0cHM6Ly9cIikpIHVybCA9IFwid3NzOi8vXCIgKyB1cmwuc2xpY2UoOCk7XG4gIGVsc2UgaWYgKHVybC5zdGFydHNXaXRoKFwiaHR0cDovL1wiKSkgdXJsID0gXCJ3czovL1wiICsgdXJsLnNsaWNlKDcpO1xuICBpZiAoIXVybC5zdGFydHNXaXRoKFwid3M6Ly9cIikgJiYgIXVybC5zdGFydHNXaXRoKFwid3NzOi8vXCIpKSByZXR1cm4gbnVsbDtcbiAgLy8gU3RyaXAgdHJhaWxpbmcgc2xhc2ggZm9yIGNvbnNpc3RlbmN5XG4gIHJldHVybiB1cmwucmVwbGFjZSgvXFwvKyQvLCBcIlwiKTtcbn1cblxuZnVuY3Rpb24gdG9CYXNlNjRVcmwoYnl0ZXM6IFVpbnQ4QXJyYXkpOiBzdHJpbmcge1xuICBsZXQgYmluYXJ5ID0gXCJcIjtcbiAgZm9yIChjb25zdCBiIG9mIGJ5dGVzKSBiaW5hcnkgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShiKTtcbiAgcmV0dXJuIGJ0b2EoYmluYXJ5KS5yZXBsYWNlKC9cXCsvZywgXCItXCIpLnJlcGxhY2UoL1xcLy9nLCBcIl9cIikucmVwbGFjZSgvPSskL2csIFwiXCIpO1xufVxuXG5mdW5jdGlvbiBmcm9tQmFzZTY0VXJsKHM6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBwYWRkZWQgPSBzLnJlcGxhY2UoLy0vZywgXCIrXCIpLnJlcGxhY2UoL18vZywgXCIvXCIpICsgXCI9XCIucmVwZWF0KCg0IC0gKHMubGVuZ3RoICUgNCkpICUgNCk7XG4gIGNvbnN0IGJpbmFyeSA9IGF0b2IocGFkZGVkKTtcbiAgY29uc3QgYnl0ZXMgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIGJ5dGVzW2ldID0gYmluYXJ5LmNoYXJDb2RlQXQoaSk7XG4gIHJldHVybiBieXRlcztcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGRhdGE6IFVpbnQ4QXJyYXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBoYXNoID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIGRhdGEuYnVmZmVyKTtcbiAgcmV0dXJuIEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoaGFzaCksIChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCBcIjBcIikpLmpvaW4oXCJcIik7XG59XG5cbmludGVyZmFjZSBEZXZpY2VJZGVudGl0eSB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nO1xuICBwcml2YXRlS2V5OiBzdHJpbmc7XG4gIGNyeXB0b0tleTogQ3J5cHRvS2V5O1xufVxuXG5hc3luYyBmdW5jdGlvbiBnZXRPckNyZWF0ZURldmljZUlkZW50aXR5KFxuICBsb2FkRGF0YTogKCkgPT4gUHJvbWlzZTxSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiB8IG51bGw+LFxuICBzYXZlRGF0YTogKGRhdGE6IFJlY29yZDxzdHJpbmcsIHVua25vd24+KSA9PiBQcm9taXNlPHZvaWQ+XG4pOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIGNvbnN0IGRhdGEgPSBhd2FpdCBsb2FkRGF0YSgpO1xuICBjb25zdCBkZXZpY2VJZCA9IHR5cGVvZiBkYXRhPy5kZXZpY2VJZCA9PT0gXCJzdHJpbmdcIiA/IGRhdGEuZGV2aWNlSWQgOiBudWxsO1xuICBjb25zdCBkZXZpY2VQdWJsaWNLZXkgPSB0eXBlb2YgZGF0YT8uZGV2aWNlUHVibGljS2V5ID09PSBcInN0cmluZ1wiID8gZGF0YS5kZXZpY2VQdWJsaWNLZXkgOiBudWxsO1xuICBjb25zdCBkZXZpY2VQcml2YXRlS2V5ID0gdHlwZW9mIGRhdGE/LmRldmljZVByaXZhdGVLZXkgPT09IFwic3RyaW5nXCIgPyBkYXRhLmRldmljZVByaXZhdGVLZXkgOiBudWxsO1xuICBpZiAoZGV2aWNlSWQgJiYgZGV2aWNlUHVibGljS2V5ICYmIGRldmljZVByaXZhdGVLZXkpIHtcbiAgICAvLyBSZXN0b3JlIGV4aXN0aW5nIGlkZW50aXR5XG4gICAgY29uc3QgcHJpdkJ5dGVzID0gZnJvbUJhc2U2NFVybChkZXZpY2VQcml2YXRlS2V5KTtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgIFwicGtjczhcIixcbiAgICAgIHByaXZCeXRlcyxcbiAgICAgIHsgbmFtZTogXCJFZDI1NTE5XCIgfSxcbiAgICAgIGZhbHNlLFxuICAgICAgW1wic2lnblwiXVxuICAgICk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGRldmljZUlkLFxuICAgICAgcHVibGljS2V5OiBkZXZpY2VQdWJsaWNLZXksXG4gICAgICBwcml2YXRlS2V5OiBkZXZpY2VQcml2YXRlS2V5LFxuICAgICAgY3J5cHRvS2V5LFxuICAgIH07XG4gIH1cblxuICAvLyBHZW5lcmF0ZSBuZXcgRWQyNTUxOSBrZXlwYWlyXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFwiRWQyNTUxOVwiLCB0cnVlLCBbXCJzaWduXCIsIFwidmVyaWZ5XCJdKTtcbiAgY29uc3QgcHViUmF3ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJyYXdcIiwga2V5UGFpci5wdWJsaWNLZXkpKTtcbiAgY29uc3QgcHJpdlBrY3M4ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXlQYWlyLnByaXZhdGVLZXkpKTtcbiAgY29uc3QgbmV3RGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcbiAgY29uc3QgcHVibGljS2V5ID0gdG9CYXNlNjRVcmwocHViUmF3KTtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IHRvQmFzZTY0VXJsKHByaXZQa2NzOCk7XG5cbiAgLy8gU2F2ZSB0byBwbHVnaW4gZGF0YVxuICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBsb2FkRGF0YSgpKSA/PyB7fTtcbiAgZXhpc3RpbmcuZGV2aWNlSWQgPSBuZXdEZXZpY2VJZDtcbiAgZXhpc3RpbmcuZGV2aWNlUHVibGljS2V5ID0gcHVibGljS2V5O1xuICBleGlzdGluZy5kZXZpY2VQcml2YXRlS2V5ID0gcHJpdmF0ZUtleTtcbiAgYXdhaXQgc2F2ZURhdGEoZXhpc3RpbmcpO1xuXG4gIHJldHVybiB7IGRldmljZUlkOiBuZXdEZXZpY2VJZCwgcHVibGljS2V5LCBwcml2YXRlS2V5LCBjcnlwdG9LZXk6IGtleVBhaXIucHJpdmF0ZUtleSB9O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGVuY29kZWQgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUocGF5bG9hZCk7XG4gIGxldCBjcnlwdG9LZXkgPSBpZGVudGl0eS5jcnlwdG9LZXk7XG4gIC8vIElmIGNyeXB0b0tleSBkb2Vzbid0IGhhdmUgc2lnbiB1c2FnZSwgcmUtaW1wb3J0XG4gIGlmICghY3J5cHRvS2V5KSB7XG4gICAgY29uc3QgcHJpdkJ5dGVzID0gZnJvbUJhc2U2NFVybChpZGVudGl0eS5wcml2YXRlS2V5KTtcbiAgICBjcnlwdG9LZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcInBrY3M4XCIsIHByaXZCeXRlcywgeyBuYW1lOiBcIkVkMjU1MTlcIiB9LCBmYWxzZSwgW1wic2lnblwiXSk7XG4gIH1cbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFwiRWQyNTUxOVwiLCBjcnlwdG9LZXksIGVuY29kZWQpO1xuICByZXR1cm4gdG9CYXNlNjRVcmwobmV3IFVpbnQ4QXJyYXkoc2lnKSk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkU2lnbmF0dXJlUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZyB8IG51bGw7XG4gIG5vbmNlOiBzdHJpbmcgfCBudWxsO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyBcInYyXCIgOiBcInYxXCI7XG4gIGNvbnN0IHBhcnRzID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBwYXJhbXMuc2NvcGVzLmpvaW4oXCIsXCIpLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuID8/IFwiXCIsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSBcInYyXCIpIHBhcnRzLnB1c2gocGFyYW1zLm5vbmNlID8/IFwiXCIpO1xuICByZXR1cm4gcGFydHMuam9pbihcInxcIik7XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBHYXRld2F5IFR5cGVzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5pbnRlcmZhY2UgR2F0ZXdheVBheWxvYWQge1xuICBba2V5OiBzdHJpbmddOiB1bmtub3duO1xufVxuXG5pbnRlcmZhY2UgR2F0ZXdheU1lc3NhZ2Uge1xuICB0eXBlOiBzdHJpbmc7XG4gIGlkPzogc3RyaW5nO1xuICBldmVudD86IHN0cmluZztcbiAgcGF5bG9hZD86IEdhdGV3YXlQYXlsb2FkO1xuICBvaz86IGJvb2xlYW47XG4gIGVycm9yPzogeyBtZXNzYWdlPzogc3RyaW5nIH07XG4gIHNlcT86IG51bWJlcjtcbn1cblxuaW50ZXJmYWNlIFNlc3Npb25JbmZvIHtcbiAga2V5OiBzdHJpbmc7XG4gIGxhYmVsPzogc3RyaW5nO1xuICBkaXNwbGF5TmFtZT86IHN0cmluZztcbiAgbW9kZWw/OiBzdHJpbmc7XG4gIHRvdGFsVG9rZW5zPzogbnVtYmVyO1xuICBjb250ZXh0VG9rZW5zPzogbnVtYmVyO1xuICBjcmVhdGVkQXQ/OiBudW1iZXI7XG4gIHVwZGF0ZWRBdD86IG51bWJlcjtcbn1cblxuaW50ZXJmYWNlIEFnZW50TGlzdEl0ZW0ge1xuICBpZD86IHN0cmluZztcbiAgbmFtZT86IHN0cmluZztcbn1cblxuaW50ZXJmYWNlIE1vZGVsSW5mbyB7XG4gIGlkOiBzdHJpbmc7XG4gIG5hbWU/OiBzdHJpbmc7XG4gIHByb3ZpZGVyOiBzdHJpbmc7XG59XG5cbmludGVyZmFjZSBDb250ZW50QmxvY2sge1xuICB0eXBlOiBzdHJpbmc7XG4gIHRleHQ/OiBzdHJpbmc7XG4gIGNvbnRlbnQ/OiBzdHJpbmcgfCBDb250ZW50QmxvY2tbXTtcbiAgbmFtZT86IHN0cmluZztcbiAgaW5wdXQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbiAgYXJndW1lbnRzPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIGltYWdlX3VybD86IHsgdXJsOiBzdHJpbmcgfTtcbn1cblxuaW50ZXJmYWNlIEhpc3RvcnlNZXNzYWdlIHtcbiAgcm9sZTogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmcgfCBDb250ZW50QmxvY2tbXTtcbiAgdGltZXN0YW1wPzogbnVtYmVyO1xufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgR2F0ZXdheSBDbGllbnQgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbnR5cGUgR2F0ZXdheUV2ZW50SGFuZGxlciA9IChldmVudDogeyBldmVudDogc3RyaW5nOyBwYXlsb2FkOiBHYXRld2F5UGF5bG9hZDsgc2VxPzogbnVtYmVyIH0pID0+IHZvaWQ7XG50eXBlIEdhdGV3YXlIZWxsb0hhbmRsZXIgPSAocGF5bG9hZDogR2F0ZXdheVBheWxvYWQpID0+IHZvaWQ7XG50eXBlIEdhdGV3YXlDbG9zZUhhbmRsZXIgPSAoaW5mbzogeyBjb2RlOiBudW1iZXI7IHJlYXNvbjogc3RyaW5nIH0pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBHYXRld2F5Q2xpZW50T3B0cyB7XG4gIHVybDogc3RyaW5nO1xuICB0b2tlbj86IHN0cmluZztcbiAgZGV2aWNlSWRlbnRpdHk/OiBEZXZpY2VJZGVudGl0eTtcbiAgb25FdmVudD86IEdhdGV3YXlFdmVudEhhbmRsZXI7XG4gIG9uSGVsbG8/OiBHYXRld2F5SGVsbG9IYW5kbGVyO1xuICBvbkNsb3NlPzogR2F0ZXdheUNsb3NlSGFuZGxlcjtcbn1cblxuZnVuY3Rpb24gZ2VuZXJhdGVJZCgpOiBzdHJpbmcge1xuICBjb25zdCBhcnIgPSBuZXcgVWludDhBcnJheSgxNik7XG4gIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMoYXJyKTtcbiAgcmV0dXJuIEFycmF5LmZyb20oYXJyLCAoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgXCIwXCIpKS5qb2luKFwiXCIpO1xufVxuXG4vKipcbiAqIERlbGV0ZSBhIHNlc3Npb24gdmlhIGdhdGV3YXksIHdpdGggZmFsbGJhY2sgZm9yIHVucHJlZml4ZWQgc3RvcmUga2V5cy5cbiAqIFRoZSBnYXRld2F5IHN0b3JlcyBjaGFubmVsIHNlc3Npb25zICh0ZWxlZ3JhbTosIGRpc2NvcmQ6LCBldGMuKSB3aXRob3V0IHRoZVxuICogYWdlbnQ6bWFpbjogcHJlZml4LCBidXQgc2Vzc2lvbnMubGlzdCByZXR1cm5zIHRoZW0gcHJlZml4ZWQuIFNlbmRpbmcgdGhlXG4gKiBwcmVmaXhlZCBrZXkgdG8gc2Vzc2lvbnMuZGVsZXRlIHN1Y2NlZWRzICh7b2s6dHJ1ZX0pIGJ1dCByZXR1cm5zIGRlbGV0ZWQ6ZmFsc2VcbiAqIGJlY2F1c2UgdGhlIGtleSBsb29rdXAgbWlzc2VzIHRoZSB1bnByZWZpeGVkIHN0b3JlIGVudHJ5LlxuICogRml4OiBpZiB0aGUgZmlyc3QgYXR0ZW1wdCByZXR1cm5zIGRlbGV0ZWQ6ZmFsc2UgYW5kIHRoZSBrZXkgaGFzIGFuIGFnZW50IHByZWZpeCxcbiAqIHJldHJ5IHdpdGggdGhlIHJhdyBzdWZmaXggKHRoZSBhY3R1YWwgc3RvcmUga2V5KS5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gZGVsZXRlU2Vzc2lvbldpdGhGYWxsYmFjayhcbiAgZ2F0ZXdheTogR2F0ZXdheUNsaWVudCxcbiAga2V5OiBzdHJpbmcsXG4gIGRlbGV0ZVRyYW5zY3JpcHQgPSB0cnVlXG4pOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ2F0ZXdheS5yZXF1ZXN0KFwic2Vzc2lvbnMuZGVsZXRlXCIsIHsga2V5LCBkZWxldGVUcmFuc2NyaXB0IH0pIGFzIHsgZGVsZXRlZD86IGJvb2xlYW4gfSB8IG51bGw7XG4gIGlmIChyZXN1bHQ/LmRlbGV0ZWQpIHJldHVybiB0cnVlO1xuXG4gIC8vIEZhbGxiYWNrOiBzdHJpcCBhZ2VudDo8aWQ+OiBwcmVmaXggYW5kIHJldHJ5IHdpdGggcmF3IGtleVxuICBjb25zdCBtYXRjaCA9IGtleS5tYXRjaCgvXmFnZW50OlteOl0rOiguKykkLyk7XG4gIGlmIChtYXRjaCkge1xuICAgIGNvbnN0IHJhd0tleSA9IG1hdGNoWzFdO1xuICAgIGNvbnN0IHJldHJ5ID0gYXdhaXQgZ2F0ZXdheS5yZXF1ZXN0KFwic2Vzc2lvbnMuZGVsZXRlXCIsIHsga2V5OiByYXdLZXksIGRlbGV0ZVRyYW5zY3JpcHQgfSkgYXMgeyBkZWxldGVkPzogYm9vbGVhbiB9IHwgbnVsbDtcbiAgICByZXR1cm4gISFyZXRyeT8uZGVsZXRlZDtcbiAgfVxuICByZXR1cm4gZmFsc2U7XG59XG5cbmNsYXNzIEdhdGV3YXlDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBwZW5kaW5nID0gbmV3IE1hcDxzdHJpbmcsIHsgcmVzb2x2ZTogKHY6IHVua25vd24pID0+IHZvaWQ7IHJlamVjdDogKGU6IEVycm9yKSA9PiB2b2lkIH0+KCk7XG4gIHByaXZhdGUgY2xvc2VkID0gZmFsc2U7XG4gIHByaXZhdGUgY29ubmVjdFNlbnQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGJhY2tvZmZNcyA9IDgwMDtcbiAgcHJpdmF0ZSBvcHRzOiBHYXRld2F5Q2xpZW50T3B0cztcbiAgcHJpdmF0ZSBjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcGVuZGluZ1RpbWVvdXRzID0gbmV3IE1hcDxzdHJpbmcsIFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+PigpO1xuXG4gIGNvbnN0cnVjdG9yKG9wdHM6IEdhdGV3YXlDbGllbnRPcHRzKSB7XG4gICAgdGhpcy5vcHRzID0gb3B0cztcbiAgfVxuXG4gIGdldCBjb25uZWN0ZWQoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMud3M/LnJlYWR5U3RhdGUgPT09IFdlYlNvY2tldC5PUEVOO1xuICB9XG5cbiAgc3RhcnQoKTogdm9pZCB7XG4gICAgdGhpcy5jbG9zZWQgPSBmYWxzZTtcbiAgICB0aGlzLmRvQ29ubmVjdCgpO1xuICB9XG5cbiAgc3RvcCgpOiB2b2lkIHtcbiAgICB0aGlzLmNsb3NlZCA9IHRydWU7XG4gICAgaWYgKHRoaXMuY29ubmVjdFRpbWVyICE9PSBudWxsKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5jb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5jb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IFssIHRdIG9mIHRoaXMucGVuZGluZ1RpbWVvdXRzKSBjbGVhclRpbWVvdXQodCk7XG4gICAgdGhpcy5wZW5kaW5nVGltZW91dHMuY2xlYXIoKTtcbiAgICB0aGlzLndzPy5jbG9zZSgpO1xuICAgIHRoaXMud3MgPSBudWxsO1xuICAgIHRoaXMuZmx1c2hQZW5kaW5nKG5ldyBFcnJvcihcImNsaWVudCBzdG9wcGVkXCIpKTtcbiAgfVxuXG4gIGFzeW5jIHJlcXVlc3QobWV0aG9kOiBzdHJpbmcsIHBhcmFtcz86IHVua25vd24pOiBQcm9taXNlPHVua25vd24+IHtcbiAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwibm90IGNvbm5lY3RlZFwiKTtcbiAgICB9XG4gICAgY29uc3QgaWQgPSBnZW5lcmF0ZUlkKCk7XG4gICAgY29uc3QgbXNnID0geyB0eXBlOiBcInJlcVwiLCBpZCwgbWV0aG9kLCBwYXJhbXMgfTtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5wZW5kaW5nLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG4gICAgICAvLyBUaW1lb3V0IHJlcXVlc3RzIGFmdGVyIDMwc1xuICAgICAgY29uc3QgdCA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5wZW5kaW5nLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmcuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKFwicmVxdWVzdCB0aW1lb3V0XCIpKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzAwMDApO1xuICAgICAgdGhpcy5wZW5kaW5nVGltZW91dHMuc2V0KGlkLCB0KTtcbiAgICAgIHRoaXMud3MhLnNlbmQoSlNPTi5zdHJpbmdpZnkobXNnKSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGRvQ29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5jbG9zZWQpIHJldHVybjtcblxuICAgIC8vIE5vcm1hbGl6ZSBhbmQgdmFsaWRhdGUgVVJMXG4gICAgY29uc3QgdXJsID0gbm9ybWFsaXplR2F0ZXdheVVybCh0aGlzLm9wdHMudXJsKTtcbiAgICBpZiAoIXVybCkge1xuICAgICAgY29uc29sZS5lcnJvcihcIltPYnNpZGlhbkNsYXddIEludmFsaWQgZ2F0ZXdheSBVUkw6IG11c3QgYmUgYSB2YWxpZCB3czovLywgd3NzOi8vLCBodHRwOi8vLCBvciBodHRwczovLyBVUkxcIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy53cyA9IG5ldyBXZWJTb2NrZXQodXJsKTtcbiAgICB0aGlzLndzLmFkZEV2ZW50TGlzdGVuZXIoXCJvcGVuXCIsICgpID0+IHRoaXMucXVldWVDb25uZWN0KCkpO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgKGUpID0+IHRoaXMuaGFuZGxlTWVzc2FnZShzdHIoZS5kYXRhKSkpO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcImNsb3NlXCIsIChlKSA9PiB7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICAgIHRoaXMuZmx1c2hQZW5kaW5nKG5ldyBFcnJvcihgY2xvc2VkICgke2UuY29kZX0pYCkpO1xuICAgICAgdGhpcy5vcHRzLm9uQ2xvc2U/Lih7IGNvZGU6IGUuY29kZSwgcmVhc29uOiBlLnJlYXNvbiB8fCBcIlwiIH0pO1xuICAgICAgdGhpcy5zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgIH0pO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcImVycm9yXCIsICgpID0+IHt9KTtcbiAgfVxuXG4gIHByaXZhdGUgc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuY2xvc2VkKSByZXR1cm47XG4gICAgY29uc3QgZGVsYXkgPSB0aGlzLmJhY2tvZmZNcztcbiAgICB0aGlzLmJhY2tvZmZNcyA9IE1hdGgubWluKHRoaXMuYmFja29mZk1zICogMS43LCAxNTAwMCk7XG4gICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmRvQ29ubmVjdCgpLCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGZsdXNoUGVuZGluZyhlcnI6IEVycm9yKTogdm9pZCB7XG4gICAgZm9yIChjb25zdCBbaWQsIHBdIG9mIHRoaXMucGVuZGluZykge1xuICAgICAgY29uc3QgdCA9IHRoaXMucGVuZGluZ1RpbWVvdXRzLmdldChpZCk7XG4gICAgICBpZiAodCkgY2xlYXJUaW1lb3V0KHQpO1xuICAgICAgcC5yZWplY3QoZXJyKTtcbiAgICB9XG4gICAgdGhpcy5wZW5kaW5nLmNsZWFyKCk7XG4gICAgdGhpcy5wZW5kaW5nVGltZW91dHMuY2xlYXIoKTtcbiAgfVxuXG4gIHByaXZhdGUgcXVldWVDb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuY29ubmVjdE5vbmNlID0gbnVsbDtcbiAgICB0aGlzLmNvbm5lY3RTZW50ID0gZmFsc2U7XG4gICAgaWYgKHRoaXMuY29ubmVjdFRpbWVyICE9PSBudWxsKSBjbGVhclRpbWVvdXQodGhpcy5jb25uZWN0VGltZXIpO1xuICAgIHRoaXMuY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB2b2lkIHRoaXMuc2VuZENvbm5lY3QoKSwgNzUwKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgc2VuZENvbm5lY3QoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuY29ubmVjdFNlbnQpIHJldHVybjtcbiAgICB0aGlzLmNvbm5lY3RTZW50ID0gdHJ1ZTtcbiAgICBpZiAodGhpcy5jb25uZWN0VGltZXIgIT09IG51bGwpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLmNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLmNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuXG4gICAgY29uc3QgQ0xJRU5UX0lEID0gXCJnYXRld2F5LWNsaWVudFwiO1xuICAgIGNvbnN0IENMSUVOVF9NT0RFID0gXCJ1aVwiO1xuICAgIGNvbnN0IFJPTEUgPSBcIm9wZXJhdG9yXCI7XG4gICAgY29uc3QgU0NPUEVTID0gW1wib3BlcmF0b3IuYWRtaW5cIiwgXCJvcGVyYXRvci53cml0ZVwiLCBcIm9wZXJhdG9yLnJlYWRcIl07XG5cbiAgICBjb25zdCBhdXRoID0gdGhpcy5vcHRzLnRva2VuID8geyB0b2tlbjogdGhpcy5vcHRzLnRva2VuIH0gOiB1bmRlZmluZWQ7XG5cbiAgICAvLyBCdWlsZCBkZXZpY2UgZmluZ2VycHJpbnQgaWYgaWRlbnRpdHkgaXMgYXZhaWxhYmxlXG4gICAgbGV0IGRldmljZTogeyBpZDogc3RyaW5nOyBwdWJsaWNLZXk6IHN0cmluZzsgc2lnbmF0dXJlOiBzdHJpbmc7IHNpZ25lZEF0OiBudW1iZXI7IG5vbmNlPzogc3RyaW5nIH0gfCB1bmRlZmluZWQgPSB1bmRlZmluZWQ7XG4gICAgY29uc3QgaWRlbnRpdHkgPSB0aGlzLm9wdHMuZGV2aWNlSWRlbnRpdHk7XG4gICAgaWYgKGlkZW50aXR5KSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3Qgbm9uY2UgPSB0aGlzLmNvbm5lY3ROb25jZSA/PyBudWxsO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGRTaWduYXR1cmVQYXlsb2FkKHtcbiAgICAgICAgICBkZXZpY2VJZDogaWRlbnRpdHkuZGV2aWNlSWQsXG4gICAgICAgICAgY2xpZW50SWQ6IENMSUVOVF9JRCxcbiAgICAgICAgICBjbGllbnRNb2RlOiBDTElFTlRfTU9ERSxcbiAgICAgICAgICByb2xlOiBST0xFLFxuICAgICAgICAgIHNjb3BlczogU0NPUEVTLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMub3B0cy50b2tlbiA/PyBudWxsLFxuICAgICAgICAgIG5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuICAgICAgICBkZXZpY2UgPSB7XG4gICAgICAgICAgaWQ6IGlkZW50aXR5LmRldmljZUlkLFxuICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgIHNpZ25hdHVyZSxcbiAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICBub25jZTogbm9uY2UgPz8gdW5kZWZpbmVkLFxuICAgICAgICB9O1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmVycm9yKFwiW09ic2lkaWFuQ2xhd10gRGV2aWNlIHNpZ25pbmcgZmFpbGVkOlwiLCBlKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBwYXJhbXMgPSB7XG4gICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgY2xpZW50OiB7XG4gICAgICAgIGlkOiBDTElFTlRfSUQsXG4gICAgICAgIHZlcnNpb246IFwiMC4xLjBcIixcbiAgICAgICAgcGxhdGZvcm06IFwib2JzaWRpYW5cIixcbiAgICAgICAgbW9kZTogQ0xJRU5UX01PREUsXG4gICAgICB9LFxuICAgICAgcm9sZTogUk9MRSxcbiAgICAgIHNjb3BlczogU0NPUEVTLFxuICAgICAgYXV0aCxcbiAgICAgIGRldmljZSxcbiAgICAgIGNhcHM6IFtcInRvb2wtZXZlbnRzXCJdLFxuICAgIH07XG5cbiAgICB2b2lkIHRoaXMucmVxdWVzdChcImNvbm5lY3RcIiwgcGFyYW1zKVxuICAgICAgLnRoZW4oKHBheWxvYWQpID0+IHtcbiAgICAgICAgdGhpcy5iYWNrb2ZmTXMgPSA4MDA7XG4gICAgICAgIHRoaXMub3B0cy5vbkhlbGxvPy4ocGF5bG9hZCBhcyBHYXRld2F5UGF5bG9hZCk7XG4gICAgICB9KVxuICAgICAgLmNhdGNoKCgpID0+IHtcbiAgICAgICAgdGhpcy53cz8uY2xvc2UoNDAwOCwgXCJjb25uZWN0IGZhaWxlZFwiKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBoYW5kbGVNZXNzYWdlKHJhdzogc3RyaW5nKTogdm9pZCB7XG4gICAgbGV0IG1zZzogR2F0ZXdheU1lc3NhZ2U7XG4gICAgdHJ5IHtcbiAgICAgIG1zZyA9IEpTT04ucGFyc2UocmF3KSBhcyBHYXRld2F5TWVzc2FnZTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAobXNnLnR5cGUgPT09IFwiZXZlbnRcIikge1xuICAgICAgaWYgKG1zZy5ldmVudCA9PT0gXCJjb25uZWN0LmNoYWxsZW5nZVwiKSB7XG4gICAgICAgIGNvbnN0IG5vbmNlID0gbXNnLnBheWxvYWQ/Lm5vbmNlO1xuICAgICAgICBpZiAodHlwZW9mIG5vbmNlID09PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgdGhpcy5jb25uZWN0Tm9uY2UgPSBub25jZTtcbiAgICAgICAgICB2b2lkIHRoaXMuc2VuZENvbm5lY3QoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICB0aGlzLm9wdHMub25FdmVudD8uKG1zZyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKG1zZy50eXBlID09PSBcInJlc1wiKSB7XG4gICAgICBjb25zdCBwID0gdGhpcy5wZW5kaW5nLmdldChtc2cuaWQpO1xuICAgICAgaWYgKCFwKSByZXR1cm47XG4gICAgICB0aGlzLnBlbmRpbmcuZGVsZXRlKG1zZy5pZCk7XG4gICAgICBjb25zdCB0ID0gdGhpcy5wZW5kaW5nVGltZW91dHMuZ2V0KG1zZy5pZCk7XG4gICAgICBpZiAodCkge1xuICAgICAgICBjbGVhclRpbWVvdXQodCk7XG4gICAgICAgIHRoaXMucGVuZGluZ1RpbWVvdXRzLmRlbGV0ZShtc2cuaWQpO1xuICAgICAgfVxuICAgICAgaWYgKG1zZy5vaykge1xuICAgICAgICBwLnJlc29sdmUobXNnLnBheWxvYWQpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcC5yZWplY3QobmV3IEVycm9yKG1zZy5lcnJvcj8ubWVzc2FnZSA/PyBcInJlcXVlc3QgZmFpbGVkXCIpKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENoYXQgTWVzc2FnZSBUeXBlcyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgcm9sZTogXCJ1c2VyXCIgfCBcImFzc2lzdGFudFwiO1xuICB0ZXh0OiBzdHJpbmc7XG4gIGltYWdlczogc3RyaW5nW107IC8vIGRhdGEgVVJJcyBvciBVUkxzXG4gIHRpbWVzdGFtcDogbnVtYmVyO1xuICBjb250ZW50QmxvY2tzPzogQ29udGVudEJsb2NrW107IC8vIHJhdyBjb250ZW50IGFycmF5IGZyb20gaGlzdG9yeSAocHJlc2VydmVzIHRvb2xfdXNlIGludGVybGVhdmluZylcbiAgdm9pY2VSZWZzPzogc3RyaW5nW107IC8vIFZPSUNFOmZpbGVuYW1lLmI2NCByZWZzIGZvciBhdWRpbyBwbGF5YmFjayB2aWEgZ2F0ZXdheVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgT25ib2FyZGluZyBNb2RhbCBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuY2xhc3MgT25ib2FyZGluZ01vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIHN0ZXAgPSAwO1xuICBwcml2YXRlIHBhdGg6IFwiZnJlc2hcIiB8IFwiZXhpc3RpbmdcIiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHN0YXR1c0VsOiBIVE1MRWxlbWVudCB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHBhaXJpbmdQb2xsVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuXG4gIC8vIFNldHVwIHN0YXRlIGZvciBmcmVzaCBpbnN0YWxsIHBhdGhcbiAgcHJpdmF0ZSBzZXR1cEtleXMgPSB7IGNsYXVkZTE6ICcnLCBjbGF1ZGUyOiAnJywgZ29vZ2xlYWk6ICcnLCBicmF2ZTogJycsIGVsZXZlbmxhYnM6ICcnIH07XG4gIHByaXZhdGUgc2V0dXBCb3RzOiB7IG5hbWU6IHN0cmluZzsgbW9kZWw6IHN0cmluZyB9W10gPSBbeyBuYW1lOiAnQXNzaXN0YW50JywgbW9kZWw6ICdhbnRocm9waWMvY2xhdWRlLXNvbm5ldC00LTYnIH1dO1xuXG4gIHByaXZhdGUgc3RhdGljIE1PREVMUyA9IFtcbiAgICB7IGlkOiAnYW50aHJvcGljL2NsYXVkZS1vcHVzLTQtNicsIGxhYmVsOiAnQ2xhdWRlIE9wdXMgNCcgfSxcbiAgICB7IGlkOiAnYW50aHJvcGljL2NsYXVkZS1zb25uZXQtNC02JywgbGFiZWw6ICdDbGF1ZGUgU29ubmV0IDQnIH0sXG4gICAgeyBpZDogJ2FudGhyb3BpYy9jbGF1ZGUtc29ubmV0LTQtNScsIGxhYmVsOiAnQ2xhdWRlIFNvbm5ldCA0LjUnIH0sXG4gICAgeyBpZDogJ2dvb2dsZS9nZW1pbmktMi41LXBybycsIGxhYmVsOiAnR2VtaW5pIDIuNSBQcm8nIH0sXG4gICAgeyBpZDogJ2dvb2dsZS9nZW1pbmktMi41LWZsYXNoJywgbGFiZWw6ICdHZW1pbmkgMi41IEZsYXNoJyB9LFxuICBdO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIG9uT3BlbigpOiB2b2lkIHtcbiAgICB0aGlzLm1vZGFsRWwuYWRkQ2xhc3MoXCJvcGVuY2xhdy1vbmJvYXJkaW5nXCIpO1xuICAgIHRoaXMucmVuZGVyU3RlcCgpO1xuICB9XG5cbiAgb25DbG9zZSgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5wYWlyaW5nUG9sbFRpbWVyKSB7IGNsZWFySW50ZXJ2YWwodGhpcy5wYWlyaW5nUG9sbFRpbWVyKTsgdGhpcy5wYWlyaW5nUG9sbFRpbWVyID0gbnVsbDsgfVxuICB9XG5cbiAgLyoqIFNhZmVseSByZW5kZXIgc2ltcGxlIEhUTUwgKHRleHQsIDxhPiwgPGNvZGU+LCA8c3Ryb25nPikgaW50byBhbiBlbGVtZW50IHVzaW5nIERPTSBBUEkgKi9cbiAgcHJpdmF0ZSBzZXRSaWNoVGV4dChlbDogSFRNTEVsZW1lbnQsIGh0bWw6IHN0cmluZyk6IHZvaWQge1xuICAgIGVsLmVtcHR5KCk7XG4gICAgY29uc3QgcGFyc2VyID0gbmV3IERPTVBhcnNlcigpO1xuICAgIGNvbnN0IGRvYyA9IHBhcnNlci5wYXJzZUZyb21TdHJpbmcoYDxzcGFuPiR7aHRtbH08L3NwYW4+YCwgXCJ0ZXh0L2h0bWxcIik7XG4gICAgY29uc3Qgc291cmNlID0gZG9jLmJvZHkuZmlyc3RFbGVtZW50Q2hpbGQ7XG4gICAgaWYgKCFzb3VyY2UpIHsgZWwuc2V0VGV4dChodG1sKTsgcmV0dXJuOyB9XG4gICAgZm9yIChjb25zdCBub2RlIG9mIEFycmF5LmZyb20oc291cmNlLmNoaWxkTm9kZXMpKSB7XG4gICAgICBpZiAobm9kZS5ub2RlVHlwZSA9PT0gTm9kZS5URVhUX05PREUpIHtcbiAgICAgICAgZWwuYXBwZW5kVGV4dChub2RlLnRleHRDb250ZW50ID8/IFwiXCIpO1xuICAgICAgfSBlbHNlIGlmIChub2RlIGluc3RhbmNlb2YgSFRNTEVsZW1lbnQpIHtcbiAgICAgICAgY29uc3QgdGFnID0gbm9kZS50YWdOYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgIGlmICh0YWcgPT09IFwiYVwiKSB7XG4gICAgICAgICAgZWwuY3JlYXRlRWwoXCJhXCIsIHsgdGV4dDogbm9kZS50ZXh0Q29udGVudCA/PyBcIlwiLCBocmVmOiBub2RlLmdldEF0dHJpYnV0ZShcImhyZWZcIikgPz8gXCJcIiB9KTtcbiAgICAgICAgfSBlbHNlIGlmICh0YWcgPT09IFwiY29kZVwiKSB7XG4gICAgICAgICAgZWwuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogbm9kZS50ZXh0Q29udGVudCA/PyBcIlwiIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHRhZyA9PT0gXCJzdHJvbmdcIikge1xuICAgICAgICAgIGVsLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogbm9kZS50ZXh0Q29udGVudCA/PyBcIlwiIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGVsLmFwcGVuZFRleHQobm9kZS50ZXh0Q29udGVudCA/PyBcIlwiKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgcmVuZGVyU3RlcCgpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuZW1wdHkoKTtcbiAgICB0aGlzLnN0YXR1c0VsID0gbnVsbDtcblxuICAgIC8vIFN0ZXAgaW5kaWNhdG9yIFx1MjAxNCBhZGFwdHMgdG8gcGF0aFxuICAgIGNvbnN0IHN0ZXBMYWJlbHMgPSB0aGlzLnBhdGggPT09IFwiZnJlc2hcIlxuICAgICAgPyBbXCJTdGFydFwiLCBcIktleXNcIiwgXCJCb3RzXCIsIFwiSW5zdGFsbFwiLCBcIkNvbm5lY3RcIiwgXCJQYWlyXCIsIFwiRG9uZVwiXVxuICAgICAgOiB0aGlzLnBhdGggPT09IFwiZXhpc3RpbmdcIlxuICAgICAgICA/IFtcIlN0YXJ0XCIsIFwiTmV0d29ya1wiLCBcIkdhdGV3YXlcIiwgXCJDb25uZWN0XCIsIFwiUGFpclwiLCBcIkRvbmVcIl1cbiAgICAgICAgOiBbXCJTdGFydFwiXTtcbiAgICBjb25zdCBpbmRpY2F0b3IgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1zdGVwc1wiKTtcbiAgICBzdGVwTGFiZWxzLmZvckVhY2goKGxhYmVsLCBpKSA9PiB7XG4gICAgICBjb25zdCBkb3QgPSBpbmRpY2F0b3IuY3JlYXRlU3BhbihcIm9wZW5jbGF3LXN0ZXAtZG90XCIgKyAoaSA9PT0gdGhpcy5zdGVwID8gXCIgYWN0aXZlXCIgOiBpIDwgdGhpcy5zdGVwID8gXCIgZG9uZVwiIDogXCJcIikpO1xuICAgICAgZG90LnRleHRDb250ZW50ID0gaSA8IHRoaXMuc3RlcCA/IFwiXHUyNzEzXCIgOiBTdHJpbmcoaSArIDEpO1xuICAgICAgaWYgKGkgPCBzdGVwTGFiZWxzLmxlbmd0aCAtIDEpIGluZGljYXRvci5jcmVhdGVTcGFuKFwib3BlbmNsYXctc3RlcC1saW5lXCIgKyAoaSA8IHRoaXMuc3RlcCA/IFwiIGRvbmVcIiA6IFwiXCIpKTtcbiAgICB9KTtcblxuICAgIC8vIFJvdXRlIHRvIGNvcnJlY3Qgc3RlcCByZW5kZXJlclxuICAgIGlmICh0aGlzLnN0ZXAgPT09IDApIHJldHVybiB0aGlzLnJlbmRlcldlbGNvbWUoY29udGVudEVsKTtcblxuICAgIGlmICh0aGlzLnBhdGggPT09IFwiZnJlc2hcIikge1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gMSkgcmV0dXJuIHRoaXMucmVuZGVyS2V5cyhjb250ZW50RWwpO1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gMikgcmV0dXJuIHRoaXMucmVuZGVyQm90cyhjb250ZW50RWwpO1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gMykgcmV0dXJuIHRoaXMucmVuZGVySW5zdGFsbENtZChjb250ZW50RWwpO1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gNCkgcmV0dXJuIHRoaXMucmVuZGVyQ29ubmVjdChjb250ZW50RWwpO1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gNSkgcmV0dXJuIHRoaXMucmVuZGVyUGFpcmluZyhjb250ZW50RWwpO1xuICAgICAgaWYgKHRoaXMuc3RlcCA9PT0gNikgcmV0dXJuIHRoaXMucmVuZGVyRG9uZShjb250ZW50RWwpO1xuICAgIH0gZWxzZSB7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAxKSByZXR1cm4gdGhpcy5yZW5kZXJOZXR3b3JrKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAyKSByZXR1cm4gdGhpcy5yZW5kZXJHYXRld2F5KGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAzKSByZXR1cm4gdGhpcy5yZW5kZXJDb25uZWN0KGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSA0KSByZXR1cm4gdGhpcy5yZW5kZXJQYWlyaW5nKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSA1KSByZXR1cm4gdGhpcy5yZW5kZXJEb25lKGNvbnRlbnRFbCk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFN0ZXAgMDogV2VsY29tZSAoYnJhbmNoaW5nKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlcldlbGNvbWUoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiV2VsY29tZSB0byBPcGVuQ2xhd1wiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIlRoaXMgcGx1Z2luIGNvbm5lY3RzIE9ic2lkaWFuIHRvIHlvdXIgT3BlbkNsYXcgQUkgYWdlbnQuIFlvdXIgdmF1bHQgYmVjb21lcyB0aGUgYWdlbnQncyB3b3Jrc3BhY2UuXCIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnMgb3BlbmNsYXctb25ib2FyZC1idXR0b25zLXZlcnRpY2FsXCIpO1xuXG4gICAgY29uc3QgZnJlc2hCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkkgbmVlZCB0byBpbnN0YWxsIE9wZW5DbGF3XCIsIGNsczogXCJtb2QtY3RhIG9wZW5jbGF3LWZ1bGwtd2lkdGhcIiB9KTtcbiAgICBmcmVzaEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnBhdGggPSBcImZyZXNoXCI7IHRoaXMuc3RlcCA9IDE7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcblxuICAgIGNvbnN0IGV4aXN0QnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJPcGVuQ2xhdyBpcyBhbHJlYWR5IHJ1bm5pbmdcIiwgY2xzOiBcIm9wZW5jbGF3LWZ1bGwtd2lkdGhcIiB9KTtcbiAgICBleGlzdEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnBhdGggPSBcImV4aXN0aW5nXCI7IHRoaXMuc3RlcCA9IDE7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBGcmVzaCBwYXRoOiBTdGVwIDEgXHUyMDE0IEFQSSBLZXlzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVyS2V5cyhlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJZb3VyIEFQSSBrZXlzXCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiWW91ciBib3QgbmVlZHMgQUkgbW9kZWwgYWNjZXNzLiBQYXN0ZSB5b3VyIGtleXMgYmVsb3cgXHUyMDE0IHRoZXknbGwgYmUgaW5jbHVkZWQgaW4gdGhlIGluc3RhbGwgY29tbWFuZC4gTm90aGluZyBsZWF2ZXMgeW91ciBkZXZpY2UuXCIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBmaWVsZHM6IHsga2V5OiBrZXlvZiB0eXBlb2YgdGhpcy5zZXR1cEtleXM7IGxhYmVsOiBzdHJpbmc7IHJlcXVpcmVkPzogYm9vbGVhbjsgcGxhY2Vob2xkZXI6IHN0cmluZzsgaGVscDogc3RyaW5nIH1bXSA9IFtcbiAgICAgIHsga2V5OiBcImNsYXVkZTFcIiwgbGFiZWw6IFwiQ2xhdWRlIHRva2VuXCIsIHJlcXVpcmVkOiB0cnVlLCBwbGFjZWhvbGRlcjogXCJzay1hbnQtLi4uXCIsIGhlbHA6IFwiRnJvbSA8YSBocmVmPSdodHRwczovL2NvbnNvbGUuYW50aHJvcGljLmNvbS9zZXR0aW5ncy9rZXlzJz5jb25zb2xlLmFudGhyb3BpYy5jb208L2E+IG9yIENsYXVkZSBNYXggT0F1dGhcIiB9LFxuICAgICAgeyBrZXk6IFwiY2xhdWRlMlwiLCBsYWJlbDogXCJDbGF1ZGUgdG9rZW4gIzIgKHBhcmFsbGVsIHJlcXVlc3RzKVwiLCBwbGFjZWhvbGRlcjogXCJzay1hbnQtLi4uXCIsIGhlbHA6IFwiT3B0aW9uYWwgXHUyMDE0IGVuYWJsZXMgY29uY3VycmVudCByZXF1ZXN0c1wiIH0sXG4gICAgICB7IGtleTogXCJnb29nbGVhaVwiLCBsYWJlbDogXCJHb29nbGUgQUkgQVBJIGtleVwiLCBwbGFjZWhvbGRlcjogXCJBSXphLi4uXCIsIGhlbHA6IFwiRnJlZSBhdCA8YSBocmVmPSdodHRwczovL2Fpc3R1ZGlvLmdvb2dsZS5jb20vYXBpa2V5Jz5haXN0dWRpby5nb29nbGUuY29tPC9hPiBcdTIwMTQgZW5hYmxlcyBHZW1pbmkgbW9kZWxzXCIgfSxcbiAgICAgIHsga2V5OiBcImJyYXZlXCIsIGxhYmVsOiBcIkJyYXZlIFNlYXJjaCBBUEkga2V5XCIsIHBsYWNlaG9sZGVyOiBcIkJTQS4uLlwiLCBoZWxwOiBcIkZyZWUgYXQgPGEgaHJlZj0naHR0cHM6Ly9icmF2ZS5jb20vc2VhcmNoL2FwaS8nPmJyYXZlLmNvbS9zZWFyY2gvYXBpPC9hPiBcdTIwMTQgd2ViIHNlYXJjaFwiIH0sXG4gICAgICB7IGtleTogXCJlbGV2ZW5sYWJzXCIsIGxhYmVsOiBcIkVsZXZlbkxhYnMgQVBJIGtleVwiLCBwbGFjZWhvbGRlcjogXCJza18uLi5cIiwgaGVscDogXCJGcmVlIGF0IDxhIGhyZWY9J2h0dHBzOi8vZWxldmVubGFicy5pbyc+ZWxldmVubGFicy5pbzwvYT4gXHUyMDE0IHZvaWNlL1RUU1wiIH0sXG4gICAgXTtcblxuICAgIGZvciAoY29uc3QgZiBvZiBmaWVsZHMpIHtcbiAgICAgIGNvbnN0IGdyb3VwID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1maWVsZFwiKTtcbiAgICAgIGNvbnN0IGxhYmVsID0gZ3JvdXAuY3JlYXRlRWwoXCJsYWJlbFwiLCB7IHRleHQ6IGYubGFiZWwgfSk7XG4gICAgICBpZiAoZi5yZXF1aXJlZCkgeyBjb25zdCByZXEgPSBsYWJlbC5jcmVhdGVTcGFuKHsgY2xzOiBcIm9jLXJlcS1sYWJlbFwiIH0pOyByZXEudGV4dENvbnRlbnQgPSBcIiAocmVxdWlyZWQpXCI7IH1cbiAgICAgIGNvbnN0IGlucHV0ID0gZ3JvdXAuY3JlYXRlRWwoXCJpbnB1dFwiLCB7XG4gICAgICAgIHR5cGU6IFwicGFzc3dvcmRcIixcbiAgICAgICAgdmFsdWU6IHRoaXMuc2V0dXBLZXlzW2Yua2V5XSxcbiAgICAgICAgcGxhY2Vob2xkZXI6IGYucGxhY2Vob2xkZXIsXG4gICAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWlucHV0XCIsXG4gICAgICB9KTtcbiAgICAgIGlucHV0LmFkZEV2ZW50TGlzdGVuZXIoXCJpbnB1dFwiLCAoKSA9PiB7IHRoaXMuc2V0dXBLZXlzW2Yua2V5XSA9IGlucHV0LnZhbHVlLnRyaW0oKTsgfSk7XG4gICAgICBjb25zdCBoZWxwID0gZ3JvdXAuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIpO1xuICAgICAgdGhpcy5zZXRSaWNoVGV4dChoZWxwLCBmLmhlbHApO1xuICAgIH1cblxuICAgIGNvbnN0IG5vdGUgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWluZm9cIik7XG4gICAgbm90ZS5zZXRUZXh0KFwiXHVEODNEXHVERDEyIEtleXMgc3RheSBvbiB5b3VyIGRldmljZS4gVGhlIGluc3RhbGwgY29tbWFuZCBydW5zIGVudGlyZWx5IG9uIHlvdXIgc2VydmVyLlwiKTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMDsgdGhpcy5wYXRoID0gbnVsbDsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIk5leHQgXHUyMTkyXCIsIGNsczogXCJtb2QtY3RhXCIgfSk7XG4gICAgbmV4dEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLnNldHVwS2V5cy5jbGF1ZGUxKSB7IHRoaXMuc2hvd1N0YXR1cyhcIkNsYXVkZSB0b2tlbiBpcyByZXF1aXJlZFwiLCBcImVycm9yXCIpOyByZXR1cm47IH1cbiAgICAgIHRoaXMuc3RlcCA9IDI7IHRoaXMucmVuZGVyU3RlcCgpO1xuICAgIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEZyZXNoIHBhdGg6IFN0ZXAgMiBcdTIwMTQgQm90IGNvbmZpZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlckJvdHMoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiQ29uZmlndXJlIHlvdXIgYm90c1wiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIkVhY2ggYm90IGdldHMgaXRzIG93biBwZXJzb25hbGl0eSwgbWVtb3J5LCBhbmQgd29ya3NwYWNlIGZvbGRlci5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGxpc3RFbCA9IGVsLmNyZWF0ZURpdigpO1xuICAgIHRoaXMuc2V0dXBCb3RzLmZvckVhY2goKGJvdCwgaSkgPT4ge1xuICAgICAgY29uc3QgY2FyZCA9IGxpc3RFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJvdC1jYXJkXCIpO1xuICAgICAgY29uc3Qgcm93ID0gY2FyZC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJvdC1yb3dcIik7XG4gICAgICBjb25zdCBuYW1lSW5wdXQgPSByb3cuY3JlYXRlRWwoXCJpbnB1dFwiLCB7IHR5cGU6IFwidGV4dFwiLCB2YWx1ZTogYm90Lm5hbWUsIHBsYWNlaG9sZGVyOiBcIkJvdCBuYW1lXCIsIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWlucHV0IG9jLW5hbWUtaW5wdXRcIiB9KTtcbiAgICAgIG5hbWVJbnB1dC5hZGRFdmVudExpc3RlbmVyKFwiaW5wdXRcIiwgKCkgPT4geyBib3QubmFtZSA9IG5hbWVJbnB1dC52YWx1ZTsgfSk7XG5cbiAgICAgIGNvbnN0IHNlbGVjdCA9IHJvdy5jcmVhdGVFbChcInNlbGVjdFwiLCB7IGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWlucHV0IG9jLXNlbGVjdC1pbmxpbmVcIiB9KTtcbiAgICAgIGZvciAoY29uc3QgbSBvZiBPbmJvYXJkaW5nTW9kYWwuTU9ERUxTKSB7XG4gICAgICAgIGNvbnN0IG9wdCA9IHNlbGVjdC5jcmVhdGVFbChcIm9wdGlvblwiLCB7IHRleHQ6IG0ubGFiZWwsIHZhbHVlOiBtLmlkIH0pO1xuICAgICAgICBpZiAobS5pZCA9PT0gYm90Lm1vZGVsKSBvcHQuc2VsZWN0ZWQgPSB0cnVlO1xuICAgICAgfVxuICAgICAgc2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoXCJjaGFuZ2VcIiwgKCkgPT4geyBib3QubW9kZWwgPSBzZWxlY3QudmFsdWU7IH0pO1xuXG4gICAgICBpZiAodGhpcy5zZXR1cEJvdHMubGVuZ3RoID4gMSkge1xuICAgICAgICBjb25zdCByZW1vdmVCdG4gPSByb3cuY3JlYXRlRWwoXCJzcGFuXCIsIHsgdGV4dDogXCJcdTAwRDdcIiwgY2xzOiBcIm9jLXJlbW92ZS1idG5cIiB9KTtcbiAgICAgICAgcmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc2V0dXBCb3RzLnNwbGljZShpLCAxKTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgY29uc3QgYWRkQnRuID0gZWwuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIisgYWRkIGFub3RoZXIgYm90XCIsIGNsczogXCJvYy1hZGQtYm90LWJ0blwiIH0pO1xuICAgIGFkZEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnNldHVwQm90cy5wdXNoKHsgbmFtZTogJycsIG1vZGVsOiAnYW50aHJvcGljL2NsYXVkZS1zb25uZXQtNC02JyB9KTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuXG4gICAgY29uc3Qgbm90ZSA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaGludCBvYy1tYXJnaW4tdG9wXCIpO1xuICAgIG5vdGUuY3JlYXRlRWwoXCJzcGFuXCIsIHsgdGV4dDogXCJFYWNoIGJvdCBnZXRzIGEgZm9sZGVyIGxpa2UgXCIgfSk7XG4gICAgbm90ZS5jcmVhdGVFbChcImNvZGVcIiwgeyB0ZXh0OiBcIkFHRU5ULVlPVVJCT1QvXCIgfSk7XG4gICAgbm90ZS5jcmVhdGVFbChcInNwYW5cIiwgeyB0ZXh0OiBcIiBpbiB5b3VyIHZhdWx0LlwiIH0pO1xuXG4gICAgdGhpcy5zdGF0dXNFbCA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtc3RhdHVzXCIpO1xuXG4gICAgY29uc3QgYnRuUm93ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1idXR0b25zXCIpO1xuICAgIGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiXHUyMTkwIGJhY2tcIiB9KS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnN0ZXAgPSAxOyB0aGlzLnJlbmRlclN0ZXAoKTsgfSk7XG4gICAgY29uc3QgbmV4dEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiR2VuZXJhdGUgaW5zdGFsbCBjb21tYW5kIFx1MjE5MlwiLCBjbHM6IFwibW9kLWN0YVwiIH0pO1xuICAgIG5leHRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMzsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEZyZXNoIHBhdGg6IFN0ZXAgMyBcdTIwMTQgSW5zdGFsbCBjb21tYW5kIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVySW5zdGFsbENtZChlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJJbnN0YWxsIE9wZW5DbGF3XCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiT3BlbiBhIHRlcm1pbmFsIG9uIHlvdXIgc2VydmVyIChNYWM6IENtZCtTcGFjZSBcdTIxOTIgVGVybWluYWwsIGNsb3VkOiBzc2ggaW4pLiBSdW4gdGhpcyBjb21tYW5kOlwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtZGVzY1wiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgY29uZmlnID0gdGhpcy5nZW5lcmF0ZUNvbmZpZygpO1xuICAgIGNvbnN0IGNvbmZpZ0pzb24gPSBKU09OLnN0cmluZ2lmeShjb25maWcsIG51bGwsIDIpO1xuICAgIGNvbnN0IGNvbmZpZ0I2NCA9IGJ0b2EoQXJyYXkuZnJvbShuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoY29uZmlnSnNvbiksIGIgPT4gU3RyaW5nLmZyb21DaGFyQ29kZShiKSkuam9pbignJykpO1xuICAgIGNvbnN0IGluc3RhbGxDbWQgPSBgY3VybCAtZnNTTCBodHRwczovL29wZW5jbGF3LmFpL2luc3RhbGwuc2ggfCBiYXNoICYmIGVjaG8gJyR7Y29uZmlnQjY0fScgfCBiYXNlNjQgLWQgPiB+Ly5vcGVuY2xhdy9vcGVuY2xhdy5qc29uICYmIG9wZW5jbGF3IGdhdGV3YXkgcmVzdGFydGA7XG5cbiAgICB0aGlzLm1ha2VDb3B5Qm94KGVsLCBpbnN0YWxsQ21kKTtcblxuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVGhpcyBpbnN0YWxscyBPcGVuQ2xhdywgd3JpdGVzIHlvdXIgY29uZmlnIHdpdGggYWxsIEFQSSBrZXlzIGFuZCBib3Qgc2V0dGluZ3MsIGNvbmZpZ3VyZXMgVGFpbHNjYWxlIFNlcnZlLCBhbmQgc3RhcnRzIHRoZSBnYXRld2F5LlwiLCBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIgfSk7XG5cbiAgICAvLyBFeHBhbmRhYmxlIGNvbmZpZyBwcmV2aWV3XG4gICAgY29uc3QgZGV0YWlscyA9IGVsLmNyZWF0ZUVsKFwiZGV0YWlsc1wiLCB7IGNsczogXCJvYy1tYXJnaW4tdG9wXCIgfSk7XG4gICAgZGV0YWlscy5jcmVhdGVFbChcInN1bW1hcnlcIiwgeyB0ZXh0OiBcIlByZXZpZXcgY29uZmlnXCIsIGNsczogXCJvYy1kZXRhaWxzLXN1bW1hcnlcIiB9KTtcbiAgICBjb25zdCBwcmUgPSBkZXRhaWxzLmNyZWF0ZUVsKFwicHJlXCIsIHsgY2xzOiBcIm9jLWluc3RhbGwtcHJlXCIgfSk7XG4gICAgcHJlLnRleHRDb250ZW50ID0gSlNPTi5zdHJpbmdpZnkoY29uZmlnLCBudWxsLCAyKTtcblxuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiQWZ0ZXIgaXQgZmluaXNoZXMsIGluc3RhbGwgVGFpbHNjYWxlIGlmIHlvdSBoYXZlbid0OlwiLCBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIgfSk7XG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgXCIjIE1hYzpcXG5icmV3IGluc3RhbGwgLS1jYXNrIHRhaWxzY2FsZVxcblxcbiMgTGludXg6XFxuY3VybCAtZnNTTCBodHRwczovL3RhaWxzY2FsZS5jb20vaW5zdGFsbC5zaCB8IHNoICYmIHN1ZG8gdGFpbHNjYWxlIHVwXCIpO1xuXG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHsgdGV4dDogXCJUaGVuIGluc3RhbGwgVGFpbHNjYWxlIG9uIHRoaXMgZGV2aWNlIHRvbywgdXNpbmcgdGhlIHNhbWUgYWNjb3VudC5cIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuXG4gICAgdGhpcy5zdGF0dXNFbCA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtc3RhdHVzXCIpO1xuXG4gICAgY29uc3QgYnRuUm93ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1idXR0b25zXCIpO1xuICAgIGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiXHUyMTkwIGJhY2tcIiB9KS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnN0ZXAgPSAyOyB0aGlzLnJlbmRlclN0ZXAoKTsgfSk7XG4gICAgY29uc3QgbmV4dEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiT3BlbkNsYXcgaXMgcnVubmluZyBcdTIxOTJcIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICBuZXh0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDQ7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIHByaXZhdGUgZ2VuZXJhdGVDb25maWcoKTogUmVjb3JkPHN0cmluZywgdW5rbm93bj4ge1xuICAgIGNvbnN0IGNvbmZpZzogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gPSB7XG4gICAgICBhdXRoOiB7IHByb2ZpbGVzOiB7fSB9LFxuICAgICAgYWdlbnRzOiB7IGRlZmF1bHRzOiB7IG1vZGVsOiB7IHByaW1hcnk6IHRoaXMuc2V0dXBCb3RzWzBdPy5tb2RlbCB8fCAnYW50aHJvcGljL2NsYXVkZS1zb25uZXQtNC02JyB9IH0gfSxcbiAgICAgIGdhdGV3YXk6IHsgcG9ydDogMTg3ODksIGJpbmQ6ICdsb29wYmFjaycsIHRhaWxzY2FsZTogeyBtb2RlOiAnc2VydmUnIH0sIGF1dGg6IHsgbW9kZTogJ3Rva2VuJywgYWxsb3dUYWlsc2NhbGU6IHRydWUgfSB9LFxuICAgIH07XG4gICAgaWYgKHRoaXMuc2V0dXBLZXlzLmNsYXVkZTEpIGNvbmZpZy5hdXRoLnByb2ZpbGVzWydhbnRocm9waWM6ZGVmYXVsdCddID0geyBwcm92aWRlcjogJ2FudGhyb3BpYycsIG1vZGU6ICd0b2tlbicgfTtcbiAgICBpZiAodGhpcy5zZXR1cEtleXMuY2xhdWRlMikgY29uZmlnLmF1dGgucHJvZmlsZXNbJ2FudGhyb3BpYzpzZWNvbmRhcnknXSA9IHsgcHJvdmlkZXI6ICdhbnRocm9waWMnLCBtb2RlOiAndG9rZW4nIH07XG4gICAgaWYgKHRoaXMuc2V0dXBLZXlzLmdvb2dsZWFpKSBjb25maWcuYXV0aC5wcm9maWxlc1snZ29vZ2xlOmRlZmF1bHQnXSA9IHsgcHJvdmlkZXI6ICdnb29nbGUnLCBtb2RlOiAnYXBpX2tleScgfTtcbiAgICBpZiAodGhpcy5zZXR1cEtleXMuYnJhdmUpIGNvbmZpZy50b29scyA9IHsgd2ViOiB7IHNlYXJjaDogeyBhcGlLZXk6IHRoaXMuc2V0dXBLZXlzLmJyYXZlIH0gfSB9O1xuICAgIGlmICh0aGlzLnNldHVwS2V5cy5lbGV2ZW5sYWJzKSBjb25maWcubWVzc2FnZXMgPSB7IHR0czogeyBwcm92aWRlcjogJ2VsZXZlbmxhYnMnLCBlbGV2ZW5sYWJzOiB7IGFwaUtleTogdGhpcy5zZXR1cEtleXMuZWxldmVubGFicyB9IH0gfTtcbiAgICBpZiAodGhpcy5zZXR1cEJvdHMubGVuZ3RoID4gMSkge1xuICAgICAgY29uZmlnLmFnZW50cy5saXN0ID0gdGhpcy5zZXR1cEJvdHMubWFwKChib3QsIGkpID0+IHtcbiAgICAgICAgY29uc3QgaWQgPSBpID09PSAwID8gJ21haW4nIDogKGJvdC5uYW1lLnRvTG93ZXJDYXNlKCkucmVwbGFjZSgvW15hLXowLTldL2csICctJykgfHwgYGJvdC0ke2l9YCk7XG4gICAgICAgIGNvbnN0IGZvbGRlciA9ICdBR0VOVC0nICsgKGJvdC5uYW1lIHx8ICdCT1QnKS50b1VwcGVyQ2FzZSgpLnJlcGxhY2UoL1teQS1aMC05XS9nLCAnLScpO1xuICAgICAgICByZXR1cm4geyBpZCwgbmFtZTogYm90Lm5hbWUgfHwgYEJvdCAke2kgKyAxfWAsIHdvcmtzcGFjZTogYH4vLm9wZW5jbGF3L3dvcmtzcGFjZS8ke2ZvbGRlcn1gIH07XG4gICAgICB9KTtcbiAgICB9IGVsc2UgaWYgKHRoaXMuc2V0dXBCb3RzWzBdPy5uYW1lKSB7XG4gICAgICBjb25zdCBmb2xkZXIgPSAnQUdFTlQtJyArIHRoaXMuc2V0dXBCb3RzWzBdLm5hbWUudG9VcHBlckNhc2UoKS5yZXBsYWNlKC9bXkEtWjAtOV0vZywgJy0nKTtcbiAgICAgIGNvbmZpZy5hZ2VudHMuZGVmYXVsdHMud29ya3NwYWNlID0gYH4vLm9wZW5jbGF3L3dvcmtzcGFjZS8ke2ZvbGRlcn1gO1xuICAgIH1cbiAgICByZXR1cm4gY29uZmlnO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEV4aXN0aW5nIHBhdGg6IFN0ZXAgMSBcdTIwMTQgTmV0d29yayAoVGFpbHNjYWxlKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlck5ldHdvcmsoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiU2V0IHVwIHlvdXIgcHJpdmF0ZSBuZXR3b3JrXCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiVGFpbHNjYWxlIGNyZWF0ZXMgYW4gZW5jcnlwdGVkIHByaXZhdGUgbmV0d29yayBiZXR3ZWVuIHlvdXIgZGV2aWNlcy4gTm8gcG9ydHMgdG8gb3Blbiwgbm8gVlBOIHRvIGNvbmZpZ3VyZS5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGVsLmNyZWF0ZUVsKFwiaDNcIiwgeyB0ZXh0OiBcIkluc3RhbGwgVGFpbHNjYWxlIG9uIGJvdGggZGV2aWNlc1wiIH0pO1xuXG4gICAgY29uc3Qgc3RlcHMgPSBlbC5jcmVhdGVFbChcIm9sXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtbGlzdFwiIH0pO1xuICAgIGNvbnN0IHMxID0gc3RlcHMuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBzMS5hcHBlbmRUZXh0KFwiSW5zdGFsbCBvbiB5b3VyIFwiKTtcbiAgICBzMS5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiZ2F0ZXdheSBtYWNoaW5lXCIgfSk7XG4gICAgczEuYXBwZW5kVGV4dChcIjogXCIpO1xuICAgIHMxLmNyZWF0ZUVsKFwiYVwiLCB7IHRleHQ6IFwidGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiLCBocmVmOiBcImh0dHBzOi8vdGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiIH0pO1xuICAgIGNvbnN0IHMyID0gc3RlcHMuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBzMi5hcHBlbmRUZXh0KFwiSW5zdGFsbCBvbiBcIik7XG4gICAgczIuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcInRoaXMgZGV2aWNlXCIgfSk7XG4gICAgczIuYXBwZW5kVGV4dChcIjogXCIpO1xuICAgIHMyLmNyZWF0ZUVsKFwiYVwiLCB7IHRleHQ6IFwidGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiLCBocmVmOiBcImh0dHBzOi8vdGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiIH0pO1xuICAgIHN0ZXBzLmNyZWF0ZUVsKFwibGlcIiwgeyB0ZXh0OiBcIlNpZ24gaW4gdG8gdGhlIHNhbWUgVGFpbHNjYWxlIGFjY291bnQgb24gYm90aC5cIiB9KTtcblxuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVmVyaWZ5IGJ5IHJ1bm5pbmcgdGhpcyBvbiB0aGUgZ2F0ZXdheTpcIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goZWwsIFwidGFpbHNjYWxlIHN0YXR1c1wiKTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMDsgdGhpcy5wYXRoID0gbnVsbDsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkJvdGggb24gVGFpbHNjYWxlIFx1MjE5MlwiLCBjbHM6IFwibW9kLWN0YVwiIH0pO1xuICAgIG5leHRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMjsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEV4aXN0aW5nIHBhdGg6IFN0ZXAgMiBcdTIwMTQgR2F0ZXdheSAoVGFpbHNjYWxlIFNlcnZlKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlckdhdGV3YXkoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiRXhwb3NlIHlvdXIgZ2F0ZXdheVwiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIlRhaWxzY2FsZSBTZXJ2ZSBnaXZlcyB5b3VyIGdhdGV3YXkgYSBwcml2YXRlIEhUVFBTIGFkZHJlc3MuIFJ1biBvbiB0aGUgZ2F0ZXdheSBtYWNoaW5lOlwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtZGVzY1wiLFxuICAgIH0pO1xuXG4gICAgZWwuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIjEuIENvbmZpZ3VyZSBPcGVuQ2xhd1wiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goZWwsIFwib3BlbmNsYXcgY29uZmlnIHNldCBnYXRld2F5LmJpbmQgbG9vcGJhY2tcXG5vcGVuY2xhdyBjb25maWcgc2V0IGdhdGV3YXkudGFpbHNjYWxlLm1vZGUgc2VydmVcXG5vcGVuY2xhdyBnYXRld2F5IHJlc3RhcnRcIik7XG5cbiAgICBlbC5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiMi4gU3RhcnQgVGFpbHNjYWxlIHNlcnZlXCIgfSk7XG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgXCJ0YWlsc2NhbGUgc2VydmUgLS1iZyBodHRwOi8vMTI3LjAuMC4xOjE4Nzg5XCIpO1xuXG4gICAgZWwuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIjMuIEdldCB5b3VyIFVSTCBhbmQgdG9rZW5cIiB9KTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KGVsLCBcInRhaWxzY2FsZSBzZXJ2ZSBzdGF0dXNcIik7XG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgXCJjYXQgfi8ub3BlbmNsYXcvb3BlbmNsYXcuanNvbiB8IGdyZXAgdG9rZW5cIik7XG5cbiAgICBjb25zdCBoaW50ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIpO1xuICAgIGhpbnQuYXBwZW5kVGV4dChcIkNvcHkgdGhlIFwiKTtcbiAgICBoaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiaHR0cHM6Ly95b3VyLW1hY2hpbmUudGFpbFhYWFgudHMubmV0XCIgfSk7XG4gICAgaGludC5hcHBlbmRUZXh0KFwiIFVSTCBhbmQgdGhlIGF1dGggdG9rZW4gZm9yIHRoZSBuZXh0IHN0ZXAuXCIpO1xuXG4gICAgY29uc3QgdHJvdWJsZSA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaW5mb1wiKTtcbiAgICB0cm91YmxlLmFwcGVuZFRleHQoXCJcdUQ4M0RcdURDQTEgXCIpO1xuICAgIHRyb3VibGUuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIk5vdCB3b3JraW5nP1wiIH0pO1xuICAgIHRyb3VibGUuYXBwZW5kVGV4dChcIiBSdW46IFwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGUsIFwib3BlbmNsYXcgZG9jdG9yIC0tZml4ICYmIG9wZW5jbGF3IGdhdGV3YXkgcmVzdGFydFwiKTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkkgaGF2ZSB0aGUgVVJMIGFuZCB0b2tlbiBcdTIxOTJcIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICBuZXh0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDM7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTdGVwIDM6IENvbm5lY3QgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSByZW5kZXJDb25uZWN0KGVsOiBIVE1MRWxlbWVudCk6IHZvaWQge1xuICAgIGVsLmNyZWF0ZUVsKFwiaDJcIiwgeyB0ZXh0OiBcIkNvbm5lY3QgdG8geW91ciBnYXRld2F5XCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiUGFzdGUgdGhlIFVSTCBhbmQgdG9rZW4gZnJvbSB0aGUgcHJldmlvdXMgc3RlcC5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIC8vIFVSTCBpbnB1dFxuICAgIGNvbnN0IHVybEdyb3VwID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1maWVsZFwiKTtcbiAgICB1cmxHcm91cC5jcmVhdGVFbChcImxhYmVsXCIsIHsgdGV4dDogXCJHYXRld2F5IFVSTFwiIH0pO1xuICAgIGNvbnN0IHVybElucHV0ID0gdXJsR3JvdXAuY3JlYXRlRWwoXCJpbnB1dFwiLCB7XG4gICAgICB0eXBlOiBcInRleHRcIixcbiAgICAgIHZhbHVlOiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsIHx8IFwiXCIsXG4gICAgICBwbGFjZWhvbGRlcjogXCJodHRwczovL3lvdXItbWFjaGluZS50YWlsMTIzNC50cy5uZXRcIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWlucHV0XCIsXG4gICAgfSk7XG4gICAgY29uc3QgdXJsSGludCA9IHVybEdyb3VwLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiKTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCJUaGUgVVJMIGZyb20gXCIpO1xuICAgIHVybEhpbnQuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogXCJ0YWlsc2NhbGUgc2VydmUgc3RhdHVzXCIgfSk7XG4gICAgdXJsSGludC5hcHBlbmRUZXh0KFwiLiBZb3UgY2FuIHBhc3RlIFwiKTtcbiAgICB1cmxIaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiaHR0cHM6Ly9cIiB9KTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCIgb3IgXCIpO1xuICAgIHVybEhpbnQuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogXCJ3c3M6Ly9cIiB9KTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCIgXHUyMDE0IGJvdGggd29yay5cIik7XG5cbiAgICAvLyBUb2tlbiBpbnB1dFxuICAgIGNvbnN0IHRva2VuR3JvdXAgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWZpZWxkXCIpO1xuICAgIHRva2VuR3JvdXAuY3JlYXRlRWwoXCJsYWJlbFwiLCB7IHRleHQ6IFwiQXV0aCB0b2tlblwiIH0pO1xuICAgIGNvbnN0IHRva2VuSW5wdXQgPSB0b2tlbkdyb3VwLmNyZWF0ZUVsKFwiaW5wdXRcIiwge1xuICAgICAgdHlwZTogXCJwYXNzd29yZFwiLFxuICAgICAgdmFsdWU6IHRoaXMucGx1Z2luLnNldHRpbmdzLnRva2VuIHx8IFwiXCIsXG4gICAgICBwbGFjZWhvbGRlcjogXCJQYXN0ZSB5b3VyIGdhdGV3YXkgYXV0aCB0b2tlblwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaW5wdXRcIixcbiAgICB9KTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIC8vIFRyb3VibGVzaG9vdGluZyAoaGlkZGVuIHVudGlsIGZhaWx1cmUpXG4gICAgY29uc3QgdHJvdWJsZXNob290ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC10cm91Ymxlc2hvb3RcIik7XG4gICAgdHJvdWJsZXNob290LmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIHRyb3VibGVzaG9vdC5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogXCJUcm91Ymxlc2hvb3RpbmdcIiB9KTtcblxuICAgIGNvbnN0IGNoZWNrcyA9IHRyb3VibGVzaG9vdC5jcmVhdGVFbChcIm9sXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtbGlzdFwiIH0pO1xuXG4gICAgY29uc3QgbGkxID0gY2hlY2tzLmNyZWF0ZUVsKFwibGlcIik7XG4gICAgbGkxLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJJcyBUYWlsc2NhbGUgY29ubmVjdGVkIG9uIHRoaXMgZGV2aWNlP1wiIH0pO1xuICAgIGxpMS5hcHBlbmRUZXh0KFwiIENoZWNrIHRoZSBUYWlsc2NhbGUgaWNvbiBpbiB5b3VyIHN5c3RlbSB0cmF5IC8gbWVudSBiYXIuIElmIGl0J3Mgb2ZmLCB0dXJuIGl0IG9uLlwiKTtcblxuICAgIGNvbnN0IGxpMiA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiRE5TIG5vdCByZXNvbHZpbmc/IChtb3N0IGNvbW1vbiBvbiBtYWNPUylcIiB9KTtcbiAgICBsaTIuYXBwZW5kVGV4dChcIiBPcGVuIHRoZSBcIik7XG4gICAgbGkyLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJUYWlsc2NhbGUgYXBwXCIgfSk7XG4gICAgbGkyLmFwcGVuZFRleHQoXCIgZnJvbSB5b3VyIG1lbnUgYmFyLCB0b2dnbGUgaXQgXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiT0ZGXCIgfSk7XG4gICAgbGkyLmFwcGVuZFRleHQoXCIsIHdhaXQgNSBzZWNvbmRzLCB0b2dnbGUgaXQgXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiT05cIiB9KTtcbiAgICBsaTIuYXBwZW5kVGV4dChcIi4gVGhpcyByZXNldHMgTWFnaWNETlMsIHdoaWNoIG1hY09TIHNvbWV0aW1lcyBsb3NlcyB0cmFjayBvZi5cIik7XG5cbiAgICBjb25zdCBsaTMgPSBjaGVja3MuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBsaTMuc2V0VGV4dChcIklzIHRoZSBnYXRld2F5IHJ1bm5pbmc/IE9uIHRoZSBnYXRld2F5IG1hY2hpbmUsIHJ1bjpcIik7XG4gICAgdGhpcy5tYWtlQ29weUJveCh0cm91Ymxlc2hvb3QsIFwib3BlbmNsYXcgZG9jdG9yIC0tZml4ICYmIG9wZW5jbGF3IGdhdGV3YXkgcmVzdGFydFwiKTtcblxuICAgIGNvbnN0IGxpNCA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpNC5zZXRUZXh0KFwiSXMgVGFpbHNjYWxlIFNlcnZlIGFjdGl2ZT8gT24gdGhlIGdhdGV3YXkgbWFjaGluZSwgcnVuOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJ0YWlsc2NhbGUgc2VydmUgc3RhdHVzXCIpO1xuICAgIGNvbnN0IHRzSGludCA9IHRyb3VibGVzaG9vdC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnRcIik7XG4gICAgdHNIaW50LnNldFRleHQoXCJJZiBUYWlsc2NhbGUgU2VydmUgc2hvd3Mgbm90aGluZywgc2V0IGl0IHVwOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJ0YWlsc2NhbGUgc2VydmUgLS1iZyBodHRwOi8vMTI3LjAuMC4xOjE4Nzg5XCIpO1xuXG4gICAgY29uc3QgbGk1ID0gY2hlY2tzLmNyZWF0ZUVsKFwibGlcIik7XG4gICAgbGk1LmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJHYXRld2F5IGNvbmZpZyBicm9rZW4/XCIgfSk7XG4gICAgbGk1LmFwcGVuZFRleHQoXCIgSWYgXCIpO1xuICAgIGxpNS5jcmVhdGVFbChcImNvZGVcIiwgeyB0ZXh0OiBcIm9wZW5jbGF3IGRvY3RvclwiIH0pO1xuICAgIGxpNS5hcHBlbmRUZXh0KCcgc2hvd3MgXCJJbnZhbGlkIGNvbmZpZ1wiIGVycm9ycywgeW91ciBnYXRld2F5IGNvbmZpZyBmaWxlIG1heSBoYXZlIGJlZW4gY29ycnVwdGVkLiBUbyByZXNldCB0byB0aGUgcmVjb21tZW5kZWQgc2V0dXAsIHJ1biB0aGVzZSBvbiB0aGUgZ2F0ZXdheSBtYWNoaW5lOicpO1xuICAgIHRoaXMubWFrZUNvcHlCb3godHJvdWJsZXNob290LCBgY2F0IH4vLm9wZW5jbGF3L29wZW5jbGF3Lmpzb24gfCBweXRob24zIC1jIFwiXG5pbXBvcnQganNvbiwgc3lzXG5jID0ganNvbi5sb2FkKHN5cy5zdGRpbilcbmMuc2V0ZGVmYXVsdCgnZ2F0ZXdheScsIHt9KVsnYmluZCddID0gJ2xvb3BiYWNrJ1xuY1snZ2F0ZXdheSddLnNldGRlZmF1bHQoJ3RhaWxzY2FsZScsIHt9KVsnbW9kZSddID0gJ3NlcnZlJ1xuY1snZ2F0ZXdheSddWyd0YWlsc2NhbGUnXVsncmVzZXRPbkV4aXQnXSA9IEZhbHNlXG5qc29uLmR1bXAoYywgb3BlbihzeXMuYXJndlsxXSwgJ3cnKSwgaW5kZW50PTIpXG5wcmludCgnQ29uZmlnIGZpeGVkOiBiaW5kPWxvb3BiYWNrLCB0YWlsc2NhbGUubW9kZT1zZXJ2ZScpXG5cIiB+Ly5vcGVuY2xhdy9vcGVuY2xhdy5qc29uYCk7XG4gICAgY29uc3QgbGk1aGludCA9IHRyb3VibGVzaG9vdC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnRcIik7XG4gICAgbGk1aGludC5zZXRUZXh0KFwiVGhlbiByZXN0YXJ0IHRoZSBnYXRld2F5IGFuZCByZS1lbmFibGUgVGFpbHNjYWxlIFNlcnZlOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJvcGVuY2xhdyBnYXRld2F5IHJlc3RhcnQgJiYgdGFpbHNjYWxlIHNlcnZlIC0tYmcgaHR0cDovLzEyNy4wLjAuMToxODc4OVwiKTtcblxuICAgIGNvbnN0IGxpNiA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpNi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiU3RpbGwgc3R1Y2s/XCIgfSk7XG4gICAgbGk2LmFwcGVuZFRleHQoXCIgVHJ5IHJlc3RhcnRpbmcgdGhlIFRhaWxzY2FsZSBhcHAgZW50aXJlbHksIG9yIHJlYm9vdCB0aGlzIGRldmljZS4gbWFjT1MgRE5TIGNhbiBnZXQgc3R1Y2sgYW5kIG5lZWRzIGEgZnJlc2ggc3RhcnQuXCIpO1xuXG4gICAgY29uc3QgYnRuUm93ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1idXR0b25zXCIpO1xuICAgIGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiXHUyMTkwIGJhY2tcIiB9KS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnN0ZXAgPSAyOyB0aGlzLnJlbmRlclN0ZXAoKTsgfSk7XG5cbiAgICBjb25zdCB0ZXN0QnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJUZXN0IGNvbm5lY3Rpb25cIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICB0ZXN0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICBjb25zdCB1cmwgPSB1cmxJbnB1dC52YWx1ZS50cmltKCk7XG4gICAgICBjb25zdCB0b2tlbiA9IHRva2VuSW5wdXQudmFsdWUudHJpbSgpO1xuXG4gICAgICBpZiAoIXVybCkgeyB0aGlzLnNob3dTdGF0dXMoXCJQYXN0ZSB5b3VyIGdhdGV3YXkgVVJMIGZyb20gdGhlIHByZXZpb3VzIHN0ZXBcIiwgXCJlcnJvclwiKTsgcmV0dXJuOyB9XG4gICAgICBjb25zdCBub3JtYWxpemVkVXJsID0gbm9ybWFsaXplR2F0ZXdheVVybCh1cmwpO1xuICAgICAgaWYgKCFub3JtYWxpemVkVXJsKSB7XG4gICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIlRoYXQgZG9lc24ndCBsb29rIHJpZ2h0LiBQYXN0ZSB0aGUgVVJMIGZyb20gYHRhaWxzY2FsZSBzZXJ2ZSBzdGF0dXNgIChlLmcuIGh0dHBzOi8veW91ci1tYWNoaW5lLnRhaWwxMjM0LnRzLm5ldClcIiwgXCJlcnJvclwiKTsgcmV0dXJuO1xuICAgICAgfVxuICAgICAgaWYgKCF0b2tlbikgeyB0aGlzLnNob3dTdGF0dXMoXCJQYXN0ZSB5b3VyIGF1dGggdG9rZW5cIiwgXCJlcnJvclwiKTsgcmV0dXJuOyB9XG5cbiAgICAgIHRlc3RCdG4uZGlzYWJsZWQgPSB0cnVlO1xuICAgICAgdGVzdEJ0bi50ZXh0Q29udGVudCA9IFwiQ29ubmVjdGluZy4uLlwiO1xuICAgICAgdHJvdWJsZXNob290LmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgdGhpcy5zaG93U3RhdHVzKFwiVGVzdGluZyBjb25uZWN0aW9uLi4uXCIsIFwiaW5mb1wiKTtcblxuICAgICAgLy8gQWx3YXlzIHJlc2V0IHRvIFwibWFpblwiIHNlc3Npb24gdG8gZW5zdXJlIGNsZWFuIGNvbm5lY3Rpb25cbiAgICAgIHVybElucHV0LnZhbHVlID0gbm9ybWFsaXplZFVybDtcbiAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSBub3JtYWxpemVkVXJsO1xuICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MudG9rZW4gPSB0b2tlbjtcbiAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBcIm1haW5cIjtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuXG4gICAgICBjb25zdCBvayA9IGF3YWl0IG5ldyBQcm9taXNlPGJvb2xlYW4+KChyZXNvbHZlKSA9PiB7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHsgdGMuc3RvcCgpOyByZXNvbHZlKGZhbHNlKTsgfSwgODAwMCk7XG4gICAgICAgIGNvbnN0IHRjID0gbmV3IEdhdGV3YXlDbGllbnQoe1xuICAgICAgICAgIHVybDogbm9ybWFsaXplZFVybCwgdG9rZW4sXG4gICAgICAgICAgb25IZWxsbzogKCkgPT4geyBjbGVhclRpbWVvdXQodGltZW91dCk7IHRjLnN0b3AoKTsgcmVzb2x2ZSh0cnVlKTsgfSxcbiAgICAgICAgICBvbkNsb3NlOiAoKSA9PiB7fSxcbiAgICAgICAgfSk7XG4gICAgICAgIHRjLnN0YXJ0KCk7XG4gICAgICB9KTtcblxuICAgICAgdGVzdEJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgdGVzdEJ0bi50ZXh0Q29udGVudCA9IFwiVGVzdCBjb25uZWN0aW9uXCI7XG5cbiAgICAgIGlmIChvaykge1xuICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJcdTI3MTMgQ29ubmVjdGVkIVwiLCBcInN1Y2Nlc3NcIik7XG4gICAgICAgIHNldFRpbWVvdXQoKCkgPT4geyB0aGlzLnN0ZXAgPSA0OyB0aGlzLnJlbmRlclN0ZXAoKTsgfSwgODAwKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIkNvdWxkIG5vdCBjb25uZWN0LiBDaGVjayB0aGUgdHJvdWJsZXNob290aW5nIHN0ZXBzIGJlbG93LlwiLCBcImVycm9yXCIpO1xuICAgICAgICB0cm91Ymxlc2hvb3QucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB9XG4gICAgfSkoKSk7XG4gIH1cblxuICBwcml2YXRlIG1ha2VDb3B5Qm94KHBhcmVudDogSFRNTEVsZW1lbnQsIGNvbW1hbmQ6IHN0cmluZyk6IEhUTUxFbGVtZW50IHtcbiAgICBjb25zdCBib3ggPSBwYXJlbnQuY3JlYXRlRGl2KFwib3BlbmNsYXctY29weS1ib3hcIik7XG4gICAgYm94LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IGNvbW1hbmQgfSk7XG4gICAgY29uc3QgYnRuID0gYm94LmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1jb3B5LWJ0blwiKTtcbiAgICBidG4udGV4dENvbnRlbnQgPSBcIkNvcHlcIjtcbiAgICBib3guYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgIHZvaWQgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoY29tbWFuZCkudGhlbigoKSA9PiB7XG4gICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNzEzXCI7XG4gICAgICAgIHNldFRpbWVvdXQoKCkgPT4gYnRuLnRleHRDb250ZW50ID0gXCJDb3B5XCIsIDE1MDApO1xuICAgICAgfSk7XG4gICAgfSk7XG4gICAgcmV0dXJuIGJveDtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTdGVwIDQ6IERldmljZSBQYWlyaW5nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVyUGFpcmluZyhlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJQYWlyIHRoaXMgZGV2aWNlXCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiRm9yIHNlY3VyaXR5LCBlYWNoIGRldmljZSBuZWVkcyBvbmUtdGltZSBhcHByb3ZhbCBmcm9tIHRoZSBnYXRld2F5LiBUaGlzIGNyZWF0ZXMgYSB1bmlxdWUga2V5cGFpciBmb3IgdGhpcyBkZXZpY2Ugc28gdGhlIGdhdGV3YXkga25vd3MgaXQncyB5b3UuXCIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBoYXNLZXlzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuZGV2aWNlSWQgJiYgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZGV2aWNlUHVibGljS2V5O1xuXG4gICAgaWYgKGhhc0tleXMpIHtcbiAgICAgIGNvbnN0IGluZm8gPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWluZm9cIik7XG4gICAgICBpbmZvLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVGhpcyBkZXZpY2UgYWxyZWFkeSBoYXMgYSBrZXlwYWlyLlwiIH0pO1xuICAgICAgY29uc3QgZGV2aWNlUCA9IGluZm8uY3JlYXRlRWwoXCJwXCIpO1xuICAgICAgZGV2aWNlUC5hcHBlbmRUZXh0KFwiRGV2aWNlIElEOiBcIik7XG4gICAgICBkZXZpY2VQLmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6ICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5kZXZpY2VJZD8uc2xpY2UoMCwgMTIpID8/IFwiXCIpICsgXCIuLi5cIiB9KTtcbiAgICB9XG5cbiAgICB0aGlzLnN0YXR1c0VsID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1zdGF0dXNcIik7XG5cbiAgICAvLyBBcHByb3ZhbCBpbnN0cnVjdGlvbnMgKGFsd2F5cyB2aXNpYmxlKVxuICAgIGNvbnN0IGFwcHJvdmFsSW5mbyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtbnVtYmVyZWRcIik7XG4gICAgY29uc3QgYTEgPSBhcHByb3ZhbEluZm8uY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1udW1iZXJlZC1pdGVtXCIpO1xuICAgIGExLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJIb3cgYXBwcm92YWwgd29ya3NcIiB9KTtcbiAgICBhMS5jcmVhdGVFbChcInBcIiwgeyB0ZXh0OiBcIkNsaWNrIHRoZSBidXR0b24gYmVsb3cgdG8gc2VuZCBhIHBhaXJpbmcgcmVxdWVzdC4gVGhlbiwgb24geW91ciBnYXRld2F5IG1hY2hpbmUsIHJ1bjpcIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goYTEsIFwib3BlbmNsYXcgZGV2aWNlcyBsaXN0XCIpO1xuICAgIGExLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiWW91J2xsIHNlZSB5b3VyIHBlbmRpbmcgcmVxdWVzdC4gQXBwcm92ZSBpdCB3aXRoOlwiLCBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIgfSk7XG4gICAgdGhpcy5tYWtlQ29weUJveChhMSwgXCJvcGVuY2xhdyBkZXZpY2VzIGFwcHJvdmUgPHJlcXVlc3RJZD5cIik7XG4gICAgY29uc3QgYTFoaW50ID0gYTEuY3JlYXRlRWwoXCJwXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIGExaGludC5hcHBlbmRUZXh0KFwiUmVwbGFjZSBcIik7XG4gICAgYTFoaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiPHJlcXVlc3RJZD5cIiB9KTtcbiAgICBhMWhpbnQuYXBwZW5kVGV4dChcIiB3aXRoIHRoZSBJRCBzaG93biBpbiB0aGUgcGVuZGluZyBsaXN0LiBZb3UgY2FuIGFsc28gYXBwcm92ZSBmcm9tIHRoZSBPcGVuQ2xhdyBDb250cm9sIFVJIGRhc2hib2FyZC5cIik7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnNcIik7XG4gICAgYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJcdTIxOTAgYmFja1wiIH0pLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDM7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcblxuICAgIGNvbnN0IHBhaXJCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwge1xuICAgICAgdGV4dDogaGFzS2V5cyA/IFwiQ2hlY2sgcGFpcmluZyBzdGF0dXNcIiA6IFwiU2VuZCBwYWlyaW5nIHJlcXVlc3RcIixcbiAgICAgIGNsczogXCJtb2QtY3RhXCIsXG4gICAgfSk7XG4gICAgcGFpckJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgcGFpckJ0bi5kaXNhYmxlZCA9IHRydWU7XG4gICAgICB0aGlzLnNob3dTdGF0dXMoXCJDb25uZWN0aW5nIHRvIGdhdGV3YXkuLi5cIiwgXCJpbmZvXCIpO1xuXG4gICAgICB0cnkge1xuICAgICAgICAvLyBFbnN1cmUgd2UgaGF2ZSBhIHJlYWwgY29ubmVjdGlvbiB0byB0ZXN0IHBhaXJpbmdcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uY29ubmVjdEdhdGV3YXkoKTtcblxuICAgICAgICAvLyBXYWl0IGEgbW9tZW50IGZvciBjb25uZWN0aW9uIHRvIGVzdGFibGlzaFxuICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgMjAwMCkpO1xuXG4gICAgICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheUNvbm5lY3RlZCkge1xuICAgICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIkNvdWxkIG5vdCBjb25uZWN0IHRvIGdhdGV3YXkuIEdvIGJhY2sgYW5kIGNoZWNrIHlvdXIgc2V0dGluZ3MuXCIsIFwiZXJyb3JcIik7XG4gICAgICAgICAgcGFpckJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFRyeSBhIHNpbXBsZSByZXF1ZXN0IHRvIHZlcmlmeSBwYWlyaW5nXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheSEucmVxdWVzdChcInNlc3Npb25zLmxpc3RcIiwge30pO1xuICAgICAgICAgIGlmIChyZXN1bHQ/LnNlc3Npb25zKSB7XG4gICAgICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJcdTI3MTMgRGV2aWNlIGlzIHBhaXJlZCBhbmQgYXV0aG9yaXplZCFcIiwgXCJzdWNjZXNzXCIpO1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7IHRoaXMuc3RlcCA9IDU7IHRoaXMucmVuZGVyU3RlcCgpOyB9LCAxMDAwKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGU6IHVua25vd24pIHtcbiAgICAgICAgICAvLyBJZiB3ZSBnZXQgYW4gYXV0aCBlcnJvciwgZGV2aWNlIG5lZWRzIGFwcHJvdmFsXG4gICAgICAgICAgY29uc3QgbXNnID0gU3RyaW5nKGUpO1xuICAgICAgICAgIGlmIChtc2cuaW5jbHVkZXMoXCJzY29wZVwiKSB8fCBtc2cuaW5jbHVkZXMoXCJhdXRoXCIpIHx8IG1zZy5pbmNsdWRlcyhcInBhaXJcIikpIHtcbiAgICAgICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIlx1MjNGMyBQYWlyaW5nIHJlcXVlc3Qgc2VudCEgTm93IGFwcHJvdmUgaXQgb24geW91ciBnYXRld2F5IG1hY2hpbmUgdXNpbmcgdGhlIGNvbW1hbmRzIGFib3ZlLlxcblxcbldhaXRpbmcgZm9yIGFwcHJvdmFsLi4uXCIsIFwiaW5mb1wiKTtcbiAgICAgICAgICAgIHRoaXMuc3RhcnRQYWlyaW5nUG9sbChwYWlyQnRuKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJZiB3ZSBnb3QgaGVyZSwgY29ubmVjdGlvbiB3b3JrcyBcdTIwMTQgbWlnaHQgYWxyZWFkeSBiZSBwYWlyZWRcbiAgICAgICAgdGhpcy5zaG93U3RhdHVzKFwiXHUyNzEzIENvbm5lY3Rpb24gd29ya2luZyEgUHJvY2VlZGluZy4uLlwiLCBcInN1Y2Nlc3NcIik7XG4gICAgICAgIHNldFRpbWVvdXQoKCkgPT4geyB0aGlzLnN0ZXAgPSA1OyB0aGlzLnJlbmRlclN0ZXAoKTsgfSwgMTAwMCk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHRoaXMuc2hvd1N0YXR1cyhgRXJyb3I6ICR7ZX1gLCBcImVycm9yXCIpO1xuICAgICAgICBwYWlyQnRuLmRpc2FibGVkID0gZmFsc2U7XG4gICAgICB9XG4gICAgfSkoKSk7XG5cbiAgICBjb25zdCBza2lwQnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJTa2lwIGZvciBub3dcIiB9KTtcbiAgICBza2lwQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDU7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIHByaXZhdGUgc3RhcnRQYWlyaW5nUG9sbChidG46IEhUTUxCdXR0b25FbGVtZW50KTogdm9pZCB7XG4gICAgbGV0IGF0dGVtcHRzID0gMDtcbiAgICB0aGlzLnBhaXJpbmdQb2xsVGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICBhdHRlbXB0cysrO1xuICAgICAgaWYgKGF0dGVtcHRzID4gNjApIHsgLy8gMiBtaW51dGVzXG4gICAgICAgIGlmICh0aGlzLnBhaXJpbmdQb2xsVGltZXIpIGNsZWFySW50ZXJ2YWwodGhpcy5wYWlyaW5nUG9sbFRpbWVyKTtcbiAgICAgICAgdGhpcy5zaG93U3RhdHVzKFwiVGltZWQgb3V0IHdhaXRpbmcgZm9yIGFwcHJvdmFsLiBZb3UgY2FuIGFwcHJvdmUgbGF0ZXIgYW5kIHJlLXJ1biB0aGUgc2V0dXAgd2l6YXJkIGZyb20gc2V0dGluZ3MuXCIsIFwiZXJyb3JcIik7XG4gICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5Py5yZXF1ZXN0KFwic2Vzc2lvbnMubGlzdFwiLCB7fSk7XG4gICAgICAgIGlmIChyZXN1bHQ/LnNlc3Npb25zKSB7XG4gICAgICAgICAgaWYgKHRoaXMucGFpcmluZ1BvbGxUaW1lcikgY2xlYXJJbnRlcnZhbCh0aGlzLnBhaXJpbmdQb2xsVGltZXIpO1xuICAgICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIlx1MjcxMyBEZXZpY2UgYXBwcm92ZWQhXCIsIFwic3VjY2Vzc1wiKTtcbiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsgdGhpcy5zdGVwID0gNTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0sIDEwMDApO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIHsgLyogc3RpbGwgd2FpdGluZyAqLyB9XG4gICAgfSkoKSwgMjAwMCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgU3RlcCA1OiBEb25lIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVyRG9uZShlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJZb3UncmUgYWxsIHNldCEgXHVEODNDXHVERjg5XCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiT3BlbkNsYXcgaXMgY29ubmVjdGVkIGFuZCByZWFkeS4gWW91ciB2YXVsdCBpcyBub3cgdGhlIGFnZW50J3Mgd29ya3NwYWNlLlwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtZGVzY1wiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgdGlwcyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtdGlwc1wiKTtcbiAgICB0aXBzLmNyZWF0ZUVsKFwiaDNcIiwgeyB0ZXh0OiBcIldoYXQgeW91IGNhbiBkb1wiIH0pO1xuICAgIGNvbnN0IGxpc3QgPSB0aXBzLmNyZWF0ZUVsKFwidWxcIiwgeyBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1saXN0XCIgfSk7XG4gICAgbGlzdC5jcmVhdGVFbChcImxpXCIsIHsgdGV4dDogXCJDaGF0IHdpdGggeW91ciBBSSBhZ2VudCBpbiB0aGUgc2lkZWJhclwiIH0pO1xuICAgIGxpc3QuY3JlYXRlRWwoXCJsaVwiLCB7IHRleHQ6IFwiVXNlIENtZC9DdHJsK1AgXHUyMTkyIFxcXCJBc2sgYWJvdXQgY3VycmVudCBub3RlXFxcIiB0byBkaXNjdXNzIGFueSBub3RlXCIgfSk7XG4gICAgbGlzdC5jcmVhdGVFbChcImxpXCIsIHsgdGV4dDogXCJUaGUgYWdlbnQgY2FuIHJlYWQsIGNyZWF0ZSwgYW5kIGVkaXQgZmlsZXMgaW4geW91ciB2YXVsdFwiIH0pO1xuICAgIGxpc3QuY3JlYXRlRWwoXCJsaVwiLCB7IHRleHQ6IFwiVG9vbCBjYWxscyBhcHBlYXIgaW5saW5lIFx1MjAxNCBjbGljayBmaWxlIHBhdGhzIHRvIG9wZW4gdGhlbVwiIH0pO1xuXG4gICAgY29uc3Qgc3luY1RpcCA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaW5mb1wiKTtcbiAgICBzeW5jVGlwLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJcdUQ4M0RcdURDQTEgc3luYyB0aXA6IFwiIH0pO1xuICAgIHN5bmNUaXAuY3JlYXRlRWwoXCJzcGFuXCIsIHtcbiAgICAgIHRleHQ6IFwiRW5hYmxlIE9ic2lkaWFuIFN5bmMgdG8gYWNjZXNzIHlvdXIgYWdlbnQgZnJvbSBtdWx0aXBsZSBkZXZpY2VzLiBZb3VyIGNoYXQgc2V0dGluZ3MgYW5kIGRldmljZSBrZXlzIHN5bmMgYXV0b21hdGljYWxseSBcdTIwMTQgc2V0IHVwIG9uY2UsIHdvcmtzIGV2ZXJ5d2hlcmUuXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBjb250cm9sVGlwID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1pbmZvXCIpO1xuICAgIGNvbnRyb2xUaXAuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIlx1RDgzRFx1RERBNVx1RkUwRiBjb250cm9sIFVJOiBcIiB9KTtcbiAgICBjb25zdCBjdHJsU3BhbiA9IGNvbnRyb2xUaXAuY3JlYXRlRWwoXCJzcGFuXCIpO1xuICAgIGN0cmxTcGFuLnNldFRleHQoXCJZb3UgY2FuIGFsc28gbWFuYWdlIHlvdXIgZ2F0ZXdheSBmcm9tIGFueSBicm93c2VyIG9uIHlvdXIgVGFpbHNjYWxlIG5ldHdvcmsuIEp1c3Qgb3BlbiB5b3VyIGdhdGV3YXkgVVJMIGluIGEgYnJvd3Nlci5cIik7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnNcIik7XG4gICAgY29uc3QgZG9uZUJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiU3RhcnQgY2hhdHRpbmcgXHUyMTkyXCIsIGNsczogXCJtb2QtY3RhXCIgfSk7XG4gICAgZG9uZUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Mub25ib2FyZGluZ0NvbXBsZXRlID0gdHJ1ZTtcbiAgICAgIC8vIEFsd2F5cyByZXNldCB0byBcIm1haW5cIiBzZXNzaW9uIHRvIGVuc3VyZSBjbGVhbiBjb25uZWN0aW9uXG4gICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gXCJtYWluXCI7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheUNvbm5lY3RlZCkgdm9pZCB0aGlzLnBsdWdpbi5jb25uZWN0R2F0ZXdheSgpO1xuICAgICAgdm9pZCB0aGlzLnBsdWdpbi5hY3RpdmF0ZVZpZXcoKTtcbiAgICB9KSgpKTtcbiAgfVxuXG4gIHByaXZhdGUgc2hvd1N0YXR1cyh0ZXh0OiBzdHJpbmcsIHR5cGU6IFwiaW5mb1wiIHwgXCJzdWNjZXNzXCIgfCBcImVycm9yXCIpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuc3RhdHVzRWwpIHJldHVybjtcbiAgICB0aGlzLnN0YXR1c0VsLmVtcHR5KCk7XG4gICAgdGhpcy5zdGF0dXNFbC5jbGFzc05hbWUgPSBgb3BlbmNsYXctb25ib2FyZC1zdGF0dXMgb3BlbmNsYXctb25ib2FyZC1zdGF0dXMtJHt0eXBlfWA7XG4gICAgLy8gU3VwcG9ydCBtdWx0aWxpbmUgd2l0aCBcXG5cbiAgICBmb3IgKGNvbnN0IGxpbmUgb2YgdGV4dC5zcGxpdChcIlxcblwiKSkge1xuICAgICAgaWYgKHRoaXMuc3RhdHVzRWwuY2hpbGROb2Rlcy5sZW5ndGggPiAwKSB0aGlzLnN0YXR1c0VsLmNyZWF0ZUVsKFwiYnJcIik7XG4gICAgICB0aGlzLnN0YXR1c0VsLmFwcGVuZFRleHQobGluZSk7XG4gICAgfVxuICB9XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBDaGF0IFZpZXcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbmNvbnN0IFZJRVdfVFlQRSA9IFwib3BlbmNsYXctY2hhdFwiO1xuXG5jbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIG1lc3NhZ2VzRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSB0YWJCYXJFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIHRhYlNlc3Npb25zOiB7IGtleTogc3RyaW5nOyBsYWJlbDogc3RyaW5nOyBwY3Q6IG51bWJlciB9W10gPSBbXTtcbiAgcHJpdmF0ZSByZW5kZXJpbmdUYWJzID0gZmFsc2U7XG4gIHByaXZhdGUgdGFiRGVsZXRlSW5Qcm9ncmVzcyA9IGZhbHNlO1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBhYm9ydEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgUGVyLXNlc3Npb24gc3RyZWFtIHN0YXRlIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuICBwcml2YXRlIHN0cmVhbXMgPSBuZXcgTWFwPHN0cmluZywge1xuICAgIHJ1bklkOiBzdHJpbmc7XG4gICAgdGV4dDogc3RyaW5nIHwgbnVsbDtcbiAgICB0b29sQ2FsbHM6IHN0cmluZ1tdO1xuICAgIGl0ZW1zOiBTdHJlYW1JdGVtW107XG4gICAgc3BsaXRQb2ludHM6IG51bWJlcltdO1xuICAgIGxhc3REZWx0YVRpbWU6IG51bWJlcjtcbiAgICBjb21wYWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbiAgICB3b3JraW5nVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbiAgfT4oKTtcbiAgLyoqIE1hcCBydW5JZCAtPiBzZXNzaW9uS2V5IHNvIHdlIGNhbiByb3V0ZSBzdHJlYW0gZXZlbnRzIHRoYXQgbGFjayBzZXNzaW9uS2V5ICovXG4gIHByaXZhdGUgcnVuVG9TZXNzaW9uID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcblxuICBwcml2YXRlIHN0cmVhbUVsOiBIVE1MRWxlbWVudCB8IG51bGwgPSBudWxsO1xuXG4gIC8qKiBHZXQgY3VycmVudCBhY3RpdmUgc2Vzc2lvbiBrZXkgKi9cbiAgcHJpdmF0ZSBnZXQgYWN0aXZlU2Vzc2lvbktleSgpOiBzdHJpbmcgeyByZXR1cm4gdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSB8fCBcIm1haW5cIjsgfVxuICAvKiogR2V0IHN0cmVhbSBzdGF0ZSBmb3IgYWN0aXZlIHRhYiAoaWYgYW55KSAqL1xuICBwcml2YXRlIGdldCBhY3RpdmVTdHJlYW0oKSB7IHJldHVybiB0aGlzLnN0cmVhbXMuZ2V0KHRoaXMuYWN0aXZlU2Vzc2lvbktleSkgPz8gbnVsbDsgfVxuXG4gIHByaXZhdGUgY29udGV4dE1ldGVyRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBjb250ZXh0RmlsbEVsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgY29udGV4dExhYmVsRWwhOiBIVE1MRWxlbWVudDtcbiAgbW9kZWxMYWJlbEVsITogSFRNTEVsZW1lbnQ7XG5cbiAgY3VycmVudE1vZGVsOiBzdHJpbmcgPSBcIlwiO1xuICBjdXJyZW50TW9kZWxTZXRBdDogbnVtYmVyID0gMDsgLy8gdGltZXN0YW1wIHRvIHByZXZlbnQgc3RhbGUgb3ZlcndyaXRlc1xuICBjYWNoZWRTZXNzaW9uRGlzcGxheU5hbWU6IHN0cmluZyA9IFwiXCI7XG5cbiAgLy8gQWdlbnQgc3dpdGNoZXIgc3RhdGVcbiAgcHJpdmF0ZSBhZ2VudHM6IEFnZW50SW5mb1tdID0gW107XG4gIHByaXZhdGUgYWN0aXZlQWdlbnQ6IEFnZW50SW5mbyA9IHsgaWQ6IFwibWFpblwiLCBuYW1lOiBcIkFnZW50XCIsIGVtb2ppOiBcIlx1RDgzRVx1REQxNlwiLCBjcmVhdHVyZTogXCJcIiB9O1xuICBwcml2YXRlIHByb2ZpbGVCdG5FbDogSFRNTEVsZW1lbnQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBwcm9maWxlRHJvcGRvd25FbDogSFRNTEVsZW1lbnQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSB0eXBpbmdFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGF0dGFjaFByZXZpZXdFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGZpbGVJbnB1dEVsITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBwZW5kaW5nQXR0YWNobWVudHM6IHsgbmFtZTogc3RyaW5nOyBjb250ZW50OiBzdHJpbmc7IHZhdWx0UGF0aD86IHN0cmluZzsgYmFzZTY0Pzogc3RyaW5nOyBtaW1lVHlwZT86IHN0cmluZyB9W10gPSBbXTtcbiAgcHJpdmF0ZSBzZW5kaW5nID0gZmFsc2U7XG4gIHByaXZhdGUgcmVjb3JkaW5nID0gZmFsc2U7XG4gIHByaXZhdGUgbWVkaWFSZWNvcmRlcjogTWVkaWFSZWNvcmRlciB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHJlY29yZGVkQ2h1bmtzOiBCbG9iW10gPSBbXTtcblxuICBwcml2YXRlIHJlYWRvbmx5IG1pY1N2ZyA9IGA8c3ZnIHdpZHRoPVwiMThcIiBoZWlnaHQ9XCIxOFwiIHZpZXdCb3g9XCIwIDAgMjQgMjRcIiBmaWxsPVwibm9uZVwiIHN0cm9rZT1cImN1cnJlbnRDb2xvclwiIHN0cm9rZS13aWR0aD1cIjJcIiBzdHJva2UtbGluZWNhcD1cInJvdW5kXCIgc3Ryb2tlLWxpbmVqb2luPVwicm91bmRcIj48cGF0aCBkPVwiTTEyIDFhMyAzIDAgMDAtMyAzdjhhMyAzIDAgMDA2IDBWNGEzIDMgMCAwMC0zLTN6XCIvPjxwYXRoIGQ9XCJNMTkgMTB2MmE3IDcgMCAwMS0xNCAwdi0yXCIvPjxsaW5lIHgxPVwiMTJcIiB5MT1cIjE5XCIgeDI9XCIxMlwiIHkyPVwiMjNcIi8+PGxpbmUgeDE9XCI4XCIgeTE9XCIyM1wiIHgyPVwiMTZcIiB5Mj1cIjIzXCIvPjwvc3ZnPmA7XG4gIHByaXZhdGUgcmVhZG9ubHkgc2VuZFN2ZyA9IGA8c3ZnIHdpZHRoPVwiMThcIiBoZWlnaHQ9XCIxOFwiIHZpZXdCb3g9XCIwIDAgMjQgMjRcIiBmaWxsPVwibm9uZVwiIHN0cm9rZT1cImN1cnJlbnRDb2xvclwiIHN0cm9rZS13aWR0aD1cIjJcIiBzdHJva2UtbGluZWNhcD1cInJvdW5kXCIgc3Ryb2tlLWxpbmVqb2luPVwicm91bmRcIj48bGluZSB4MT1cIjIyXCIgeTE9XCIyXCIgeDI9XCIxMVwiIHkyPVwiMTNcIi8+PHBvbHlnb24gcG9pbnRzPVwiMjIgMiAxNSAyMiAxMSAxMyAyIDkgMjIgMlwiLz48L3N2Zz5gO1xuICBwcml2YXRlIHJlYWRvbmx5IHN0b3BTdmcgPSBgPHN2ZyB3aWR0aD1cIjE4XCIgaGVpZ2h0PVwiMThcIiB2aWV3Qm94PVwiMCAwIDI0IDI0XCIgZmlsbD1cIm5vbmVcIiBzdHJva2U9XCJyZWRcIiBzdHJva2Utd2lkdGg9XCIyLjVcIiBzdHJva2UtbGluZWNhcD1cInJvdW5kXCIgc3Ryb2tlLWxpbmVqb2luPVwicm91bmRcIj48cmVjdCB4PVwiM1wiIHk9XCIzXCIgd2lkdGg9XCIxOFwiIGhlaWdodD1cIjE4XCIgcng9XCIyXCIvPjwvc3ZnPmA7XG4gIHByaXZhdGUgYmFubmVyRWwhOiBIVE1MRWxlbWVudDtcblxuICAvKiogR2V0IHRoZSBzZXNzaW9uIGtleSBwcmVmaXggZm9yIHRoZSBhY3RpdmUgYWdlbnQgKi9cbiAgcHJpdmF0ZSBnZXQgYWdlbnRQcmVmaXgoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYGFnZW50OiR7dGhpcy5hY3RpdmVBZ2VudC5pZH06YDtcbiAgfVxuXG4gIGNvbnN0cnVjdG9yKGxlYWY6IFdvcmtzcGFjZUxlYWYsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihsZWFmKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRTtcbiAgfVxuXG4gIGdldERpc3BsYXlUZXh0KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFwiT3BlbkNsYXdcIjtcbiAgfVxuXG4gIGdldEljb24oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gXCJtZXNzYWdlLXNxdWFyZVwiO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGNvbnRhaW5lciA9IHRoaXMuY29udGFpbmVyRWwuY2hpbGRyZW5bMV0gYXMgSFRNTEVsZW1lbnQ7XG4gICAgY29udGFpbmVyLmVtcHR5KCk7XG4gICAgY29udGFpbmVyLmFkZENsYXNzKFwib3BlbmNsYXctY2hhdC1jb250YWluZXJcIik7XG5cbiAgICAvLyBUb3AgYmFyIHdpdGggdGFicyArIHByb2ZpbGVcbiAgICBjb25zdCB0b3BCYXIgPSBjb250YWluZXIuY3JlYXRlRGl2KFwib3BlbmNsYXctdG9wLWJhclwiKTtcblxuICAgIC8vIFRhYiBiYXIgKGJyb3dzZXItbGlrZSB0YWJzKVxuICAgIHRoaXMudGFiQmFyRWwgPSB0b3BCYXIuY3JlYXRlRGl2KFwib3BlbmNsYXctdGFiLWJhclwiKTtcbiAgICB0aGlzLnRhYkJhckVsLmFkZEV2ZW50TGlzdGVuZXIoXCJ3aGVlbFwiLCAoZSkgPT4geyBlLnByZXZlbnREZWZhdWx0KCk7IHRoaXMudGFiQmFyRWwuc2Nyb2xsTGVmdCArPSBlLmRlbHRhWTsgfSwgeyBwYXNzaXZlOiBmYWxzZSB9KTtcblxuICAgIC8vIEFnZW50IHN3aXRjaGVyIGJ1dHRvbiAocmlnaHQgc2lkZSBvZiB0b3AgYmFyKVxuICAgIHRoaXMucHJvZmlsZUJ0bkVsID0gdG9wQmFyLmNyZWF0ZURpdihcIm9wZW5jbGF3LWFnZW50LWJ0blwiKTtcbiAgICB0aGlzLnByb2ZpbGVCdG5FbC5zZXRBdHRyaWJ1dGUoXCJhcmlhLWxhYmVsXCIsIFwiU3dpdGNoIGFnZW50XCIpO1xuICAgIHRoaXMudXBkYXRlQWdlbnRCdXR0b24oKTtcbiAgICB0aGlzLnByb2ZpbGVCdG5FbC5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKGUpID0+IHsgZS5zdG9wUHJvcGFnYXRpb24oKTsgdGhpcy50b2dnbGVBZ2VudFN3aXRjaGVyKCk7IH0pO1xuXG4gICAgLy8gQWdlbnQgc3dpdGNoZXIgZHJvcGRvd24gKGhpZGRlbiBieSBkZWZhdWx0KVxuICAgIHRoaXMucHJvZmlsZURyb3Bkb3duRWwgPSBjb250YWluZXIuY3JlYXRlRGl2KFwib3BlbmNsYXctYWdlbnQtZHJvcGRvd25cIik7XG4gICAgdGhpcy5wcm9maWxlRHJvcGRvd25FbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcblxuICAgIC8vIENsb3NlIGRyb3Bkb3duIHdoZW4gY2xpY2tpbmcgb3V0c2lkZVxuICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IGlmICh0aGlzLnByb2ZpbGVEcm9wZG93bkVsKSB0aGlzLnByb2ZpbGVEcm9wZG93bkVsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpOyB9KTtcblxuICAgIC8vIFdlJ2xsIHJlbmRlciB0YWJzIGFmdGVyIGxvYWRpbmcgc2Vzc2lvbnNcbiAgICB2b2lkIHRoaXMucmVuZGVyVGFicygpO1xuXG4gICAgLy8gSGlkZGVuIGVsZW1lbnRzIGZvciBjb21wYXRpYmlsaXR5XG5cbiAgICB0aGlzLmNvbnRleHRNZXRlckVsID0gY3JlYXRlRGl2KCk7XG4gICAgdGhpcy5jb250ZXh0RmlsbEVsID0gY3JlYXRlRGl2KCk7XG4gICAgdGhpcy5jb250ZXh0TGFiZWxFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJzcGFuXCIpO1xuICAgIHRoaXMubW9kZWxMYWJlbEVsID0gY3JlYXRlRGl2KCk7XG5cbiAgICAvLyBTdGF0dXMgYmFubmVyIChjb21wYWN0aW9uLCBldGMuKSBcdTIwMTQgaGlkZGVuIGJ5IGRlZmF1bHRcbiAgICB0aGlzLmJhbm5lckVsID0gY29udGFpbmVyLmNyZWF0ZURpdihcIm9wZW5jbGF3LWJhbm5lclwiKTtcbiAgICB0aGlzLmJhbm5lckVsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuXG4gICAgLy8gTWVzc2FnZXMgYXJlYVxuICAgIHRoaXMubWVzc2FnZXNFbCA9IGNvbnRhaW5lci5jcmVhdGVEaXYoXCJvcGVuY2xhdy1tZXNzYWdlc1wiKTtcblxuICAgIC8vIFR5cGluZyBpbmRpY2F0b3IgKGhpZGRlbiBieSBkZWZhdWx0KVxuICAgIHRoaXMudHlwaW5nRWwgPSBjb250YWluZXIuY3JlYXRlRGl2KFwib3BlbmNsYXctdHlwaW5nXCIpO1xuICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgY29uc3QgdHlwaW5nRG90cyA9IHRoaXMudHlwaW5nRWwuY3JlYXRlRGl2KFwib3BlbmNsYXctdHlwaW5nLWlubmVyXCIpO1xuICAgIHR5cGluZ0RvdHMuY3JlYXRlU3Bhbih7IHRleHQ6IFwiVGhpbmtpbmdcIiwgY2xzOiBcIm9wZW5jbGF3LXR5cGluZy10ZXh0XCIgfSk7XG4gICAgY29uc3QgZG90c0VsID0gdHlwaW5nRG90cy5jcmVhdGVTcGFuKFwib3BlbmNsYXctdHlwaW5nLWRvdHNcIik7XG4gICAgZG90c0VsLmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1kb3RcIik7XG4gICAgZG90c0VsLmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1kb3RcIik7XG4gICAgZG90c0VsLmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1kb3RcIik7XG5cbiAgICAvLyBJbnB1dCBhcmVhXG4gICAgY29uc3QgaW5wdXRBcmVhID0gY29udGFpbmVyLmNyZWF0ZURpdihcIm9wZW5jbGF3LWlucHV0LWFyZWFcIik7XG4gICAgY29uc3QgaW5wdXRSb3cgPSBpbnB1dEFyZWEuY3JlYXRlRGl2KFwib3BlbmNsYXctaW5wdXQtcm93XCIpO1xuICAgIC8vIEJyYWluIGJ1dHRvbiAobW9kZWwgcGlja2VyKVxuICAgIGNvbnN0IGJyYWluQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctYnJhaW4tYnRuXCIsIGF0dHI6IHsgXCJhcmlhLWxhYmVsXCI6IFwiU3dpdGNoIG1vZGVsXCIgfSB9KTtcbiAgICBzZXRJY29uKGJyYWluQnRuLCBcInNwYXJrbGVzXCIpO1xuICAgIGJyYWluQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB0aGlzLm9wZW5Nb2RlbFBpY2tlcigpKTtcbiAgICAvLyBBdHRhY2ggYnV0dG9uICsgaGlkZGVuIGZpbGUgaW5wdXRcbiAgICBjb25zdCBhdHRhY2hCdG4gPSBpbnB1dFJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IGNsczogXCJvcGVuY2xhdy1hdHRhY2gtYnRuXCIsIGF0dHI6IHsgXCJhcmlhLWxhYmVsXCI6IFwiQXR0YWNoIGZpbGVcIiB9IH0pO1xuICAgIHNldEljb24oYXR0YWNoQnRuLCBcInBhcGVyY2xpcFwiKTtcbiAgICB0aGlzLmZpbGVJbnB1dEVsID0gaW5wdXRBcmVhLmNyZWF0ZUVsKFwiaW5wdXRcIiwge1xuICAgICAgY2xzOiBcIm9wZW5jbGF3LWZpbGUtaW5wdXRcIixcbiAgICAgIGF0dHI6IHsgdHlwZTogXCJmaWxlXCIsIGFjY2VwdDogXCJpbWFnZS8qLC5tZCwudHh0LC5qc29uLC5jc3YsLnBkZiwueWFtbCwueW1sLC5qcywudHMsLnB5LC5odG1sLC5jc3NcIiwgbXVsdGlwbGU6IFwidHJ1ZVwiIH0sXG4gICAgfSk7XG4gICAgdGhpcy5maWxlSW5wdXRFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB0aGlzLmZpbGVJbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoXCJjaGFuZ2VcIiwgKCkgPT4gdm9pZCB0aGlzLmhhbmRsZUZpbGVTZWxlY3QoKSk7XG4gICAgYXR0YWNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB0aGlzLmZpbGVJbnB1dEVsLmNsaWNrKCkpO1xuICAgIHRoaXMuaW5wdXRFbCA9IGlucHV0Um93LmNyZWF0ZUVsKFwidGV4dGFyZWFcIiwge1xuICAgICAgY2xzOiBcIm9wZW5jbGF3LWlucHV0XCIsXG4gICAgICBhdHRyOiB7IHBsYWNlaG9sZGVyOiBcIk1lc3NhZ2UuLi5cIiwgcm93czogXCIxXCIgfSxcbiAgICB9KTtcbiAgICAvLyBBdHRhY2htZW50IHByZXZpZXcgKGhpZGRlbiBieSBkZWZhdWx0KVxuICAgIHRoaXMuYXR0YWNoUHJldmlld0VsID0gaW5wdXRBcmVhLmNyZWF0ZURpdihcIm9wZW5jbGF3LWF0dGFjaC1wcmV2aWV3XCIpO1xuICAgIHRoaXMuYXR0YWNoUHJldmlld0VsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIHRoaXMuYWJvcnRCdG4gPSBpbnB1dFJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IGNsczogXCJvcGVuY2xhdy1hYm9ydC1idG5cIiwgYXR0cjogeyBcImFyaWEtbGFiZWxcIjogXCJTdG9wXCIgfSB9KTtcbiAgICBzZXRJY29uKHRoaXMuYWJvcnRCdG4sIFwic3F1YXJlXCIpO1xuICAgIHRoaXMuYWJvcnRCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgY29uc3Qgc2VuZFdyYXBwZXIgPSBpbnB1dFJvdy5jcmVhdGVEaXYoXCJvcGVuY2xhdy1zZW5kLXdyYXBwZXJcIik7XG4gICAgdGhpcy5zZW5kQnRuID0gc2VuZFdyYXBwZXIuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctc2VuZC1idG5cIiwgYXR0cjogeyBcImFyaWEtbGFiZWxcIjogXCJTZW5kXCIgfSB9KTtcbiAgICBzZXRJY29uKHRoaXMuc2VuZEJ0biwgXCJzZW5kXCIpO1xuICAgIHRoaXMuc2VuZEJ0bi5hZGRDbGFzcyhcIm9jLW9wYWNpdHktbG93XCIpO1xuICAgIHRoaXMucmVjb25uZWN0QnRuID0gc2VuZFdyYXBwZXIuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctcmVjb25uZWN0LWJ0blwiLCBhdHRyOiB7IFwiYXJpYS1sYWJlbFwiOiBcIlJlY29ubmVjdFwiIH0gfSk7XG4gICAgc2V0SWNvbih0aGlzLnJlY29ubmVjdEJ0biwgXCJyZWZyZXNoLWN3XCIpO1xuICAgIHRoaXMucmVjb25uZWN0QnRuLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIHRoaXMucmVjb25uZWN0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICB2b2lkIHRoaXMucGx1Z2luLmNvbm5lY3RHYXRld2F5KCk7XG4gICAgfSk7XG4gICAgdGhpcy5zdGF0dXNFbCA9IHNlbmRXcmFwcGVyLmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1zdGF0dXMtZG90XCIpO1xuXG4gICAgLy8gRXZlbnRzXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoXCJrZXlkb3duXCIsIChlKSA9PiB7XG4gICAgICBpZiAoZS5rZXkgPT09IFwiRW50ZXJcIikge1xuICAgICAgICAvLyBNb2JpbGU6IEVudGVyIGFsd2F5cyBjcmVhdGVzIG5ldyBsaW5lICh1c2Ugc2VuZCBidXR0b24gdG8gc2VuZClcbiAgICAgICAgLy8gRGVza3RvcDogRW50ZXIgc2VuZHMsIFNoaWZ0K0VudGVyIGNyZWF0ZXMgbmV3IGxpbmVcbiAgICAgICAgaWYgKFBsYXRmb3JtLmlzTW9iaWxlKSB7XG4gICAgICAgICAgLy8gTGV0IEVudGVyIGNyZWF0ZSBhIG5ldyBsaW5lIG5hdHVyYWxseVxuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWUuc2hpZnRLZXkpIHtcbiAgICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgdm9pZCB0aGlzLnNlbmRNZXNzYWdlKCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcihcImlucHV0XCIsICgpID0+IHtcbiAgICAgIHRoaXMuYXV0b1Jlc2l6ZSgpO1xuICAgICAgdGhpcy51cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoXCJmb2N1c1wiLCAoKSA9PiB7XG4gICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgdGhpcy5pbnB1dEVsLnNjcm9sbEludG9WaWV3KHsgYmxvY2s6IFwiZW5kXCIsIGJlaGF2aW9yOiBcInNtb290aFwiIH0pO1xuICAgICAgfSwgMzAwKTtcbiAgICB9KTtcbiAgICAvLyBDbGlwYm9hcmQgcGFzdGU6IGNhcHR1cmUgaW1hZ2VzIGZyb20gY2xpcGJvYXJkXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoXCJwYXN0ZVwiLCAoZSkgPT4ge1xuICAgICAgY29uc3QgaXRlbXMgPSBlLmNsaXBib2FyZERhdGE/Lml0ZW1zO1xuICAgICAgaWYgKCFpdGVtcykgcmV0dXJuO1xuICAgICAgZm9yIChjb25zdCBpdGVtIG9mIEFycmF5LmZyb20oaXRlbXMpKSB7XG4gICAgICAgIGlmIChpdGVtLnR5cGUuc3RhcnRzV2l0aChcImltYWdlL1wiKSkge1xuICAgICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgICBjb25zdCBmaWxlID0gaXRlbS5nZXRBc0ZpbGUoKTtcbiAgICAgICAgICBpZiAoZmlsZSkgdm9pZCB0aGlzLmhhbmRsZVBhc3RlZEZpbGUoZmlsZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gICAgdGhpcy5zZW5kQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICBpZiAodGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKSB8fCB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZvaWQgdGhpcy5zZW5kTWVzc2FnZSgpO1xuICAgICAgfVxuICAgICAgLy8gVm9pY2UgcmVjb3JkaW5nIGRpc2FibGVkIFx1MjAxNCBiYXNlNjQgaW4gbWVzc2FnZSB0ZXh0IGJsb2F0cyBjb250ZXh0XG4gICAgfSk7XG4gICAgdGhpcy5hYm9ydEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCB0aGlzLmFib3J0TWVzc2FnZSgpKTtcblxuICAgIC8vIEluaXRpYWwgc3RhdGVcbiAgICB0aGlzLnVwZGF0ZVN0YXR1cygpO1xuICAgIHRoaXMucGx1Z2luLmNoYXRWaWV3ID0gdGhpcztcbiAgICBcbiAgICAvLyBJbml0IHRvdWNoIGdlc3R1cmVzIGZvciBtb2JpbGVcbiAgICB0aGlzLmluaXRUb3VjaEdlc3R1cmVzKCk7XG4gICAgXG4gICAgaWYgKHRoaXMucGx1Z2luLmdhdGV3YXlDb25uZWN0ZWQpIHtcbiAgICAgIGF3YWl0IHRoaXMubG9hZEhpc3RvcnkoKTtcbiAgICAgIHZvaWQgdGhpcy5sb2FkQWdlbnRzKCk7XG4gICAgfVxuICB9XG5cbiAgb25DbG9zZSgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5wbHVnaW4uY2hhdFZpZXcgPT09IHRoaXMpIHtcbiAgICAgIHRoaXMucGx1Z2luLmNoYXRWaWV3ID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICB1cGRhdGVTdGF0dXMoKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnN0YXR1c0VsKSByZXR1cm47XG4gICAgdGhpcy5zdGF0dXNFbC5yZW1vdmVDbGFzcyhcImNvbm5lY3RlZFwiLCBcImRpc2Nvbm5lY3RlZFwiKTtcbiAgICBjb25zdCBjb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi5nYXRld2F5Q29ubmVjdGVkO1xuICAgIHRoaXMuc3RhdHVzRWwuYWRkQ2xhc3MoY29ubmVjdGVkID8gXCJjb25uZWN0ZWRcIiA6IFwiZGlzY29ubmVjdGVkXCIpO1xuXG4gICAgLy8gU3dhcCBzZW5kIGJ1dHRvbiBmb3IgcmVjb25uZWN0IHdoZW4gZGlzY29ubmVjdGVkXG4gICAgaWYgKGNvbm5lY3RlZCkge1xuICAgICAgdGhpcy5zZW5kQnRuLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgaWYgKHRoaXMucmVjb25uZWN0QnRuKSB0aGlzLnJlY29ubmVjdEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIHRoaXMuaW5wdXRFbC5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgdGhpcy5pbnB1dEVsLnBsYWNlaG9sZGVyID0gXCJNZXNzYWdlLi4uXCI7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuc2VuZEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIGlmICh0aGlzLnJlY29ubmVjdEJ0bikgdGhpcy5yZWNvbm5lY3RCdG4ucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB0aGlzLmlucHV0RWwuZGlzYWJsZWQgPSB0cnVlO1xuICAgICAgdGhpcy5pbnB1dEVsLnBsYWNlaG9sZGVyID0gXCJEaXNjb25uZWN0ZWRcIjtcbiAgICB9XG4gIH1cblxuICAvKiogRmV0Y2ggYWxsIGFnZW50cyBmcm9tIHRoZSBnYXRld2F5IGFuZCBsb2FkIHRoZWlyIGlkZW50aXRpZXMgKi9cbiAgYXN5bmMgbG9hZEFnZW50cygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICAvLyBHZXQgYWdlbnQgbGlzdFxuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiYWdlbnRzLmxpc3RcIiwge30pIGFzIHsgYWdlbnRzPzogQWdlbnRMaXN0SXRlbVtdIH0gfCBudWxsO1xuICAgICAgY29uc3QgYWdlbnRMaXN0OiBBZ2VudExpc3RJdGVtW10gPSByZXN1bHQ/LmFnZW50cyB8fCBbXTtcbiAgICAgIGlmIChhZ2VudExpc3QubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIGFnZW50TGlzdC5wdXNoKHsgaWQ6IFwibWFpblwiIH0pO1xuICAgICAgfVxuXG4gICAgICAvLyBCdWlsZCBhZ2VudCBpbmZvIGZyb20gZ2F0ZXdheSBkYXRhIG9ubHkgXHUyMDE0IG5vIGZpbGUgcGFyc2luZ1xuICAgICAgY29uc3QgYWdlbnRzOiBBZ2VudEluZm9bXSA9IFtdO1xuICAgICAgZm9yIChjb25zdCBhIG9mIGFnZW50TGlzdCkge1xuICAgICAgICBhZ2VudHMucHVzaCh7XG4gICAgICAgICAgaWQ6IGEuaWQgfHwgXCJtYWluXCIsXG4gICAgICAgICAgbmFtZTogYS5uYW1lIHx8IGEuaWQgfHwgXCJBZ2VudFwiLFxuICAgICAgICAgIGVtb2ppOiBcIlx1RDgzRVx1REQxNlwiLFxuICAgICAgICAgIGNyZWF0dXJlOiBcIlwiLFxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5hZ2VudHMgPSBhZ2VudHM7XG5cbiAgICAgIC8vIFNldCBhY3RpdmUgYWdlbnRcbiAgICAgIGNvbnN0IHNhdmVkSWQgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY3RpdmVBZ2VudElkO1xuICAgICAgY29uc3QgYWN0aXZlID0gYWdlbnRzLmZpbmQoYSA9PiBhLmlkID09PSBzYXZlZElkKSB8fCBhZ2VudHNbMF07XG4gICAgICBpZiAoYWN0aXZlKSB7XG4gICAgICAgIHRoaXMuYWN0aXZlQWdlbnQgPSBhY3RpdmU7XG4gICAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY3RpdmVBZ2VudElkICE9PSBhY3RpdmUuaWQpIHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY3RpdmVBZ2VudElkID0gYWN0aXZlLmlkO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHRoaXMudXBkYXRlQWdlbnRCdXR0b24oKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLndhcm4oXCJbT2JzaWRpYW5DbGF3XSBGYWlsZWQgdG8gbG9hZCBhZ2VudHM6XCIsIGUpO1xuICAgIH1cbiAgfVxuXG4gIC8qKiBVcGRhdGUgdGhlIGFnZW50IGJ1dHRvbiBcdTIwMTQgaGlkZGVuIGZvciBzaW5nbGUgYWdlbnQsIHZpc2libGUgZm9yIG11bHRpICovXG4gIHByaXZhdGUgdXBkYXRlQWdlbnRCdXR0b24oKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnByb2ZpbGVCdG5FbCkgcmV0dXJuO1xuICAgIGlmICh0aGlzLmFnZW50cy5sZW5ndGggPD0gMSkge1xuICAgICAgdGhpcy5wcm9maWxlQnRuRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIHRoaXMucHJvZmlsZUJ0bkVsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIGNvbnN0IGVtb2ppID0gdGhpcy5hY3RpdmVBZ2VudC5lbW9qaSB8fCBcIlx1RDgzRVx1REQxNlwiO1xuICAgIHRoaXMucHJvZmlsZUJ0bkVsLmVtcHR5KCk7XG4gICAgdGhpcy5wcm9maWxlQnRuRWwuY3JlYXRlU3Bhbih7IHRleHQ6IGVtb2ppLCBjbHM6IFwib3BlbmNsYXctYWdlbnQtZW1vamlcIiB9KTtcbiAgfVxuXG4gIC8qKiBTd2l0Y2ggdG8gYSBkaWZmZXJlbnQgYWdlbnQgKi9cbiAgcHJpdmF0ZSBhc3luYyBzd2l0Y2hBZ2VudChhZ2VudDogQWdlbnRJbmZvKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGFnZW50LmlkID09PSB0aGlzLmFjdGl2ZUFnZW50LmlkKSByZXR1cm47XG4gICAgdGhpcy5hY3RpdmVBZ2VudCA9IGFnZW50O1xuICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjdGl2ZUFnZW50SWQgPSBhZ2VudC5pZDtcbiAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gXCJtYWluXCI7IC8vIHJlc2V0IHRvIG1haW4gc2Vzc2lvbiBvZiBuZXcgYWdlbnRcbiAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICB0aGlzLnVwZGF0ZUFnZW50QnV0dG9uKCk7XG4gICAgYXdhaXQgdGhpcy5sb2FkSGlzdG9yeSgpO1xuICAgIGF3YWl0IHRoaXMucmVuZGVyVGFicygpO1xuICB9XG5cbiAgLyoqIFRvZ2dsZSB0aGUgYWdlbnQgc3dpdGNoZXIgZHJvcGRvd24gKi9cbiAgcHJpdmF0ZSB0b2dnbGVBZ2VudFN3aXRjaGVyKCk6IHZvaWQge1xuICAgIGlmICghdGhpcy5wcm9maWxlRHJvcGRvd25FbCkgcmV0dXJuO1xuICAgIGNvbnN0IHZpc2libGUgPSAhdGhpcy5wcm9maWxlRHJvcGRvd25FbC5oYXNDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICBpZiAodmlzaWJsZSkge1xuICAgICAgdGhpcy5wcm9maWxlRHJvcGRvd25FbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdGhpcy5wcm9maWxlRHJvcGRvd25FbC5lbXB0eSgpO1xuXG4gICAgZm9yIChjb25zdCBhZ2VudCBvZiB0aGlzLmFnZW50cykge1xuICAgICAgY29uc3QgaXNBY3RpdmUgPSBhZ2VudC5pZCA9PT0gdGhpcy5hY3RpdmVBZ2VudC5pZDtcbiAgICAgIGNvbnN0IGl0ZW0gPSB0aGlzLnByb2ZpbGVEcm9wZG93bkVsLmNyZWF0ZURpdih7IGNsczogYG9wZW5jbGF3LWFnZW50LWl0ZW0ke2lzQWN0aXZlID8gXCIgYWN0aXZlXCIgOiBcIlwifWAgfSk7XG4gICAgICBpdGVtLmNyZWF0ZVNwYW4oeyB0ZXh0OiBhZ2VudC5lbW9qaSB8fCBcIlx1RDgzRVx1REQxNlwiLCBjbHM6IFwib3BlbmNsYXctYWdlbnQtaXRlbS1lbW9qaVwiIH0pO1xuICAgICAgY29uc3QgaW5mbyA9IGl0ZW0uY3JlYXRlRGl2KFwib3BlbmNsYXctYWdlbnQtaXRlbS1pbmZvXCIpO1xuICAgICAgaW5mby5jcmVhdGVEaXYoeyB0ZXh0OiBhZ2VudC5uYW1lLCBjbHM6IFwib3BlbmNsYXctYWdlbnQtaXRlbS1uYW1lXCIgfSk7XG4gICAgICBpZiAoYWdlbnQuY3JlYXR1cmUpIHtcbiAgICAgICAgaW5mby5jcmVhdGVEaXYoeyB0ZXh0OiBhZ2VudC5jcmVhdHVyZSwgY2xzOiBcIm9wZW5jbGF3LWFnZW50LWl0ZW0tc3ViXCIgfSk7XG4gICAgICB9XG4gICAgICBpZiAoIWlzQWN0aXZlKSB7XG4gICAgICAgIGl0ZW0uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgICAgICB0aGlzLnByb2ZpbGVEcm9wZG93bkVsIS5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB2b2lkIHRoaXMuc3dpdGNoQWdlbnQoYWdlbnQpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aGlzLnByb2ZpbGVEcm9wZG93bkVsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICB9XG5cbiAgYXN5bmMgbG9hZEhpc3RvcnkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiY2hhdC5oaXN0b3J5XCIsIHtcbiAgICAgICAgc2Vzc2lvbktleTogdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSxcbiAgICAgICAgbGltaXQ6IDIwMCxcbiAgICAgIH0pIGFzIHsgbWVzc2FnZXM/OiBIaXN0b3J5TWVzc2FnZVtdIH0gfCBudWxsO1xuICAgICAgaWYgKHJlc3VsdD8ubWVzc2FnZXMgJiYgQXJyYXkuaXNBcnJheShyZXN1bHQubWVzc2FnZXMpKSB7XG4gICAgICAgIHRoaXMubWVzc2FnZXMgPSByZXN1bHQubWVzc2FnZXNcbiAgICAgICAgICAuZmlsdGVyKChtOiBIaXN0b3J5TWVzc2FnZSkgPT4gbS5yb2xlID09PSBcInVzZXJcIiB8fCBtLnJvbGUgPT09IFwiYXNzaXN0YW50XCIpXG4gICAgICAgICAgLm1hcCgobTogSGlzdG9yeU1lc3NhZ2UpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IHsgdGV4dCwgaW1hZ2VzIH0gPSB0aGlzLmV4dHJhY3RDb250ZW50KG0uY29udGVudCk7XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICByb2xlOiBtLnJvbGUgYXMgXCJ1c2VyXCIgfCBcImFzc2lzdGFudFwiLFxuICAgICAgICAgICAgICB0ZXh0LFxuICAgICAgICAgICAgICBpbWFnZXMsXG4gICAgICAgICAgICAgIHRpbWVzdGFtcDogbS50aW1lc3RhbXAgPz8gRGF0ZS5ub3coKSxcbiAgICAgICAgICAgICAgY29udGVudEJsb2NrczogQXJyYXkuaXNBcnJheShtLmNvbnRlbnQpID8gbS5jb250ZW50IDogdW5kZWZpbmVkLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9KVxuICAgICAgICAgIC5maWx0ZXIoKG06IENoYXRNZXNzYWdlKSA9PiAobS50ZXh0LnRyaW0oKSB8fCBtLmltYWdlcy5sZW5ndGggPiAwKSAmJiAhbS50ZXh0LnN0YXJ0c1dpdGgoXCJIRUFSVEJFQVRcIikpO1xuXG4gICAgICAgIC8vIEhpZGUgdGhlIGZpcnN0IHVzZXIgbWVzc2FnZSAodHlwaWNhbGx5IHRoZSAvbmV3IG9yIC9yZXNldCBzeXN0ZW0gcHJvbXB0KVxuICAgICAgICBpZiAodGhpcy5tZXNzYWdlcy5sZW5ndGggPiAwICYmIHRoaXMubWVzc2FnZXNbMF0ucm9sZSA9PT0gXCJ1c2VyXCIpIHtcbiAgICAgICAgICB0aGlzLm1lc3NhZ2VzID0gdGhpcy5tZXNzYWdlcy5zbGljZSgxKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIE5vIHBvc3QtcHJvY2Vzc2luZyBuZWVkZWQ6IFZPSUNFOiByZWZzIGFyZSBpbiB0aGUgYXNzaXN0YW50IG1lc3NhZ2UgdGV4dCBpdHNlbGZcblxuICAgICAgICBhd2FpdCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG4gICAgICAgIHZvaWQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKFwiW09ic2lkaWFuQ2xhd10gRmFpbGVkIHRvIGxvYWQgaGlzdG9yeTpcIiwgZSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBleHRyYWN0Q29udGVudChjb250ZW50OiBzdHJpbmcgfCBDb250ZW50QmxvY2tbXSB8IHVuZGVmaW5lZCk6IHsgdGV4dDogc3RyaW5nOyBpbWFnZXM6IHN0cmluZ1tdIH0ge1xuICAgIGxldCB0ZXh0ID0gXCJcIjtcbiAgICBjb25zdCBpbWFnZXM6IHN0cmluZ1tdID0gW107XG5cbiAgICBpZiAodHlwZW9mIGNvbnRlbnQgPT09IFwic3RyaW5nXCIpIHtcbiAgICAgIHRleHQgPSBjb250ZW50O1xuICAgIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgICAgZm9yIChjb25zdCBjIG9mIGNvbnRlbnQpIHtcbiAgICAgICAgaWYgKGMudHlwZSA9PT0gXCJ0ZXh0XCIpIHtcbiAgICAgICAgICB0ZXh0ICs9ICh0ZXh0ID8gXCJcXG5cIiA6IFwiXCIpICsgYy50ZXh0O1xuICAgICAgICB9IGVsc2UgaWYgKGMudHlwZSA9PT0gXCJ0b29sX3Jlc3VsdFwiKSB7XG4gICAgICAgICAgLy8gRXh0cmFjdCB0ZXh0IGZyb20gdG9vbF9yZXN1bHQgY29udGVudCAoZS5nLiwgVFRTIE1FRElBOiBwYXRocylcbiAgICAgICAgICBjb25zdCB0ckNvbnRlbnQgPSBjLmNvbnRlbnQ7XG4gICAgICAgICAgaWYgKHR5cGVvZiB0ckNvbnRlbnQgPT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgICAgIHRleHQgKz0gKHRleHQgPyBcIlxcblwiIDogXCJcIikgKyB0ckNvbnRlbnQ7XG4gICAgICAgICAgfSBlbHNlIGlmIChBcnJheS5pc0FycmF5KHRyQ29udGVudCkpIHtcbiAgICAgICAgICAgIGZvciAoY29uc3QgdGMgb2YgdHJDb250ZW50KSB7XG4gICAgICAgICAgICAgIGlmICh0Yz8udHlwZSA9PT0gXCJ0ZXh0XCIgJiYgdGMudGV4dCkgdGV4dCArPSAodGV4dCA/IFwiXFxuXCIgOiBcIlwiKSArIHRjLnRleHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgaWYgKGMudHlwZSA9PT0gXCJpbWFnZV91cmxcIiAmJiBjLmltYWdlX3VybD8udXJsKSB7XG4gICAgICAgICAgaW1hZ2VzLnB1c2goYy5pbWFnZV91cmwudXJsKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEV4dHJhY3QgdmF1bHQgaW1hZ2UgcGF0aHMgZnJvbSBcIkZpbGUgc2F2ZWQgYXQ6XCIgbGluZXNcbiAgICBjb25zdCBzYXZlZEF0UmVnZXggPSAvRmlsZSBzYXZlZCBhdDpcXHMqKC4rP29wZW5jbGF3LWF0dGFjaG1lbnRzXFwvW15cXHNcXG5dKykvZztcbiAgICBsZXQgbWF0Y2g7XG4gICAgd2hpbGUgKChtYXRjaCA9IHNhdmVkQXRSZWdleC5leGVjKHRleHQpKSAhPT0gbnVsbCkge1xuICAgICAgLy8gVHJ5IHRvIHJlc29sdmUgYXMgdmF1bHQtcmVsYXRpdmUgcGF0aFxuICAgICAgY29uc3QgZnVsbFBhdGggPSBtYXRjaFsxXS50cmltKCk7XG4gICAgICBjb25zdCB2YXVsdFJlbGF0aXZlID0gZnVsbFBhdGguaW5jbHVkZXMoXCJvcGVuY2xhdy1hdHRhY2htZW50cy9cIilcbiAgICAgICAgPyBcIm9wZW5jbGF3LWF0dGFjaG1lbnRzL1wiICsgZnVsbFBhdGguc3BsaXQoXCJvcGVuY2xhdy1hdHRhY2htZW50cy9cIilbMV1cbiAgICAgICAgOiBudWxsO1xuICAgICAgaWYgKHZhdWx0UmVsYXRpdmUpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCByZXNvdXJjZVBhdGggPSB0aGlzLmFwcC52YXVsdC5hZGFwdGVyLmdldFJlc291cmNlUGF0aCh2YXVsdFJlbGF0aXZlKTtcbiAgICAgICAgICBpZiAocmVzb3VyY2VQYXRoKSBpbWFnZXMucHVzaChyZXNvdXJjZVBhdGgpO1xuICAgICAgICB9IGNhdGNoIHsgLyogaWdub3JlICovIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBFeHRyYWN0IGlubGluZSBkYXRhIFVSSXMgZnJvbSB0ZXh0IChsZWdhY3kpXG4gICAgY29uc3QgZGF0YVVyaVJlZ2V4ID0gLyg/Ol58XFxuKWRhdGE6KGltYWdlXFwvW147XSspO2Jhc2U2NCxbQS1aYS16MC05Ky89XFxuXSsvZztcbiAgICB3aGlsZSAoKG1hdGNoID0gZGF0YVVyaVJlZ2V4LmV4ZWModGV4dCkpICE9PSBudWxsKSB7XG4gICAgICBpbWFnZXMucHVzaChtYXRjaFswXS5yZXBsYWNlKC9eXFxuLywgXCJcIikudHJpbSgpKTtcbiAgICB9XG4gICAgLy8gUmVtb3ZlIGRhdGEgVVJJcyBmcm9tIHRleHQgZGlzcGxheVxuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL1xcbj9kYXRhOmltYWdlXFwvW147XSs7YmFzZTY0LFtBLVphLXowLTkrLz1cXG5dKy9nLCBcIlwiKS50cmltKCk7XG4gICAgLy8gU3RyaXAgW0F0dGFjaGVkIGltYWdlOiAuLi5dIGFuZCBcIkZpbGUgc2F2ZWQgYXQ6XCIgbGluZXNcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eXFxbQXR0YWNoZWQgaW1hZ2U6Lio/XFxdXFxzKi9nbSwgXCJcIikudHJpbSgpO1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15GaWxlIHNhdmVkIGF0Oi4qJC9nbSwgXCJcIikudHJpbSgpO1xuXG4gICAgLy8gU3RyaXAgZ2F0ZXdheSBtZXRhZGF0YSBibG9ja3MgKENvbnZlcnNhdGlvbiBpbmZvICsgSlNPTiBjb2RlIGJsb2NrKVxuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL0NvbnZlcnNhdGlvbiBpbmZvIFxcKHVudHJ1c3RlZCBtZXRhZGF0YVxcKTpcXHMqYGBganNvbltcXHNcXFNdKj9gYGBcXHMqL2csIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBhbnkgcmVtYWluaW5nIHN0YW5kYWxvbmUgbWV0YWRhdGEgSlNPTiBibG9ja3NcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eYGBganNvblxccypcXHtcXHMqXCJtZXNzYWdlX2lkXCJbXFxzXFxTXSo/YGBgXFxzKi9nbSwgXCJcIikudHJpbSgpO1xuICAgIC8vIFN0cmlwIHRpbWVzdGFtcCBwcmVmaXhlcyBsaWtlIFwiW1N1biAyMDI2LTAyLTIyIDIxOjU4IEdNVCs3XSBcIlxuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15cXFsuKj9HTVRbKy1dXFxkK1xcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBtZWRpYSBhdHRhY2htZW50IGxpbmVzXG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXlxcW21lZGlhIGF0dGFjaGVkOi4qP1xcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBcIlRvIHNlbmQgYW4gaW1hZ2UgYmFjay4uLlwiIGluc3RydWN0aW9uIGxpbmVzXG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXlRvIHNlbmQgYW4gaW1hZ2UgYmFjay4qJC9nbSwgXCJcIikudHJpbSgpO1xuICAgIC8vIFN0cmlwIFwiTk9fUkVQTFlcIiByZXNwb25zZXNcbiAgICBpZiAodGV4dCA9PT0gXCJOT19SRVBMWVwiIHx8IHRleHQgPT09IFwiSEVBUlRCRUFUX09LXCIpIHRleHQgPSBcIlwiO1xuICAgIHJldHVybiB7IHRleHQsIGltYWdlcyB9O1xuICB9XG5cbiAgcHJpdmF0ZSB1cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpIHx8IHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyaWJ1dGUoXCJhcmlhLWxhYmVsXCIsIFwiU2VuZFwiKTtcbiAgICAgIHRoaXMuc2VuZEJ0bi5yZW1vdmVDbGFzcyhcIm9jLW9wYWNpdHktbG93XCIpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cmlidXRlKFwiYXJpYS1sYWJlbFwiLCBcIlNlbmRcIik7XG4gICAgICB0aGlzLnNlbmRCdG4uYWRkQ2xhc3MoXCJvYy1vcGFjaXR5LWxvd1wiKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHN0YXJ0UmVjb3JkaW5nKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzdHJlYW0gPSBhd2FpdCBuYXZpZ2F0b3IubWVkaWFEZXZpY2VzLmdldFVzZXJNZWRpYSh7IGF1ZGlvOiB0cnVlIH0pO1xuICAgICAgdGhpcy5yZWNvcmRlZENodW5rcyA9IFtdO1xuXG4gICAgICAvLyBUcnkgb3B1cyBmaXJzdCwgZmFsbCBiYWNrIHRvIGRlZmF1bHRcbiAgICAgIGNvbnN0IG1pbWVUeXBlID0gTWVkaWFSZWNvcmRlci5pc1R5cGVTdXBwb3J0ZWQoXCJhdWRpby93ZWJtO2NvZGVjcz1vcHVzXCIpXG4gICAgICAgID8gXCJhdWRpby93ZWJtO2NvZGVjcz1vcHVzXCJcbiAgICAgICAgOiBNZWRpYVJlY29yZGVyLmlzVHlwZVN1cHBvcnRlZChcImF1ZGlvL3dlYm1cIilcbiAgICAgICAgPyBcImF1ZGlvL3dlYm1cIlxuICAgICAgICA6IFwiXCI7XG5cbiAgICAgIHRoaXMubWVkaWFSZWNvcmRlciA9IG5ldyBNZWRpYVJlY29yZGVyKHN0cmVhbSwgbWltZVR5cGUgPyB7IG1pbWVUeXBlIH0gOiB7fSk7XG4gICAgICB0aGlzLm1lZGlhUmVjb3JkZXIuYWRkRXZlbnRMaXN0ZW5lcihcImRhdGFhdmFpbGFibGVcIiwgKGUpID0+IHtcbiAgICAgICAgaWYgKGUuZGF0YS5zaXplID4gMCkgdGhpcy5yZWNvcmRlZENodW5rcy5wdXNoKGUuZGF0YSk7XG4gICAgICB9KTtcbiAgICAgIHRoaXMubWVkaWFSZWNvcmRlci5hZGRFdmVudExpc3RlbmVyKFwic3RvcFwiLCAoKSA9PiB7XG4gICAgICAgIHN0cmVhbS5nZXRUcmFja3MoKS5mb3JFYWNoKHQgPT4gdC5zdG9wKCkpO1xuICAgICAgICB2b2lkIHRoaXMuZmluaXNoUmVjb3JkaW5nKCk7XG4gICAgICB9KTtcblxuICAgICAgdGhpcy5tZWRpYVJlY29yZGVyLnN0YXJ0KCk7XG4gICAgICB0aGlzLnJlY29yZGluZyA9IHRydWU7XG4gICAgICB0aGlzLnVwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICAgIHRoaXMuaW5wdXRFbC5wbGFjZWhvbGRlciA9IFwiUmVjb3JkaW5nLi4uIHRhcCBcdTI1QTAgdG8gc3RvcFwiO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoXCJbT2JzaWRpYW5DbGF3XSBNaWMgYWNjZXNzIGZhaWxlZDpcIiwgZSk7XG4gICAgICBuZXcgTm90aWNlKFwiTWljcm9waG9uZSBhY2Nlc3MgZGVuaWVkXCIpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgc3RvcFJlY29yZGluZygpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5tZWRpYVJlY29yZGVyICYmIHRoaXMubWVkaWFSZWNvcmRlci5zdGF0ZSAhPT0gXCJpbmFjdGl2ZVwiKSB7XG4gICAgICB0aGlzLm1lZGlhUmVjb3JkZXIuc3RvcCgpO1xuICAgIH1cbiAgICB0aGlzLnJlY29yZGluZyA9IGZhbHNlO1xuICAgIHRoaXMudXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIHRoaXMuaW5wdXRFbC5wbGFjZWhvbGRlciA9IFwiTWVzc2FnZS4uLlwiO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBmaW5pc2hSZWNvcmRpbmcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMucmVjb3JkZWRDaHVua3MubGVuZ3RoID09PSAwKSByZXR1cm47XG4gICAgY29uc3QgYmxvYiA9IG5ldyBCbG9iKHRoaXMucmVjb3JkZWRDaHVua3MsIHsgdHlwZTogdGhpcy5tZWRpYVJlY29yZGVyPy5taW1lVHlwZSB8fCBcImF1ZGlvL3dlYm1cIiB9KTtcbiAgICB0aGlzLnJlY29yZGVkQ2h1bmtzID0gW107XG5cbiAgICAvLyBDb252ZXJ0IHRvIGJhc2U2NFxuICAgIGNvbnN0IGFycmF5QnVmID0gYXdhaXQgYmxvYi5hcnJheUJ1ZmZlcigpO1xuICAgIGNvbnN0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWYpO1xuICAgIGxldCBiaW5hcnkgPSBcIlwiO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYnl0ZXMubGVuZ3RoOyBpKyspIGJpbmFyeSArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVzW2ldKTtcbiAgICBjb25zdCBiNjQgPSBidG9hKGJpbmFyeSk7XG4gICAgY29uc3QgbWltZSA9IGJsb2IudHlwZSB8fCBcImF1ZGlvL3dlYm1cIjtcblxuICAgIC8vIFVwbG9hZCB0byBnYXRld2F5IHN0YXRpYyBkaXIgdmlhIHRoZSBhZ2VudCAoZXhlYyksIGFuZCBzZW5kIFZPSUNFOiByZWZcbiAgICAvLyBGb3Igbm93OiBzZW5kIGFzIEFVRElPX0RBVEEgaW4gbWVzc2FnZSB0ZXh0LCBhZ2VudCBoYW5kbGVzIHRyYW5zY3JpcHRpb25cbiAgICBjb25zdCBtYXJrZXIgPSBgQVVESU9fREFUQToke21pbWV9O2Jhc2U2NCwke2I2NH1gO1xuXG4gICAgLy8gU2hvdyB2b2ljZSBtZXNzYWdlIGluIGxvY2FsIFVJXG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKHsgcm9sZTogXCJ1c2VyXCIsIHRleHQ6IFwiXHVEODNDXHVERkE0IFZvaWNlIG1lc3NhZ2VcIiwgaW1hZ2VzOiBbXSwgdGltZXN0YW1wOiBEYXRlLm5vdygpIH0pO1xuICAgIGF3YWl0IHRoaXMucmVuZGVyTWVzc2FnZXMoKTtcblxuICAgIC8vIFNlbmQgdG8gZ2F0ZXdheVxuICAgIGNvbnN0IHJ1bklkID0gZ2VuZXJhdGVJZCgpO1xuICAgIGNvbnN0IHNlbmRTZXNzaW9uS2V5ID0gdGhpcy5hY3RpdmVTZXNzaW9uS2V5O1xuICAgIGNvbnN0IHNzID0ge1xuICAgICAgcnVuSWQsXG4gICAgICB0ZXh0OiBcIlwiIGFzIHN0cmluZyB8IG51bGwsXG4gICAgICB0b29sQ2FsbHM6IFtdIGFzIHN0cmluZ1tdLFxuICAgICAgaXRlbXM6IFtdIGFzIFN0cmVhbUl0ZW1bXSxcbiAgICAgIHNwbGl0UG9pbnRzOiBbXSBhcyBudW1iZXJbXSxcbiAgICAgIGxhc3REZWx0YVRpbWU6IDAsXG4gICAgICBjb21wYWN0VGltZXI6IG51bGwgYXMgUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsLFxuICAgICAgd29ya2luZ1RpbWVyOiBudWxsIGFzIFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCxcbiAgICB9O1xuICAgIHRoaXMuc3RyZWFtcy5zZXQoc2VuZFNlc3Npb25LZXksIHNzKTtcbiAgICB0aGlzLnJ1blRvU2Vzc2lvbi5zZXQocnVuSWQsIHNlbmRTZXNzaW9uS2V5KTtcbiAgICB0aGlzLmFib3J0QnRuLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgY29uc3QgdGhpbmtUZXh0ID0gdGhpcy50eXBpbmdFbC5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LXR5cGluZy10ZXh0XCIpO1xuICAgIGlmICh0aGlua1RleHQpIHRoaW5rVGV4dC50ZXh0Q29udGVudCA9IFwiVGhpbmtpbmdcIjtcbiAgICB0aGlzLnNjcm9sbFRvQm90dG9tKCk7XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiY2hhdC5zZW5kXCIsIHtcbiAgICAgICAgc2Vzc2lvbktleTogc2VuZFNlc3Npb25LZXksXG4gICAgICAgIG1lc3NhZ2U6IG1hcmtlcixcbiAgICAgICAgZGVsaXZlcjogZmFsc2UsXG4gICAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIHRoaXMubWVzc2FnZXMucHVzaCh7IHJvbGU6IFwiYXNzaXN0YW50XCIsIHRleHQ6IGBFcnJvcjogJHtlfWAsIGltYWdlczogW10sIHRpbWVzdGFtcDogRGF0ZS5ub3coKSB9KTtcbiAgICAgIHRoaXMuc3RyZWFtcy5kZWxldGUoc2VuZFNlc3Npb25LZXkpO1xuICAgICAgdGhpcy5ydW5Ub1Nlc3Npb24uZGVsZXRlKHJ1bklkKTtcbiAgICAgIHRoaXMuYWJvcnRCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICBhd2FpdCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgc2VuZE1lc3NhZ2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgbGV0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGNvbnN0IGhhc0F0dGFjaG1lbnRzID0gdGhpcy5wZW5kaW5nQXR0YWNobWVudHMubGVuZ3RoID4gMDtcbiAgICBpZiAoIXRleHQgJiYgIWhhc0F0dGFjaG1lbnRzKSByZXR1cm47XG4gICAgaWYgKHRoaXMuc2VuZGluZykgcmV0dXJuO1xuICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSB7XG4gICAgICBuZXcgTm90aWNlKFwiTm90IGNvbm5lY3RlZCB0byBPcGVuQ2xhdyBnYXRld2F5XCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMuc2VuZGluZyA9IHRydWU7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gdHJ1ZTtcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSBcIlwiO1xuICAgIHRoaXMuYXV0b1Jlc2l6ZSgpO1xuXG4gICAgLy8gQnVpbGQgYXR0YWNobWVudHMgZm9yIGdhdGV3YXlcbiAgICBsZXQgZnVsbE1lc3NhZ2UgPSB0ZXh0O1xuICAgIGNvbnN0IGRpc3BsYXlUZXh0ID0gdGV4dDtcbiAgICBjb25zdCB1c2VySW1hZ2VzOiBzdHJpbmdbXSA9IFtdO1xuICAgIGNvbnN0IGdhdGV3YXlBdHRhY2htZW50czogeyB0eXBlOiBzdHJpbmc7IG1pbWVUeXBlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcbiAgICBpZiAodGhpcy5wZW5kaW5nQXR0YWNobWVudHMubGVuZ3RoID4gMCkge1xuICAgICAgZm9yIChjb25zdCBhdHQgb2YgdGhpcy5wZW5kaW5nQXR0YWNobWVudHMpIHtcbiAgICAgICAgaWYgKGF0dC5iYXNlNjQgJiYgYXR0Lm1pbWVUeXBlKSB7XG4gICAgICAgICAgLy8gSW1hZ2U6IHNlbmQgdmlhIGF0dGFjaG1lbnRzIGZpZWxkIChnYXRld2F5IHNhdmVzIHRvIGRpc2spXG4gICAgICAgICAgZ2F0ZXdheUF0dGFjaG1lbnRzLnB1c2goeyB0eXBlOiBcImltYWdlXCIsIG1pbWVUeXBlOiBhdHQubWltZVR5cGUsIGNvbnRlbnQ6IGF0dC5iYXNlNjQgfSk7XG4gICAgICAgICAgLy8gU2hvdyBwcmV2aWV3IGluIGNoYXQgaGlzdG9yeVxuICAgICAgICAgIHVzZXJJbWFnZXMucHVzaChgZGF0YToke2F0dC5taW1lVHlwZX07YmFzZTY0LCR7YXR0LmJhc2U2NH1gKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAvLyBUZXh0IGZpbGVzOiBhcHBlbmQgdG8gbWVzc2FnZSBhcyBiZWZvcmVcbiAgICAgICAgICBmdWxsTWVzc2FnZSA9IChmdWxsTWVzc2FnZSA/IGZ1bGxNZXNzYWdlICsgXCJcXG5cXG5cIiA6IFwiXCIpICsgYXR0LmNvbnRlbnQ7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmICghdGV4dCkge1xuICAgICAgICB0ZXh0ID0gYFx1RDgzRFx1RENDRSAke3RoaXMucGVuZGluZ0F0dGFjaG1lbnRzLm1hcChhID0+IGEubmFtZSkuam9pbihcIiwgXCIpfWA7XG4gICAgICAgIGZ1bGxNZXNzYWdlID0gdGV4dDtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzID0gW107XG4gICAgICB0aGlzLmF0dGFjaFByZXZpZXdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB9XG5cbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2goeyByb2xlOiBcInVzZXJcIiwgdGV4dDogZGlzcGxheVRleHQgfHwgdGV4dCwgaW1hZ2VzOiB1c2VySW1hZ2VzLCB0aW1lc3RhbXA6IERhdGUubm93KCkgfSk7XG4gICAgYXdhaXQgdGhpcy5yZW5kZXJNZXNzYWdlcygpO1xuXG4gICAgY29uc3QgcnVuSWQgPSBnZW5lcmF0ZUlkKCk7XG4gICAgY29uc3Qgc2VuZFNlc3Npb25LZXkgPSB0aGlzLmFjdGl2ZVNlc3Npb25LZXk7XG5cbiAgICAvLyBDcmVhdGUgcGVyLXNlc3Npb24gc3RyZWFtIHN0YXRlXG4gICAgY29uc3Qgc3MgPSB7XG4gICAgICBydW5JZCxcbiAgICAgIHRleHQ6IFwiXCIgYXMgc3RyaW5nIHwgbnVsbCxcbiAgICAgIHRvb2xDYWxsczogW10gYXMgc3RyaW5nW10sXG4gICAgICBpdGVtczogW10gYXMgU3RyZWFtSXRlbVtdLFxuICAgICAgc3BsaXRQb2ludHM6IFtdIGFzIG51bWJlcltdLFxuICAgICAgbGFzdERlbHRhVGltZTogMCxcbiAgICAgIGNvbXBhY3RUaW1lcjogbnVsbCBhcyBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwsXG4gICAgICB3b3JraW5nVGltZXI6IG51bGwgYXMgUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsLFxuICAgIH07XG4gICAgdGhpcy5zdHJlYW1zLnNldChzZW5kU2Vzc2lvbktleSwgc3MpO1xuICAgIHRoaXMucnVuVG9TZXNzaW9uLnNldChydW5JZCwgc2VuZFNlc3Npb25LZXkpO1xuXG4gICAgLy8gU2hvdyBVSSBmb3IgYWN0aXZlIHRhYlxuICAgIHRoaXMuYWJvcnRCdG4ucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICBjb25zdCB0aGlua1RleHQgPSB0aGlzLnR5cGluZ0VsLnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdHlwaW5nLXRleHRcIik7XG4gICAgaWYgKHRoaW5rVGV4dCkgdGhpbmtUZXh0LnRleHRDb250ZW50ID0gXCJUaGlua2luZ1wiO1xuICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTtcblxuICAgIC8vIEZhbGxiYWNrOiBpZiBubyBldmVudHMgYXQgYWxsIGFmdGVyIDE1cywgc2hvdyBnZW5lcmljIHN0YXR1c1xuICAgIHNzLmNvbXBhY3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgY29uc3QgY3VycmVudCA9IHRoaXMuc3RyZWFtcy5nZXQoc2VuZFNlc3Npb25LZXkpO1xuICAgICAgaWYgKGN1cnJlbnQ/LnJ1bklkID09PSBydW5JZCAmJiAhY3VycmVudC50ZXh0KSB7XG4gICAgICAgIC8vIE9ubHkgdXBkYXRlIERPTSBpZiB0aGlzIHNlc3Npb24gaXMgc3RpbGwgYWN0aXZlIHRhYlxuICAgICAgICBpZiAodGhpcy5hY3RpdmVTZXNzaW9uS2V5ID09PSBzZW5kU2Vzc2lvbktleSkge1xuICAgICAgICAgIGNvbnN0IHR0ID0gdGhpcy50eXBpbmdFbC5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LXR5cGluZy10ZXh0XCIpO1xuICAgICAgICAgIGlmICh0dCAmJiB0dC50ZXh0Q29udGVudCA9PT0gXCJUaGlua2luZ1wiKSB0dC50ZXh0Q29udGVudCA9IFwiU3RpbGwgdGhpbmtpbmdcIjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0sIDE1MDAwKTtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBzZW5kUGFyYW1zOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9IHtcbiAgICAgICAgc2Vzc2lvbktleTogc2VuZFNlc3Npb25LZXksXG4gICAgICAgIG1lc3NhZ2U6IGZ1bGxNZXNzYWdlLFxuICAgICAgICBkZWxpdmVyOiBmYWxzZSxcbiAgICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgfTtcbiAgICAgIGlmIChnYXRld2F5QXR0YWNobWVudHMubGVuZ3RoID4gMCkge1xuICAgICAgICBzZW5kUGFyYW1zLmF0dGFjaG1lbnRzID0gZ2F0ZXdheUF0dGFjaG1lbnRzO1xuICAgICAgfVxuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiY2hhdC5zZW5kXCIsIHNlbmRQYXJhbXMpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGlmIChzcy5jb21wYWN0VGltZXIpIGNsZWFyVGltZW91dChzcy5jb21wYWN0VGltZXIpO1xuICAgICAgdGhpcy5tZXNzYWdlcy5wdXNoKHsgcm9sZTogXCJhc3Npc3RhbnRcIiwgdGV4dDogYEVycm9yOiAke2V9YCwgaW1hZ2VzOiBbXSwgdGltZXN0YW1wOiBEYXRlLm5vdygpIH0pO1xuICAgICAgdGhpcy5zdHJlYW1zLmRlbGV0ZShzZW5kU2Vzc2lvbktleSk7XG4gICAgICB0aGlzLnJ1blRvU2Vzc2lvbi5kZWxldGUocnVuSWQpO1xuICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIGF3YWl0IHRoaXMucmVuZGVyTWVzc2FnZXMoKTtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgdGhpcy5zZW5kaW5nID0gZmFsc2U7XG4gICAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBhYm9ydE1lc3NhZ2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3Qgc3MgPSB0aGlzLmFjdGl2ZVN0cmVhbTtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCB8fCAhc3MpIHJldHVybjtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiY2hhdC5hYm9ydFwiLCB7XG4gICAgICAgIHNlc3Npb25LZXk6IHRoaXMuYWN0aXZlU2Vzc2lvbktleSxcbiAgICAgICAgcnVuSWQ6IHNzLnJ1bklkLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG4gIH1cblxuICBhc3luYyB1cGRhdGVDb250ZXh0TWV0ZXIoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwic2Vzc2lvbnMubGlzdFwiLCB7fSkgYXMgeyBzZXNzaW9ucz86IFNlc3Npb25JbmZvW10gfSB8IG51bGw7XG4gICAgICBjb25zdCBzZXNzaW9uczogU2Vzc2lvbkluZm9bXSA9IHJlc3VsdD8uc2Vzc2lvbnMgfHwgW107XG4gICAgICAvLyBGaW5kIHNlc3Npb24gbWF0Y2hpbmcgY3VycmVudCBzZXNzaW9uS2V5ICh0cnkgZXhhY3QgbWF0Y2gsIHRoZW4gd2l0aCBhZ2VudCBwcmVmaXgpXG4gICAgICBjb25zdCBzayA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgfHwgXCJtYWluXCI7XG4gICAgICBjb25zdCBzZXNzaW9uID0gc2Vzc2lvbnMuZmluZCgoczogU2Vzc2lvbkluZm8pID0+IHMua2V5ID09PSBzaykgfHxcbiAgICAgICAgc2Vzc2lvbnMuZmluZCgoczogU2Vzc2lvbkluZm8pID0+IHMua2V5ID09PSBgJHt0aGlzLmFnZW50UHJlZml4fSR7c2t9YCkgfHxcbiAgICAgICAgc2Vzc2lvbnMuZmluZCgoczogU2Vzc2lvbkluZm8pID0+IHMua2V5LmVuZHNXaXRoKGA6JHtza31gKSk7XG4gICAgICBpZiAoIXNlc3Npb24pIHJldHVybjtcbiAgICAgIGNvbnN0IHVzZWQgPSBzZXNzaW9uLnRvdGFsVG9rZW5zIHx8IDA7XG4gICAgICBjb25zdCBtYXggPSBzZXNzaW9uLmNvbnRleHRUb2tlbnMgfHwgMjAwMDAwO1xuICAgICAgY29uc3QgcGN0ID0gTWF0aC5taW4oMTAwLCBNYXRoLnJvdW5kKCh1c2VkIC8gbWF4KSAqIDEwMCkpO1xuICAgICAgdGhpcy5jb250ZXh0RmlsbEVsLnNldENzc1N0eWxlcyh7IHdpZHRoOiBwY3QgKyBcIiVcIiB9KTtcbiAgICAgIHRoaXMuY29udGV4dEZpbGxFbC5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LWNvbnRleHQtZmlsbFwiICsgKHBjdCA+IDgwID8gXCIgb3BlbmNsYXctY29udGV4dC1oaWdoXCIgOiBwY3QgPiA2MCA/IFwiIG9wZW5jbGF3LWNvbnRleHQtbWlkXCIgOiBcIlwiKTtcbiAgICAgIHRoaXMuY29udGV4dExhYmVsRWwudGV4dENvbnRlbnQgPSBgJHtwY3R9JWA7XG4gICAgICAvLyBVcGRhdGUgYWN0aXZlIHRhYiBtZXRlciBiYXJcbiAgICAgIGNvbnN0IGFjdGl2ZUZpbGwgPSB0aGlzLnRhYkJhckVsPy5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LXRhYi5hY3RpdmUgLm9wZW5jbGF3LXRhYi1tZXRlci1maWxsXCIpIGFzIEhUTUxFbGVtZW50O1xuICAgICAgaWYgKGFjdGl2ZUZpbGwpIGFjdGl2ZUZpbGwuc2V0Q3NzU3R5bGVzKHsgd2lkdGg6IHBjdCArIFwiJVwiIH0pO1xuICAgICAgLy8gVXBkYXRlIG1vZGVsIGxhYmVsIGZyb20gc2Vzc2lvbiBkYXRhIChidXQgZG9uJ3Qgb3ZlcndyaXRlIGEgcmVjZW50IG1hbnVhbCBzd2l0Y2gpXG4gICAgICBjb25zdCBmdWxsTW9kZWwgPSBzZXNzaW9uLm1vZGVsIHx8IFwiXCI7XG4gICAgICBjb25zdCBtb2RlbENvb2xkb3duID0gRGF0ZS5ub3coKSAtIHRoaXMuY3VycmVudE1vZGVsU2V0QXQgPCAxNTAwMDtcbiAgICAgIGlmIChmdWxsTW9kZWwgJiYgZnVsbE1vZGVsICE9PSB0aGlzLmN1cnJlbnRNb2RlbCAmJiAhbW9kZWxDb29sZG93bikge1xuICAgICAgICB0aGlzLmN1cnJlbnRNb2RlbCA9IGZ1bGxNb2RlbDtcbiAgICAgICAgdGhpcy51cGRhdGVNb2RlbFBpbGwoKTtcbiAgICAgIH1cbiAgICAgIC8vIFVwZGF0ZSBzZXNzaW9uIGRpc3BsYXkgbmFtZSBmcm9tIGdhdGV3YXlcbiAgICAgIGlmIChzZXNzaW9uLmRpc3BsYXlOYW1lICYmIHNlc3Npb24uZGlzcGxheU5hbWUgIT09IHRoaXMuY2FjaGVkU2Vzc2lvbkRpc3BsYXlOYW1lKSB7XG4gICAgICAgIHRoaXMuY2FjaGVkU2Vzc2lvbkRpc3BsYXlOYW1lID0gc2Vzc2lvbi5kaXNwbGF5TmFtZTtcbiAgICAgIH1cbiAgICAgIC8vIERldGVjdCBzZXNzaW9uIGxpc3QgY2hhbmdlcyBhbmQgcmUtcmVuZGVyIHRhYnMgd2hlbiBuZWVkZWRcbiAgICAgIGNvbnN0IGFnZW50UHJlZml4ID0gdGhpcy5hZ2VudFByZWZpeDtcbiAgICAgIGNvbnN0IGN1cnJlbnRTZXNzaW9uS2V5cyA9IG5ldyBTZXQoXG4gICAgICAgIHNlc3Npb25zLmZpbHRlcigoczogU2Vzc2lvbkluZm8pID0+IHMua2V5LnN0YXJ0c1dpdGgoYWdlbnRQcmVmaXgpICYmICFzLmtleS5pbmNsdWRlcyhcIjpjcm9uOlwiKSAmJiAhcy5rZXkuaW5jbHVkZXMoXCI6c3ViYWdlbnQ6XCIpKS5tYXAoKHM6IFNlc3Npb25JbmZvKSA9PiBzLmtleSlcbiAgICAgICk7XG4gICAgICBjb25zdCB0cmFja2VkS2V5cyA9IG5ldyBTZXQodGhpcy50YWJTZXNzaW9ucy5tYXAodCA9PiBgJHthZ2VudFByZWZpeH0ke3Qua2V5fWApKTtcbiAgICAgIGNvbnN0IGFkZGVkID0gWy4uLmN1cnJlbnRTZXNzaW9uS2V5c10uc29tZShrID0+ICF0cmFja2VkS2V5cy5oYXMoaykpO1xuICAgICAgY29uc3QgcmVtb3ZlZCA9IFsuLi50cmFja2VkS2V5c10uc29tZShrID0+ICFjdXJyZW50U2Vzc2lvbktleXMuaGFzKGspKTtcbiAgICAgIGlmICgoYWRkZWQgfHwgcmVtb3ZlZCkgJiYgIXRoaXMudGFiRGVsZXRlSW5Qcm9ncmVzcykge1xuICAgICAgICAvLyBJZiB2aWV3aW5nIGEgc2Vzc2lvbiB0aGF0IG5vIGxvbmdlciBleGlzdHMsIHN3aXRjaCBiYWNrIHRvIG1haW5cbiAgICAgICAgaWYgKHJlbW92ZWQgJiYgIWN1cnJlbnRTZXNzaW9uS2V5cy5oYXMoYCR7YWdlbnRQcmVmaXh9JHtza31gKSkge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBcIm1haW5cIjtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5sb2FkSGlzdG9yeSgpO1xuICAgICAgICAgIHRoaXMudXBkYXRlU3RhdHVzKCk7XG4gICAgICAgIH1cbiAgICAgICAgYXdhaXQgdGhpcy5yZW5kZXJUYWJzKCk7XG4gICAgICB9XG4gICAgfSBjYXRjaCB7IC8qIGlnbm9yZSAqLyB9XG4gIH1cblxuICB1cGRhdGVNb2RlbFBpbGwoKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLm1vZGVsTGFiZWxFbCkgcmV0dXJuO1xuICAgIGNvbnN0IG1vZGVsID0gdGhpcy5jdXJyZW50TW9kZWwgPyB0aGlzLnNob3J0TW9kZWxOYW1lKHRoaXMuY3VycmVudE1vZGVsKSA6IFwibW9kZWxcIjtcbiAgICB0aGlzLm1vZGVsTGFiZWxFbC5lbXB0eSgpO1xuICAgIHRoaXMubW9kZWxMYWJlbEVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBtb2RlbCwgY2xzOiBcIm9wZW5jbGF3LWN0eC1waWxsLXRleHRcIiB9KTtcbiAgICB0aGlzLm1vZGVsTGFiZWxFbC5jcmVhdGVTcGFuKHsgdGV4dDogXCIgXHUyNUJFXCIsIGNsczogXCJvcGVuY2xhdy1jdHgtcGlsbC1hcnJvd1wiIH0pO1xuICB9XG5cbiAgYXN5bmMgcmVuZGVyVGFicygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMudGFiQmFyRWwgfHwgdGhpcy5yZW5kZXJpbmdUYWJzKSByZXR1cm47XG4gICAgdGhpcy5yZW5kZXJpbmdUYWJzID0gdHJ1ZTtcbiAgICB0cnkgeyBhd2FpdCB0aGlzLl9yZW5kZXJUYWJzSW5uZXIoKTsgfSBmaW5hbGx5IHsgdGhpcy5yZW5kZXJpbmdUYWJzID0gZmFsc2U7IH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3JlbmRlclRhYnNJbm5lcigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnRhYkJhckVsLmVtcHR5KCk7XG4gICAgY29uc3QgY3VycmVudEtleSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgfHwgXCJtYWluXCI7XG5cbiAgICAvLyBGZXRjaCBzZXNzaW9ucyBmcm9tIGdhdGV3YXlcbiAgICBsZXQgc2Vzc2lvbnM6IFNlc3Npb25JbmZvW10gPSBbXTtcbiAgICBpZiAodGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJzZXNzaW9ucy5saXN0XCIsIHt9KSBhcyB7IHNlc3Npb25zPzogU2Vzc2lvbkluZm9bXSB9IHwgbnVsbDtcbiAgICAgICAgc2Vzc2lvbnMgPSByZXN1bHQ/LnNlc3Npb25zIHx8IFtdO1xuICAgICAgfSBjYXRjaCB7IC8qIHVzZSBlbXB0eSAqLyB9XG4gICAgfVxuXG4gICAgLy8gRmlsdGVyOiBzaG93IGFsbCBhZ2VudCBzZXNzaW9ucyBleGNlcHQgY3JvbiBhbmQgc3ViLWFnZW50c1xuICAgIGNvbnN0IGFnZW50UHJlZml4ID0gdGhpcy5hZ2VudFByZWZpeDtcbiAgICBjb25zdCBjb252U2Vzc2lvbnMgPSBzZXNzaW9ucy5maWx0ZXIocyA9PiB7XG4gICAgICBpZiAoIXMua2V5LnN0YXJ0c1dpdGgoYWdlbnRQcmVmaXgpKSByZXR1cm4gZmFsc2U7XG4gICAgICBpZiAocy5rZXkuaW5jbHVkZXMoXCI6Y3JvbjpcIikpIHJldHVybiBmYWxzZTtcbiAgICAgIGlmIChzLmtleS5pbmNsdWRlcyhcIjpzdWJhZ2VudDpcIikpIHJldHVybiBmYWxzZTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0pO1xuXG4gICAgLy8gQnVpbGQgdGFiIGxpc3QgXHUyMDE0IGVuc3VyZSBcIm1haW5cIiBpcyBhbHdheXMgZmlyc3RcbiAgICB0aGlzLnRhYlNlc3Npb25zID0gW107XG4gICAgY29uc3QgbWFpblNlc3Npb24gPSBjb252U2Vzc2lvbnMuZmluZChzID0+IHMua2V5ID09PSBgJHt0aGlzLmFnZW50UHJlZml4fW1haW5gKTtcbiAgICBpZiAobWFpblNlc3Npb24pIHtcbiAgICAgIGNvbnN0IHVzZWQgPSBtYWluU2Vzc2lvbi50b3RhbFRva2VucyB8fCAwO1xuICAgICAgY29uc3QgbWF4ID0gbWFpblNlc3Npb24uY29udGV4dFRva2VucyB8fCAyMDAwMDA7XG4gICAgICB0aGlzLnRhYlNlc3Npb25zLnB1c2goeyBrZXk6IFwibWFpblwiLCBsYWJlbDogXCJNYWluXCIsIHBjdDogTWF0aC5taW4oMTAwLCBNYXRoLnJvdW5kKCh1c2VkIC8gbWF4KSAqIDEwMCkpIH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLnRhYlNlc3Npb25zLnB1c2goeyBrZXk6IFwibWFpblwiLCBsYWJlbDogXCJNYWluXCIsIHBjdDogMCB9KTtcbiAgICB9XG5cbiAgICAvLyBBZGQgb3RoZXIgc2Vzc2lvbnMgaW4gY3JlYXRpb24gb3JkZXIgKG9sZGVzdCBmaXJzdClcbiAgICBjb25zdCBvdGhlcnMgPSBjb252U2Vzc2lvbnNcbiAgICAgIC5maWx0ZXIocyA9PiBzLmtleS5zbGljZShhZ2VudFByZWZpeC5sZW5ndGgpICE9PSBcIm1haW5cIilcbiAgICAgIC5zb3J0KChhLCBiKSA9PiAoYS5jcmVhdGVkQXQgfHwgYS51cGRhdGVkQXQgfHwgMCkgLSAoYi5jcmVhdGVkQXQgfHwgYi51cGRhdGVkQXQgfHwgMCkpO1xuICAgIGxldCBudW0gPSAxO1xuICAgIGZvciAoY29uc3QgcyBvZiBvdGhlcnMpIHtcbiAgICAgIGNvbnN0IHNrID0gcy5rZXkuc2xpY2UoYWdlbnRQcmVmaXgubGVuZ3RoKTtcbiAgICAgIGNvbnN0IHVzZWQgPSBzLnRvdGFsVG9rZW5zIHx8IDA7XG4gICAgICBjb25zdCBtYXggPSBzLmNvbnRleHRUb2tlbnMgfHwgMjAwMDAwO1xuICAgICAgY29uc3QgcGN0ID0gTWF0aC5taW4oMTAwLCBNYXRoLnJvdW5kKCh1c2VkIC8gbWF4KSAqIDEwMCkpO1xuICAgICAgY29uc3QgbGFiZWwgPSBzLmxhYmVsIHx8IHMuZGlzcGxheU5hbWUgfHwgU3RyaW5nKG51bSk7XG4gICAgICB0aGlzLnRhYlNlc3Npb25zLnB1c2goeyBrZXk6IHNrLCBsYWJlbCwgcGN0IH0pO1xuICAgICAgbnVtKys7XG4gICAgfVxuXG4gICAgLy8gUmVuZGVyIGVhY2ggdGFiXG4gICAgZm9yIChjb25zdCB0YWIgb2YgdGhpcy50YWJTZXNzaW9ucykge1xuICAgICAgY29uc3QgaXNDdXJyZW50ID0gdGFiLmtleSA9PT0gY3VycmVudEtleTtcbiAgICAgIGNvbnN0IHRhYkNscyA9IGBvcGVuY2xhdy10YWIke2lzQ3VycmVudCA/IFwiIGFjdGl2ZVwiIDogXCJcIn1gO1xuICAgICAgY29uc3QgdGFiRWwgPSB0aGlzLnRhYkJhckVsLmNyZWF0ZURpdih7IGNsczogdGFiQ2xzIH0pO1xuXG4gICAgICAvLyBSb3c6IGxhYmVsICsgXHUwMEQ3IChcdTAwRDcgcHVzaGVkIHRvIGZhciByaWdodCB2aWEgQ1NTKVxuICAgICAgY29uc3Qgcm93ID0gdGFiRWwuY3JlYXRlRGl2KHsgY2xzOiBcIm9wZW5jbGF3LXRhYi1yb3dcIiB9KTtcbiAgICAgIGNvbnN0IGxhYmVsU3BhbiA9IHJvdy5jcmVhdGVTcGFuKHsgdGV4dDogdGFiLmxhYmVsLCBjbHM6IFwib3BlbmNsYXctdGFiLWxhYmVsXCIgfSk7XG5cbiAgICAgIC8vIERvdWJsZS1jbGljayB0byByZW5hbWUgKG5vdCBtYWluKVxuICAgICAgaWYgKHRhYi5rZXkgIT09IFwibWFpblwiKSB7XG4gICAgICAgIGxhYmVsU3Bhbi50aXRsZSA9IFwiRG91YmxlLWNsaWNrIHRvIHJlbmFtZVwiO1xuICAgICAgICBsYWJlbFNwYW4uYWRkRXZlbnRMaXN0ZW5lcihcImRibGNsaWNrXCIsIChlKSA9PiB7XG4gICAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTtcbiAgICAgICAgICBjb25zdCBpbnB1dCA9IGNyZWF0ZUVsKFwiaW5wdXRcIiwgeyBjbHM6IFwib3BlbmNsYXctdGFiLWxhYmVsLWlucHV0XCIgfSk7XG4gICAgICAgICAgaW5wdXQudmFsdWUgPSB0YWIubGFiZWw7XG4gICAgICAgICAgaW5wdXQubWF4TGVuZ3RoID0gMzA7XG4gICAgICAgICAgbGFiZWxTcGFuLnJlcGxhY2VXaXRoKGlucHV0KTtcbiAgICAgICAgICBpbnB1dC5mb2N1cygpO1xuICAgICAgICAgIGlucHV0LnNlbGVjdCgpO1xuICAgICAgICAgIGNvbnN0IGZpbmlzaCA9IGFzeW5jIChzYXZlOiBib29sZWFuKSA9PiB7XG4gICAgICAgICAgICBjb25zdCBuZXdOYW1lID0gaW5wdXQudmFsdWUudHJpbSgpO1xuICAgICAgICAgICAgaWYgKHNhdmUgJiYgbmV3TmFtZSAmJiBuZXdOYW1lICE9PSB0YWIubGFiZWwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5Py5yZXF1ZXN0KFwic2Vzc2lvbnMucGF0Y2hcIiwge1xuICAgICAgICAgICAgICAgICAga2V5OiBgJHt0aGlzLmFnZW50UHJlZml4fSR7dGFiLmtleX1gLFxuICAgICAgICAgICAgICAgICAgbGFiZWw6IG5ld05hbWUsXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgdGFiLmxhYmVsID0gbmV3TmFtZTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7IC8qIGtlZXAgb2xkIG5hbWUgKi8gfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaW5wdXQucmVwbGFjZVdpdGgobGFiZWxTcGFuKTtcbiAgICAgICAgICAgIGxhYmVsU3Bhbi50ZXh0Q29udGVudCA9IHRhYi5sYWJlbDtcbiAgICAgICAgICAgIHZvaWQgdGhpcy5yZW5kZXJUYWJzKCk7XG4gICAgICAgICAgfTtcbiAgICAgICAgICBpbnB1dC5hZGRFdmVudExpc3RlbmVyKFwia2V5ZG93blwiLCAoZXY6IEtleWJvYXJkRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGlmIChldi5rZXkgPT09IFwiRW50ZXJcIikgeyBldi5wcmV2ZW50RGVmYXVsdCgpOyB2b2lkIGZpbmlzaCh0cnVlKTsgfVxuICAgICAgICAgICAgaWYgKGV2LmtleSA9PT0gXCJFc2NhcGVcIikgeyBldi5wcmV2ZW50RGVmYXVsdCgpOyB2b2lkIGZpbmlzaChmYWxzZSk7IH1cbiAgICAgICAgICB9KTtcbiAgICAgICAgICBpbnB1dC5hZGRFdmVudExpc3RlbmVyKFwiYmx1clwiLCAoKSA9PiB2b2lkIGZpbmlzaCh0cnVlKSk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICAvLyBcdTAwRDcgYnV0dG9uOiBNYWluID0gcmVzZXQsIGV2ZXJ5dGhpbmcgZWxzZSA9IGNsb3NlL2RlbGV0ZVxuICAgICAgY29uc3QgaXNSZXNldE9ubHkgPSB0YWIua2V5ID09PSBcIm1haW5cIjtcbiAgICAgIGNvbnN0IGNsb3NlQnRuID0gcm93LmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIlx1MDBEN1wiLCBjbHM6IFwib3BlbmNsYXctdGFiLWNsb3NlXCIgfSk7XG4gICAgICBpZiAoaXNSZXNldE9ubHkpIHtcbiAgICAgICAgY2xvc2VCdG4udGl0bGUgPSBcIlJlc2V0IGNvbnZlcnNhdGlvblwiO1xuICAgICAgICBjbG9zZUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKGUpID0+IHsgZS5zdG9wUHJvcGFnYXRpb24oKTsgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSByZXR1cm47XG4gICAgICAgICAgLy8gQ29uZmlybSBiZWZvcmUgcmVzZXRcbiAgICAgICAgICBpZiAoIXRoaXMuaXNDbG9zZUNvbmZpcm1EaXNhYmxlZCgpKSB7XG4gICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCB0aGlzLmNvbmZpcm1UYWJDbG9zZShcIlJlc2V0IG1haW4gdGFiP1wiLCBcIlRoaXMgd2lsbCBjbGVhciB0aGUgY29udmVyc2F0aW9uLlwiKTtcbiAgICAgICAgICAgIGlmICghY29uZmlybWVkKSByZXR1cm47XG4gICAgICAgICAgfVxuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICAgICAgICBzZXNzaW9uS2V5OiB0YWIua2V5LFxuICAgICAgICAgICAgICBtZXNzYWdlOiBcIi9yZXNldFwiLFxuICAgICAgICAgICAgICBkZWxpdmVyOiBmYWxzZSxcbiAgICAgICAgICAgICAgaWRlbXBvdGVuY3lLZXk6IFwicmVzZXQtXCIgKyBEYXRlLm5vdygpLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBuZXcgTm90aWNlKGBSZXNldDogJHt0YWIubGFiZWx9YCk7XG4gICAgICAgICAgICBpZiAodGFiLmtleSA9PT0gY3VycmVudEtleSkge1xuICAgICAgICAgICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICAgICAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgICAgIH0gY2F0Y2ggKGVycjogdW5rbm93bikge1xuICAgICAgICAgICAgbmV3IE5vdGljZShgUmVzZXQgZmFpbGVkOiAke2VyciBpbnN0YW5jZW9mIEVycm9yID8gZXJyLm1lc3NhZ2UgOiBTdHJpbmcoZXJyKX1gKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pKCk7IH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY2xvc2VCdG4udGl0bGUgPSBcIkNsb3NlIHRhYlwiO1xuICAgICAgICBjbG9zZUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKGUpID0+IHsgZS5zdG9wUHJvcGFnYXRpb24oKTsgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkIHx8IHRoaXMudGFiRGVsZXRlSW5Qcm9ncmVzcykgcmV0dXJuO1xuICAgICAgICAgIC8vIENvbmZpcm0gYmVmb3JlIGNsb3NlXG4gICAgICAgICAgaWYgKCF0aGlzLmlzQ2xvc2VDb25maXJtRGlzYWJsZWQoKSkge1xuICAgICAgICAgICAgY29uc3QgY29uZmlybWVkID0gYXdhaXQgdGhpcy5jb25maXJtVGFiQ2xvc2UoXCJDbG9zZSB0YWI/XCIsIGBDbG9zZSBcIiR7dGFiLmxhYmVsfVwiPyBDaGF0IGhpc3Rvcnkgd2lsbCBiZSBsb3N0LmApO1xuICAgICAgICAgICAgaWYgKCFjb25maXJtZWQpIHJldHVybjtcbiAgICAgICAgICB9XG4gICAgICAgICAgdGhpcy50YWJEZWxldGVJblByb2dyZXNzID0gdHJ1ZTtcbiAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgZGVsZXRlZCA9IGF3YWl0IGRlbGV0ZVNlc3Npb25XaXRoRmFsbGJhY2sodGhpcy5wbHVnaW4uZ2F0ZXdheSwgYCR7dGhpcy5hZ2VudFByZWZpeH0ke3RhYi5rZXl9YCk7XG4gICAgICAgICAgICBuZXcgTm90aWNlKGRlbGV0ZWQgPyBgQ2xvc2VkOiAke3RhYi5sYWJlbH1gIDogYENvdWxkIG5vdCBkZWxldGU6ICR7dGFiLmxhYmVsfWApO1xuICAgICAgICAgIH0gY2F0Y2ggKGVycjogdW5rbm93bikge1xuICAgICAgICAgICAgbmV3IE5vdGljZShgQ2xvc2UgZmFpbGVkOiAke2VyciBpbnN0YW5jZW9mIEVycm9yID8gZXJyLm1lc3NhZ2UgOiBTdHJpbmcoZXJyKX1gKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gQ2xlYW4gdXAgYW55IHN0cmVhbSBzdGF0ZSBmb3IgdGhlIGRlbGV0ZWQgdGFiXG4gICAgICAgICAgdGhpcy5maW5pc2hTdHJlYW0odGFiLmtleSk7XG4gICAgICAgICAgLy8gU3dpdGNoIHRvIG1haW4gaWYgd2UgY2xvc2VkIHRoZSBhY3RpdmUgdGFiXG4gICAgICAgICAgaWYgKHRhYi5rZXkgPT09IGN1cnJlbnRLZXkpIHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBcIm1haW5cIjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgICAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLmxvYWRIaXN0b3J5KCk7XG4gICAgICAgICAgICB0aGlzLnJlc3RvcmVTdHJlYW1VSSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLnRhYkRlbGV0ZUluUHJvZ3Jlc3MgPSBmYWxzZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgICB9KSgpOyB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gUHJvZ3Jlc3MgYmFyIChncmF5IGNvbnRhaW5lciwgYmxhY2sgZmlsbClcbiAgICAgIGNvbnN0IG1ldGVyID0gdGFiRWwuY3JlYXRlRGl2KHsgY2xzOiBcIm9wZW5jbGF3LXRhYi1tZXRlclwiIH0pO1xuICAgICAgY29uc3QgZmlsbCA9IG1ldGVyLmNyZWF0ZURpdih7IGNsczogXCJvcGVuY2xhdy10YWItbWV0ZXItZmlsbFwiIH0pO1xuICAgICAgZmlsbC5zZXRDc3NTdHlsZXMoeyB3aWR0aDogdGFiLnBjdCArIFwiJVwiIH0pO1xuXG4gICAgICAvLyBDbGljayB0byBzd2l0Y2hcbiAgICAgIGlmICghaXNDdXJyZW50KSB7XG4gICAgICAgIHRhYkVsLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgICAgLy8gQ2xlYXIgRE9NIGZyb20gb2xkIHRhYlxuICAgICAgICAgIHRoaXMuc3RyZWFtRWwgPSBudWxsO1xuICAgICAgICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcblxuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB0YWIua2V5O1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcbiAgICAgICAgICB0aGlzLmNhY2hlZFNlc3Npb25EaXNwbGF5TmFtZSA9IHRhYi5sYWJlbDtcbiAgICAgICAgICBhd2FpdCB0aGlzLmxvYWRIaXN0b3J5KCk7XG5cbiAgICAgICAgICAvLyBSZXN0b3JlIHN0cmVhbSBVSSBpZiBuZXcgdGFiIGhhcyBhbiBhY3RpdmUgc3RyZWFtXG4gICAgICAgICAgdGhpcy5yZXN0b3JlU3RyZWFtVUkoKTtcblxuICAgICAgICAgIGF3YWl0IHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICAgICAgdm9pZCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgICAgICB0aGlzLnVwZGF0ZVN0YXR1cygpO1xuICAgICAgICB9KSgpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyArIGJ1dHRvbiB0byBhZGQgbmV3IHRhYlxuICAgIGNvbnN0IGFkZEJ0biA9IHRoaXMudGFiQmFyRWwuY3JlYXRlRGl2KHsgY2xzOiBcIm9wZW5jbGF3LXRhYiBvcGVuY2xhdy10YWItYWRkXCIgfSk7XG4gICAgYWRkQnRuLmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIitcIiwgY2xzOiBcIm9wZW5jbGF3LXRhYi1sYWJlbFwiIH0pO1xuICAgIGFkZEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgLy8gQXV0by1uYW1lOiBmaW5kIG5leHQgbnVtYmVyXG4gICAgICBjb25zdCBudW1zID0gdGhpcy50YWJTZXNzaW9ucy5tYXAodCA9PiBwYXJzZUludCh0LmxhYmVsKSkuZmlsdGVyKG4gPT4gIWlzTmFOKG4pKTtcbiAgICAgIGNvbnN0IG5leHROdW0gPSBudW1zLmxlbmd0aCA+IDAgPyBNYXRoLm1heCguLi5udW1zKSArIDEgOiAxO1xuICAgICAgY29uc3Qgc2Vzc2lvbktleSA9IGB0YWItJHtuZXh0TnVtfWA7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5Py5yZXF1ZXN0KFwiY2hhdC5zZW5kXCIsIHtcbiAgICAgICAgICBzZXNzaW9uS2V5OiBzZXNzaW9uS2V5LFxuICAgICAgICAgIG1lc3NhZ2U6IFwiL25ld1wiLFxuICAgICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICAgIGlkZW1wb3RlbmN5S2V5OiBcIm5ld3RhYi1cIiArIERhdGUubm93KCksXG4gICAgICAgIH0pO1xuICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgNTAwKSk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheT8ucmVxdWVzdChcInNlc3Npb25zLnBhdGNoXCIsIHtcbiAgICAgICAgICAgIGtleTogYCR7dGhpcy5hZ2VudFByZWZpeH0ke3Nlc3Npb25LZXl9YCxcbiAgICAgICAgICAgIGxhYmVsOiBTdHJpbmcobmV4dE51bSksXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gY2F0Y2ggeyAvKiBsYWJlbCBvcHRpb25hbCAqLyB9XG4gICAgICAgIC8vIFN3aXRjaCB0byBpdCAtIGNsZWFyIG9sZCB0YWIncyBzdHJlYW0gVUlcbiAgICAgICAgdGhpcy5zdHJlYW1FbCA9IG51bGw7XG4gICAgICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgIHRoaXMuYWJvcnRCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgIHRoaXMuaGlkZUJhbm5lcigpO1xuXG4gICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zdHJlYW1JdGVtc01hcCkgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXAgPSB7fTtcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgICBhd2FpdCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgICAgbmV3IE5vdGljZShgTmV3IHRhYjogJHtuZXh0TnVtfWApO1xuICAgICAgfSBjYXRjaCAoZXJyOiB1bmtub3duKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoYEZhaWxlZCB0byBjcmVhdGUgdGFiOiAke2VyciBpbnN0YW5jZW9mIEVycm9yID8gZXJyLm1lc3NhZ2UgOiBTdHJpbmcoZXJyKX1gKTtcbiAgICAgIH1cbiAgICB9KSgpKTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBDb25maXJtIGNsb3NlIGRpYWxvZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGlzQ2xvc2VDb25maXJtRGlzYWJsZWQoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKFwib3BlbmNsYXctY29uZmlybS1jbG9zZS1kaXNhYmxlZFwiKSA9PT0gXCJ0cnVlXCI7XG4gIH1cblxuICBwcml2YXRlIGNvbmZpcm1UYWJDbG9zZSh0aXRsZTogc3RyaW5nLCBtc2c6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIGNvbnN0IG1vZGFsID0gbmV3IENvbmZpcm1DbG9zZU1vZGFsKHRoaXMuYXBwLCB0aXRsZSwgbXNnLCAocmVzdWx0LCBkb250QXNrKSA9PiB7XG4gICAgICAgIGlmIChyZXN1bHQgJiYgZG9udEFzaykge1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFwib3BlbmNsYXctY29uZmlybS1jbG9zZS1kaXNhYmxlZFwiLCBcInRydWVcIik7XG4gICAgICAgIH1cbiAgICAgICAgcmVzb2x2ZShyZXN1bHQpO1xuICAgICAgfSk7XG4gICAgICBtb2RhbC5vcGVuKCk7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgVG91Y2ggZ2VzdHVyZXMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBpbml0VG91Y2hHZXN0dXJlcygpOiB2b2lkIHtcbiAgICBsZXQgdG91Y2hTdGFydFggPSAwO1xuICAgIGxldCB0b3VjaFN0YXJ0WSA9IDA7XG4gICAgbGV0IHB1bGxpbmcgPSBmYWxzZTtcblxuICAgIHRoaXMubWVzc2FnZXNFbC5hZGRFdmVudExpc3RlbmVyKFwidG91Y2hzdGFydFwiLCAoZTogVG91Y2hFdmVudCkgPT4ge1xuICAgICAgdG91Y2hTdGFydFggPSBlLnRvdWNoZXNbMF0uY2xpZW50WDtcbiAgICAgIHRvdWNoU3RhcnRZID0gZS50b3VjaGVzWzBdLmNsaWVudFk7XG4gICAgICBwdWxsaW5nID0gZmFsc2U7XG4gICAgfSwgeyBwYXNzaXZlOiB0cnVlIH0pO1xuXG4gICAgdGhpcy5tZXNzYWdlc0VsLmFkZEV2ZW50TGlzdGVuZXIoXCJ0b3VjaG1vdmVcIiwgKGU6IFRvdWNoRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IGRlbHRhWSA9IGUudG91Y2hlc1swXS5jbGllbnRZIC0gdG91Y2hTdGFydFk7XG4gICAgICBpZiAodGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA8PSAwICYmIGRlbHRhWSA+IDYwKSB7XG4gICAgICAgIHB1bGxpbmcgPSB0cnVlO1xuICAgICAgfVxuICAgIH0sIHsgcGFzc2l2ZTogdHJ1ZSB9KTtcblxuICAgIHRoaXMubWVzc2FnZXNFbC5hZGRFdmVudExpc3RlbmVyKFwidG91Y2hlbmRcIiwgKGU6IFRvdWNoRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IGRlbHRhWCA9IGUuY2hhbmdlZFRvdWNoZXNbMF0uY2xpZW50WCAtIHRvdWNoU3RhcnRYO1xuICAgICAgY29uc3QgZGVsdGFZID0gZS5jaGFuZ2VkVG91Y2hlc1swXS5jbGllbnRZIC0gdG91Y2hTdGFydFk7XG5cbiAgICAgIC8vIFB1bGwtdG8tcmVmcmVzaFxuICAgICAgaWYgKHB1bGxpbmcpIHtcbiAgICAgICAgcHVsbGluZyA9IGZhbHNlO1xuICAgICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgICB2b2lkIHRoaXMubG9hZEhpc3RvcnkoKS50aGVuKCgpID0+IHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCkpO1xuICAgICAgICBuZXcgTm90aWNlKFwiUmVmcmVzaGVkXCIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIFN3aXBlIGJldHdlZW4gdGFic1xuICAgICAgaWYgKE1hdGguYWJzKGRlbHRhWCkgPiA4MCAmJiBNYXRoLmFicyhkZWx0YVgpID4gTWF0aC5hYnMoZGVsdGFZKSAqIDEuNSkge1xuICAgICAgICBjb25zdCBjdXJyZW50SWR4ID0gdGhpcy50YWJTZXNzaW9ucy5maW5kSW5kZXgodCA9PiB0LmtleSA9PT0gdGhpcy5hY3RpdmVTZXNzaW9uS2V5KTtcbiAgICAgICAgaWYgKGN1cnJlbnRJZHggPCAwKSByZXR1cm47XG4gICAgICAgIGNvbnN0IG5leHRJZHggPSBkZWx0YVggPCAwID8gY3VycmVudElkeCArIDEgOiBjdXJyZW50SWR4IC0gMTtcbiAgICAgICAgaWYgKG5leHRJZHggPj0gMCAmJiBuZXh0SWR4IDwgdGhpcy50YWJTZXNzaW9ucy5sZW5ndGgpIHtcbiAgICAgICAgICBjb25zdCB0YWIgPSB0aGlzLnRhYlNlc3Npb25zW25leHRJZHhdO1xuICAgICAgICAgIHRoaXMuc3RyZWFtRWwgPSBudWxsO1xuICAgICAgICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdGFiLmtleTtcbiAgICAgICAgICB2b2lkIHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcbiAgICAgICAgICB0aGlzLmNhY2hlZFNlc3Npb25EaXNwbGF5TmFtZSA9IHRhYi5sYWJlbDtcbiAgICAgICAgICB2b2lkIHRoaXMubG9hZEhpc3RvcnkoKTtcbiAgICAgICAgICB2b2lkIHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICAgICAgdm9pZCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgICAgICB0aGlzLnVwZGF0ZVN0YXR1cygpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgeyBwYXNzaXZlOiB0cnVlIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBjb250ZXh0Q29sb3IocGN0OiBudW1iZXIpOiBzdHJpbmcge1xuICAgIGlmIChwY3QgPiA4MCkgcmV0dXJuIFwiI2M0NFwiO1xuICAgIGlmIChwY3QgPiA2MCkgcmV0dXJuIFwiI2Q0YTg0M1wiO1xuICAgIGlmIChwY3QgPiAzMCkgcmV0dXJuIFwiIzdhN1wiO1xuICAgIHJldHVybiBcIiM1YTVcIjtcbiAgfVxuXG4gIGFzeW5jIHJlc2V0Q3VycmVudFRhYigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICBzZXNzaW9uS2V5OiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgICBtZXNzYWdlOiBcIi9yZXNldFwiLFxuICAgICAgICBkZWxpdmVyOiBmYWxzZSxcbiAgICAgICAgaWRlbXBvdGVuY3lLZXk6IFwicmVzZXQtXCIgKyBEYXRlLm5vdygpLFxuICAgICAgfSk7XG4gICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXApIHRoaXMucGx1Z2luLnNldHRpbmdzLnN0cmVhbUl0ZW1zTWFwID0ge307XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgIGF3YWl0IHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgbmV3IE5vdGljZShcIlRhYiByZXNldFwiKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBuZXcgTm90aWNlKGBSZXNldCBmYWlsZWQ6ICR7ZX1gKTtcbiAgICB9XG4gIH1cblxuICBvcGVuTW9kZWxQaWNrZXIoKTogdm9pZCB7XG4gICAgbmV3IE1vZGVsUGlja2VyTW9kYWwodGhpcy5hcHAsIHRoaXMucGx1Z2luLCB0aGlzKS5vcGVuKCk7XG4gIH1cblxuICBhc3luYyBjb21wYWN0U2Vzc2lvbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICB0aGlzLnNob3dCYW5uZXIoXCJDb21wYWN0aW5nIGNvbnRleHQuLi5cIik7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICBzZXNzaW9uS2V5OiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgICBtZXNzYWdlOiBcIi9jb21wYWN0XCIsXG4gICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICBpZGVtcG90ZW5jeUtleTogXCJjb21wYWN0LVwiICsgRGF0ZS5ub3coKSxcbiAgICAgIH0pO1xuICAgICAgLy8gUG9sbCBjb250ZXh0IG1ldGVyIHRvIGFuaW1hdGUgdGhlIGRlY3JlYXNlXG4gICAgICBjb25zdCBwb2xsSW50ZXJ2YWwgPSBzZXRJbnRlcnZhbCgoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICB9KSgpLCAyMDAwKTtcbiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBjbGVhckludGVydmFsKHBvbGxJbnRlcnZhbCk7XG4gICAgICAgIHRoaXMuaGlkZUJhbm5lcigpO1xuICAgICAgICBhd2FpdCB0aGlzLmxvYWRIaXN0b3J5KCk7XG4gICAgICAgIGF3YWl0IHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICB9KSgpLCAxMjAwMCk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgdGhpcy5oaWRlQmFubmVyKCk7XG4gICAgICBuZXcgTm90aWNlKGBDb21wYWN0IGZhaWxlZDogJHtlfWApO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIG5ld1Nlc3Npb24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheS5yZXF1ZXN0KFwiY2hhdC5zZW5kXCIsIHtcbiAgICAgICAgc2Vzc2lvbktleTogdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSxcbiAgICAgICAgbWVzc2FnZTogXCIvbmV3XCIsXG4gICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICBpZGVtcG90ZW5jeUtleTogXCJuZXctXCIgKyBEYXRlLm5vdygpLFxuICAgICAgfSk7XG4gICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXApIHRoaXMucGx1Z2luLnNldHRpbmdzLnN0cmVhbUl0ZW1zTWFwID0ge307XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgIG5ldyBOb3RpY2UoXCJOZXcgc2Vzc2lvbiBzdGFydGVkXCIpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIG5ldyBOb3RpY2UoYE5ldyBzZXNzaW9uIGZhaWxlZDogJHtlfWApO1xuICAgIH1cbiAgfVxuXG4gIHNob3J0TW9kZWxOYW1lKGZ1bGxJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICAvLyBcImFudGhyb3BpYy9jbGF1ZGUtb3B1cy00LTZcIiAtPiBcIm9wdXMtNC02XCIgKHNlbGVjdGVkIGRpc3BsYXkpXG4gICAgLy8gU3RyaXAgcHJvdmlkZXIgcHJlZml4LCBzdHJpcCBcImNsYXVkZS1cIiBwcmVmaXggZm9yIGJyZXZpdHlcbiAgICBjb25zdCBtb2RlbCA9IGZ1bGxJZC5pbmNsdWRlcyhcIi9cIikgPyBmdWxsSWQuc3BsaXQoXCIvXCIpWzFdIDogZnVsbElkO1xuICAgIHJldHVybiBtb2RlbC5yZXBsYWNlKC9eY2xhdWRlLS8sIFwiXCIpO1xuICB9XG5cblxuXG5cblxuICBhc3luYyBoYW5kbGVGaWxlU2VsZWN0KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGZpbGVzID0gdGhpcy5maWxlSW5wdXRFbC5maWxlcztcbiAgICBpZiAoIWZpbGVzIHx8IGZpbGVzLmxlbmd0aCA9PT0gMCkgcmV0dXJuO1xuXG4gICAgZm9yIChjb25zdCBmaWxlIG9mIEFycmF5LmZyb20oZmlsZXMpKSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpc0ltYWdlID0gZmlsZS50eXBlLnN0YXJ0c1dpdGgoXCJpbWFnZS9cIik7XG4gICAgICAgIGNvbnN0IGlzVGV4dCA9IGZpbGUudHlwZS5zdGFydHNXaXRoKFwidGV4dC9cIikgfHxcbiAgICAgICAgICBbXCJhcHBsaWNhdGlvbi9qc29uXCIsIFwiYXBwbGljYXRpb24veWFtbFwiLCBcImFwcGxpY2F0aW9uL3htbFwiLCBcImFwcGxpY2F0aW9uL2phdmFzY3JpcHRcIl0uaW5jbHVkZXMoZmlsZS50eXBlKSB8fFxuICAgICAgICAgIC9cXC4obWR8dHh0fGpzb258Y3N2fHlhbWx8eW1sfGpzfHRzfHB5fGh0bWx8Y3NzfHhtbHx0b21sfGluaXxzaHxsb2cpJC9pLnRlc3QoZmlsZS5uYW1lKTtcblxuICAgICAgICBpZiAoaXNJbWFnZSkge1xuICAgICAgICAgIGNvbnN0IHJlc2l6ZWQgPSBhd2FpdCB0aGlzLnJlc2l6ZUltYWdlKGZpbGUsIDIwNDgsIDAuODUpO1xuICAgICAgICAgIHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLnB1c2goe1xuICAgICAgICAgICAgbmFtZTogZmlsZS5uYW1lLFxuICAgICAgICAgICAgY29udGVudDogYFtBdHRhY2hlZCBpbWFnZTogJHtmaWxlLm5hbWV9XWAsXG4gICAgICAgICAgICBiYXNlNjQ6IHJlc2l6ZWQuYmFzZTY0LFxuICAgICAgICAgICAgbWltZVR5cGU6IHJlc2l6ZWQubWltZVR5cGUsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSBpZiAoaXNUZXh0KSB7XG4gICAgICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IGZpbGUudGV4dCgpO1xuICAgICAgICAgIGNvbnN0IHRydW5jYXRlZCA9IGNvbnRlbnQubGVuZ3RoID4gMTAwMDAgPyBjb250ZW50LnNsaWNlKDAsIDEwMDAwKSArIFwiXFxuLi4uKHRydW5jYXRlZClcIiA6IGNvbnRlbnQ7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nQXR0YWNobWVudHMucHVzaCh7XG4gICAgICAgICAgICBuYW1lOiBmaWxlLm5hbWUsXG4gICAgICAgICAgICBjb250ZW50OiBgRmlsZTogJHtmaWxlLm5hbWV9XFxuXFxgXFxgXFxgXFxuJHt0cnVuY2F0ZWR9XFxuXFxgXFxgXFxgYCxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5wdXNoKHtcbiAgICAgICAgICAgIG5hbWU6IGZpbGUubmFtZSxcbiAgICAgICAgICAgIGNvbnRlbnQ6IGBbQXR0YWNoZWQgZmlsZTogJHtmaWxlLm5hbWV9ICgke2ZpbGUudHlwZSB8fCBcInVua25vd24gdHlwZVwifSwgJHtNYXRoLnJvdW5kKGZpbGUuc2l6ZS8xMDI0KX1LQildYCxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBuZXcgTm90aWNlKGBGYWlsZWQgdG8gYXR0YWNoICR7ZmlsZS5uYW1lfTogJHtlfWApO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIFVwZGF0ZSBwcmV2aWV3XG4gICAgdGhpcy5yZW5kZXJBdHRhY2hQcmV2aWV3KCk7XG4gICAgdGhpcy5maWxlSW5wdXRFbC52YWx1ZSA9IFwiXCI7XG4gIH1cblxuICBhc3luYyBoYW5kbGVQYXN0ZWRGaWxlKGZpbGU6IEZpbGUpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXh0ID0gZmlsZS50eXBlLnNwbGl0KFwiL1wiKVsxXSB8fCBcInBuZ1wiO1xuICAgICAgY29uc3QgcmVzaXplZCA9IGF3YWl0IHRoaXMucmVzaXplSW1hZ2UoZmlsZSwgMjA0OCwgMC44NSk7XG4gICAgICB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5wdXNoKHtcbiAgICAgICAgbmFtZTogYGNsaXBib2FyZC4ke2V4dH1gLFxuICAgICAgICBjb250ZW50OiBgW0F0dGFjaGVkIGltYWdlOiBjbGlwYm9hcmQuJHtleHR9XWAsXG4gICAgICAgIGJhc2U2NDogcmVzaXplZC5iYXNlNjQsXG4gICAgICAgIG1pbWVUeXBlOiByZXNpemVkLm1pbWVUeXBlLFxuICAgICAgfSk7XG4gICAgICB0aGlzLnJlbmRlckF0dGFjaFByZXZpZXcoKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBuZXcgTm90aWNlKGBGYWlsZWQgdG8gcGFzdGUgaW1hZ2U6ICR7ZX1gKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHJlc2l6ZUltYWdlKGZpbGU6IEZpbGUsIG1heFNpZGU6IG51bWJlciwgcXVhbGl0eTogbnVtYmVyKTogUHJvbWlzZTx7IGJhc2U2NDogc3RyaW5nOyBtaW1lVHlwZTogc3RyaW5nIH0+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgY29uc3QgaW1nID0gbmV3IEltYWdlKCk7XG4gICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGZpbGUpO1xuICAgICAgaW1nLm9ubG9hZCA9ICgpID0+IHtcbiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpO1xuICAgICAgICBsZXQgeyB3aWR0aCwgaGVpZ2h0IH0gPSBpbWc7XG4gICAgICAgIGlmICh3aWR0aCA+IG1heFNpZGUgfHwgaGVpZ2h0ID4gbWF4U2lkZSkge1xuICAgICAgICAgIGNvbnN0IHNjYWxlID0gbWF4U2lkZSAvIE1hdGgubWF4KHdpZHRoLCBoZWlnaHQpO1xuICAgICAgICAgIHdpZHRoID0gTWF0aC5yb3VuZCh3aWR0aCAqIHNjYWxlKTtcbiAgICAgICAgICBoZWlnaHQgPSBNYXRoLnJvdW5kKGhlaWdodCAqIHNjYWxlKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwiY2FudmFzXCIpO1xuICAgICAgICBjYW52YXMud2lkdGggPSB3aWR0aDtcbiAgICAgICAgY2FudmFzLmhlaWdodCA9IGhlaWdodDtcbiAgICAgICAgY29uc3QgY3R4ID0gY2FudmFzLmdldENvbnRleHQoXCIyZFwiKTtcbiAgICAgICAgaWYgKCFjdHgpIHsgcmVqZWN0KG5ldyBFcnJvcihcIk5vIGNhbnZhcyBjb250ZXh0XCIpKTsgcmV0dXJuOyB9XG4gICAgICAgIGN0eC5kcmF3SW1hZ2UoaW1nLCAwLCAwLCB3aWR0aCwgaGVpZ2h0KTtcbiAgICAgICAgY29uc3QgZGF0YVVybCA9IGNhbnZhcy50b0RhdGFVUkwoXCJpbWFnZS9qcGVnXCIsIHF1YWxpdHkpO1xuICAgICAgICBjb25zdCBiYXNlNjQgPSBkYXRhVXJsLnNwbGl0KFwiLFwiKVsxXTtcbiAgICAgICAgcmVzb2x2ZSh7IGJhc2U2NCwgbWltZVR5cGU6IFwiaW1hZ2UvanBlZ1wiIH0pO1xuICAgICAgfTtcbiAgICAgIGltZy5vbmVycm9yID0gKCkgPT4geyBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7IHJlamVjdChuZXcgRXJyb3IoXCJGYWlsZWQgdG8gbG9hZCBpbWFnZVwiKSk7IH07XG4gICAgICBpbWcuc3JjID0gdXJsO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSByZW5kZXJBdHRhY2hQcmV2aWV3KCk6IHZvaWQge1xuICAgIHRoaXMuYXR0YWNoUHJldmlld0VsLmVtcHR5KCk7XG4gICAgaWYgKHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5hdHRhY2hQcmV2aWV3RWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIHRoaXMuYXR0YWNoUHJldmlld0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgYXR0ID0gdGhpcy5wZW5kaW5nQXR0YWNobWVudHNbaV07XG4gICAgICBjb25zdCBjaGlwID0gdGhpcy5hdHRhY2hQcmV2aWV3RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctYXR0YWNoLWNoaXBcIik7XG5cbiAgICAgIC8vIFNob3cgdGh1bWJuYWlsIGZvciBpbWFnZXNcbiAgICAgIGlmIChhdHQuYmFzZTY0ICYmIGF0dC5taW1lVHlwZSkge1xuICAgICAgICBjb25zdCBzcmMgPSBgZGF0YToke2F0dC5taW1lVHlwZX07YmFzZTY0LCR7YXR0LmJhc2U2NH1gO1xuICAgICAgICBjaGlwLmNyZWF0ZUVsKFwiaW1nXCIsIHsgY2xzOiBcIm9wZW5jbGF3LWF0dGFjaC10aHVtYlwiLCBhdHRyOiB7IHNyYyB9IH0pO1xuICAgICAgfSBlbHNlIGlmIChhdHQudmF1bHRQYXRoKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3Qgc3JjID0gdGhpcy5hcHAudmF1bHQuYWRhcHRlci5nZXRSZXNvdXJjZVBhdGgoYXR0LnZhdWx0UGF0aCk7XG4gICAgICAgICAgaWYgKHNyYykgY2hpcC5jcmVhdGVFbChcImltZ1wiLCB7IGNsczogXCJvcGVuY2xhdy1hdHRhY2gtdGh1bWJcIiwgYXR0cjogeyBzcmMgfSB9KTtcbiAgICAgICAgfSBjYXRjaCB7IC8qIGlnbm9yZSAqLyB9XG4gICAgICB9XG5cbiAgICAgIGNoaXAuY3JlYXRlU3Bhbih7IHRleHQ6IGF0dC5uYW1lLCBjbHM6IFwib3BlbmNsYXctYXR0YWNoLW5hbWVcIiB9KTtcbiAgICAgIGNvbnN0IHJlbW92ZUJ0biA9IGNoaXAuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjcxNVwiLCBjbHM6IFwib3BlbmNsYXctYXR0YWNoLXJlbW92ZVwiIH0pO1xuICAgICAgY29uc3QgaWR4ID0gaTtcbiAgICAgIHJlbW92ZUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgICB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5zcGxpY2UoaWR4LCAxKTtcbiAgICAgICAgdGhpcy5yZW5kZXJBdHRhY2hQcmV2aWV3KCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGJ1aWxkVG9vbExhYmVsKHRvb2xOYW1lOiBzdHJpbmcsIGFyZ3M6IFJlY29yZDxzdHJpbmcsIHVua25vd24+IHwgdW5kZWZpbmVkKTogeyBsYWJlbDogc3RyaW5nOyB1cmw/OiBzdHJpbmcgfSB7XG4gICAgY29uc3QgYSA9IGFyZ3MgPz8ge307XG4gICAgc3dpdGNoICh0b29sTmFtZSkge1xuICAgICAgY2FzZSBcImV4ZWNcIjoge1xuICAgICAgICBjb25zdCBjbWQgPSBzdHIoYT8uY29tbWFuZCk7XG4gICAgICAgIGNvbnN0IHNob3J0ID0gY21kLmxlbmd0aCA+IDYwID8gY21kLnNsaWNlKDAsIDYwKSArIFwiXHUyMDI2XCIgOiBjbWQ7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNEXHVERDI3ICR7c2hvcnQgfHwgXCJSdW5uaW5nIGNvbW1hbmRcIn1gIH07XG4gICAgICB9XG4gICAgICBjYXNlIFwicmVhZFwiOiBjYXNlIFwiUmVhZFwiOiB7XG4gICAgICAgIGNvbnN0IHAgPSBzdHIoYT8ucGF0aCwgc3RyKGE/LmZpbGVfcGF0aCkpO1xuICAgICAgICBjb25zdCBuYW1lID0gcC5zcGxpdChcIi9cIikucG9wKCkgfHwgXCJmaWxlXCI7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNEXHVEQ0M0IFJlYWRpbmcgJHtuYW1lfWAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJ3cml0ZVwiOiBjYXNlIFwiV3JpdGVcIjoge1xuICAgICAgICBjb25zdCBwID0gc3RyKGE/LnBhdGgsIHN0cihhPy5maWxlX3BhdGgpKTtcbiAgICAgICAgY29uc3QgbmFtZSA9IHAuc3BsaXQoXCIvXCIpLnBvcCgpIHx8IFwiZmlsZVwiO1xuICAgICAgICByZXR1cm4geyBsYWJlbDogYFx1MjcwRlx1RkUwRiBXcml0aW5nICR7bmFtZX1gIH07XG4gICAgICB9XG4gICAgICBjYXNlIFwiZWRpdFwiOiBjYXNlIFwiRWRpdFwiOiB7XG4gICAgICAgIGNvbnN0IHAgPSBzdHIoYT8ucGF0aCwgc3RyKGE/LmZpbGVfcGF0aCkpO1xuICAgICAgICBjb25zdCBuYW1lID0gcC5zcGxpdChcIi9cIikucG9wKCkgfHwgXCJmaWxlXCI7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHUyNzBGXHVGRTBGIEVkaXRpbmcgJHtuYW1lfWAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJ3ZWJfc2VhcmNoXCI6IHtcbiAgICAgICAgY29uc3QgcSA9IHN0cihhPy5xdWVyeSk7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNEXHVERDBEIFNlYXJjaGluZyBcIiR7cS5sZW5ndGggPiA0MCA/IHEuc2xpY2UoMCwgNDApICsgXCJcdTIwMjZcIiA6IHF9XCJgIH07XG4gICAgICB9XG4gICAgICBjYXNlIFwid2ViX2ZldGNoXCI6IHtcbiAgICAgICAgY29uc3QgcmF3VXJsID0gc3RyKGE/LnVybCk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgZG9tYWluID0gbmV3IFVSTChyYXdVcmwpLmhvc3RuYW1lO1xuICAgICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNDXHVERjEwIEZldGNoaW5nICR7ZG9tYWlufWAsIHVybDogcmF3VXJsIH07XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNDXHVERjEwIEZldGNoaW5nIHBhZ2VgLCB1cmw6IHJhd1VybCB8fCB1bmRlZmluZWQgfTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgY2FzZSBcImJyb3dzZXJcIjpcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IFwiXHVEODNDXHVERjEwIFVzaW5nIGJyb3dzZXJcIiB9O1xuICAgICAgY2FzZSBcImltYWdlXCI6XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBcIlx1RDgzRFx1REM0MVx1RkUwRiBWaWV3aW5nIGltYWdlXCIgfTtcbiAgICAgIGNhc2UgXCJtZW1vcnlfc2VhcmNoXCI6IHtcbiAgICAgICAgY29uc3QgcSA9IHN0cihhPy5xdWVyeSk7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNFXHVEREUwIFNlYXJjaGluZyBcIiR7cS5sZW5ndGggPiA0MCA/IHEuc2xpY2UoMCwgNDApICsgXCJcdTIwMjZcIiA6IHF9XCJgIH07XG4gICAgICB9XG4gICAgICBjYXNlIFwibWVtb3J5X2dldFwiOiB7XG4gICAgICAgIGNvbnN0IHAgPSBzdHIoYT8ucGF0aCk7XG4gICAgICAgIGNvbnN0IG5hbWUgPSBwLnNwbGl0KFwiL1wiKS5wb3AoKSB8fCBcIm1lbW9yeVwiO1xuICAgICAgICByZXR1cm4geyBsYWJlbDogYFx1RDgzRVx1RERFMCBSZWFkaW5nICR7bmFtZX1gIH07XG4gICAgICB9XG4gICAgICBjYXNlIFwibWVzc2FnZVwiOlxuICAgICAgICByZXR1cm4geyBsYWJlbDogXCJcdUQ4M0RcdURDQUMgU2VuZGluZyBtZXNzYWdlXCIgfTtcbiAgICAgIGNhc2UgXCJ0dHNcIjpcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IFwiXHVEODNEXHVERDBBIFNwZWFraW5nXCIgfTtcbiAgICAgIGNhc2UgXCJzZXNzaW9uc19zcGF3blwiOlxuICAgICAgICByZXR1cm4geyBsYWJlbDogXCJcdUQ4M0VcdUREMTYgU3Bhd25pbmcgc3ViLWFnZW50XCIgfTtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiB0b29sTmFtZSA/IGBcdTI2QTEgJHt0b29sTmFtZX1gIDogXCJXb3JraW5nXCIgfTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFwcGVuZFRvb2xDYWxsKGxhYmVsOiBzdHJpbmcsIHVybD86IHN0cmluZywgYWN0aXZlID0gZmFsc2UpOiB2b2lkIHtcbiAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJkaXZcIik7XG4gICAgZWwuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy10b29sLWl0ZW1cIiArIChhY3RpdmUgPyBcIiBvcGVuY2xhdy10b29sLWFjdGl2ZVwiIDogXCJcIik7XG4gICAgaWYgKHVybCkge1xuICAgICAgY29uc3QgbGluayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJhXCIpO1xuICAgICAgbGluay5ocmVmID0gdXJsO1xuICAgICAgbGluay50ZXh0Q29udGVudCA9IGxhYmVsO1xuICAgICAgbGluay5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LXRvb2wtbGlua1wiO1xuICAgICAgbGluay5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKGUpID0+IHtcbiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB3aW5kb3cub3Blbih1cmwsIFwiX2JsYW5rXCIpO1xuICAgICAgfSk7XG4gICAgICBlbC5hcHBlbmRDaGlsZChsaW5rKTtcbiAgICB9IGVsc2Uge1xuICAgICAgY29uc3Qgc3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJzcGFuXCIpO1xuICAgICAgc3Bhbi50ZXh0Q29udGVudCA9IGxhYmVsO1xuICAgICAgZWwuYXBwZW5kQ2hpbGQoc3Bhbik7XG4gICAgfVxuICAgIGlmIChhY3RpdmUpIHtcbiAgICAgIGNvbnN0IGRvdHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwic3BhblwiKTtcbiAgICAgIGRvdHMuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy10b29sLWRvdHNcIjtcbiAgICAgIGRvdHMuY3JlYXRlU3BhbihcIm9wZW5jbGF3LWRvdFwiKTtcbiAgICAgIGRvdHMuY3JlYXRlU3BhbihcIm9wZW5jbGF3LWRvdFwiKTtcbiAgICAgIGRvdHMuY3JlYXRlU3BhbihcIm9wZW5jbGF3LWRvdFwiKTtcbiAgICAgIGVsLmFwcGVuZENoaWxkKGRvdHMpO1xuICAgIH1cbiAgICB0aGlzLm1lc3NhZ2VzRWwuYXBwZW5kQ2hpbGQoZWwpO1xuICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTtcbiAgfVxuXG4gIHByaXZhdGUgZGVhY3RpdmF0ZUxhc3RUb29sSXRlbSgpOiB2b2lkIHtcbiAgICBjb25zdCBpdGVtcyA9IHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yQWxsKFwiLm9wZW5jbGF3LXRvb2wtYWN0aXZlXCIpO1xuICAgIGNvbnN0IGxhc3QgPSBpdGVtc1tpdGVtcy5sZW5ndGggLSAxXTtcbiAgICBpZiAobGFzdCkge1xuICAgICAgbGFzdC5yZW1vdmVDbGFzcyhcIm9wZW5jbGF3LXRvb2wtYWN0aXZlXCIpO1xuICAgICAgY29uc3QgZG90cyA9IGxhc3QucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10b29sLWRvdHNcIik7XG4gICAgICBpZiAoZG90cykgZG90cy5yZW1vdmUoKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHBsYXlUVFNBdWRpbyhfYXVkaW9QYXRoOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBMb2NhbCBmaWxlIHN5c3RlbSBhY2Nlc3Mgbm90IGF2YWlsYWJsZSBpbiB0aGUgT2JzaWRpYW4gcGx1Z2luIHNhbmRib3guXG4gICAgLy8gQXVkaW8gaXMgc3RyZWFtZWQgdmlhIGdhdGV3YXkgSFRUUCB1c2luZyByZW5kZXJBdWRpb1BsYXllciBpbnN0ZWFkLlxuICB9XG5cbiAgcHJpdmF0ZSBzaG93QmFubmVyKHRleHQ6IHN0cmluZyk6IHZvaWQge1xuICAgIGlmICghdGhpcy5iYW5uZXJFbCkgcmV0dXJuO1xuICAgIHRoaXMuYmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0O1xuICAgIHRoaXMuYmFubmVyRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gIH1cblxuICBwcml2YXRlIGhpZGVCYW5uZXIoKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLmJhbm5lckVsKSByZXR1cm47XG4gICAgdGhpcy5iYW5uZXJFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgfVxuXG4gIC8qKiBSZXNvbHZlIHdoaWNoIHNlc3Npb24gYSBzdHJlYW0vYWdlbnQgZXZlbnQgYmVsb25ncyB0byAqL1xuICBwcml2YXRlIHJlc29sdmVTdHJlYW1TZXNzaW9uKHBheWxvYWQ6IEdhdGV3YXlQYXlsb2FkKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgLy8gVHJ5IHNlc3Npb25LZXkgb24gcGF5bG9hZCBmaXJzdFxuICAgIGNvbnN0IHNrID0gc3RyKHBheWxvYWQuc2Vzc2lvbktleSk7XG4gICAgaWYgKHNrKSB7XG4gICAgICAvLyBOb3JtYWxpemU6IHN0cmlwIGFnZW50Om1haW46IHByZWZpeFxuICAgICAgY29uc3QgcHJlZml4ID0gdGhpcy5hZ2VudFByZWZpeDtcbiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBzay5zdGFydHNXaXRoKHByZWZpeCkgPyBzay5zbGljZShwcmVmaXgubGVuZ3RoKSA6IHNrO1xuICAgICAgaWYgKHRoaXMuc3RyZWFtcy5oYXMobm9ybWFsaXplZCkpIHJldHVybiBub3JtYWxpemVkO1xuICAgIH1cbiAgICAvLyBGYWxsIGJhY2sgdG8gcnVuSWQgbWFwcGluZ1xuICAgIGNvbnN0IGRhdGEgPSBwYXlsb2FkLmRhdGEgYXMgR2F0ZXdheVBheWxvYWQgfCB1bmRlZmluZWQ7XG4gICAgY29uc3QgcnVuSWQgPSBzdHIocGF5bG9hZC5ydW5JZCwgc3RyKGRhdGE/LnJ1bklkKSk7XG4gICAgaWYgKHJ1bklkICYmIHRoaXMucnVuVG9TZXNzaW9uLmhhcyhydW5JZCkpIHJldHVybiB0aGlzLnJ1blRvU2Vzc2lvbi5nZXQocnVuSWQpITtcbiAgICAvLyBMYXN0IHJlc29ydDogaWYgb25seSBvbmUgc3RyZWFtIGlzIGFjdGl2ZSwgdXNlIHRoYXRcbiAgICBpZiAodGhpcy5zdHJlYW1zLnNpemUgPT09IDEpIHJldHVybiB0aGlzLnN0cmVhbXMua2V5cygpLm5leHQoKS52YWx1ZSE7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBoYW5kbGVTdHJlYW1FdmVudChwYXlsb2FkOiBHYXRld2F5UGF5bG9hZCk6IHZvaWQge1xuICAgIGNvbnN0IHN0cmVhbSA9IHN0cihwYXlsb2FkLnN0cmVhbSk7XG4gICAgY29uc3Qgc3RhdGUgPSBzdHIocGF5bG9hZC5zdGF0ZSk7XG4gICAgY29uc3QgcGF5bG9hZERhdGEgPSBwYXlsb2FkLmRhdGEgYXMgR2F0ZXdheVBheWxvYWQgfCB1bmRlZmluZWQ7XG5cbiAgICBjb25zdCBzZXNzaW9uS2V5ID0gdGhpcy5yZXNvbHZlU3RyZWFtU2Vzc2lvbihwYXlsb2FkKTtcbiAgICBjb25zdCBpc0FjdGl2ZVRhYiA9IHNlc3Npb25LZXkgPT09IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcblxuICAgIC8vIENvbXBhY3Rpb24gY2FuIGFycml2ZSB3aXRob3V0IGFuIGFjdGl2ZSBzdHJlYW1cbiAgICBpZiAoIXNlc3Npb25LZXkgfHwgIXRoaXMuc3RyZWFtcy5oYXMoc2Vzc2lvbktleSkpIHtcbiAgICAgIGlmIChzdHJlYW0gPT09IFwiY29tcGFjdGlvblwiIHx8IHN0YXRlID09PSBcImNvbXBhY3RpbmdcIikge1xuICAgICAgICBjb25zdCBjUGhhc2UgPSBzdHIocGF5bG9hZERhdGE/LnBoYXNlKTtcbiAgICAgICAgaWYgKGlzQWN0aXZlVGFiIHx8ICFzZXNzaW9uS2V5KSB7XG4gICAgICAgICAgaWYgKGNQaGFzZSA9PT0gXCJlbmRcIikge1xuICAgICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmhpZGVCYW5uZXIoKSwgMjAwMCk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuc2hvd0Jhbm5lcihcIkNvbXBhY3RpbmcgY29udGV4dC4uLlwiKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBzcyA9IHRoaXMuc3RyZWFtcy5nZXQoc2Vzc2lvbktleSkhO1xuICAgIGNvbnN0IHR5cGluZ1RleHQgPSB0aGlzLnR5cGluZ0VsLnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdHlwaW5nLXRleHRcIik7XG5cbiAgICAvLyBBZ2VudCBcImFzc2lzdGFudFwiIGV2ZW50cyA9IGFnZW50IGlzIGFjdGl2ZWx5IHdvcmtpbmdcbiAgICBpZiAoc3RhdGUgPT09IFwiYXNzaXN0YW50XCIpIHtcbiAgICAgIGNvbnN0IHRpbWVTaW5jZURlbHRhID0gRGF0ZS5ub3coKSAtIHNzLmxhc3REZWx0YVRpbWU7XG4gICAgICBpZiAoc3MudGV4dCAmJiB0aW1lU2luY2VEZWx0YSA+IDE1MDApIHtcbiAgICAgICAgaWYgKCFzcy53b3JraW5nVGltZXIpIHtcbiAgICAgICAgICBzcy53b3JraW5nVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgICAgIGlmICh0aGlzLnN0cmVhbXMuaGFzKHNlc3Npb25LZXkpKSB7XG4gICAgICAgICAgICAgIGlmIChpc0FjdGl2ZVRhYiAmJiB0aGlzLnR5cGluZ0VsLmhhc0NsYXNzKFwib2MtaGlkZGVuXCIpKSB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGluZ1RleHQpIHR5cGluZ1RleHQudGV4dENvbnRlbnQgPSBcIldvcmtpbmdcIjtcbiAgICAgICAgICAgICAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBzcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgICAgICAgIH0sIDUwMCk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSBpZiAoIXNzLnRleHQgJiYgIXNzLmxhc3REZWx0YVRpbWUgJiYgaXNBY3RpdmVUYWIpIHtcbiAgICAgICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHN0YXRlID09PSBcImxpZmVjeWNsZVwiKSB7XG4gICAgICBpZiAoIXNzLnRleHQgJiYgaXNBY3RpdmVUYWIgJiYgdHlwaW5nVGV4dCkge1xuICAgICAgICB0eXBpbmdUZXh0LnRleHRDb250ZW50ID0gXCJUaGlua2luZ1wiO1xuICAgICAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEhhbmRsZSBleHBsaWNpdCB0b29sIGV2ZW50c1xuICAgIGNvbnN0IHRvb2xOYW1lID0gc3RyKHBheWxvYWREYXRhPy5uYW1lLCBzdHIocGF5bG9hZERhdGE/LnRvb2xOYW1lLCBzdHIocGF5bG9hZC50b29sTmFtZSwgc3RyKHBheWxvYWQubmFtZSkpKSk7XG4gICAgY29uc3QgcGhhc2UgPSBzdHIocGF5bG9hZERhdGE/LnBoYXNlLCBzdHIocGF5bG9hZC5waGFzZSkpO1xuXG4gICAgaWYgKChzdHJlYW0gPT09IFwidG9vbFwiIHx8IHRvb2xOYW1lKSAmJiAocGhhc2UgPT09IFwic3RhcnRcIiB8fCBzdGF0ZSA9PT0gXCJ0b29sX3VzZVwiKSkge1xuICAgICAgaWYgKHNzLmNvbXBhY3RUaW1lcikgeyBjbGVhclRpbWVvdXQoc3MuY29tcGFjdFRpbWVyKTsgc3MuY29tcGFjdFRpbWVyID0gbnVsbDsgfVxuICAgICAgaWYgKHNzLndvcmtpbmdUaW1lcikgeyBjbGVhclRpbWVvdXQoc3Mud29ya2luZ1RpbWVyKTsgc3Mud29ya2luZ1RpbWVyID0gbnVsbDsgfVxuICAgICAgaWYgKHNzLnRleHQpIHtcbiAgICAgICAgc3Muc3BsaXRQb2ludHMucHVzaChzcy50ZXh0Lmxlbmd0aCk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGxhYmVsLCB1cmwgfSA9IHRoaXMuYnVpbGRUb29sTGFiZWwodG9vbE5hbWUsIChwYXlsb2FkRGF0YT8uYXJncyB8fCBwYXlsb2FkLmFyZ3MpIGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+IHwgdW5kZWZpbmVkKTtcbiAgICAgIHNzLnRvb2xDYWxscy5wdXNoKGxhYmVsKTtcbiAgICAgIHNzLml0ZW1zLnB1c2goeyB0eXBlOiBcInRvb2xcIiwgbGFiZWwsIHVybCB9IGFzIFN0cmVhbUl0ZW0pO1xuICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgIHRoaXMuYXBwZW5kVG9vbENhbGwobGFiZWwsIHVybCwgdHJ1ZSk7XG4gICAgICAgIGlmICh0eXBpbmdUZXh0KSB0eXBpbmdUZXh0LnRleHRDb250ZW50ID0gbGFiZWw7XG4gICAgICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB9XG4gICAgfSBlbHNlIGlmICgoc3RyZWFtID09PSBcInRvb2xcIiB8fCB0b29sTmFtZSkgJiYgcGhhc2UgPT09IFwicmVzdWx0XCIpIHtcbiAgICAgIGlmIChpc0FjdGl2ZVRhYikge1xuICAgICAgICB0aGlzLmRlYWN0aXZhdGVMYXN0VG9vbEl0ZW0oKTtcbiAgICAgICAgaWYgKHR5cGluZ1RleHQpIHR5cGluZ1RleHQudGV4dENvbnRlbnQgPSBcIlRoaW5raW5nXCI7XG4gICAgICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHN0cmVhbSA9PT0gXCJjb21wYWN0aW9uXCIgfHwgc3RhdGUgPT09IFwiY29tcGFjdGluZ1wiKSB7XG4gICAgICBpZiAocGhhc2UgPT09IFwiZW5kXCIpIHtcbiAgICAgICAgaWYgKGlzQWN0aXZlVGFiKSBzZXRUaW1lb3V0KCgpID0+IHRoaXMuaGlkZUJhbm5lcigpLCAyMDAwKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHNzLnRvb2xDYWxscy5wdXNoKFwiQ29tcGFjdGluZyBtZW1vcnlcIik7XG4gICAgICAgIHNzLml0ZW1zLnB1c2goeyB0eXBlOiBcInRvb2xcIiwgbGFiZWw6IFwiQ29tcGFjdGluZyBtZW1vcnlcIiB9KTtcbiAgICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgICAgdGhpcy5hcHBlbmRUb29sQ2FsbChcIkNvbXBhY3RpbmcgbWVtb3J5XCIpO1xuICAgICAgICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgICAgdGhpcy5zaG93QmFubmVyKFwiQ29tcGFjdGluZyBjb250ZXh0Li4uXCIpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgaGFuZGxlQ2hhdEV2ZW50KHBheWxvYWQ6IEdhdGV3YXlQYXlsb2FkKTogdm9pZCB7XG4gICAgLy8gUmVzb2x2ZSB3aGljaCBzZXNzaW9uIHRoaXMgZXZlbnQgYmVsb25ncyB0b1xuICAgIGNvbnN0IHBheWxvYWRTayA9IHN0cihwYXlsb2FkLnNlc3Npb25LZXkpO1xuICAgIGNvbnN0IHByZWZpeCA9IHRoaXMuYWdlbnRQcmVmaXg7XG4gICAgbGV0IGV2ZW50U2Vzc2lvbktleTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgLy8gVHJ5IHRvIG1hdGNoIGFnYWluc3Qga25vd24gc2Vzc2lvbnNcbiAgICBmb3IgKGNvbnN0IHNrIG9mIFsuLi50aGlzLnN0cmVhbXMua2V5cygpLCB0aGlzLmFjdGl2ZVNlc3Npb25LZXldKSB7XG4gICAgICBpZiAocGF5bG9hZFNrID09PSBzayB8fCBwYXlsb2FkU2sgPT09IGAke3ByZWZpeH0ke3NrfWAgfHwgcGF5bG9hZFNrLmVuZHNXaXRoKGA6JHtza31gKSkge1xuICAgICAgICBldmVudFNlc3Npb25LZXkgPSBzaztcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuICAgIC8vIElmIG5vIHN0cmVhbSBtYXRjaCwgY2hlY2sgaWYgaXQncyBmb3IgdGhlIGFjdGl2ZSB0YWIgKHBhc3NpdmUgZGV2aWNlIGNhc2UpXG4gICAgaWYgKCFldmVudFNlc3Npb25LZXkpIHtcbiAgICAgIGNvbnN0IGFjdGl2ZSA9IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcbiAgICAgIGlmIChwYXlsb2FkU2sgPT09IGFjdGl2ZSB8fCBwYXlsb2FkU2sgPT09IGAke3ByZWZpeH0ke2FjdGl2ZX1gIHx8IHBheWxvYWRTay5lbmRzV2l0aChgOiR7YWN0aXZlfWApKSB7XG4gICAgICAgIGV2ZW50U2Vzc2lvbktleSA9IGFjdGl2ZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybjsgLy8gTm90IGZvciBhbnkga25vd24gc2Vzc2lvblxuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IHNzID0gdGhpcy5zdHJlYW1zLmdldChldmVudFNlc3Npb25LZXkpO1xuICAgIGNvbnN0IGlzQWN0aXZlVGFiID0gZXZlbnRTZXNzaW9uS2V5ID09PSB0aGlzLmFjdGl2ZVNlc3Npb25LZXk7XG4gICAgY29uc3QgY2hhdFN0YXRlID0gc3RyKHBheWxvYWQuc3RhdGUpO1xuXG4gICAgLy8gTm8gYWN0aXZlIHN0cmVhbSBmb3IgdGhpcyBzZXNzaW9uIChwYXNzaXZlIGRldmljZSk6IHN0aWxsIHJlZnJlc2ggaGlzdG9yeVxuICAgIGlmICghc3MgJiYgKGNoYXRTdGF0ZSA9PT0gXCJmaW5hbFwiIHx8IGNoYXRTdGF0ZSA9PT0gXCJhYm9ydGVkXCIgfHwgY2hhdFN0YXRlID09PSBcImVycm9yXCIpKSB7XG4gICAgICBpZiAoaXNBY3RpdmVUYWIpIHtcbiAgICAgICAgdGhpcy5oaWRlQmFubmVyKCk7XG4gICAgICAgIHZvaWQgdGhpcy5sb2FkSGlzdG9yeSgpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmIChjaGF0U3RhdGUgPT09IFwiZGVsdGFcIiAmJiBzcykge1xuICAgICAgaWYgKHNzLmNvbXBhY3RUaW1lcikgeyBjbGVhclRpbWVvdXQoc3MuY29tcGFjdFRpbWVyKTsgc3MuY29tcGFjdFRpbWVyID0gbnVsbDsgfVxuICAgICAgaWYgKHNzLndvcmtpbmdUaW1lcikgeyBjbGVhclRpbWVvdXQoc3Mud29ya2luZ1RpbWVyKTsgc3Mud29ya2luZ1RpbWVyID0gbnVsbDsgfVxuICAgICAgc3MubGFzdERlbHRhVGltZSA9IERhdGUubm93KCk7XG4gICAgICBjb25zdCB0ZXh0ID0gdGhpcy5leHRyYWN0RGVsdGFUZXh0KHBheWxvYWQubWVzc2FnZSBhcyBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiB8IHN0cmluZyB8IHVuZGVmaW5lZCk7XG4gICAgICBpZiAodGV4dCkge1xuICAgICAgICBzcy50ZXh0ID0gdGV4dDtcbiAgICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgICAgdGhpcy50eXBpbmdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcbiAgICAgICAgICB0aGlzLnVwZGF0ZVN0cmVhbUJ1YmJsZSgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIGlmIChjaGF0U3RhdGUgPT09IFwiZmluYWxcIikge1xuICAgICAgY29uc3QgaXRlbXMgPSBzcyA/IFsuLi5zcy5pdGVtc10gOiBbXTtcbiAgICAgIHRoaXMuZmluaXNoU3RyZWFtKGV2ZW50U2Vzc2lvbktleSk7XG5cbiAgICAgIGlmIChpc0FjdGl2ZVRhYikge1xuICAgICAgICB2b2lkIHRoaXMubG9hZEhpc3RvcnkoKS50aGVuKGFzeW5jICgpID0+IHtcbiAgICAgICAgICBhd2FpdCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG4gICAgICAgICAgdm9pZCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgICAgIGlmIChpdGVtcy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICBjb25zdCBsYXN0QXNzaXN0YW50ID0gWy4uLnRoaXMubWVzc2FnZXNdLnJldmVyc2UoKS5maW5kKG0gPT4gbS5yb2xlID09PSBcImFzc2lzdGFudFwiKTtcbiAgICAgICAgICAgIGlmIChsYXN0QXNzaXN0YW50KSB7XG4gICAgICAgICAgICAgIGNvbnN0IGtleSA9IFN0cmluZyhsYXN0QXNzaXN0YW50LnRpbWVzdGFtcCk7XG4gICAgICAgICAgICAgIGlmICghdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXApIHRoaXMucGx1Z2luLnNldHRpbmdzLnN0cmVhbUl0ZW1zTWFwID0ge307XG4gICAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnN0cmVhbUl0ZW1zTWFwW2tleV0gPSBpdGVtcztcbiAgICAgICAgICAgICAgdm9pZCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gTm90IGFjdGl2ZSB0YWI6IGp1c3QgY2xlYW4gdXAsIGhpc3Rvcnkgd2lsbCBsb2FkIHdoZW4gdXNlciBzd2l0Y2hlcyB0byBpdFxuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoY2hhdFN0YXRlID09PSBcImFib3J0ZWRcIikge1xuICAgICAgaWYgKGlzQWN0aXZlVGFiICYmIHNzPy50ZXh0KSB7XG4gICAgICAgIHRoaXMubWVzc2FnZXMucHVzaCh7IHJvbGU6IFwiYXNzaXN0YW50XCIsIHRleHQ6IHNzLnRleHQsIGltYWdlczogW10sIHRpbWVzdGFtcDogRGF0ZS5ub3coKSB9KTtcbiAgICAgIH1cbiAgICAgIHRoaXMuZmluaXNoU3RyZWFtKGV2ZW50U2Vzc2lvbktleSk7XG4gICAgICBpZiAoaXNBY3RpdmVUYWIpIHZvaWQgdGhpcy5yZW5kZXJNZXNzYWdlcygpO1xuICAgIH0gZWxzZSBpZiAoY2hhdFN0YXRlID09PSBcImVycm9yXCIpIHtcbiAgICAgIGlmIChpc0FjdGl2ZVRhYikge1xuICAgICAgICB0aGlzLm1lc3NhZ2VzLnB1c2goe1xuICAgICAgICAgIHJvbGU6IFwiYXNzaXN0YW50XCIsXG4gICAgICAgICAgdGV4dDogYEVycm9yOiAke3N0cihwYXlsb2FkLmVycm9yTWVzc2FnZSwgXCJ1bmtub3duIGVycm9yXCIpfWAsXG4gICAgICAgICAgaW1hZ2VzOiBbXSxcbiAgICAgICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgdGhpcy5maW5pc2hTdHJlYW0oZXZlbnRTZXNzaW9uS2V5KTtcbiAgICAgIGlmIChpc0FjdGl2ZVRhYikgdm9pZCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBmaW5pc2hTdHJlYW0oc2Vzc2lvbktleT86IHN0cmluZyk6IHZvaWQge1xuICAgIGNvbnN0IHNrID0gc2Vzc2lvbktleSA/PyB0aGlzLmFjdGl2ZVNlc3Npb25LZXk7XG4gICAgY29uc3Qgc3MgPSB0aGlzLnN0cmVhbXMuZ2V0KHNrKTtcbiAgICBpZiAoc3MpIHtcbiAgICAgIGlmIChzcy5jb21wYWN0VGltZXIpIGNsZWFyVGltZW91dChzcy5jb21wYWN0VGltZXIpO1xuICAgICAgaWYgKHNzLndvcmtpbmdUaW1lcikgY2xlYXJUaW1lb3V0KHNzLndvcmtpbmdUaW1lcik7XG4gICAgICB0aGlzLnJ1blRvU2Vzc2lvbi5kZWxldGUoc3MucnVuSWQpO1xuICAgICAgdGhpcy5zdHJlYW1zLmRlbGV0ZShzayk7XG4gICAgfVxuICAgIC8vIE9ubHkgY2xlYXIgRE9NIGlmIHRoaXMgaXMgdGhlIGFjdGl2ZSB0YWJcbiAgICBpZiAoc2sgPT09IHRoaXMuYWN0aXZlU2Vzc2lvbktleSkge1xuICAgICAgdGhpcy5oaWRlQmFubmVyKCk7XG4gICAgICB0aGlzLnN0cmVhbUVsID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB0aGlzLnR5cGluZ0VsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgY29uc3QgdHlwaW5nVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcbiAgICAgIGlmICh0eXBpbmdUZXh0KSB0eXBpbmdUZXh0LnRleHRDb250ZW50ID0gXCJUaGlua2luZ1wiO1xuICAgIH1cbiAgfVxuXG4gIC8qKiBSZXN0b3JlIHN0cmVhbSBVSSAodHlwaW5nLCB0b29sIGNhbGxzLCBzdHJlYW0gYnViYmxlKSBmb3IgdGhlIGFjdGl2ZSB0YWIgYWZ0ZXIgYSB0YWIgc3dpdGNoICovXG4gIHByaXZhdGUgcmVzdG9yZVN0cmVhbVVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHNzID0gdGhpcy5hY3RpdmVTdHJlYW07XG4gICAgaWYgKCFzcykgcmV0dXJuO1xuXG4gICAgLy8gU2hvdyBhYm9ydCBidXR0b25cbiAgICB0aGlzLmFib3J0QnRuLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuXG4gICAgLy8gUmVzdG9yZSB0b29sIGNhbGwgaXRlbXMgaW4gdGhlIERPTVxuICAgIGZvciAoY29uc3QgaXRlbSBvZiBzcy5pdGVtcykge1xuICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gXCJ0b29sXCIpIHtcbiAgICAgICAgdGhpcy5hcHBlbmRUb29sQ2FsbChpdGVtLmxhYmVsLCBpdGVtLnVybCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gUmVzdG9yZSBzdHJlYW0gdGV4dCBidWJibGUgaWYgd2UgaGF2ZSBkZWx0YSB0ZXh0XG4gICAgaWYgKHNzLnRleHQpIHtcbiAgICAgIHRoaXMudXBkYXRlU3RyZWFtQnViYmxlKCk7XG4gICAgICAvLyBJZiB0ZXh0IGlzIHN0cmVhbWluZywgc2hvdyB3b3JraW5nIGluZGljYXRvciAodGV4dCBleGlzdHMgYnV0IG1pZ2h0IHN0aWxsIGJlIGNvbWluZylcbiAgICAgIGNvbnN0IHR5cGluZ1RleHQgPSB0aGlzLnR5cGluZ0VsLnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdHlwaW5nLXRleHRcIik7XG4gICAgICBpZiAodHlwaW5nVGV4dCkgdHlwaW5nVGV4dC50ZXh0Q29udGVudCA9IFwiV29ya2luZ1wiO1xuICAgICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gTm8gdGV4dCB5ZXQsIHNob3cgdGhpbmtpbmdcbiAgICAgIGNvbnN0IHR5cGluZ1RleHQgPSB0aGlzLnR5cGluZ0VsLnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdHlwaW5nLXRleHRcIik7XG4gICAgICBpZiAodHlwaW5nVGV4dCkgdHlwaW5nVGV4dC50ZXh0Q29udGVudCA9IFwiVGhpbmtpbmdcIjtcbiAgICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgfVxuXG4gICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuICB9XG5cbiAgcHJpdmF0ZSBpbnNlcnRTdHJlYW1JdGVtc0JlZm9yZUxhc3RBc3Npc3RhbnQoaXRlbXM6IFN0cmVhbUl0ZW1bXSk6IHZvaWQge1xuICAgIGlmIChpdGVtcy5sZW5ndGggPT09IDApIHJldHVybjtcbiAgICBjb25zdCBidWJibGVzID0gdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3JBbGwoXCIub3BlbmNsYXctbXNnLWFzc2lzdGFudFwiKTtcbiAgICBjb25zdCBsYXN0QnViYmxlID0gYnViYmxlc1tidWJibGVzLmxlbmd0aCAtIDFdO1xuICAgIGlmICghbGFzdEJ1YmJsZSkgcmV0dXJuO1xuXG4gICAgZm9yIChjb25zdCBpdGVtIG9mIGl0ZW1zKSB7XG4gICAgICBjb25zdCBlbCA9IHRoaXMuY3JlYXRlU3RyZWFtSXRlbUVsKGl0ZW0pO1xuICAgICAgbGFzdEJ1YmJsZS5wYXJlbnRFbGVtZW50Py5pbnNlcnRCZWZvcmUoZWwsIGxhc3RCdWJibGUpO1xuICAgIH1cbiAgICB0aGlzLnNjcm9sbFRvQm90dG9tKCk7XG4gIH1cblxuICBwcml2YXRlIGNyZWF0ZVN0cmVhbUl0ZW1FbChpdGVtOiBTdHJlYW1JdGVtKTogSFRNTEVsZW1lbnQge1xuICAgIGlmIChpdGVtLnR5cGUgPT09IFwidG9vbFwiKSB7XG4gICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJkaXZcIik7XG4gICAgICBlbC5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LXRvb2wtaXRlbVwiO1xuICAgICAgaWYgKGl0ZW0udXJsKSB7XG4gICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwiYVwiKTtcbiAgICAgICAgbGluay5ocmVmID0gaXRlbS51cmw7XG4gICAgICAgIGxpbmsudGV4dENvbnRlbnQgPSBpdGVtLmxhYmVsO1xuICAgICAgICBsaW5rLmNsYXNzTmFtZSA9IFwib3BlbmNsYXctdG9vbC1saW5rXCI7XG4gICAgICAgIGxpbmsuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsIChlKSA9PiB7IGUucHJldmVudERlZmF1bHQoKTsgd2luZG93Lm9wZW4oaXRlbS51cmwsIFwiX2JsYW5rXCIpOyB9KTtcbiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobGluayk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBlbC50ZXh0Q29udGVudCA9IGl0ZW0ubGFiZWw7XG4gICAgICB9XG4gICAgICByZXR1cm4gZWw7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IGRldGFpbHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwiZGV0YWlsc1wiKTtcbiAgICAgIGRldGFpbHMuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy1pbnRlcm1lZGlhcnlcIjtcbiAgICAgIGNvbnN0IHN1bW1hcnkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwic3VtbWFyeVwiKTtcbiAgICAgIHN1bW1hcnkuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy1pbnRlcm1lZGlhcnktc3VtbWFyeVwiO1xuICAgICAgY29uc3QgcHJldmlldyA9IGl0ZW0udGV4dC5sZW5ndGggPiA2MCA/IGl0ZW0udGV4dC5zbGljZSgwLCA2MCkgKyBcIi4uLlwiIDogaXRlbS50ZXh0O1xuICAgICAgc3VtbWFyeS50ZXh0Q29udGVudCA9IHByZXZpZXc7XG4gICAgICBkZXRhaWxzLmFwcGVuZENoaWxkKHN1bW1hcnkpO1xuICAgICAgY29uc3QgY29udGVudCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJkaXZcIik7XG4gICAgICBjb250ZW50LmNsYXNzTmFtZSA9IFwib3BlbmNsYXctaW50ZXJtZWRpYXJ5LWNvbnRlbnRcIjtcbiAgICAgIGNvbnRlbnQudGV4dENvbnRlbnQgPSBpdGVtLnRleHQ7XG4gICAgICBkZXRhaWxzLmFwcGVuZENoaWxkKGNvbnRlbnQpO1xuICAgICAgcmV0dXJuIGRldGFpbHM7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBjbGVhblRleHQodGV4dDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9Db252ZXJzYXRpb24gaW5mbyBcXCh1bnRydXN0ZWQgbWV0YWRhdGFcXCk6XFxzKmBgYGpzb25bXFxzXFxTXSo/YGBgXFxzKi9nLCBcIlwiKS50cmltKCk7XG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXmBgYGpzb25cXHMqXFx7XFxzKlwibWVzc2FnZV9pZFwiW1xcc1xcU10qP2BgYFxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eXFxbLio/R01UWystXVxcZCtcXF1cXHMqL2dtLCBcIlwiKS50cmltKCk7XG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXlxcW21lZGlhIGF0dGFjaGVkOi4qP1xcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eVG8gc2VuZCBhbiBpbWFnZSBiYWNrLiokL2dtLCBcIlwiKS50cmltKCk7XG4gICAgLy8gU3RyaXAgVFRTIGRpcmVjdGl2ZXMgYW5kIE1FRElBOiBwYXRocyAocmVuZGVyZWQgYXMgYXVkaW8gcGxheWVycyBzZXBhcmF0ZWx5KVxuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15cXFtcXFthdWRpb19hc192b2ljZVxcXVxcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eTUVESUE6XFwvW15cXG5dKyQvZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eVk9JQ0U6W15cXHNcXG5dKyQvZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBpbmJvdW5kIHZvaWNlIGRhdGEgKHNob3duIGFzIFwiXHVEODNDXHVERkE0IFZvaWNlIG1lc3NhZ2VcIiBpbiBVSSlcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eQVVESU9fREFUQTpbXlxcbl0rJC9nbSwgXCJcIikudHJpbSgpO1xuICAgIGlmICh0ZXh0ID09PSBcIlx1RDgzQ1x1REZBNCBWb2ljZSBtZXNzYWdlXCIpIHRleHQgPSBcIlx1RDgzQ1x1REZBNCBWb2ljZSBtZXNzYWdlXCI7IC8vIGtlZXAgdGhlIGxhYmVsXG4gICAgaWYgKHRleHQgPT09IFwiTk9fUkVQTFlcIiB8fCB0ZXh0ID09PSBcIkhFQVJUQkVBVF9PS1wiKSByZXR1cm4gXCJcIjtcbiAgICByZXR1cm4gdGV4dDtcbiAgfVxuXG4gIC8qKiBFeHRyYWN0IFZPSUNFOnBhdGggcmVmZXJlbmNlcyBmcm9tIG1lc3NhZ2UgdGV4dCAqL1xuICBwcml2YXRlIGV4dHJhY3RWb2ljZVJlZnModGV4dDogc3RyaW5nKTogc3RyaW5nW10ge1xuICAgIGNvbnN0IHJlZnM6IHN0cmluZ1tdID0gW107XG4gICAgY29uc3QgcmUgPSAvXlZPSUNFOihbXlxcc1xcbl0rXFwuKD86bXAzfG9wdXN8b2dnfHdhdnxtNGF8bXA0KSkkL2dtO1xuICAgIGxldCBtYXRjaDogUmVnRXhwRXhlY0FycmF5IHwgbnVsbDtcbiAgICB3aGlsZSAoKG1hdGNoID0gcmUuZXhlYyh0ZXh0KSkgIT09IG51bGwpIHtcbiAgICAgIHJlZnMucHVzaChtYXRjaFsxXS50cmltKCkpO1xuICAgIH1cbiAgICByZXR1cm4gcmVmcztcbiAgfVxuXG4gIC8qKiBCdWlsZCBIVFRQIFVSTCBmb3IgYSB2b2ljZSBmaWxlIHNlcnZlZCBieSB0aGUgZ2F0ZXdheSAqL1xuICBwcml2YXRlIGJ1aWxkVm9pY2VVcmwodm9pY2VQYXRoOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIC8vIEdhdGV3YXkgVVJMIGlzIHdzOi8vIG9yIHdzczovLyBcdTIwMTQgY29udmVydCB0byBodHRwOi8vIG9yIGh0dHBzOi8vXG4gICAgY29uc3QgZ3dVcmwgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsIHx8IFwiXCI7XG4gICAgY29uc3QgaHR0cFVybCA9IGd3VXJsLnJlcGxhY2UoL153cyhzPyk6XFwvXFwvLywgXCJodHRwJDE6Ly9cIik7XG4gICAgcmV0dXJuIGAke2h0dHBVcmx9LyR7dm9pY2VQYXRofWA7XG4gIH1cblxuICAvKiogUmVuZGVyIGFuIGlubGluZSBhdWRpbyBwbGF5ZXIgdGhhdCBmZXRjaGVzIGF1ZGlvIHZpYSBnYXRld2F5IEhUVFAgKi9cbiAgcHJpdmF0ZSByZW5kZXJBdWRpb1BsYXllcihjb250YWluZXI6IEhUTUxFbGVtZW50LCB2b2ljZVJlZjogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgcGxheWVyRWwgPSBjb250YWluZXIuY3JlYXRlRGl2KFwib3BlbmNsYXctYXVkaW8tcGxheWVyXCIpO1xuICAgIGNvbnN0IHBsYXlCdG4gPSBwbGF5ZXJFbC5jcmVhdGVFbChcImJ1dHRvblwiLCB7IGNsczogXCJvcGVuY2xhdy1hdWRpby1wbGF5LWJ0blwiLCB0ZXh0OiBcIlx1MjVCNiB2b2ljZSBtZXNzYWdlXCIgfSk7XG4gICAgY29uc3QgcHJvZ3Jlc3NFbCA9IHBsYXllckVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LWF1ZGlvLXByb2dyZXNzXCIpO1xuICAgIGNvbnN0IGJhckVsID0gcHJvZ3Jlc3NFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1hdWRpby1iYXJcIik7XG5cbiAgICBsZXQgYXVkaW86IEhUTUxBdWRpb0VsZW1lbnQgfCBudWxsID0gbnVsbDtcblxuICAgIHBsYXlCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChhdWRpbyAmJiAhYXVkaW8ucGF1c2VkKSB7XG4gICAgICAgIGF1ZGlvLnBhdXNlKCk7XG4gICAgICAgIHBsYXlCdG4udGV4dENvbnRlbnQgPSBcIlx1MjVCNiB2b2ljZSBtZXNzYWdlXCI7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgaWYgKCFhdWRpbykge1xuICAgICAgICBwbGF5QnRuLnRleHRDb250ZW50ID0gXCJcdTIzRjMgbG9hZGluZy4uLlwiO1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGNvbnN0IHVybCA9IHRoaXMuYnVpbGRWb2ljZVVybCh2b2ljZVJlZik7XG4gICAgICAgICAgY29uc29sZS5kZWJ1ZyhcIltPYnNpZGlhbkNsYXddIExvYWRpbmcgYXVkaW8gZnJvbTpcIiwgdXJsKTtcbiAgICAgICAgICBhdWRpbyA9IG5ldyBBdWRpbyh1cmwpO1xuXG4gICAgICAgICAgYXdhaXQgbmV3IFByb21pc2U8dm9pZD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgdGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHJlamVjdChuZXcgRXJyb3IoXCJ0aW1lb3V0XCIpKSwgMTAwMDApO1xuICAgICAgICAgICAgYXVkaW8hLmFkZEV2ZW50TGlzdGVuZXIoXCJjYW5wbGF5dGhyb3VnaFwiLCAoKSA9PiB7IGNsZWFyVGltZW91dCh0aW1lcik7IHJlc29sdmUoKTsgfSwgeyBvbmNlOiB0cnVlIH0pO1xuICAgICAgICAgICAgYXVkaW8hLmFkZEV2ZW50TGlzdGVuZXIoXCJlcnJvclwiLCAoKSA9PiB7IGNsZWFyVGltZW91dCh0aW1lcik7IHJlamVjdChuZXcgRXJyb3IoXCJsb2FkIGVycm9yXCIpKTsgfSwgeyBvbmNlOiB0cnVlIH0pO1xuICAgICAgICAgICAgYXVkaW8hLmxvYWQoKTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIGF1ZGlvLmFkZEV2ZW50TGlzdGVuZXIoXCJ0aW1ldXBkYXRlXCIsICgpID0+IHtcbiAgICAgICAgICAgIGlmIChhdWRpbyAmJiBhdWRpby5kdXJhdGlvbikgYmFyRWwuc2V0Q3NzU3R5bGVzKHsgd2lkdGg6IGAkeyhhdWRpby5jdXJyZW50VGltZSAvIGF1ZGlvLmR1cmF0aW9uKSAqIDEwMH0lYCB9KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBhdWRpby5hZGRFdmVudExpc3RlbmVyKFwiZW5kZWRcIiwgKCkgPT4ge1xuICAgICAgICAgICAgcGxheUJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNUI2IHZvaWNlIG1lc3NhZ2VcIjtcbiAgICAgICAgICAgIGJhckVsLnNldENzc1N0eWxlcyh7IHdpZHRoOiBcIjAlXCIgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKFwiW09ic2lkaWFuQ2xhd10gQXVkaW8gbG9hZCBmYWlsZWQ6XCIsIGUpO1xuICAgICAgICAgIHBsYXlCdG4udGV4dENvbnRlbnQgPSBcIlx1MjZBMCBhdWRpbyB1bmF2YWlsYWJsZVwiO1xuICAgICAgICAgIHBsYXlCdG4uZGlzYWJsZWQgPSB0cnVlO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBwbGF5QnRuLnRleHRDb250ZW50ID0gXCJcdTIzRjggcGxheWluZy4uLlwiO1xuICAgICAgYXVkaW8ucGxheSgpLmNhdGNoKCgpID0+IHsgcGxheUJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNkEwIGF1ZGlvIHVuYXZhaWxhYmxlXCI7IHBsYXlCdG4uZGlzYWJsZWQgPSB0cnVlOyB9KTtcbiAgICB9KSgpKTtcbiAgfVxuXG4gIHByaXZhdGUgZXh0cmFjdERlbHRhVGV4dChtc2c6IFJlY29yZDxzdHJpbmcsIHVua25vd24+IHwgc3RyaW5nIHwgdW5kZWZpbmVkKTogc3RyaW5nIHtcbiAgICBpZiAodHlwZW9mIG1zZyA9PT0gXCJzdHJpbmdcIikgcmV0dXJuIG1zZztcbiAgICBpZiAoIW1zZykgcmV0dXJuIFwiXCI7XG4gICAgLy8gR2F0ZXdheSBzZW5kcyB7cm9sZSwgY29udGVudCwgdGltZXN0YW1wfSB3aGVyZSBjb250ZW50IGlzIFt7dHlwZTpcInRleHRcIiwgdGV4dDpcIi4uLlwifV1cbiAgICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnO1xuICAgIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgICBsZXQgdGV4dCA9IFwiXCI7XG4gICAgICBmb3IgKGNvbnN0IGJsb2NrIG9mIGNvbnRlbnQpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBibG9jayA9PT0gXCJzdHJpbmdcIikgeyB0ZXh0ICs9IGJsb2NrOyB9XG4gICAgICAgIGVsc2UgaWYgKGJsb2NrICYmIHR5cGVvZiBibG9jayA9PT0gXCJvYmplY3RcIiAmJiBcInRleHRcIiBpbiBibG9jaykgeyB0ZXh0ICs9ICh0ZXh0ID8gXCJcXG5cIiA6IFwiXCIpICsgU3RyaW5nKChibG9jayBhcyB7IHRleHQ6IHN0cmluZyB9KS50ZXh0KTsgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIHRleHQ7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgY29udGVudCA9PT0gXCJzdHJpbmdcIikgcmV0dXJuIGNvbnRlbnQ7XG4gICAgcmV0dXJuIHN0cihtc2cudGV4dCk7XG4gIH1cblxuICBwcml2YXRlIHVwZGF0ZVN0cmVhbUJ1YmJsZSgpOiB2b2lkIHtcbiAgICBjb25zdCBzcyA9IHRoaXMuYWN0aXZlU3RyZWFtO1xuICAgIGNvbnN0IHZpc2libGVUZXh0ID0gc3M/LnRleHQ7XG4gICAgaWYgKCF2aXNpYmxlVGV4dCkgcmV0dXJuO1xuICAgIGlmICghdGhpcy5zdHJlYW1FbCkge1xuICAgICAgdGhpcy5zdHJlYW1FbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1tc2cgb3BlbmNsYXctbXNnLWFzc2lzdGFudCBvcGVuY2xhdy1zdHJlYW1pbmdcIik7XG4gICAgICB0aGlzLnNjcm9sbFRvQm90dG9tKCk7IC8vIFNjcm9sbCBvbmNlIHdoZW4gYnViYmxlIGZpcnN0IGFwcGVhcnNcbiAgICB9XG4gICAgdGhpcy5zdHJlYW1FbC5lbXB0eSgpO1xuICAgIHRoaXMuc3RyZWFtRWwuY3JlYXRlRGl2KHsgdGV4dDogdmlzaWJsZVRleHQsIGNsczogXCJvcGVuY2xhdy1tc2ctdGV4dFwiIH0pO1xuICAgIC8vIERvbid0IGF1dG8tc2Nyb2xsIGR1cmluZyB0ZXh0IHN0cmVhbWluZyBcdTIwMTQgbGV0IHVzZXIgcmVhZCBmcm9tIHRoZSB0b3BcbiAgfVxuXG4gIGFzeW5jIHJlbmRlck1lc3NhZ2VzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgIGZvciAoY29uc3QgbXNnIG9mIHRoaXMubWVzc2FnZXMpIHtcbiAgICAgIGlmIChtc2cucm9sZSA9PT0gXCJhc3Npc3RhbnRcIikge1xuICAgICAgICBjb25zdCBoYXNDb250ZW50VG9vbHMgPSBtc2cuY29udGVudEJsb2Nrcz8uc29tZSgoYjogQ29udGVudEJsb2NrKSA9PiBiLnR5cGUgPT09IFwidG9vbF91c2VcIiB8fCBiLnR5cGUgPT09IFwidG9vbENhbGxcIikgfHwgZmFsc2U7XG5cbiAgICAgICAgaWYgKGhhc0NvbnRlbnRUb29scyAmJiBtc2cuY29udGVudEJsb2Nrcykge1xuICAgICAgICAgIC8vIFJlbmRlciBpbnRlcmxlYXZlZCB0ZXh0ICsgdG9vbCBibG9ja3MgZGlyZWN0bHlcbiAgICAgICAgICBmb3IgKGNvbnN0IGJsb2NrIG9mIG1zZy5jb250ZW50QmxvY2tzKSB7XG4gICAgICAgICAgICBpZiAoYmxvY2sudHlwZSA9PT0gXCJ0ZXh0XCIgJiYgYmxvY2sudGV4dD8udHJpbSgpKSB7XG4gICAgICAgICAgICAgIGNvbnN0IGJsb2NrQXVkaW8gPSB0aGlzLmV4dHJhY3RWb2ljZVJlZnMoYmxvY2sudGV4dCk7XG4gICAgICAgICAgICAgIGNvbnN0IGNsZWFuZWQgPSB0aGlzLmNsZWFuVGV4dChibG9jay50ZXh0KTtcbiAgICAgICAgICAgICAgLy8gUmVuZGVyIHRleHQgYnViYmxlIGlmIHRoZXJlJ3MgdmlzaWJsZSB0ZXh0XG4gICAgICAgICAgICAgIGlmIChjbGVhbmVkKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgYnViYmxlID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW1zZyBvcGVuY2xhdy1tc2ctYXNzaXN0YW50XCIpO1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICBhd2FpdCBNYXJrZG93blJlbmRlcmVyLnJlbmRlcih0aGlzLmFwcCwgY2xlYW5lZCwgYnViYmxlLCBcIlwiLCB0aGlzKTtcbiAgICAgICAgICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgIGJ1YmJsZS5jcmVhdGVEaXYoeyB0ZXh0OiBjbGVhbmVkLCBjbHM6IFwib3BlbmNsYXctbXNnLXRleHRcIiB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gQXVkaW8gcGxheWVycyBpbnNpZGUgdGV4dCBidWJibGVcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGFwIG9mIGJsb2NrQXVkaW8pIHtcbiAgICAgICAgICAgICAgICAgIHRoaXMucmVuZGVyQXVkaW9QbGF5ZXIoYnViYmxlLCBhcCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9IGVsc2UgaWYgKGJsb2NrQXVkaW8ubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgIC8vIE5vIHZpc2libGUgdGV4dCBidXQgaGFzIGF1ZGlvIFx1MjAxNCBjcmVhdGUgYSBidWJibGUganVzdCBmb3IgdGhlIHBsYXllclxuICAgICAgICAgICAgICAgIGNvbnN0IGJ1YmJsZSA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1tc2cgb3BlbmNsYXctbXNnLWFzc2lzdGFudFwiKTtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGFwIG9mIGJsb2NrQXVkaW8pIHtcbiAgICAgICAgICAgICAgICAgIHRoaXMucmVuZGVyQXVkaW9QbGF5ZXIoYnViYmxlLCBhcCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2UgaWYgKGJsb2NrLnR5cGUgPT09IFwidG9vbF91c2VcIiB8fCBibG9jay50eXBlID09PSBcInRvb2xDYWxsXCIpIHtcbiAgICAgICAgICAgICAgY29uc3QgeyBsYWJlbCwgdXJsIH0gPSB0aGlzLmJ1aWxkVG9vbExhYmVsKGJsb2NrLm5hbWUgfHwgXCJcIiwgYmxvY2suaW5wdXQgfHwgYmxvY2suYXJndW1lbnRzIHx8IHt9KTtcbiAgICAgICAgICAgICAgY29uc3QgZWwgPSB0aGlzLmNyZWF0ZVN0cmVhbUl0ZW1FbCh7IHR5cGU6IFwidG9vbFwiLCBsYWJlbCwgdXJsIH0gYXMgU3RyZWFtSXRlbSk7XG4gICAgICAgICAgICAgIHRoaXMubWVzc2FnZXNFbC5hcHBlbmRDaGlsZChlbCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICB9XG5cbiAgICAgIH1cbiAgICAgIGNvbnN0IGNscyA9IG1zZy5yb2xlID09PSBcInVzZXJcIiA/IFwib3BlbmNsYXctbXNnLXVzZXJcIiA6IFwib3BlbmNsYXctbXNnLWFzc2lzdGFudFwiO1xuICAgICAgY29uc3QgYnViYmxlID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdihgb3BlbmNsYXctbXNnICR7Y2xzfWApO1xuICAgICAgLy8gUmVuZGVyIGltYWdlc1xuICAgICAgaWYgKG1zZy5pbWFnZXMgJiYgbXNnLmltYWdlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIGNvbnN0IGltZ0NvbnRhaW5lciA9IGJ1YmJsZS5jcmVhdGVEaXYoXCJvcGVuY2xhdy1tc2ctaW1hZ2VzXCIpO1xuICAgICAgICBmb3IgKGNvbnN0IHNyYyBvZiBtc2cuaW1hZ2VzKSB7XG4gICAgICAgICAgY29uc3QgaW1nID0gaW1nQ29udGFpbmVyLmNyZWF0ZUVsKFwiaW1nXCIsIHtcbiAgICAgICAgICAgIGNsczogXCJvcGVuY2xhdy1tc2ctaW1nXCIsXG4gICAgICAgICAgICBhdHRyOiB7IHNyYywgbG9hZGluZzogXCJsYXp5XCIgfSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBpbWcuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgICAgICAgIC8vIE9wZW4gZnVsbC1zaXplIGluIGEgbW9kYWwtbGlrZSBvdmVybGF5XG4gICAgICAgICAgICBjb25zdCBvdmVybGF5ID0gZG9jdW1lbnQuYm9keS5jcmVhdGVEaXYoXCJvcGVuY2xhdy1pbWctb3ZlcmxheVwiKTtcbiAgICAgICAgICAgIG92ZXJsYXkuY3JlYXRlRWwoXCJpbWdcIiwgeyBhdHRyOiB7IHNyYyB9IH0pO1xuICAgICAgICAgICAgb3ZlcmxheS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gb3ZlcmxheS5yZW1vdmUoKSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIC8vIENvbWJpbmUgYXVkaW8gcGF0aHMgZnJvbSBtZXNzYWdlIG1ldGFkYXRhICsgdGV4dCBjb250ZW50XG4gICAgICBjb25zdCBhbGxBdWRpbyA9IG1zZy50ZXh0ID8gdGhpcy5leHRyYWN0Vm9pY2VSZWZzKG1zZy50ZXh0KSA6IFtdO1xuXG4gICAgICAvLyBSZW5kZXIgdGV4dFxuICAgICAgaWYgKG1zZy50ZXh0KSB7XG4gICAgICAgIGNvbnN0IGRpc3BsYXlUZXh0ID0gbXNnLnJvbGUgPT09IFwiYXNzaXN0YW50XCIgPyB0aGlzLmNsZWFuVGV4dChtc2cudGV4dCkgOiBtc2cudGV4dDtcbiAgICAgICAgaWYgKGRpc3BsYXlUZXh0KSB7XG4gICAgICAgICAgaWYgKG1zZy5yb2xlID09PSBcImFzc2lzdGFudFwiKSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBhd2FpdCBNYXJrZG93blJlbmRlcmVyLnJlbmRlcih0aGlzLmFwcCwgZGlzcGxheVRleHQsIGJ1YmJsZSwgXCJcIiwgdGhpcyk7XG4gICAgICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICAgICAgYnViYmxlLmNyZWF0ZURpdih7IHRleHQ6IGRpc3BsYXlUZXh0LCBjbHM6IFwib3BlbmNsYXctbXNnLXRleHRcIiB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgYnViYmxlLmNyZWF0ZURpdih7IHRleHQ6IGRpc3BsYXlUZXh0LCBjbHM6IFwib3BlbmNsYXctbXNnLXRleHRcIiB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gUmVuZGVyIGF1ZGlvIHBsYXllcnMgZm9yIHZvaWNlIG1lc3NhZ2VzXG4gICAgICBmb3IgKGNvbnN0IGFwIG9mIGFsbEF1ZGlvKSB7XG4gICAgICAgIHRoaXMucmVuZGVyQXVkaW9QbGF5ZXIoYnViYmxlLCBhcCk7XG4gICAgICB9XG4gICAgfVxuICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTtcbiAgfVxuXG4gIHByaXZhdGUgc2Nyb2xsVG9Cb3R0b20oKTogdm9pZCB7XG4gICAgaWYgKHRoaXMubWVzc2FnZXNFbCkge1xuICAgICAgLy8gVXNlIHJlcXVlc3RBbmltYXRpb25GcmFtZSB0byBlbnN1cmUgRE9NIGhhcyB1cGRhdGVkXG4gICAgICByZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCkgPT4ge1xuICAgICAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXV0b1Jlc2l6ZSgpOiB2b2lkIHtcbiAgICB0aGlzLmlucHV0RWwuc2V0Q3NzU3R5bGVzKHsgaGVpZ2h0OiBcImF1dG9cIiB9KTtcbiAgICB0aGlzLmlucHV0RWwuc2V0Q3NzU3R5bGVzKHsgaGVpZ2h0OiBNYXRoLm1pbih0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0LCAxNTApICsgXCJweFwiIH0pO1xuICB9XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBNYWluIFBsdWdpbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5nczogT3BlbkNsYXdTZXR0aW5ncyA9IERFRkFVTFRfU0VUVElOR1M7XG4gIGdhdGV3YXk6IEdhdGV3YXlDbGllbnQgfCBudWxsID0gbnVsbDtcbiAgZ2F0ZXdheUNvbm5lY3RlZCA9IGZhbHNlO1xuICBjaGF0VmlldzogT3BlbkNsYXdDaGF0VmlldyB8IG51bGwgPSBudWxsO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy5yZWdpc3RlclZpZXcoVklFV19UWVBFLCAobGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcykpO1xuXG4gICAgLy8gUmliYm9uIGljb25cbiAgICB0aGlzLmFkZFJpYmJvbkljb24oXCJtZXNzYWdlLXNxdWFyZVwiLCBcIk9wZW5DbGF3IGNoYXRcIiwgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLmFjdGl2YXRlVmlldygpO1xuICAgIH0pO1xuXG4gICAgLy8gQ29tbWFuZHNcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6IFwidG9nZ2xlLWNoYXRcIixcbiAgICAgIG5hbWU6IFwiVG9nZ2xlIGNoYXQgc2lkZWJhclwiLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IHZvaWQgdGhpcy5hY3RpdmF0ZVZpZXcoKSxcbiAgICB9KTtcblxuICAgIHRoaXMuYWRkQ29tbWFuZCh7XG4gICAgICBpZDogXCJhc2stYWJvdXQtbm90ZVwiLFxuICAgICAgbmFtZTogXCJBc2sgYWJvdXQgY3VycmVudCBub3RlXCIsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLmFza0Fib3V0Tm90ZSgpLFxuICAgIH0pO1xuXG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiBcInJlY29ubmVjdFwiLFxuICAgICAgbmFtZTogXCJSZWNvbm5lY3QgdG8gZ2F0ZXdheVwiLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IHZvaWQgdGhpcy5jb25uZWN0R2F0ZXdheSgpLFxuICAgIH0pO1xuXG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiBcInNldHVwXCIsXG4gICAgICBuYW1lOiBcIlJ1biBzZXR1cCB3aXphcmRcIixcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiBuZXcgT25ib2FyZGluZ01vZGFsKHRoaXMuYXBwLCB0aGlzKS5vcGVuKCksXG4gICAgfSk7XG5cbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gU2hvdyBvbmJvYXJkaW5nIG9uIGZpcnN0IHJ1biwgb3RoZXJ3aXNlIGF1dG8tY29ubmVjdCBhbmQgb3BlbiBjaGF0XG4gICAgaWYgKCF0aGlzLnNldHRpbmdzLm9uYm9hcmRpbmdDb21wbGV0ZSkge1xuICAgICAgLy8gU21hbGwgZGVsYXkgc28gT2JzaWRpYW4gZmluaXNoZXMgbG9hZGluZ1xuICAgICAgc2V0VGltZW91dCgoKSA9PiBuZXcgT25ib2FyZGluZ01vZGFsKHRoaXMuYXBwLCB0aGlzKS5vcGVuKCksIDUwMCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHZvaWQgdGhpcy5jb25uZWN0R2F0ZXdheSgpO1xuICAgICAgLy8gQXV0by1vcGVuIGNoYXQgc2lkZWJhciBhZnRlciB3b3Jrc3BhY2UgaXMgcmVhZHlcbiAgICAgIHRoaXMuYXBwLndvcmtzcGFjZS5vbkxheW91dFJlYWR5KCgpID0+IHtcbiAgICAgICAgdm9pZCB0aGlzLmFjdGl2YXRlVmlldygpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgb251bmxvYWQoKTogdm9pZCB7XG4gICAgdGhpcy5nYXRld2F5Py5zdG9wKCk7XG4gICAgdGhpcy5nYXRld2F5ID0gbnVsbDtcbiAgICB0aGlzLmdhdGV3YXlDb25uZWN0ZWQgPSBmYWxzZTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgYXN5bmMgY29ubmVjdEdhdGV3YXkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5nYXRld2F5Py5zdG9wKCk7XG4gICAgdGhpcy5nYXRld2F5Q29ubmVjdGVkID0gZmFsc2U7XG4gICAgdGhpcy5jaGF0Vmlldz8udXBkYXRlU3RhdHVzKCk7XG5cbiAgICBjb25zdCByYXdVcmwgPSB0aGlzLnNldHRpbmdzLmdhdGV3YXlVcmwudHJpbSgpO1xuICAgIGlmICghcmF3VXJsKSByZXR1cm47XG5cbiAgICAvLyBOb3JtYWxpemUgVVJMIChhY2NlcHQgaHR0cHM6Ly8gYW5kIGh0dHA6Ly8gYXMgd2VsbClcbiAgICBjb25zdCB1cmwgPSBub3JtYWxpemVHYXRld2F5VXJsKHJhd1VybCk7XG4gICAgaWYgKCF1cmwpIHtcbiAgICAgIG5ldyBOb3RpY2UoXCJPcGVuQ2xhdzogSW52YWxpZCBnYXRld2F5IFVSTC4gVXNlIHlvdXIgVGFpbHNjYWxlIFNlcnZlIFVSTCAoZS5nLiB3c3M6Ly95b3VyLW1hY2hpbmUudGFpbDEyMzQudHMubmV0KVwiKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBQZXJzaXN0IHRoZSBub3JtYWxpemVkIGZvcm0gaWYgaXQgY2hhbmdlZFxuICAgIGlmICh1cmwgIT09IHJhd1VybCkge1xuICAgICAgdGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsID0gdXJsO1xuICAgICAgYXdhaXQgdGhpcy5zYXZlU2V0dGluZ3MoKTtcbiAgICB9XG5cbiAgICAvLyBHZXQgb3IgY3JlYXRlIGRldmljZSBpZGVudGl0eSBmb3Igc2NvcGUgYXV0aG9yaXphdGlvblxuICAgIGxldCBkZXZpY2VJZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgfCB1bmRlZmluZWQ7XG4gICAgdHJ5IHtcbiAgICAgIGRldmljZUlkZW50aXR5ID0gYXdhaXQgZ2V0T3JDcmVhdGVEZXZpY2VJZGVudGl0eShcbiAgICAgICAgKCkgPT4gdGhpcy5sb2FkRGF0YSgpLFxuICAgICAgICAoZGF0YSkgPT4gdGhpcy5zYXZlRGF0YShkYXRhKVxuICAgICAgKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLndhcm4oXCJbT2JzaWRpYW5DbGF3XSBEZXZpY2UgaWRlbnRpdHkgY3JlYXRpb24gZmFpbGVkLCBjb25uZWN0aW5nIHdpdGhvdXQgc2NvcGVzOlwiLCBlKTtcbiAgICB9XG5cbiAgICB0aGlzLmdhdGV3YXkgPSBuZXcgR2F0ZXdheUNsaWVudCh7XG4gICAgICB1cmwsXG4gICAgICB0b2tlbjogdGhpcy5zZXR0aW5ncy50b2tlbi50cmltKCkgfHwgdW5kZWZpbmVkLFxuICAgICAgZGV2aWNlSWRlbnRpdHksXG4gICAgICBvbkhlbGxvOiAoKSA9PiB7XG4gICAgICAgIHRoaXMuZ2F0ZXdheUNvbm5lY3RlZCA9IHRydWU7XG4gICAgICAgIHRoaXMuY2hhdFZpZXc/LnVwZGF0ZVN0YXR1cygpO1xuICAgICAgICB2b2lkIHRoaXMuY2hhdFZpZXc/LmxvYWRIaXN0b3J5KCk7XG4gICAgICAgIHZvaWQgdGhpcy5jaGF0Vmlldz8ucmVuZGVyVGFicygpO1xuICAgICAgICB2b2lkIHRoaXMuY2hhdFZpZXc/LmxvYWRBZ2VudHMoKTtcbiAgICAgICAgLy8gUmVzdG9yZSBwZXJzaXN0ZWQgbW9kZWwgc2VsZWN0aW9uXG4gICAgICAgIGlmICh0aGlzLnNldHRpbmdzLmN1cnJlbnRNb2RlbCAmJiB0aGlzLmNoYXRWaWV3KSB7XG4gICAgICAgICAgdGhpcy5jaGF0Vmlldy5jdXJyZW50TW9kZWwgPSB0aGlzLnNldHRpbmdzLmN1cnJlbnRNb2RlbDtcbiAgICAgICAgICB0aGlzLmNoYXRWaWV3LnVwZGF0ZU1vZGVsUGlsbCgpO1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgb25DbG9zZTogKGluZm8pID0+IHtcbiAgICAgICAgdGhpcy5nYXRld2F5Q29ubmVjdGVkID0gZmFsc2U7XG4gICAgICAgIHRoaXMuY2hhdFZpZXc/LnVwZGF0ZVN0YXR1cygpO1xuICAgICAgICAvLyBTaG93IHBhaXJpbmcgaW5zdHJ1Y3Rpb25zIGlmIG5lZWRlZFxuICAgICAgICBpZiAoaW5mby5yZWFzb24uaW5jbHVkZXMoXCJwYWlyaW5nIHJlcXVpcmVkXCIpIHx8IGluZm8ucmVhc29uLmluY2x1ZGVzKFwiZGV2aWNlIGlkZW50aXR5IHJlcXVpcmVkXCIpKSB7XG4gICAgICAgICAgbmV3IE5vdGljZShcIk9wZW5DbGF3OiBEZXZpY2UgcGFpcmluZyByZXF1aXJlZC4gUnVuICdvcGVuY2xhdyBkZXZpY2VzIGFwcHJvdmUnIG9uIHlvdXIgZ2F0ZXdheSBtYWNoaW5lLlwiLCAxMDAwMCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBvbkV2ZW50OiAoZXZ0KSA9PiB7XG4gICAgICAgIGlmIChldnQuZXZlbnQgPT09IFwiY2hhdFwiKSB7XG4gICAgICAgICAgdGhpcy5jaGF0Vmlldz8uaGFuZGxlQ2hhdEV2ZW50KGV2dC5wYXlsb2FkKTtcbiAgICAgICAgfSBlbHNlIGlmIChldnQuZXZlbnQgPT09IFwic3RyZWFtXCIgfHwgZXZ0LmV2ZW50ID09PSBcImFnZW50XCIpIHtcbiAgICAgICAgICB0aGlzLmNoYXRWaWV3Py5oYW5kbGVTdHJlYW1FdmVudChldnQucGF5bG9hZCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICB0aGlzLmdhdGV3YXkuc3RhcnQoKTtcbiAgfVxuXG4gIGFzeW5jIGFjdGl2YXRlVmlldygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBleGlzdGluZyA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGxlYWYgPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAobGVhZikge1xuICAgICAgYXdhaXQgbGVhZi5zZXRWaWV3U3RhdGUoeyB0eXBlOiBWSUVXX1RZUEUsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgYXNrQWJvdXROb3RlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGZpbGUgPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICAgIGlmICghZmlsZSkge1xuICAgICAgbmV3IE5vdGljZShcIk5vIGFjdGl2ZSBub3RlXCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCB0aGlzLmFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIGlmICghY29udGVudC50cmltKCkpIHtcbiAgICAgIG5ldyBOb3RpY2UoXCJOb3RlIGlzIGVtcHR5XCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuYWN0aXZhdGVWaWV3KCk7XG5cbiAgICBpZiAoIXRoaXMuY2hhdFZpZXcgfHwgIXRoaXMuZ2F0ZXdheT8uY29ubmVjdGVkKSB7XG4gICAgICBuZXcgTm90aWNlKFwiTm90IGNvbm5lY3RlZCB0byBPcGVuQ2xhd1wiKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtZXNzYWdlID0gYEhlcmUgaXMgbXkgY3VycmVudCBub3RlIFwiJHtmaWxlLmJhc2VuYW1lfVwiOlxcblxcbiR7Y29udGVudH1cXG5cXG5XaGF0IGNhbiB5b3UgdGVsbCBtZSBhYm91dCB0aGlzP2A7XG4gICAgY29uc3QgaW5wdXRFbCA9IHRoaXMuY2hhdFZpZXcuY29udGFpbmVyRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy1pbnB1dFwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICAgIGlmIChpbnB1dEVsKSB7XG4gICAgICBpbnB1dEVsLnZhbHVlID0gbWVzc2FnZTtcbiAgICAgIGlucHV0RWwuZm9jdXMoKTtcbiAgICB9XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbmZpcm0gTW9kYWwgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cblxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgTW9kZWwgUGlja2VyIE1vZGFsIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jbGFzcyBNb2RlbFBpY2tlck1vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBjaGF0VmlldzogT3BlbkNsYXdDaGF0VmlldztcbiAgcHJpdmF0ZSBtb2RlbHM6IE1vZGVsSW5mb1tdID0gW107XG4gIHByaXZhdGUgY3VycmVudE1vZGVsOiBzdHJpbmcgPSBcIlwiO1xuICBwcml2YXRlIHNlbGVjdGVkUHJvdmlkZXI6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luLCBjaGF0VmlldzogT3BlbkNsYXdDaGF0Vmlldykge1xuICAgIHN1cGVyKGFwcCk7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0VmlldyA9IGNoYXRWaWV3O1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMubW9kYWxFbC5hZGRDbGFzcyhcIm9wZW5jbGF3LXBpY2tlclwiKTtcbiAgICB0aGlzLmNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItbG9hZGluZ1wiKS50ZXh0Q29udGVudCA9IFwiTG9hZGluZyBtb2RlbHMuLi5cIjtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5Py5yZXF1ZXN0KFwibW9kZWxzLmxpc3RcIiwge30pIGFzIHsgbW9kZWxzPzogTW9kZWxJbmZvW10gfSB8IHVuZGVmaW5lZDtcbiAgICAgIHRoaXMubW9kZWxzID0gcmVzdWx0Py5tb2RlbHMgfHwgW107XG4gICAgfSBjYXRjaCB7IHRoaXMubW9kZWxzID0gW107IH1cblxuICAgIC8vIE5vcm1hbGl6ZSBjdXJyZW50TW9kZWwgdG8gYWx3YXlzIGJlIHByb3ZpZGVyL2lkIGZvcm1hdFxuICAgIHRoaXMuY3VycmVudE1vZGVsID0gdGhpcy5jaGF0Vmlldy5jdXJyZW50TW9kZWwgfHwgXCJcIjtcbiAgICBpZiAodGhpcy5jdXJyZW50TW9kZWwgJiYgIXRoaXMuY3VycmVudE1vZGVsLmluY2x1ZGVzKFwiL1wiKSkge1xuICAgICAgY29uc3QgbWF0Y2ggPSB0aGlzLm1vZGVscy5maW5kKChtOiBNb2RlbEluZm8pID0+IG0uaWQgPT09IHRoaXMuY3VycmVudE1vZGVsKTtcbiAgICAgIGlmIChtYXRjaCkgdGhpcy5jdXJyZW50TW9kZWwgPSBgJHttYXRjaC5wcm92aWRlcn0vJHttYXRjaC5pZH1gO1xuICAgIH1cblxuICAgIC8vIEF1dG8tc2VsZWN0IHByb3ZpZGVyIG9mIGN1cnJlbnQgbW9kZWxcbiAgICBpZiAodGhpcy5jdXJyZW50TW9kZWwuaW5jbHVkZXMoXCIvXCIpKSB7XG4gICAgICB0aGlzLnNlbGVjdGVkUHJvdmlkZXIgPSB0aGlzLmN1cnJlbnRNb2RlbC5zcGxpdChcIi9cIilbMF07XG4gICAgfVxuXG4gICAgLy8gSWYgb25seSBvbmUgcHJvdmlkZXIsIHNraXAgc3RyYWlnaHQgdG8gbW9kZWxzXG4gICAgY29uc3QgcHJvdmlkZXJzID0gbmV3IFNldCh0aGlzLm1vZGVscy5tYXAoKG06IE1vZGVsSW5mbykgPT4gbS5wcm92aWRlcikpO1xuICAgIGlmIChwcm92aWRlcnMuc2l6ZSA9PT0gMSkge1xuICAgICAgdGhpcy5yZW5kZXJNb2RlbHMoWy4uLnByb3ZpZGVyc11bMF0pO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLnJlbmRlclByb3ZpZGVycygpO1xuICAgIH1cbiAgfVxuXG4gIG9uQ2xvc2UoKTogdm9pZCB7IHRoaXMuY29udGVudEVsLmVtcHR5KCk7IH1cblxuICBwcml2YXRlIHJlbmRlclByb3ZpZGVycygpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuZW1wdHkoKTtcblxuICAgIC8vIEdyb3VwIG1vZGVscyBieSBwcm92aWRlclxuICAgIGNvbnN0IHByb3ZpZGVyTWFwID0gbmV3IE1hcDxzdHJpbmcsIE1vZGVsSW5mb1tdPigpO1xuICAgIGZvciAoY29uc3QgbSBvZiB0aGlzLm1vZGVscykge1xuICAgICAgY29uc3QgcCA9IG0ucHJvdmlkZXIgfHwgXCJ1bmtub3duXCI7XG4gICAgICBpZiAoIXByb3ZpZGVyTWFwLmhhcyhwKSkgcHJvdmlkZXJNYXAuc2V0KHAsIFtdKTtcbiAgICAgIHByb3ZpZGVyTWFwLmdldChwKSEucHVzaChtKTtcbiAgICB9XG5cbiAgICAvLyBDdXJyZW50IHByb3ZpZGVyIGZyb20gY3VycmVudE1vZGVsXG4gICAgY29uc3QgY3VycmVudFByb3ZpZGVyID0gdGhpcy5jdXJyZW50TW9kZWwuaW5jbHVkZXMoXCIvXCIpID8gdGhpcy5jdXJyZW50TW9kZWwuc3BsaXQoXCIvXCIpWzBdIDogXCJcIjtcblxuICAgIGNvbnN0IGxpc3QgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLWxpc3RcIik7XG5cbiAgICBmb3IgKGNvbnN0IFtwcm92aWRlciwgbW9kZWxzXSBvZiBwcm92aWRlck1hcCkge1xuICAgICAgY29uc3QgaXNDdXJyZW50ID0gcHJvdmlkZXIgPT09IGN1cnJlbnRQcm92aWRlcjtcbiAgICAgIGNvbnN0IHJvdyA9IGxpc3QuY3JlYXRlRGl2KHsgY2xzOiBgb3BlbmNsYXctcGlja2VyLXJvdyR7aXNDdXJyZW50ID8gXCIgYWN0aXZlXCIgOiBcIlwifWAgfSk7XG5cbiAgICAgIGNvbnN0IGxlZnQgPSByb3cuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLXJvdy1sZWZ0XCIpO1xuICAgICAgaWYgKGlzQ3VycmVudCkgbGVmdC5jcmVhdGVTcGFuKHsgdGV4dDogXCJcdTI1Q0YgXCIsIGNsczogXCJvcGVuY2xhdy1waWNrZXItZG90XCIgfSk7XG4gICAgICBsZWZ0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBwcm92aWRlciwgY2xzOiBcIm9wZW5jbGF3LXBpY2tlci1wcm92aWRlci1uYW1lXCIgfSk7XG5cbiAgICAgIGNvbnN0IHJpZ2h0ID0gcm93LmNyZWF0ZURpdihcIm9wZW5jbGF3LXBpY2tlci1yb3ctcmlnaHRcIik7XG4gICAgICByaWdodC5jcmVhdGVTcGFuKHsgdGV4dDogYCR7bW9kZWxzLmxlbmd0aH0gbW9kZWwke21vZGVscy5sZW5ndGggIT09IDEgPyBcInNcIiA6IFwiXCJ9YCwgY2xzOiBcIm9wZW5jbGF3LXBpY2tlci1tZXRhXCIgfSk7XG4gICAgICByaWdodC5jcmVhdGVTcGFuKHsgdGV4dDogXCIgXHUyMTkyXCIsIGNsczogXCJvcGVuY2xhdy1waWNrZXItYXJyb3dcIiB9KTtcblxuICAgICAgcm93LmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICAgIHRoaXMuc2VsZWN0ZWRQcm92aWRlciA9IHByb3ZpZGVyO1xuICAgICAgICB0aGlzLnJlbmRlck1vZGVscyhwcm92aWRlcik7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBGb290ZXJcbiAgICBjb25zdCBmb290ZXIgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLWhpbnQgb3BlbmNsYXctcGlja2VyLWZvb3RlclwiKTtcbiAgICBmb290ZXIuYXBwZW5kVGV4dChcIldhbnQgbW9yZSBtb2RlbHM/IFwiKTtcbiAgICBmb290ZXIuY3JlYXRlRWwoXCJhXCIsIHsgdGV4dDogXCJBZGQgdGhlbSBpbiB5b3VyIGdhdGV3YXkgY29uZmlnLlwiLCBocmVmOiBcImh0dHBzOi8vZG9jcy5vcGVuY2xhdy5haS9nYXRld2F5L2NvbmZpZ3VyYXRpb24jY2hvb3NlLWFuZC1jb25maWd1cmUtbW9kZWxzXCIgfSk7XG4gIH1cblxuICBwcml2YXRlIHJlbmRlck1vZGVscyhwcm92aWRlcjogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmVtcHR5KCk7XG5cbiAgICAvLyBCYWNrIGJ1dHRvblxuICAgIGNvbnN0IHByb3ZpZGVycyA9IG5ldyBTZXQodGhpcy5tb2RlbHMubWFwKChtOiBNb2RlbEluZm8pID0+IG0ucHJvdmlkZXIpKTtcbiAgICBpZiAocHJvdmlkZXJzLnNpemUgPiAxKSB7XG4gICAgICBjb25zdCBoZWFkZXIgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLWhlYWRlclwiKTtcbiAgICAgIGNvbnN0IGJhY2tCdG4gPSBoZWFkZXIuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctcGlja2VyLWJhY2tcIiwgdGV4dDogXCJcdTIxOTAgXCIgKyBwcm92aWRlciB9KTtcbiAgICAgIGJhY2tCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHRoaXMucmVuZGVyUHJvdmlkZXJzKCkpO1xuICAgIH1cblxuICAgIGNvbnN0IG1vZGVscyA9IHRoaXMubW9kZWxzLmZpbHRlcigobTogTW9kZWxJbmZvKSA9PiBtLnByb3ZpZGVyID09PSBwcm92aWRlcik7XG4gICAgY29uc3QgbGlzdCA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItbGlzdCBvcGVuY2xhdy1waWNrZXItbW9kZWwtbGlzdFwiKTtcblxuICAgIGZvciAoY29uc3QgbSBvZiBtb2RlbHMpIHtcbiAgICAgIGNvbnN0IGZ1bGxJZCA9IGAke20ucHJvdmlkZXJ9LyR7bS5pZH1gO1xuICAgICAgY29uc3QgaXNDdXJyZW50ID0gZnVsbElkID09PSB0aGlzLmN1cnJlbnRNb2RlbDtcbiAgICAgIGNvbnN0IHJvdyA9IGxpc3QuY3JlYXRlRGl2KHsgY2xzOiBgb3BlbmNsYXctcGlja2VyLXJvdyR7aXNDdXJyZW50ID8gXCIgYWN0aXZlXCIgOiBcIlwifWAgfSk7XG5cbiAgICAgIGNvbnN0IGxlZnQgPSByb3cuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLXJvdy1sZWZ0XCIpO1xuICAgICAgaWYgKGlzQ3VycmVudCkgbGVmdC5jcmVhdGVTcGFuKHsgdGV4dDogXCJcdTI1Q0YgXCIsIGNsczogXCJvcGVuY2xhdy1waWNrZXItZG90XCIgfSk7XG4gICAgICBsZWZ0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBtLm5hbWUgfHwgbS5pZCB9KTtcblxuICAgICAgLy8gQWx3YXlzIGNsaWNrYWJsZSAtIGV2ZW4gdGhlIGN1cnJlbnQgbW9kZWwgKHVzZXIgbWlnaHQgd2FudCB0byByZS1zZWxlY3QgaXQpXG4gICAgICByb3cuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICAgICAgcm93LmFkZENsYXNzKFwib3BlbmNsYXctcGlja2VyLXNlbGVjdGluZ1wiKTtcbiAgICAgICAgcm93LnRleHRDb250ZW50ID0gXCJTd2l0Y2hpbmcuLi5cIjtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICAgICAgc2Vzc2lvbktleTogdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSxcbiAgICAgICAgICAgIG1lc3NhZ2U6IGAvbW9kZWwgJHtmdWxsSWR9YCxcbiAgICAgICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICAgICAgaWRlbXBvdGVuY3lLZXk6IFwibW9kZWwtXCIgKyBEYXRlLm5vdygpLFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIHRoaXMuY2hhdFZpZXcuY3VycmVudE1vZGVsID0gZnVsbElkO1xuICAgICAgICAgIHRoaXMuY2hhdFZpZXcuY3VycmVudE1vZGVsU2V0QXQgPSBEYXRlLm5vdygpO1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmN1cnJlbnRNb2RlbCA9IGZ1bGxJZDtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB0aGlzLmNoYXRWaWV3LnVwZGF0ZU1vZGVsUGlsbCgpO1xuICAgICAgICAgIG5ldyBOb3RpY2UoYE1vZGVsOiAke20ubmFtZSB8fCBtLmlkfWApO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgIG5ldyBOb3RpY2UoYEZhaWxlZDogJHtlfWApO1xuICAgICAgICAgIHRoaXMucmVuZGVyTW9kZWxzKHByb3ZpZGVyKTtcbiAgICAgICAgfVxuICAgICAgfSkoKSk7XG4gICAgfVxuICB9XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBDb25maXJtIE1vZGFsIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jbGFzcyBDb25maXJtTW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHByaXZhdGUgY29uZmlnOiB7IHRpdGxlOiBzdHJpbmc7IG1lc3NhZ2U6IHN0cmluZzsgY29uZmlybVRleHQ6IHN0cmluZzsgb25Db25maXJtOiAoKSA9PiB2b2lkIH07XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIGNvbmZpZzogeyB0aXRsZTogc3RyaW5nOyBtZXNzYWdlOiBzdHJpbmc7IGNvbmZpcm1UZXh0OiBzdHJpbmc7IG9uQ29uZmlybTogKCkgPT4gdm9pZCB9KSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLmNvbmZpZyA9IGNvbmZpZztcbiAgfVxuXG4gIG9uT3BlbigpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuYWRkQ2xhc3MoXCJvcGVuY2xhdy1jb25maXJtLW1vZGFsXCIpO1xuICAgIGNvbnRlbnRFbC5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogdGhpcy5jb25maWcudGl0bGUsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLXRpdGxlXCIgfSk7XG4gICAgY29udGVudEVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IHRoaXMuY29uZmlnLm1lc3NhZ2UsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLW1lc3NhZ2VcIiB9KTtcbiAgICBjb25zdCBidG5Sb3cgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctY29uZmlybS1idXR0b25zXCIpO1xuICAgIGNvbnN0IGNhbmNlbEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiQ2FuY2VsXCIsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLWNhbmNlbFwiIH0pO1xuICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICBjb25zdCBjb25maXJtQnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogdGhpcy5jb25maWcuY29uZmlybVRleHQsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLW9rXCIgfSk7XG4gICAgY29uZmlybUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgdGhpcy5jbG9zZSgpO1xuICAgICAgdGhpcy5jb25maWcub25Db25maXJtKCk7XG4gICAgfSk7XG4gIH1cblxuICBvbkNsb3NlKCk6IHZvaWQge1xuICAgIHRoaXMuY29udGVudEVsLmVtcHR5KCk7XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbmZpcm0gQ2xvc2UgTW9kYWwgKHdpdGggXCJkb24ndCBhc2sgYWdhaW5cIikgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbmNsYXNzIENvbmZpcm1DbG9zZU1vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwcml2YXRlIHRpdGxlOiBzdHJpbmc7XG4gIHByaXZhdGUgbWVzc2FnZTogc3RyaW5nO1xuICBwcml2YXRlIGNhbGxiYWNrOiAocmVzdWx0OiBib29sZWFuLCBkb250QXNrOiBib29sZWFuKSA9PiB2b2lkO1xuICBwcml2YXRlIGNoZWNrYm94RWwhOiBIVE1MSW5wdXRFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCB0aXRsZTogc3RyaW5nLCBtZXNzYWdlOiBzdHJpbmcsIGNhbGxiYWNrOiAocmVzdWx0OiBib29sZWFuLCBkb250QXNrOiBib29sZWFuKSA9PiB2b2lkKSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLnRpdGxlID0gdGl0bGU7XG4gICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICB0aGlzLmNhbGxiYWNrID0gY2FsbGJhY2s7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmFkZENsYXNzKFwib3BlbmNsYXctY29uZmlybS1tb2RhbFwiKTtcbiAgICBjb250ZW50RWwuY3JlYXRlRWwoXCJoM1wiLCB7IHRleHQ6IHRoaXMudGl0bGUsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLXRpdGxlXCIgfSk7XG4gICAgY29udGVudEVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IHRoaXMubWVzc2FnZSwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tbWVzc2FnZVwiIH0pO1xuICAgIFxuICAgIGNvbnN0IGNoZWNrUm93ID0gY29udGVudEVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LWNvbmZpcm0tY2hlY2tcIik7XG4gICAgdGhpcy5jaGVja2JveEVsID0gY2hlY2tSb3cuY3JlYXRlRWwoXCJpbnB1dFwiLCB7IHR5cGU6IFwiY2hlY2tib3hcIiB9KTtcbiAgICB0aGlzLmNoZWNrYm94RWwuaWQgPSBcImNvbmZpcm0tZG9udC1hc2tcIjtcbiAgICBjaGVja1Jvdy5jcmVhdGVFbChcImxhYmVsXCIsIHsgdGV4dDogXCJEb24ndCBhc2sgbWUgYWdhaW5cIiwgYXR0cjogeyBmb3I6IFwiY29uZmlybS1kb250LWFza1wiIH0gfSk7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctY29uZmlybS1idXR0b25zXCIpO1xuICAgIGNvbnN0IGNhbmNlbEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiQ2FuY2VsXCIsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLWNhbmNlbFwiIH0pO1xuICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgdGhpcy5jYWxsYmFjayhmYWxzZSwgZmFsc2UpO1xuICAgICAgdGhpcy5jbG9zZSgpO1xuICAgIH0pO1xuICAgIGNvbnN0IGNvbmZpcm1CdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiB0aGlzLnRpdGxlLnN0YXJ0c1dpdGgoXCJSZXNldFwiKSA/IFwiUmVzZXRcIiA6IFwiQ2xvc2VcIiwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tb2tcIiB9KTtcbiAgICBjb25maXJtQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICB0aGlzLmNhbGxiYWNrKHRydWUsIHRoaXMuY2hlY2tib3hFbC5jaGVja2VkKTtcbiAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICB9KTtcbiAgfVxuXG4gIG9uQ2xvc2UoKTogdm9pZCB7XG4gICAgdGhpcy5jb250ZW50RWwuZW1wdHkoKTtcbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgVGV4dCBJbnB1dCBNb2RhbCBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuY2xhc3MgVGV4dElucHV0TW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHByaXZhdGUgY29uZmlnOiB7IHRpdGxlOiBzdHJpbmc7IHBsYWNlaG9sZGVyOiBzdHJpbmc7IGNvbmZpcm1UZXh0OiBzdHJpbmc7IGluaXRpYWxWYWx1ZT86IHN0cmluZzsgb25Db25maXJtOiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCB9O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MSW5wdXRFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBjb25maWc6IHsgdGl0bGU6IHN0cmluZzsgcGxhY2Vob2xkZXI6IHN0cmluZzsgY29uZmlybVRleHQ6IHN0cmluZzsgaW5pdGlhbFZhbHVlPzogc3RyaW5nOyBvbkNvbmZpcm06ICh2YWx1ZTogc3RyaW5nKSA9PiB2b2lkIH0pIHtcbiAgICBzdXBlcihhcHApO1xuICAgIHRoaXMuY29uZmlnID0gY29uZmlnO1xuICB9XG5cbiAgb25PcGVuKCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGVudEVsIH0gPSB0aGlzO1xuICAgIGNvbnRlbnRFbC5hZGRDbGFzcyhcIm9wZW5jbGF3LWNvbmZpcm0tbW9kYWxcIik7XG4gICAgY29udGVudEVsLmNyZWF0ZUVsKFwiaDNcIiwgeyB0ZXh0OiB0aGlzLmNvbmZpZy50aXRsZSwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tdGl0bGVcIiB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBjb250ZW50RWwuY3JlYXRlRWwoXCJpbnB1dFwiLCB7XG4gICAgICB0eXBlOiBcInRleHRcIixcbiAgICAgIHBsYWNlaG9sZGVyOiB0aGlzLmNvbmZpZy5wbGFjZWhvbGRlcixcbiAgICAgIGNsczogXCJvcGVuY2xhdy10ZXh0LWlucHV0XCIsXG4gICAgfSk7XG4gICAgaWYgKHRoaXMuY29uZmlnLmluaXRpYWxWYWx1ZSkgdGhpcy5pbnB1dEVsLnZhbHVlID0gdGhpcy5jb25maWcuaW5pdGlhbFZhbHVlO1xuICAgIHRoaXMuaW5wdXRFbC5mb2N1cygpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKFwia2V5ZG93blwiLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSBcIkVudGVyXCIpIHtcbiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB0aGlzLnN1Ym1pdCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIGNvbnN0IGJ0blJvdyA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1jb25maXJtLWJ1dHRvbnNcIik7XG4gICAgY29uc3QgY2FuY2VsQnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJDYW5jZWxcIiwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tY2FuY2VsXCIgfSk7XG4gICAgY2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB0aGlzLmNsb3NlKCkpO1xuICAgIGNvbnN0IGNvbmZpcm1CdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiB0aGlzLmNvbmZpZy5jb25maXJtVGV4dCwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tb2tcIiB9KTtcbiAgICBjb25maXJtQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB0aGlzLnN1Ym1pdCgpKTtcbiAgfVxuXG4gIHByaXZhdGUgc3VibWl0KCk6IHZvaWQge1xuICAgIGNvbnN0IHZhbHVlID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXZhbHVlKSByZXR1cm47XG4gICAgdGhpcy5jbG9zZSgpO1xuICAgIHRoaXMuY29uZmlnLm9uQ29uZmlybSh2YWx1ZSk7XG4gIH1cblxuICBvbkNsb3NlKCk6IHZvaWQge1xuICAgIHRoaXMuY29udGVudEVsLmVtcHR5KCk7XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEF0dGFjaG1lbnQgUGlja2VyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jbGFzcyBBdHRhY2htZW50TW9kYWwgZXh0ZW5kcyBGdXp6eVN1Z2dlc3RNb2RhbDxURmlsZT4ge1xuICBwcml2YXRlIGZpbGVzOiBURmlsZVtdO1xuICBwcml2YXRlIG9uQ2hvb3NlOiAoZmlsZTogVEZpbGUpID0+IHZvaWQ7XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIGZpbGVzOiBURmlsZVtdLCBvbkNob29zZTogKGZpbGU6IFRGaWxlKSA9PiB2b2lkKSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLmZpbGVzID0gZmlsZXM7XG4gICAgdGhpcy5vbkNob29zZSA9IG9uQ2hvb3NlO1xuICAgIHRoaXMuc2V0UGxhY2Vob2xkZXIoXCJTZWFyY2ggZmlsZXMgdG8gYXR0YWNoLi4uXCIpO1xuICB9XG5cbiAgZ2V0SXRlbXMoKTogVEZpbGVbXSB7XG4gICAgcmV0dXJuIHRoaXMuZmlsZXM7XG4gIH1cblxuICBnZXRJdGVtVGV4dChmaWxlOiBURmlsZSk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGZpbGUucGF0aDtcbiAgfVxuXG4gIG9uQ2hvb3NlSXRlbShmaWxlOiBURmlsZSk6IHZvaWQge1xuICAgIHRoaXMub25DaG9vc2UoZmlsZSk7XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFNldHRpbmdzIFRhYiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKS5zZXROYW1lKFwiT3BlbkNsYXdcIikuc2V0SGVhZGluZygpO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFNldHVwIFdpemFyZCAodG9wLCBtb3N0IHByb21pbmVudCkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG4gICAgY29uc3Qgd2l6YXJkU2VjdGlvbiA9IGNvbnRhaW5lckVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LXNldHRpbmdzLXdpemFyZFwiKTtcbiAgICBjb25zdCB3aXphcmREZXNjID0gd2l6YXJkU2VjdGlvbi5jcmVhdGVEaXYoXCJvcGVuY2xhdy1zZXR0aW5ncy13aXphcmQtZGVzY1wiKTtcbiAgICB3aXphcmREZXNjLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJTZXR1cCB3aXphcmRcIiB9KTtcbiAgICB3aXphcmREZXNjLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIlRoZSBlYXNpZXN0IHdheSB0byBjb25uZWN0LiBXYWxrcyB5b3UgdGhyb3VnaCBUYWlsc2NhbGUsIGdhdGV3YXkgc2V0dXAsIGFuZCBkZXZpY2UgcGFpcmluZyBzdGVwIGJ5IHN0ZXAuXCIsXG4gICAgICBjbHM6IFwic2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uXCIsXG4gICAgfSk7XG4gICAgY29uc3Qgd2l6YXJkQnRuID0gd2l6YXJkU2VjdGlvbi5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiUnVuIHNldHVwIHdpemFyZFwiLCBjbHM6IFwibW9kLWN0YSBvcGVuY2xhdy1zZXR0aW5ncy13aXphcmQtYnRuXCIgfSk7XG4gICAgd2l6YXJkQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICBuZXcgT25ib2FyZGluZ01vZGFsKHRoaXMuYXBwLCB0aGlzLnBsdWdpbikub3BlbigpO1xuICAgIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFN0YXR1cyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBzdGF0dXNTZWN0aW9uID0gY29udGFpbmVyRWwuY3JlYXRlRGl2KFwib3BlbmNsYXctc2V0dGluZ3Mtc3RhdHVzXCIpO1xuICAgIGNvbnN0IGNvbm5lY3RlZCA9IHRoaXMucGx1Z2luLmdhdGV3YXlDb25uZWN0ZWQ7XG4gICAgc3RhdHVzU2VjdGlvbi5jcmVhdGVTcGFuKHsgY2xzOiBgb3BlbmNsYXctc2V0dGluZ3MtZG90ICR7Y29ubmVjdGVkID8gXCJjb25uZWN0ZWRcIiA6IFwiZGlzY29ubmVjdGVkXCJ9YCB9KTtcbiAgICBzdGF0dXNTZWN0aW9uLmNyZWF0ZVNwYW4oeyB0ZXh0OiBjb25uZWN0ZWQgPyBcIkNvbm5lY3RlZFwiIDogXCJEaXNjb25uZWN0ZWRcIiwgY2xzOiBcIm9wZW5jbGF3LXNldHRpbmdzLXN0YXR1cy10ZXh0XCIgfSk7XG4gICAgaWYgKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpIHtcbiAgICAgIHN0YXR1c1NlY3Rpb24uY3JlYXRlU3Bhbih7XG4gICAgICAgIHRleHQ6IGAgXHUyMDE0ICR7dGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybC5yZXBsYWNlKC9ed3NzPzpcXC9cXC8vLCBcIlwiKX1gLFxuICAgICAgICBjbHM6IFwib3BlbmNsYXctc2V0dGluZ3Mtc3RhdHVzLXVybFwiLFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFNlc3Npb24gXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpLnNldE5hbWUoXCJTZXNzaW9uXCIpLnNldEhlYWRpbmcoKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoXCJDb252ZXJzYXRpb25cIilcbiAgICAgIC5zZXREZXNjKFwiQ3VycmVudCBjb252ZXJzYXRpb24ga2V5LiBVc2UgXFxcIm1haW5cXFwiIGZvciB0aGUgZGVmYXVsdCBzZXNzaW9uLlwiKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoXCJNYWluXCIpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHZhbHVlIHx8IFwibWFpblwiO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgIClcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuXG4gICAgICAgICAgLnNldEJ1dHRvblRleHQoXCJSZXNldCB0byBtYWluXCIpXG4gICAgICAgICAgLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IFwibWFpblwiO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgICB0aGlzLmRpc3BsYXkoKTsgLy8gcmVmcmVzaCB0aGUgc2V0dGluZ3MgVUlcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmNvbm5lY3RHYXRld2F5KCk7XG4gICAgICAgICAgICBuZXcgTm90aWNlKFwiUmVzZXQgdG8gbWFpbiBjb252ZXJzYXRpb25cIik7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgQmVoYXZpb3IgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZShcIkNvbmZpcm0gYmVmb3JlIGNsb3NpbmcgdGFic1wiKVxuICAgICAgLnNldERlc2MoXCJTaG93IGEgY29uZmlybWF0aW9uIGRpYWxvZyBiZWZvcmUgY2xvc2luZyBvciByZXNldHRpbmcgdGFic1wiKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGVcbiAgICAgICAgICAuc2V0VmFsdWUobG9jYWxTdG9yYWdlLmdldEl0ZW0oXCJvcGVuY2xhdy1jb25maXJtLWNsb3NlLWRpc2FibGVkXCIpICE9PSBcInRydWVcIilcbiAgICAgICAgICAub25DaGFuZ2UoKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShcIm9wZW5jbGF3LWNvbmZpcm0tY2xvc2UtZGlzYWJsZWRcIiwgdmFsdWUgPyBcImZhbHNlXCIgOiBcInRydWVcIik7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgQ29ubmVjdGlvbiAoQWR2YW5jZWQpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKS5zZXROYW1lKFwiQ29ubmVjdGlvblwiKS5zZXREZXNjKFwiVGhlc2UgYXJlIHNldCBhdXRvbWF0aWNhbGx5IGJ5IHRoZSBzZXR1cCB3aXphcmQuIEVkaXQgbWFudWFsbHkgb25seSBpZiB5b3Uga25vdyB3aGF0IHlvdSdyZSBkb2luZy5cIikuc2V0SGVhZGluZygpO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZShcIkdhdGV3YXkgVVJMXCIpXG4gICAgICAuc2V0RGVzYyhcIlRhaWxzY2FsZSBTZXJ2ZSBVUkwgKGUuZy4gd3NzOi8veW91ci1tYWNoaW5lLnRhaWwxMjM0LnRzLm5ldClcIilcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKFwid3NzOi8veW91ci1tYWNoaW5lLnRhaWwxMjM0LnRzLm5ldFwiKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBub3JtYWxpemVHYXRld2F5VXJsKHZhbHVlKTtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSBub3JtYWxpemVkIHx8IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKFwiQXV0aCB0b2tlblwiKVxuICAgICAgLnNldERlc2MoXCJHYXRld2F5IGF1dGggdG9rZW5cIilcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PiB7XG4gICAgICAgIHRleHQuaW5wdXRFbC50eXBlID0gXCJwYXNzd29yZFwiO1xuICAgICAgICByZXR1cm4gdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcihcIlRva2VuXCIpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnRva2VuKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZShcIlJlY29ubmVjdFwiKVxuICAgICAgLnNldERlc2MoXCJSZS1lc3RhYmxpc2ggdGhlIGdhdGV3YXkgY29ubmVjdGlvblwiKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dChcIlJlY29ubmVjdFwiKS5vbkNsaWNrKCgpID0+IHtcbiAgICAgICAgICB2b2lkIHRoaXMucGx1Z2luLmNvbm5lY3RHYXRld2F5KCk7XG4gICAgICAgICAgbmV3IE5vdGljZShcIk9wZW5DbGF3OiBSZWNvbm5lY3RpbmcuLi5cIik7XG4gICAgICAgIH0pXG4gICAgICApO1xuICB9XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLHNCQWNPO0FBT1AsU0FBUyxJQUFJLEdBQVksV0FBVyxJQUFZO0FBQzlDLFNBQU8sT0FBTyxNQUFNLFdBQVcsSUFBSTtBQUNyQztBQXVCQSxJQUFNLG1CQUFxQztBQUFBLEVBQ3pDLFlBQVk7QUFBQSxFQUNaLE9BQU87QUFBQSxFQUNQLFlBQVk7QUFBQSxFQUNaLG9CQUFvQjtBQUN0QjtBQUtBLFNBQVMsb0JBQW9CLEtBQTRCO0FBQ3ZELE1BQUksTUFBTSxJQUFJLEtBQUs7QUFDbkIsTUFBSSxJQUFJLFdBQVcsVUFBVTtBQUFHLFVBQU0sV0FBVyxJQUFJLE1BQU0sQ0FBQztBQUFB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TSxLQUFLLE9BQU8sYUFBYTtBQUMvQixhQUFLLFFBQVE7QUFDYixjQUFNLEtBQUssT0FBTyxlQUFlO0FBQ2pDLFlBQUksdUJBQU8sNEJBQTRCO0FBQUEsTUFDekMsQ0FBQztBQUFBLElBQ0w7QUFHRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSw2QkFBNkIsRUFDckMsUUFBUSw2REFBNkQsRUFDckU7QUFBQSxNQUFVLENBQUMsV0FDVixPQUNHLFNBQVMsYUFBYSxRQUFRLGlDQUFpQyxNQUFNLE1BQU0sRUFDM0UsU0FBUyxDQUFDLFVBQVU7QUFDbkIscUJBQWEsUUFBUSxtQ0FBbUMsUUFBUSxVQUFVLE1BQU07QUFBQSxNQUNsRixDQUFDO0FBQUEsSUFDTDtBQUdGLFFBQUksd0JBQVEsV0FBVyxFQUFFLFFBQVEsWUFBWSxFQUFFLFFBQVEsb0dBQW9HLEVBQUUsV0FBVztBQUV4SyxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxhQUFhLEVBQ3JCLFFBQVEsK0RBQStELEVBQ3ZFO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLG9DQUFvQyxFQUNuRCxTQUFTLEtBQUssT0FBTyxTQUFTLFVBQVUsRUFDeEMsU0FBUyxPQUFPLFVBQVU7QUFDekIsY0FBTSxhQUFhLG9CQUFvQixLQUFLO0FBQzVDLGFBQUssT0FBTyxTQUFTLGFBQWEsY0FBYztBQUNoRCxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsQ0FBQztBQUFBLElBQ0w7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxZQUFZLEVBQ3BCLFFBQVEsb0JBQW9CLEVBQzVCLFFBQVEsQ0FBQyxTQUFTO0FBQ2pCLFdBQUssUUFBUSxPQUFPO0FBQ3BCLGFBQU8sS0FDSixlQUFlLE9BQU8sRUFDdEIsU0FBUyxLQUFLLE9BQU8sU0FBUyxLQUFLLEVBQ25DLFNBQVMsT0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLFFBQVE7QUFDN0IsY0FBTSxLQUFLLE9BQU8sYUFBYTtBQUFBLE1BQ2pDLENBQUM7QUFBQSxJQUNMLENBQUM7QUFFSCxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxXQUFXLEVBQ25CLFFBQVEscUNBQXFDLEVBQzdDO0FBQUEsTUFBVSxDQUFDLFFBQ1YsSUFBSSxjQUFjLFdBQVcsRUFBRSxRQUFRLE1BQU07QUFDM0MsYUFBSyxLQUFLLE9BQU8sZUFBZTtBQUNoQyxZQUFJLHVCQUFPLDJCQUEyQjtBQUFBLE1BQ3hDLENBQUM7QUFBQSxJQUNIO0FBQUEsRUFDSjtBQUNGOyIsCiAgIm5hbWVzIjogWyJfYSIsICJfYiIsICJlIiwgImJ1YmJsZSJdCn0K
