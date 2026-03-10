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
    var _a, _b, _c, _d, _e, _f, _g;
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
      if (msg.event)
        (_d = (_c = this.opts).onEvent) == null ? void 0 : _d.call(_c, { event: msg.event, payload: (_b = msg.payload) != null ? _b : {}, seq: msg.seq });
      return;
    }
    if (msg.type === "res") {
      const msgId = (_e = msg.id) != null ? _e : "";
      const p = this.pending.get(msgId);
      if (!p)
        return;
      this.pending.delete(msgId);
      const t = this.pendingTimeouts.get(msgId);
      if (t) {
        clearTimeout(t);
        this.pendingTimeouts.delete(msgId);
      }
      if (msg.ok) {
        p.resolve(msg.payload);
      } else {
        p.reject(new Error((_g = (_f = msg.error) == null ? void 0 : _f.message) != null ? _g : "request failed"));
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
      const fKey = f.key;
      const input = group.createEl("input", {
        type: "password",
        value: this.setupKeys[fKey],
        placeholder: f.placeholder,
        cls: "openclaw-onboard-input"
      });
      input.addEventListener("input", () => {
        this.setupKeys[fKey] = input.value.trim();
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
    const auth = { profiles: {} };
    const agents = { defaults: { model: { primary: ((_a = this.setupBots[0]) == null ? void 0 : _a.model) || "anthropic/claude-sonnet-4-6" } } };
    const config = {
      auth,
      agents,
      gateway: { port: 18789, bind: "loopback", tailscale: { mode: "serve" }, auth: { mode: "token", allowTailscale: true } }
    };
    const profiles = auth.profiles;
    if (this.setupKeys.claude1)
      profiles["anthropic:default"] = { provider: "anthropic", mode: "token" };
    if (this.setupKeys.claude2)
      profiles["anthropic:secondary"] = { provider: "anthropic", mode: "token" };
    if (this.setupKeys.googleai)
      profiles["google:default"] = { provider: "google", mode: "api_key" };
    if (this.setupKeys.brave)
      config.tools = { web: { search: { apiKey: this.setupKeys.brave } } };
    if (this.setupKeys.elevenlabs)
      config.messages = { tts: { provider: "elevenlabs", elevenlabs: { apiKey: this.setupKeys.elevenlabs } } };
    if (this.setupBots.length > 1) {
      agents.list = this.setupBots.map((bot, i) => {
        const id = i === 0 ? "main" : bot.name.toLowerCase().replace(/[^a-z0-9]/g, "-") || `bot-${i}`;
        const folder = "AGENT-" + (bot.name || "BOT").toUpperCase().replace(/[^A-Z0-9]/g, "-");
        return { id, name: bot.name || `Bot ${i + 1}`, workspace: `~/.openclaw/workspace/${folder}` };
      });
    } else if ((_b = this.setupBots[0]) == null ? void 0 : _b.name) {
      const folder = "AGENT-" + this.setupBots[0].name.toUpperCase().replace(/[^A-Z0-9]/g, "-");
      agents.defaults.workspace = `~/.openclaw/workspace/${folder}`;
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
  async onClose() {
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
    new import_obsidian.Setting(containerEl).setName("Chat").setHeading();
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsibWFpbi50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHtcbiAgQXBwLFxuICBGdXp6eVN1Z2dlc3RNb2RhbCxcbiAgSXRlbVZpZXcsXG4gIE1hcmtkb3duUmVuZGVyZXIsXG4gIE1vZGFsLFxuICBOb3RpY2UsXG4gIFBsYXRmb3JtLFxuICBQbHVnaW4sXG4gIFBsdWdpblNldHRpbmdUYWIsXG4gIFNldHRpbmcsXG4gIFRGaWxlLFxuICBXb3Jrc3BhY2VMZWFmLFxuICBzZXRJY29uLFxufSBmcm9tIFwib2JzaWRpYW5cIjtcblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFNldHRpbmdzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG50eXBlIFN0cmVhbUl0ZW0gPSB7IHR5cGU6IFwidG9vbFwiOyBsYWJlbDogc3RyaW5nOyB1cmw/OiBzdHJpbmc7IHRleHRQb3M/OiBudW1iZXIgfSB8IHsgdHlwZTogXCJ0ZXh0XCI7IHRleHQ6IHN0cmluZyB9O1xuXG4vKiogU2FmZWx5IGV4dHJhY3QgYSBzdHJpbmcgZnJvbSBhbiB1bmtub3duIHZhbHVlIChhdm9pZHMgW29iamVjdCBPYmplY3RdIGNvZXJjaW9uKS4gKi9cbmZ1bmN0aW9uIHN0cih2OiB1bmtub3duLCBmYWxsYmFjayA9IFwiXCIpOiBzdHJpbmcge1xuICByZXR1cm4gdHlwZW9mIHYgPT09IFwic3RyaW5nXCIgPyB2IDogZmFsbGJhY2s7XG59XG5cbmludGVyZmFjZSBBZ2VudEluZm8ge1xuICBpZDogc3RyaW5nO1xuICBuYW1lOiBzdHJpbmc7XG4gIGVtb2ppOiBzdHJpbmc7XG4gIGNyZWF0dXJlOiBzdHJpbmc7XG59XG5cbmludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICB0b2tlbjogc3RyaW5nO1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIGFjdGl2ZUFnZW50SWQ/OiBzdHJpbmc7ICAvLyBjdXJyZW50bHkgc2VsZWN0ZWQgYWdlbnQgaWRcbiAgY3VycmVudE1vZGVsPzogc3RyaW5nOyAgLy8gcGVyc2lzdGVkIG1vZGVsIHNlbGVjdGlvbiAocHJvdmlkZXIvbW9kZWwgZm9ybWF0KVxuICBvbmJvYXJkaW5nQ29tcGxldGU6IGJvb2xlYW47XG4gIGRldmljZUlkPzogc3RyaW5nO1xuICBkZXZpY2VQdWJsaWNLZXk/OiBzdHJpbmc7XG4gIGRldmljZVByaXZhdGVLZXk/OiBzdHJpbmc7XG4gIC8qKiBQZXJzaXN0ZWQgc3RyZWFtIGl0ZW1zICh0b29sIGNhbGxzICsgaW50ZXJtZWRpYXJ5IHRleHQpIGtleWVkIGJ5IGFzc2lzdGFudCBtZXNzYWdlIGluZGV4ICovXG4gIHN0cmVhbUl0ZW1zTWFwPzogUmVjb3JkPHN0cmluZywgU3RyZWFtSXRlbVtdPjtcbn1cblxuY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogXCJcIixcbiAgdG9rZW46IFwiXCIsXG4gIHNlc3Npb25LZXk6IFwibWFpblwiLFxuICBvbmJvYXJkaW5nQ29tcGxldGU6IGZhbHNlLFxufTtcblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIERldmljZSBJZGVudGl0eSAoRWQyNTUxOSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbi8qKiBOb3JtYWxpemUgYSBnYXRld2F5IFVSTDogYWNjZXB0cyB3czovLywgd3NzOi8vLCBodHRwOi8vLCBodHRwczovLyBhbmQgcmV0dXJucyB3czovLyBvciB3c3M6Ly8uIFJldHVybnMgbnVsbCBpZiBpbnZhbGlkLiAqL1xuZnVuY3Rpb24gbm9ybWFsaXplR2F0ZXdheVVybChyYXc6IHN0cmluZyk6IHN0cmluZyB8IG51bGwge1xuICBsZXQgdXJsID0gcmF3LnRyaW0oKTtcbiAgaWYgKHVybC5zdGFydHNXaXRoKFwiaHR0cHM6Ly9cIikpIHVybCA9IFwid3NzOi8vXCIgKyB1cmwuc2xpY2UoOCk7XG4gIGVsc2UgaWYgKHVybC5zdGFydHNXaXRoKFwiaHR0cDovL1wiKSkgdXJsID0gXCJ3czovL1wiICsgdXJsLnNsaWNlKDcpO1xuICBpZiAoIXVybC5zdGFydHNXaXRoKFwid3M6Ly9cIikgJiYgIXVybC5zdGFydHNXaXRoKFwid3NzOi8vXCIpKSByZXR1cm4gbnVsbDtcbiAgLy8gU3RyaXAgdHJhaWxpbmcgc2xhc2ggZm9yIGNvbnNpc3RlbmN5XG4gIHJldHVybiB1cmwucmVwbGFjZSgvXFwvKyQvLCBcIlwiKTtcbn1cblxuZnVuY3Rpb24gdG9CYXNlNjRVcmwoYnl0ZXM6IFVpbnQ4QXJyYXkpOiBzdHJpbmcge1xuICBsZXQgYmluYXJ5ID0gXCJcIjtcbiAgZm9yIChjb25zdCBiIG9mIGJ5dGVzKSBiaW5hcnkgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShiKTtcbiAgcmV0dXJuIGJ0b2EoYmluYXJ5KS5yZXBsYWNlKC9cXCsvZywgXCItXCIpLnJlcGxhY2UoL1xcLy9nLCBcIl9cIikucmVwbGFjZSgvPSskL2csIFwiXCIpO1xufVxuXG5mdW5jdGlvbiBmcm9tQmFzZTY0VXJsKHM6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBwYWRkZWQgPSBzLnJlcGxhY2UoLy0vZywgXCIrXCIpLnJlcGxhY2UoL18vZywgXCIvXCIpICsgXCI9XCIucmVwZWF0KCg0IC0gKHMubGVuZ3RoICUgNCkpICUgNCk7XG4gIGNvbnN0IGJpbmFyeSA9IGF0b2IocGFkZGVkKTtcbiAgY29uc3QgYnl0ZXMgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIGJ5dGVzW2ldID0gYmluYXJ5LmNoYXJDb2RlQXQoaSk7XG4gIHJldHVybiBieXRlcztcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGRhdGE6IFVpbnQ4QXJyYXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBoYXNoID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIGRhdGEuYnVmZmVyKTtcbiAgcmV0dXJuIEFycmF5LmZyb20obmV3IFVpbnQ4QXJyYXkoaGFzaCksIChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCBcIjBcIikpLmpvaW4oXCJcIik7XG59XG5cbmludGVyZmFjZSBEZXZpY2VJZGVudGl0eSB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nO1xuICBwcml2YXRlS2V5OiBzdHJpbmc7XG4gIGNyeXB0b0tleTogQ3J5cHRvS2V5O1xufVxuXG5hc3luYyBmdW5jdGlvbiBnZXRPckNyZWF0ZURldmljZUlkZW50aXR5KFxuICBsb2FkRGF0YTogKCkgPT4gUHJvbWlzZTxSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiB8IG51bGw+LFxuICBzYXZlRGF0YTogKGRhdGE6IFJlY29yZDxzdHJpbmcsIHVua25vd24+KSA9PiBQcm9taXNlPHZvaWQ+XG4pOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIGNvbnN0IGRhdGEgPSBhd2FpdCBsb2FkRGF0YSgpO1xuICBjb25zdCBkZXZpY2VJZCA9IHR5cGVvZiBkYXRhPy5kZXZpY2VJZCA9PT0gXCJzdHJpbmdcIiA/IGRhdGEuZGV2aWNlSWQgOiBudWxsO1xuICBjb25zdCBkZXZpY2VQdWJsaWNLZXkgPSB0eXBlb2YgZGF0YT8uZGV2aWNlUHVibGljS2V5ID09PSBcInN0cmluZ1wiID8gZGF0YS5kZXZpY2VQdWJsaWNLZXkgOiBudWxsO1xuICBjb25zdCBkZXZpY2VQcml2YXRlS2V5ID0gdHlwZW9mIGRhdGE/LmRldmljZVByaXZhdGVLZXkgPT09IFwic3RyaW5nXCIgPyBkYXRhLmRldmljZVByaXZhdGVLZXkgOiBudWxsO1xuICBpZiAoZGV2aWNlSWQgJiYgZGV2aWNlUHVibGljS2V5ICYmIGRldmljZVByaXZhdGVLZXkpIHtcbiAgICAvLyBSZXN0b3JlIGV4aXN0aW5nIGlkZW50aXR5XG4gICAgY29uc3QgcHJpdkJ5dGVzID0gZnJvbUJhc2U2NFVybChkZXZpY2VQcml2YXRlS2V5KTtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgIFwicGtjczhcIixcbiAgICAgIHByaXZCeXRlcyxcbiAgICAgIHsgbmFtZTogXCJFZDI1NTE5XCIgfSxcbiAgICAgIGZhbHNlLFxuICAgICAgW1wic2lnblwiXVxuICAgICk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGRldmljZUlkLFxuICAgICAgcHVibGljS2V5OiBkZXZpY2VQdWJsaWNLZXksXG4gICAgICBwcml2YXRlS2V5OiBkZXZpY2VQcml2YXRlS2V5LFxuICAgICAgY3J5cHRvS2V5LFxuICAgIH07XG4gIH1cblxuICAvLyBHZW5lcmF0ZSBuZXcgRWQyNTUxOSBrZXlwYWlyXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFwiRWQyNTUxOVwiLCB0cnVlLCBbXCJzaWduXCIsIFwidmVyaWZ5XCJdKTtcbiAgY29uc3QgcHViUmF3ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJyYXdcIiwga2V5UGFpci5wdWJsaWNLZXkpKTtcbiAgY29uc3QgcHJpdlBrY3M4ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXlQYWlyLnByaXZhdGVLZXkpKTtcbiAgY29uc3QgbmV3RGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcbiAgY29uc3QgcHVibGljS2V5ID0gdG9CYXNlNjRVcmwocHViUmF3KTtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IHRvQmFzZTY0VXJsKHByaXZQa2NzOCk7XG5cbiAgLy8gU2F2ZSB0byBwbHVnaW4gZGF0YVxuICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBsb2FkRGF0YSgpKSA/PyB7fTtcbiAgZXhpc3RpbmcuZGV2aWNlSWQgPSBuZXdEZXZpY2VJZDtcbiAgZXhpc3RpbmcuZGV2aWNlUHVibGljS2V5ID0gcHVibGljS2V5O1xuICBleGlzdGluZy5kZXZpY2VQcml2YXRlS2V5ID0gcHJpdmF0ZUtleTtcbiAgYXdhaXQgc2F2ZURhdGEoZXhpc3RpbmcpO1xuXG4gIHJldHVybiB7IGRldmljZUlkOiBuZXdEZXZpY2VJZCwgcHVibGljS2V5LCBwcml2YXRlS2V5LCBjcnlwdG9LZXk6IGtleVBhaXIucHJpdmF0ZUtleSB9O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGVuY29kZWQgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUocGF5bG9hZCk7XG4gIGxldCBjcnlwdG9LZXkgPSBpZGVudGl0eS5jcnlwdG9LZXk7XG4gIC8vIElmIGNyeXB0b0tleSBkb2Vzbid0IGhhdmUgc2lnbiB1c2FnZSwgcmUtaW1wb3J0XG4gIGlmICghY3J5cHRvS2V5KSB7XG4gICAgY29uc3QgcHJpdkJ5dGVzID0gZnJvbUJhc2U2NFVybChpZGVudGl0eS5wcml2YXRlS2V5KTtcbiAgICBjcnlwdG9LZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcInBrY3M4XCIsIHByaXZCeXRlcywgeyBuYW1lOiBcIkVkMjU1MTlcIiB9LCBmYWxzZSwgW1wic2lnblwiXSk7XG4gIH1cbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFwiRWQyNTUxOVwiLCBjcnlwdG9LZXksIGVuY29kZWQpO1xuICByZXR1cm4gdG9CYXNlNjRVcmwobmV3IFVpbnQ4QXJyYXkoc2lnKSk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkU2lnbmF0dXJlUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZyB8IG51bGw7XG4gIG5vbmNlOiBzdHJpbmcgfCBudWxsO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyBcInYyXCIgOiBcInYxXCI7XG4gIGNvbnN0IHBhcnRzID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBwYXJhbXMuc2NvcGVzLmpvaW4oXCIsXCIpLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuID8/IFwiXCIsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSBcInYyXCIpIHBhcnRzLnB1c2gocGFyYW1zLm5vbmNlID8/IFwiXCIpO1xuICByZXR1cm4gcGFydHMuam9pbihcInxcIik7XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBHYXRld2F5IFR5cGVzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5pbnRlcmZhY2UgR2F0ZXdheVBheWxvYWQge1xuICBba2V5OiBzdHJpbmddOiB1bmtub3duO1xufVxuXG5pbnRlcmZhY2UgR2F0ZXdheU1lc3NhZ2Uge1xuICB0eXBlOiBzdHJpbmc7XG4gIGlkPzogc3RyaW5nO1xuICBldmVudD86IHN0cmluZztcbiAgcGF5bG9hZD86IEdhdGV3YXlQYXlsb2FkO1xuICBvaz86IGJvb2xlYW47XG4gIGVycm9yPzogeyBtZXNzYWdlPzogc3RyaW5nIH07XG4gIHNlcT86IG51bWJlcjtcbn1cblxuaW50ZXJmYWNlIFNlc3Npb25JbmZvIHtcbiAga2V5OiBzdHJpbmc7XG4gIGxhYmVsPzogc3RyaW5nO1xuICBkaXNwbGF5TmFtZT86IHN0cmluZztcbiAgbW9kZWw/OiBzdHJpbmc7XG4gIHRvdGFsVG9rZW5zPzogbnVtYmVyO1xuICBjb250ZXh0VG9rZW5zPzogbnVtYmVyO1xuICBjcmVhdGVkQXQ/OiBudW1iZXI7XG4gIHVwZGF0ZWRBdD86IG51bWJlcjtcbn1cblxuaW50ZXJmYWNlIEFnZW50TGlzdEl0ZW0ge1xuICBpZD86IHN0cmluZztcbiAgbmFtZT86IHN0cmluZztcbn1cblxuaW50ZXJmYWNlIE1vZGVsSW5mbyB7XG4gIGlkOiBzdHJpbmc7XG4gIG5hbWU/OiBzdHJpbmc7XG4gIHByb3ZpZGVyOiBzdHJpbmc7XG59XG5cbmludGVyZmFjZSBDb250ZW50QmxvY2sge1xuICB0eXBlOiBzdHJpbmc7XG4gIHRleHQ/OiBzdHJpbmc7XG4gIGNvbnRlbnQ/OiBzdHJpbmcgfCBDb250ZW50QmxvY2tbXTtcbiAgbmFtZT86IHN0cmluZztcbiAgaW5wdXQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbiAgYXJndW1lbnRzPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIGltYWdlX3VybD86IHsgdXJsOiBzdHJpbmcgfTtcbn1cblxuaW50ZXJmYWNlIEhpc3RvcnlNZXNzYWdlIHtcbiAgcm9sZTogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmcgfCBDb250ZW50QmxvY2tbXTtcbiAgdGltZXN0YW1wPzogbnVtYmVyO1xufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgR2F0ZXdheSBDbGllbnQgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbnR5cGUgR2F0ZXdheUV2ZW50SGFuZGxlciA9IChldmVudDogeyBldmVudDogc3RyaW5nOyBwYXlsb2FkOiBHYXRld2F5UGF5bG9hZDsgc2VxPzogbnVtYmVyIH0pID0+IHZvaWQ7XG50eXBlIEdhdGV3YXlIZWxsb0hhbmRsZXIgPSAocGF5bG9hZDogR2F0ZXdheVBheWxvYWQpID0+IHZvaWQ7XG50eXBlIEdhdGV3YXlDbG9zZUhhbmRsZXIgPSAoaW5mbzogeyBjb2RlOiBudW1iZXI7IHJlYXNvbjogc3RyaW5nIH0pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBHYXRld2F5Q2xpZW50T3B0cyB7XG4gIHVybDogc3RyaW5nO1xuICB0b2tlbj86IHN0cmluZztcbiAgZGV2aWNlSWRlbnRpdHk/OiBEZXZpY2VJZGVudGl0eTtcbiAgb25FdmVudD86IEdhdGV3YXlFdmVudEhhbmRsZXI7XG4gIG9uSGVsbG8/OiBHYXRld2F5SGVsbG9IYW5kbGVyO1xuICBvbkNsb3NlPzogR2F0ZXdheUNsb3NlSGFuZGxlcjtcbn1cblxuZnVuY3Rpb24gZ2VuZXJhdGVJZCgpOiBzdHJpbmcge1xuICBjb25zdCBhcnIgPSBuZXcgVWludDhBcnJheSgxNik7XG4gIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMoYXJyKTtcbiAgcmV0dXJuIEFycmF5LmZyb20oYXJyLCAoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgXCIwXCIpKS5qb2luKFwiXCIpO1xufVxuXG4vKipcbiAqIERlbGV0ZSBhIHNlc3Npb24gdmlhIGdhdGV3YXksIHdpdGggZmFsbGJhY2sgZm9yIHVucHJlZml4ZWQgc3RvcmUga2V5cy5cbiAqIFRoZSBnYXRld2F5IHN0b3JlcyBjaGFubmVsIHNlc3Npb25zICh0ZWxlZ3JhbTosIGRpc2NvcmQ6LCBldGMuKSB3aXRob3V0IHRoZVxuICogYWdlbnQ6bWFpbjogcHJlZml4LCBidXQgc2Vzc2lvbnMubGlzdCByZXR1cm5zIHRoZW0gcHJlZml4ZWQuIFNlbmRpbmcgdGhlXG4gKiBwcmVmaXhlZCBrZXkgdG8gc2Vzc2lvbnMuZGVsZXRlIHN1Y2NlZWRzICh7b2s6dHJ1ZX0pIGJ1dCByZXR1cm5zIGRlbGV0ZWQ6ZmFsc2VcbiAqIGJlY2F1c2UgdGhlIGtleSBsb29rdXAgbWlzc2VzIHRoZSB1bnByZWZpeGVkIHN0b3JlIGVudHJ5LlxuICogRml4OiBpZiB0aGUgZmlyc3QgYXR0ZW1wdCByZXR1cm5zIGRlbGV0ZWQ6ZmFsc2UgYW5kIHRoZSBrZXkgaGFzIGFuIGFnZW50IHByZWZpeCxcbiAqIHJldHJ5IHdpdGggdGhlIHJhdyBzdWZmaXggKHRoZSBhY3R1YWwgc3RvcmUga2V5KS5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gZGVsZXRlU2Vzc2lvbldpdGhGYWxsYmFjayhcbiAgZ2F0ZXdheTogR2F0ZXdheUNsaWVudCxcbiAga2V5OiBzdHJpbmcsXG4gIGRlbGV0ZVRyYW5zY3JpcHQgPSB0cnVlXG4pOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZ2F0ZXdheS5yZXF1ZXN0KFwic2Vzc2lvbnMuZGVsZXRlXCIsIHsga2V5LCBkZWxldGVUcmFuc2NyaXB0IH0pIGFzIHsgZGVsZXRlZD86IGJvb2xlYW4gfSB8IG51bGw7XG4gIGlmIChyZXN1bHQ/LmRlbGV0ZWQpIHJldHVybiB0cnVlO1xuXG4gIC8vIEZhbGxiYWNrOiBzdHJpcCBhZ2VudDo8aWQ+OiBwcmVmaXggYW5kIHJldHJ5IHdpdGggcmF3IGtleVxuICBjb25zdCBtYXRjaCA9IGtleS5tYXRjaCgvXmFnZW50OlteOl0rOiguKykkLyk7XG4gIGlmIChtYXRjaCkge1xuICAgIGNvbnN0IHJhd0tleSA9IG1hdGNoWzFdO1xuICAgIGNvbnN0IHJldHJ5ID0gYXdhaXQgZ2F0ZXdheS5yZXF1ZXN0KFwic2Vzc2lvbnMuZGVsZXRlXCIsIHsga2V5OiByYXdLZXksIGRlbGV0ZVRyYW5zY3JpcHQgfSkgYXMgeyBkZWxldGVkPzogYm9vbGVhbiB9IHwgbnVsbDtcbiAgICByZXR1cm4gISFyZXRyeT8uZGVsZXRlZDtcbiAgfVxuICByZXR1cm4gZmFsc2U7XG59XG5cbmNsYXNzIEdhdGV3YXlDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBwZW5kaW5nID0gbmV3IE1hcDxzdHJpbmcsIHsgcmVzb2x2ZTogKHY6IHVua25vd24pID0+IHZvaWQ7IHJlamVjdDogKGU6IEVycm9yKSA9PiB2b2lkIH0+KCk7XG4gIHByaXZhdGUgY2xvc2VkID0gZmFsc2U7XG4gIHByaXZhdGUgY29ubmVjdFNlbnQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGJhY2tvZmZNcyA9IDgwMDtcbiAgcHJpdmF0ZSBvcHRzOiBHYXRld2F5Q2xpZW50T3B0cztcbiAgcHJpdmF0ZSBjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcGVuZGluZ1RpbWVvdXRzID0gbmV3IE1hcDxzdHJpbmcsIFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+PigpO1xuXG4gIGNvbnN0cnVjdG9yKG9wdHM6IEdhdGV3YXlDbGllbnRPcHRzKSB7XG4gICAgdGhpcy5vcHRzID0gb3B0cztcbiAgfVxuXG4gIGdldCBjb25uZWN0ZWQoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMud3M/LnJlYWR5U3RhdGUgPT09IFdlYlNvY2tldC5PUEVOO1xuICB9XG5cbiAgc3RhcnQoKTogdm9pZCB7XG4gICAgdGhpcy5jbG9zZWQgPSBmYWxzZTtcbiAgICB0aGlzLmRvQ29ubmVjdCgpO1xuICB9XG5cbiAgc3RvcCgpOiB2b2lkIHtcbiAgICB0aGlzLmNsb3NlZCA9IHRydWU7XG4gICAgaWYgKHRoaXMuY29ubmVjdFRpbWVyICE9PSBudWxsKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5jb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5jb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IFssIHRdIG9mIHRoaXMucGVuZGluZ1RpbWVvdXRzKSBjbGVhclRpbWVvdXQodCk7XG4gICAgdGhpcy5wZW5kaW5nVGltZW91dHMuY2xlYXIoKTtcbiAgICB0aGlzLndzPy5jbG9zZSgpO1xuICAgIHRoaXMud3MgPSBudWxsO1xuICAgIHRoaXMuZmx1c2hQZW5kaW5nKG5ldyBFcnJvcihcImNsaWVudCBzdG9wcGVkXCIpKTtcbiAgfVxuXG4gIGFzeW5jIHJlcXVlc3QobWV0aG9kOiBzdHJpbmcsIHBhcmFtcz86IHVua25vd24pOiBQcm9taXNlPHVua25vd24+IHtcbiAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwibm90IGNvbm5lY3RlZFwiKTtcbiAgICB9XG4gICAgY29uc3QgaWQgPSBnZW5lcmF0ZUlkKCk7XG4gICAgY29uc3QgbXNnID0geyB0eXBlOiBcInJlcVwiLCBpZCwgbWV0aG9kLCBwYXJhbXMgfTtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5wZW5kaW5nLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG4gICAgICAvLyBUaW1lb3V0IHJlcXVlc3RzIGFmdGVyIDMwc1xuICAgICAgY29uc3QgdCA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5wZW5kaW5nLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmcuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKFwicmVxdWVzdCB0aW1lb3V0XCIpKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzAwMDApO1xuICAgICAgdGhpcy5wZW5kaW5nVGltZW91dHMuc2V0KGlkLCB0KTtcbiAgICAgIHRoaXMud3MhLnNlbmQoSlNPTi5zdHJpbmdpZnkobXNnKSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGRvQ29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5jbG9zZWQpIHJldHVybjtcblxuICAgIC8vIE5vcm1hbGl6ZSBhbmQgdmFsaWRhdGUgVVJMXG4gICAgY29uc3QgdXJsID0gbm9ybWFsaXplR2F0ZXdheVVybCh0aGlzLm9wdHMudXJsKTtcbiAgICBpZiAoIXVybCkge1xuICAgICAgY29uc29sZS5lcnJvcihcIltPYnNpZGlhbkNsYXddIEludmFsaWQgZ2F0ZXdheSBVUkw6IG11c3QgYmUgYSB2YWxpZCB3czovLywgd3NzOi8vLCBodHRwOi8vLCBvciBodHRwczovLyBVUkxcIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy53cyA9IG5ldyBXZWJTb2NrZXQodXJsKTtcbiAgICB0aGlzLndzLmFkZEV2ZW50TGlzdGVuZXIoXCJvcGVuXCIsICgpID0+IHRoaXMucXVldWVDb25uZWN0KCkpO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgKGUpID0+IHRoaXMuaGFuZGxlTWVzc2FnZShzdHIoZS5kYXRhKSkpO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcImNsb3NlXCIsIChlKSA9PiB7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICAgIHRoaXMuZmx1c2hQZW5kaW5nKG5ldyBFcnJvcihgY2xvc2VkICgke2UuY29kZX0pYCkpO1xuICAgICAgdGhpcy5vcHRzLm9uQ2xvc2U/Lih7IGNvZGU6IGUuY29kZSwgcmVhc29uOiBlLnJlYXNvbiB8fCBcIlwiIH0pO1xuICAgICAgdGhpcy5zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgIH0pO1xuICAgIHRoaXMud3MuYWRkRXZlbnRMaXN0ZW5lcihcImVycm9yXCIsICgpID0+IHt9KTtcbiAgfVxuXG4gIHByaXZhdGUgc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuY2xvc2VkKSByZXR1cm47XG4gICAgY29uc3QgZGVsYXkgPSB0aGlzLmJhY2tvZmZNcztcbiAgICB0aGlzLmJhY2tvZmZNcyA9IE1hdGgubWluKHRoaXMuYmFja29mZk1zICogMS43LCAxNTAwMCk7XG4gICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmRvQ29ubmVjdCgpLCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGZsdXNoUGVuZGluZyhlcnI6IEVycm9yKTogdm9pZCB7XG4gICAgZm9yIChjb25zdCBbaWQsIHBdIG9mIHRoaXMucGVuZGluZykge1xuICAgICAgY29uc3QgdCA9IHRoaXMucGVuZGluZ1RpbWVvdXRzLmdldChpZCk7XG4gICAgICBpZiAodCkgY2xlYXJUaW1lb3V0KHQpO1xuICAgICAgcC5yZWplY3QoZXJyKTtcbiAgICB9XG4gICAgdGhpcy5wZW5kaW5nLmNsZWFyKCk7XG4gICAgdGhpcy5wZW5kaW5nVGltZW91dHMuY2xlYXIoKTtcbiAgfVxuXG4gIHByaXZhdGUgcXVldWVDb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuY29ubmVjdE5vbmNlID0gbnVsbDtcbiAgICB0aGlzLmNvbm5lY3RTZW50ID0gZmFsc2U7XG4gICAgaWYgKHRoaXMuY29ubmVjdFRpbWVyICE9PSBudWxsKSBjbGVhclRpbWVvdXQodGhpcy5jb25uZWN0VGltZXIpO1xuICAgIHRoaXMuY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB2b2lkIHRoaXMuc2VuZENvbm5lY3QoKSwgNzUwKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgc2VuZENvbm5lY3QoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuY29ubmVjdFNlbnQpIHJldHVybjtcbiAgICB0aGlzLmNvbm5lY3RTZW50ID0gdHJ1ZTtcbiAgICBpZiAodGhpcy5jb25uZWN0VGltZXIgIT09IG51bGwpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLmNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLmNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuXG4gICAgY29uc3QgQ0xJRU5UX0lEID0gXCJnYXRld2F5LWNsaWVudFwiO1xuICAgIGNvbnN0IENMSUVOVF9NT0RFID0gXCJ1aVwiO1xuICAgIGNvbnN0IFJPTEUgPSBcIm9wZXJhdG9yXCI7XG4gICAgY29uc3QgU0NPUEVTID0gW1wib3BlcmF0b3IuYWRtaW5cIiwgXCJvcGVyYXRvci53cml0ZVwiLCBcIm9wZXJhdG9yLnJlYWRcIl07XG5cbiAgICBjb25zdCBhdXRoID0gdGhpcy5vcHRzLnRva2VuID8geyB0b2tlbjogdGhpcy5vcHRzLnRva2VuIH0gOiB1bmRlZmluZWQ7XG5cbiAgICAvLyBCdWlsZCBkZXZpY2UgZmluZ2VycHJpbnQgaWYgaWRlbnRpdHkgaXMgYXZhaWxhYmxlXG4gICAgbGV0IGRldmljZTogeyBpZDogc3RyaW5nOyBwdWJsaWNLZXk6IHN0cmluZzsgc2lnbmF0dXJlOiBzdHJpbmc7IHNpZ25lZEF0OiBudW1iZXI7IG5vbmNlPzogc3RyaW5nIH0gfCB1bmRlZmluZWQgPSB1bmRlZmluZWQ7XG4gICAgY29uc3QgaWRlbnRpdHkgPSB0aGlzLm9wdHMuZGV2aWNlSWRlbnRpdHk7XG4gICAgaWYgKGlkZW50aXR5KSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3Qgbm9uY2UgPSB0aGlzLmNvbm5lY3ROb25jZSA/PyBudWxsO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGRTaWduYXR1cmVQYXlsb2FkKHtcbiAgICAgICAgICBkZXZpY2VJZDogaWRlbnRpdHkuZGV2aWNlSWQsXG4gICAgICAgICAgY2xpZW50SWQ6IENMSUVOVF9JRCxcbiAgICAgICAgICBjbGllbnRNb2RlOiBDTElFTlRfTU9ERSxcbiAgICAgICAgICByb2xlOiBST0xFLFxuICAgICAgICAgIHNjb3BlczogU0NPUEVTLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMub3B0cy50b2tlbiA/PyBudWxsLFxuICAgICAgICAgIG5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuICAgICAgICBkZXZpY2UgPSB7XG4gICAgICAgICAgaWQ6IGlkZW50aXR5LmRldmljZUlkLFxuICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgIHNpZ25hdHVyZSxcbiAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICBub25jZTogbm9uY2UgPz8gdW5kZWZpbmVkLFxuICAgICAgICB9O1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmVycm9yKFwiW09ic2lkaWFuQ2xhd10gRGV2aWNlIHNpZ25pbmcgZmFpbGVkOlwiLCBlKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBwYXJhbXMgPSB7XG4gICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgY2xpZW50OiB7XG4gICAgICAgIGlkOiBDTElFTlRfSUQsXG4gICAgICAgIHZlcnNpb246IFwiMC4xLjBcIixcbiAgICAgICAgcGxhdGZvcm06IFwib2JzaWRpYW5cIixcbiAgICAgICAgbW9kZTogQ0xJRU5UX01PREUsXG4gICAgICB9LFxuICAgICAgcm9sZTogUk9MRSxcbiAgICAgIHNjb3BlczogU0NPUEVTLFxuICAgICAgYXV0aCxcbiAgICAgIGRldmljZSxcbiAgICAgIGNhcHM6IFtcInRvb2wtZXZlbnRzXCJdLFxuICAgIH07XG5cbiAgICB2b2lkIHRoaXMucmVxdWVzdChcImNvbm5lY3RcIiwgcGFyYW1zKVxuICAgICAgLnRoZW4oKHBheWxvYWQpID0+IHtcbiAgICAgICAgdGhpcy5iYWNrb2ZmTXMgPSA4MDA7XG4gICAgICAgIHRoaXMub3B0cy5vbkhlbGxvPy4ocGF5bG9hZCBhcyBHYXRld2F5UGF5bG9hZCk7XG4gICAgICB9KVxuICAgICAgLmNhdGNoKCgpID0+IHtcbiAgICAgICAgdGhpcy53cz8uY2xvc2UoNDAwOCwgXCJjb25uZWN0IGZhaWxlZFwiKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBoYW5kbGVNZXNzYWdlKHJhdzogc3RyaW5nKTogdm9pZCB7XG4gICAgbGV0IG1zZzogR2F0ZXdheU1lc3NhZ2U7XG4gICAgdHJ5IHtcbiAgICAgIG1zZyA9IEpTT04ucGFyc2UocmF3KSBhcyBHYXRld2F5TWVzc2FnZTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAobXNnLnR5cGUgPT09IFwiZXZlbnRcIikge1xuICAgICAgaWYgKG1zZy5ldmVudCA9PT0gXCJjb25uZWN0LmNoYWxsZW5nZVwiKSB7XG4gICAgICAgIGNvbnN0IG5vbmNlID0gbXNnLnBheWxvYWQ/Lm5vbmNlO1xuICAgICAgICBpZiAodHlwZW9mIG5vbmNlID09PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgdGhpcy5jb25uZWN0Tm9uY2UgPSBub25jZTtcbiAgICAgICAgICB2b2lkIHRoaXMuc2VuZENvbm5lY3QoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBpZiAobXNnLmV2ZW50KSB0aGlzLm9wdHMub25FdmVudD8uKHsgZXZlbnQ6IG1zZy5ldmVudCwgcGF5bG9hZDogbXNnLnBheWxvYWQgPz8ge30sIHNlcTogbXNnLnNlcSB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAobXNnLnR5cGUgPT09IFwicmVzXCIpIHtcbiAgICAgIGNvbnN0IG1zZ0lkID0gbXNnLmlkID8/IFwiXCI7XG4gICAgICBjb25zdCBwID0gdGhpcy5wZW5kaW5nLmdldChtc2dJZCk7XG4gICAgICBpZiAoIXApIHJldHVybjtcbiAgICAgIHRoaXMucGVuZGluZy5kZWxldGUobXNnSWQpO1xuICAgICAgY29uc3QgdCA9IHRoaXMucGVuZGluZ1RpbWVvdXRzLmdldChtc2dJZCk7XG4gICAgICBpZiAodCkge1xuICAgICAgICBjbGVhclRpbWVvdXQodCk7XG4gICAgICAgIHRoaXMucGVuZGluZ1RpbWVvdXRzLmRlbGV0ZShtc2dJZCk7XG4gICAgICB9XG4gICAgICBpZiAobXNnLm9rKSB7XG4gICAgICAgIHAucmVzb2x2ZShtc2cucGF5bG9hZCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBwLnJlamVjdChuZXcgRXJyb3IobXNnLmVycm9yPy5tZXNzYWdlID8/IFwicmVxdWVzdCBmYWlsZWRcIikpO1xuICAgICAgfVxuICAgIH1cbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgQ2hhdCBNZXNzYWdlIFR5cGVzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5pbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICByb2xlOiBcInVzZXJcIiB8IFwiYXNzaXN0YW50XCI7XG4gIHRleHQ6IHN0cmluZztcbiAgaW1hZ2VzOiBzdHJpbmdbXTsgLy8gZGF0YSBVUklzIG9yIFVSTHNcbiAgdGltZXN0YW1wOiBudW1iZXI7XG4gIGNvbnRlbnRCbG9ja3M/OiBDb250ZW50QmxvY2tbXTsgLy8gcmF3IGNvbnRlbnQgYXJyYXkgZnJvbSBoaXN0b3J5IChwcmVzZXJ2ZXMgdG9vbF91c2UgaW50ZXJsZWF2aW5nKVxuICB2b2ljZVJlZnM/OiBzdHJpbmdbXTsgLy8gVk9JQ0U6ZmlsZW5hbWUuYjY0IHJlZnMgZm9yIGF1ZGlvIHBsYXliYWNrIHZpYSBnYXRld2F5XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBPbmJvYXJkaW5nIE1vZGFsIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jbGFzcyBPbmJvYXJkaW5nTW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgc3RlcCA9IDA7XG4gIHByaXZhdGUgcGF0aDogXCJmcmVzaFwiIHwgXCJleGlzdGluZ1wiIHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgc3RhdHVzRWw6IEhUTUxFbGVtZW50IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcGFpcmluZ1BvbGxUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gU2V0dXAgc3RhdGUgZm9yIGZyZXNoIGluc3RhbGwgcGF0aFxuICBwcml2YXRlIHNldHVwS2V5cyA9IHsgY2xhdWRlMTogJycsIGNsYXVkZTI6ICcnLCBnb29nbGVhaTogJycsIGJyYXZlOiAnJywgZWxldmVubGFiczogJycgfTtcbiAgcHJpdmF0ZSBzZXR1cEJvdHM6IHsgbmFtZTogc3RyaW5nOyBtb2RlbDogc3RyaW5nIH1bXSA9IFt7IG5hbWU6ICdBc3Npc3RhbnQnLCBtb2RlbDogJ2FudGhyb3BpYy9jbGF1ZGUtc29ubmV0LTQtNicgfV07XG5cbiAgcHJpdmF0ZSBzdGF0aWMgTU9ERUxTID0gW1xuICAgIHsgaWQ6ICdhbnRocm9waWMvY2xhdWRlLW9wdXMtNC02JywgbGFiZWw6ICdDbGF1ZGUgT3B1cyA0JyB9LFxuICAgIHsgaWQ6ICdhbnRocm9waWMvY2xhdWRlLXNvbm5ldC00LTYnLCBsYWJlbDogJ0NsYXVkZSBTb25uZXQgNCcgfSxcbiAgICB7IGlkOiAnYW50aHJvcGljL2NsYXVkZS1zb25uZXQtNC01JywgbGFiZWw6ICdDbGF1ZGUgU29ubmV0IDQuNScgfSxcbiAgICB7IGlkOiAnZ29vZ2xlL2dlbWluaS0yLjUtcHJvJywgbGFiZWw6ICdHZW1pbmkgMi41IFBybycgfSxcbiAgICB7IGlkOiAnZ29vZ2xlL2dlbWluaS0yLjUtZmxhc2gnLCBsYWJlbDogJ0dlbWluaSAyLjUgRmxhc2gnIH0sXG4gIF07XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHApO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICB9XG5cbiAgb25PcGVuKCk6IHZvaWQge1xuICAgIHRoaXMubW9kYWxFbC5hZGRDbGFzcyhcIm9wZW5jbGF3LW9uYm9hcmRpbmdcIik7XG4gICAgdGhpcy5yZW5kZXJTdGVwKCk7XG4gIH1cblxuICBvbkNsb3NlKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnBhaXJpbmdQb2xsVGltZXIpIHsgY2xlYXJJbnRlcnZhbCh0aGlzLnBhaXJpbmdQb2xsVGltZXIpOyB0aGlzLnBhaXJpbmdQb2xsVGltZXIgPSBudWxsOyB9XG4gIH1cblxuICAvKiogU2FmZWx5IHJlbmRlciBzaW1wbGUgSFRNTCAodGV4dCwgPGE+LCA8Y29kZT4sIDxzdHJvbmc+KSBpbnRvIGFuIGVsZW1lbnQgdXNpbmcgRE9NIEFQSSAqL1xuICBwcml2YXRlIHNldFJpY2hUZXh0KGVsOiBIVE1MRWxlbWVudCwgaHRtbDogc3RyaW5nKTogdm9pZCB7XG4gICAgZWwuZW1wdHkoKTtcbiAgICBjb25zdCBwYXJzZXIgPSBuZXcgRE9NUGFyc2VyKCk7XG4gICAgY29uc3QgZG9jID0gcGFyc2VyLnBhcnNlRnJvbVN0cmluZyhgPHNwYW4+JHtodG1sfTwvc3Bhbj5gLCBcInRleHQvaHRtbFwiKTtcbiAgICBjb25zdCBzb3VyY2UgPSBkb2MuYm9keS5maXJzdEVsZW1lbnRDaGlsZDtcbiAgICBpZiAoIXNvdXJjZSkgeyBlbC5zZXRUZXh0KGh0bWwpOyByZXR1cm47IH1cbiAgICBmb3IgKGNvbnN0IG5vZGUgb2YgQXJyYXkuZnJvbShzb3VyY2UuY2hpbGROb2RlcykpIHtcbiAgICAgIGlmIChub2RlLm5vZGVUeXBlID09PSBOb2RlLlRFWFRfTk9ERSkge1xuICAgICAgICBlbC5hcHBlbmRUZXh0KG5vZGUudGV4dENvbnRlbnQgPz8gXCJcIik7XG4gICAgICB9IGVsc2UgaWYgKG5vZGUgaW5zdGFuY2VvZiBIVE1MRWxlbWVudCkge1xuICAgICAgICBjb25zdCB0YWcgPSBub2RlLnRhZ05hbWUudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgaWYgKHRhZyA9PT0gXCJhXCIpIHtcbiAgICAgICAgICBlbC5jcmVhdGVFbChcImFcIiwgeyB0ZXh0OiBub2RlLnRleHRDb250ZW50ID8/IFwiXCIsIGhyZWY6IG5vZGUuZ2V0QXR0cmlidXRlKFwiaHJlZlwiKSA/PyBcIlwiIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHRhZyA9PT0gXCJjb2RlXCIpIHtcbiAgICAgICAgICBlbC5jcmVhdGVFbChcImNvZGVcIiwgeyB0ZXh0OiBub2RlLnRleHRDb250ZW50ID8/IFwiXCIgfSk7XG4gICAgICAgIH0gZWxzZSBpZiAodGFnID09PSBcInN0cm9uZ1wiKSB7XG4gICAgICAgICAgZWwuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBub2RlLnRleHRDb250ZW50ID8/IFwiXCIgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgZWwuYXBwZW5kVGV4dChub2RlLnRleHRDb250ZW50ID8/IFwiXCIpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSByZW5kZXJTdGVwKCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGVudEVsIH0gPSB0aGlzO1xuICAgIGNvbnRlbnRFbC5lbXB0eSgpO1xuICAgIHRoaXMuc3RhdHVzRWwgPSBudWxsO1xuXG4gICAgLy8gU3RlcCBpbmRpY2F0b3IgXHUyMDE0IGFkYXB0cyB0byBwYXRoXG4gICAgY29uc3Qgc3RlcExhYmVscyA9IHRoaXMucGF0aCA9PT0gXCJmcmVzaFwiXG4gICAgICA/IFtcIlN0YXJ0XCIsIFwiS2V5c1wiLCBcIkJvdHNcIiwgXCJJbnN0YWxsXCIsIFwiQ29ubmVjdFwiLCBcIlBhaXJcIiwgXCJEb25lXCJdXG4gICAgICA6IHRoaXMucGF0aCA9PT0gXCJleGlzdGluZ1wiXG4gICAgICAgID8gW1wiU3RhcnRcIiwgXCJOZXR3b3JrXCIsIFwiR2F0ZXdheVwiLCBcIkNvbm5lY3RcIiwgXCJQYWlyXCIsIFwiRG9uZVwiXVxuICAgICAgICA6IFtcIlN0YXJ0XCJdO1xuICAgIGNvbnN0IGluZGljYXRvciA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0ZXBzXCIpO1xuICAgIHN0ZXBMYWJlbHMuZm9yRWFjaCgobGFiZWwsIGkpID0+IHtcbiAgICAgIGNvbnN0IGRvdCA9IGluZGljYXRvci5jcmVhdGVTcGFuKFwib3BlbmNsYXctc3RlcC1kb3RcIiArIChpID09PSB0aGlzLnN0ZXAgPyBcIiBhY3RpdmVcIiA6IGkgPCB0aGlzLnN0ZXAgPyBcIiBkb25lXCIgOiBcIlwiKSk7XG4gICAgICBkb3QudGV4dENvbnRlbnQgPSBpIDwgdGhpcy5zdGVwID8gXCJcdTI3MTNcIiA6IFN0cmluZyhpICsgMSk7XG4gICAgICBpZiAoaSA8IHN0ZXBMYWJlbHMubGVuZ3RoIC0gMSkgaW5kaWNhdG9yLmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1zdGVwLWxpbmVcIiArIChpIDwgdGhpcy5zdGVwID8gXCIgZG9uZVwiIDogXCJcIikpO1xuICAgIH0pO1xuXG4gICAgLy8gUm91dGUgdG8gY29ycmVjdCBzdGVwIHJlbmRlcmVyXG4gICAgaWYgKHRoaXMuc3RlcCA9PT0gMCkgcmV0dXJuIHRoaXMucmVuZGVyV2VsY29tZShjb250ZW50RWwpO1xuXG4gICAgaWYgKHRoaXMucGF0aCA9PT0gXCJmcmVzaFwiKSB7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAxKSByZXR1cm4gdGhpcy5yZW5kZXJLZXlzKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAyKSByZXR1cm4gdGhpcy5yZW5kZXJCb3RzKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSAzKSByZXR1cm4gdGhpcy5yZW5kZXJJbnN0YWxsQ21kKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSA0KSByZXR1cm4gdGhpcy5yZW5kZXJDb25uZWN0KGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSA1KSByZXR1cm4gdGhpcy5yZW5kZXJQYWlyaW5nKGNvbnRlbnRFbCk7XG4gICAgICBpZiAodGhpcy5zdGVwID09PSA2KSByZXR1cm4gdGhpcy5yZW5kZXJEb25lKGNvbnRlbnRFbCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICh0aGlzLnN0ZXAgPT09IDEpIHJldHVybiB0aGlzLnJlbmRlck5ldHdvcmsoY29udGVudEVsKTtcbiAgICAgIGlmICh0aGlzLnN0ZXAgPT09IDIpIHJldHVybiB0aGlzLnJlbmRlckdhdGV3YXkoY29udGVudEVsKTtcbiAgICAgIGlmICh0aGlzLnN0ZXAgPT09IDMpIHJldHVybiB0aGlzLnJlbmRlckNvbm5lY3QoY29udGVudEVsKTtcbiAgICAgIGlmICh0aGlzLnN0ZXAgPT09IDQpIHJldHVybiB0aGlzLnJlbmRlclBhaXJpbmcoY29udGVudEVsKTtcbiAgICAgIGlmICh0aGlzLnN0ZXAgPT09IDUpIHJldHVybiB0aGlzLnJlbmRlckRvbmUoY29udGVudEVsKTtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDBcdTI1MDAgU3RlcCAwOiBXZWxjb21lIChicmFuY2hpbmcpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVyV2VsY29tZShlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJXZWxjb21lIHRvIE9wZW5DbGF3XCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiVGhpcyBwbHVnaW4gY29ubmVjdHMgT2JzaWRpYW4gdG8geW91ciBPcGVuQ2xhdyBBSSBhZ2VudC4gWW91ciB2YXVsdCBiZWNvbWVzIHRoZSBhZ2VudCdzIHdvcmtzcGFjZS5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9ucyBvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnMtdmVydGljYWxcIik7XG5cbiAgICBjb25zdCBmcmVzaEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiSSBuZWVkIHRvIGluc3RhbGwgT3BlbkNsYXdcIiwgY2xzOiBcIm1vZC1jdGEgb3BlbmNsYXctZnVsbC13aWR0aFwiIH0pO1xuICAgIGZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMucGF0aCA9IFwiZnJlc2hcIjsgdGhpcy5zdGVwID0gMTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuXG4gICAgY29uc3QgZXhpc3RCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIk9wZW5DbGF3IGlzIGFscmVhZHkgcnVubmluZ1wiLCBjbHM6IFwib3BlbmNsYXctZnVsbC13aWR0aFwiIH0pO1xuICAgIGV4aXN0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMucGF0aCA9IFwiZXhpc3RpbmdcIjsgdGhpcy5zdGVwID0gMTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEZyZXNoIHBhdGg6IFN0ZXAgMSBcdTIwMTQgQVBJIEtleXMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSByZW5kZXJLZXlzKGVsOiBIVE1MRWxlbWVudCk6IHZvaWQge1xuICAgIGVsLmNyZWF0ZUVsKFwiaDJcIiwgeyB0ZXh0OiBcIllvdXIgQVBJIGtleXNcIiB9KTtcbiAgICBlbC5jcmVhdGVFbChcInBcIiwge1xuICAgICAgdGV4dDogXCJZb3VyIGJvdCBuZWVkcyBBSSBtb2RlbCBhY2Nlc3MuIFBhc3RlIHlvdXIga2V5cyBiZWxvdyBcdTIwMTQgdGhleSdsbCBiZSBpbmNsdWRlZCBpbiB0aGUgaW5zdGFsbCBjb21tYW5kLiBOb3RoaW5nIGxlYXZlcyB5b3VyIGRldmljZS5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGZpZWxkczogeyBrZXk6IGtleW9mIHR5cGVvZiB0aGlzLnNldHVwS2V5czsgbGFiZWw6IHN0cmluZzsgcmVxdWlyZWQ/OiBib29sZWFuOyBwbGFjZWhvbGRlcjogc3RyaW5nOyBoZWxwOiBzdHJpbmcgfVtdID0gW1xuICAgICAgeyBrZXk6IFwiY2xhdWRlMVwiLCBsYWJlbDogXCJDbGF1ZGUgdG9rZW5cIiwgcmVxdWlyZWQ6IHRydWUsIHBsYWNlaG9sZGVyOiBcInNrLWFudC0uLi5cIiwgaGVscDogXCJGcm9tIDxhIGhyZWY9J2h0dHBzOi8vY29uc29sZS5hbnRocm9waWMuY29tL3NldHRpbmdzL2tleXMnPmNvbnNvbGUuYW50aHJvcGljLmNvbTwvYT4gb3IgQ2xhdWRlIE1heCBPQXV0aFwiIH0sXG4gICAgICB7IGtleTogXCJjbGF1ZGUyXCIsIGxhYmVsOiBcIkNsYXVkZSB0b2tlbiAjMiAocGFyYWxsZWwgcmVxdWVzdHMpXCIsIHBsYWNlaG9sZGVyOiBcInNrLWFudC0uLi5cIiwgaGVscDogXCJPcHRpb25hbCBcdTIwMTQgZW5hYmxlcyBjb25jdXJyZW50IHJlcXVlc3RzXCIgfSxcbiAgICAgIHsga2V5OiBcImdvb2dsZWFpXCIsIGxhYmVsOiBcIkdvb2dsZSBBSSBBUEkga2V5XCIsIHBsYWNlaG9sZGVyOiBcIkFJemEuLi5cIiwgaGVscDogXCJGcmVlIGF0IDxhIGhyZWY9J2h0dHBzOi8vYWlzdHVkaW8uZ29vZ2xlLmNvbS9hcGlrZXknPmFpc3R1ZGlvLmdvb2dsZS5jb208L2E+IFx1MjAxNCBlbmFibGVzIEdlbWluaSBtb2RlbHNcIiB9LFxuICAgICAgeyBrZXk6IFwiYnJhdmVcIiwgbGFiZWw6IFwiQnJhdmUgU2VhcmNoIEFQSSBrZXlcIiwgcGxhY2Vob2xkZXI6IFwiQlNBLi4uXCIsIGhlbHA6IFwiRnJlZSBhdCA8YSBocmVmPSdodHRwczovL2JyYXZlLmNvbS9zZWFyY2gvYXBpLyc+YnJhdmUuY29tL3NlYXJjaC9hcGk8L2E+IFx1MjAxNCB3ZWIgc2VhcmNoXCIgfSxcbiAgICAgIHsga2V5OiBcImVsZXZlbmxhYnNcIiwgbGFiZWw6IFwiRWxldmVuTGFicyBBUEkga2V5XCIsIHBsYWNlaG9sZGVyOiBcInNrXy4uLlwiLCBoZWxwOiBcIkZyZWUgYXQgPGEgaHJlZj0naHR0cHM6Ly9lbGV2ZW5sYWJzLmlvJz5lbGV2ZW5sYWJzLmlvPC9hPiBcdTIwMTQgdm9pY2UvVFRTXCIgfSxcbiAgICBdO1xuXG4gICAgZm9yIChjb25zdCBmIG9mIGZpZWxkcykge1xuICAgICAgY29uc3QgZ3JvdXAgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWZpZWxkXCIpO1xuICAgICAgY29uc3QgbGFiZWwgPSBncm91cC5jcmVhdGVFbChcImxhYmVsXCIsIHsgdGV4dDogZi5sYWJlbCB9KTtcbiAgICAgIGlmIChmLnJlcXVpcmVkKSB7IGNvbnN0IHJlcSA9IGxhYmVsLmNyZWF0ZVNwYW4oeyBjbHM6IFwib2MtcmVxLWxhYmVsXCIgfSk7IHJlcS50ZXh0Q29udGVudCA9IFwiIChyZXF1aXJlZClcIjsgfVxuICAgICAgY29uc3QgZktleSA9IGYua2V5IGFzIGtleW9mIHR5cGVvZiB0aGlzLnNldHVwS2V5cztcbiAgICAgIGNvbnN0IGlucHV0ID0gZ3JvdXAuY3JlYXRlRWwoXCJpbnB1dFwiLCB7XG4gICAgICAgIHR5cGU6IFwicGFzc3dvcmRcIixcbiAgICAgICAgdmFsdWU6IHRoaXMuc2V0dXBLZXlzW2ZLZXldLFxuICAgICAgICBwbGFjZWhvbGRlcjogZi5wbGFjZWhvbGRlcixcbiAgICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaW5wdXRcIixcbiAgICAgIH0pO1xuICAgICAgaW5wdXQuYWRkRXZlbnRMaXN0ZW5lcihcImlucHV0XCIsICgpID0+IHsgdGhpcy5zZXR1cEtleXNbZktleV0gPSBpbnB1dC52YWx1ZS50cmltKCk7IH0pO1xuICAgICAgY29uc3QgaGVscCA9IGdyb3VwLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiKTtcbiAgICAgIHRoaXMuc2V0UmljaFRleHQoaGVscCwgZi5oZWxwKTtcbiAgICB9XG5cbiAgICBjb25zdCBub3RlID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1pbmZvXCIpO1xuICAgIG5vdGUuc2V0VGV4dChcIlx1RDgzRFx1REQxMiBLZXlzIHN0YXkgb24geW91ciBkZXZpY2UuIFRoZSBpbnN0YWxsIGNvbW1hbmQgcnVucyBlbnRpcmVseSBvbiB5b3VyIHNlcnZlci5cIik7XG5cbiAgICB0aGlzLnN0YXR1c0VsID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1zdGF0dXNcIik7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnNcIik7XG4gICAgYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJcdTIxOTAgYmFja1wiIH0pLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDA7IHRoaXMucGF0aCA9IG51bGw7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgICBjb25zdCBuZXh0QnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJOZXh0IFx1MjE5MlwiLCBjbHM6IFwibW9kLWN0YVwiIH0pO1xuICAgIG5leHRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgIGlmICghdGhpcy5zZXR1cEtleXMuY2xhdWRlMSkgeyB0aGlzLnNob3dTdGF0dXMoXCJDbGF1ZGUgdG9rZW4gaXMgcmVxdWlyZWRcIiwgXCJlcnJvclwiKTsgcmV0dXJuOyB9XG4gICAgICB0aGlzLnN0ZXAgPSAyOyB0aGlzLnJlbmRlclN0ZXAoKTtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBGcmVzaCBwYXRoOiBTdGVwIDIgXHUyMDE0IEJvdCBjb25maWcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSByZW5kZXJCb3RzKGVsOiBIVE1MRWxlbWVudCk6IHZvaWQge1xuICAgIGVsLmNyZWF0ZUVsKFwiaDJcIiwgeyB0ZXh0OiBcIkNvbmZpZ3VyZSB5b3VyIGJvdHNcIiB9KTtcbiAgICBlbC5jcmVhdGVFbChcInBcIiwge1xuICAgICAgdGV4dDogXCJFYWNoIGJvdCBnZXRzIGl0cyBvd24gcGVyc29uYWxpdHksIG1lbW9yeSwgYW5kIHdvcmtzcGFjZSBmb2xkZXIuXCIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBsaXN0RWwgPSBlbC5jcmVhdGVEaXYoKTtcbiAgICB0aGlzLnNldHVwQm90cy5mb3JFYWNoKChib3QsIGkpID0+IHtcbiAgICAgIGNvbnN0IGNhcmQgPSBsaXN0RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1ib3QtY2FyZFwiKTtcbiAgICAgIGNvbnN0IHJvdyA9IGNhcmQuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1ib3Qtcm93XCIpO1xuICAgICAgY29uc3QgbmFtZUlucHV0ID0gcm93LmNyZWF0ZUVsKFwiaW5wdXRcIiwgeyB0eXBlOiBcInRleHRcIiwgdmFsdWU6IGJvdC5uYW1lLCBwbGFjZWhvbGRlcjogXCJCb3QgbmFtZVwiLCBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1pbnB1dCBvYy1uYW1lLWlucHV0XCIgfSk7XG4gICAgICBuYW1lSW5wdXQuYWRkRXZlbnRMaXN0ZW5lcihcImlucHV0XCIsICgpID0+IHsgYm90Lm5hbWUgPSBuYW1lSW5wdXQudmFsdWU7IH0pO1xuXG4gICAgICBjb25zdCBzZWxlY3QgPSByb3cuY3JlYXRlRWwoXCJzZWxlY3RcIiwgeyBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1pbnB1dCBvYy1zZWxlY3QtaW5saW5lXCIgfSk7XG4gICAgICBmb3IgKGNvbnN0IG0gb2YgT25ib2FyZGluZ01vZGFsLk1PREVMUykge1xuICAgICAgICBjb25zdCBvcHQgPSBzZWxlY3QuY3JlYXRlRWwoXCJvcHRpb25cIiwgeyB0ZXh0OiBtLmxhYmVsLCB2YWx1ZTogbS5pZCB9KTtcbiAgICAgICAgaWYgKG0uaWQgPT09IGJvdC5tb2RlbCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgIH1cbiAgICAgIHNlbGVjdC5hZGRFdmVudExpc3RlbmVyKFwiY2hhbmdlXCIsICgpID0+IHsgYm90Lm1vZGVsID0gc2VsZWN0LnZhbHVlOyB9KTtcblxuICAgICAgaWYgKHRoaXMuc2V0dXBCb3RzLmxlbmd0aCA+IDEpIHtcbiAgICAgICAgY29uc3QgcmVtb3ZlQnRuID0gcm93LmNyZWF0ZUVsKFwic3BhblwiLCB7IHRleHQ6IFwiXHUwMEQ3XCIsIGNsczogXCJvYy1yZW1vdmUtYnRuXCIgfSk7XG4gICAgICAgIHJlbW92ZUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnNldHVwQm90cy5zcGxpY2UoaSwgMSk7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGNvbnN0IGFkZEJ0biA9IGVsLmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCIrIGFkZCBhbm90aGVyIGJvdFwiLCBjbHM6IFwib2MtYWRkLWJvdC1idG5cIiB9KTtcbiAgICBhZGRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zZXR1cEJvdHMucHVzaCh7IG5hbWU6ICcnLCBtb2RlbDogJ2FudGhyb3BpYy9jbGF1ZGUtc29ubmV0LTQtNicgfSk7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcblxuICAgIGNvbnN0IG5vdGUgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnQgb2MtbWFyZ2luLXRvcFwiKTtcbiAgICBub3RlLmNyZWF0ZUVsKFwic3BhblwiLCB7IHRleHQ6IFwiRWFjaCBib3QgZ2V0cyBhIGZvbGRlciBsaWtlIFwiIH0pO1xuICAgIG5vdGUuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogXCJBR0VOVC1ZT1VSQk9UL1wiIH0pO1xuICAgIG5vdGUuY3JlYXRlRWwoXCJzcGFuXCIsIHsgdGV4dDogXCIgaW4geW91ciB2YXVsdC5cIiB9KTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkdlbmVyYXRlIGluc3RhbGwgY29tbWFuZCBcdTIxOTJcIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICBuZXh0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDM7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBGcmVzaCBwYXRoOiBTdGVwIDMgXHUyMDE0IEluc3RhbGwgY29tbWFuZCBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlckluc3RhbGxDbWQoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiSW5zdGFsbCBPcGVuQ2xhd1wiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIk9wZW4gYSB0ZXJtaW5hbCBvbiB5b3VyIHNlcnZlciAoTWFjOiBDbWQrU3BhY2UgXHUyMTkyIFRlcm1pbmFsLCBjbG91ZDogc3NoIGluKS4gUnVuIHRoaXMgY29tbWFuZDpcIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGNvbmZpZyA9IHRoaXMuZ2VuZXJhdGVDb25maWcoKTtcbiAgICBjb25zdCBjb25maWdKc29uID0gSlNPTi5zdHJpbmdpZnkoY29uZmlnLCBudWxsLCAyKTtcbiAgICBjb25zdCBjb25maWdCNjQgPSBidG9hKEFycmF5LmZyb20obmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKGNvbmZpZ0pzb24pLCBiID0+IFN0cmluZy5mcm9tQ2hhckNvZGUoYikpLmpvaW4oJycpKTtcbiAgICBjb25zdCBpbnN0YWxsQ21kID0gYGN1cmwgLWZzU0wgaHR0cHM6Ly9vcGVuY2xhdy5haS9pbnN0YWxsLnNoIHwgYmFzaCAmJiBlY2hvICcke2NvbmZpZ0I2NH0nIHwgYmFzZTY0IC1kID4gfi8ub3BlbmNsYXcvb3BlbmNsYXcuanNvbiAmJiBvcGVuY2xhdyBnYXRld2F5IHJlc3RhcnRgO1xuXG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgaW5zdGFsbENtZCk7XG5cbiAgICBlbC5jcmVhdGVFbChcInBcIiwgeyB0ZXh0OiBcIlRoaXMgaW5zdGFsbHMgT3BlbkNsYXcsIHdyaXRlcyB5b3VyIGNvbmZpZyB3aXRoIGFsbCBBUEkga2V5cyBhbmQgYm90IHNldHRpbmdzLCBjb25maWd1cmVzIFRhaWxzY2FsZSBTZXJ2ZSwgYW5kIHN0YXJ0cyB0aGUgZ2F0ZXdheS5cIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuXG4gICAgLy8gRXhwYW5kYWJsZSBjb25maWcgcHJldmlld1xuICAgIGNvbnN0IGRldGFpbHMgPSBlbC5jcmVhdGVFbChcImRldGFpbHNcIiwgeyBjbHM6IFwib2MtbWFyZ2luLXRvcFwiIH0pO1xuICAgIGRldGFpbHMuY3JlYXRlRWwoXCJzdW1tYXJ5XCIsIHsgdGV4dDogXCJQcmV2aWV3IGNvbmZpZ1wiLCBjbHM6IFwib2MtZGV0YWlscy1zdW1tYXJ5XCIgfSk7XG4gICAgY29uc3QgcHJlID0gZGV0YWlscy5jcmVhdGVFbChcInByZVwiLCB7IGNsczogXCJvYy1pbnN0YWxsLXByZVwiIH0pO1xuICAgIHByZS50ZXh0Q29udGVudCA9IEpTT04uc3RyaW5naWZ5KGNvbmZpZywgbnVsbCwgMik7XG5cbiAgICBlbC5jcmVhdGVFbChcInBcIiwgeyB0ZXh0OiBcIkFmdGVyIGl0IGZpbmlzaGVzLCBpbnN0YWxsIFRhaWxzY2FsZSBpZiB5b3UgaGF2ZW4ndDpcIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtZGVzY1wiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goZWwsIFwiIyBNYWM6XFxuYnJldyBpbnN0YWxsIC0tY2FzayB0YWlsc2NhbGVcXG5cXG4jIExpbnV4OlxcbmN1cmwgLWZzU0wgaHR0cHM6Ly90YWlsc2NhbGUuY29tL2luc3RhbGwuc2ggfCBzaCAmJiBzdWRvIHRhaWxzY2FsZSB1cFwiKTtcblxuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVGhlbiBpbnN0YWxsIFRhaWxzY2FsZSBvbiB0aGlzIGRldmljZSB0b28sIHVzaW5nIHRoZSBzYW1lIGFjY291bnQuXCIsIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnRcIiB9KTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMjsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIk9wZW5DbGF3IGlzIHJ1bm5pbmcgXHUyMTkyXCIsIGNsczogXCJtb2QtY3RhXCIgfSk7XG4gICAgbmV4dEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnN0ZXAgPSA0OyB0aGlzLnJlbmRlclN0ZXAoKTsgfSk7XG4gIH1cblxuICBwcml2YXRlIGdlbmVyYXRlQ29uZmlnKCk6IFJlY29yZDxzdHJpbmcsIHVua25vd24+IHtcbiAgICBjb25zdCBhdXRoOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9IHsgcHJvZmlsZXM6IHt9IGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+IH07XG4gICAgY29uc3QgYWdlbnRzOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9IHsgZGVmYXVsdHM6IHsgbW9kZWw6IHsgcHJpbWFyeTogdGhpcy5zZXR1cEJvdHNbMF0/Lm1vZGVsIHx8ICdhbnRocm9waWMvY2xhdWRlLXNvbm5ldC00LTYnIH0gfSB9O1xuICAgIGNvbnN0IGNvbmZpZzogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gPSB7XG4gICAgICBhdXRoLFxuICAgICAgYWdlbnRzLFxuICAgICAgZ2F0ZXdheTogeyBwb3J0OiAxODc4OSwgYmluZDogJ2xvb3BiYWNrJywgdGFpbHNjYWxlOiB7IG1vZGU6ICdzZXJ2ZScgfSwgYXV0aDogeyBtb2RlOiAndG9rZW4nLCBhbGxvd1RhaWxzY2FsZTogdHJ1ZSB9IH0sXG4gICAgfTtcbiAgICBjb25zdCBwcm9maWxlcyA9IGF1dGgucHJvZmlsZXMgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gICAgaWYgKHRoaXMuc2V0dXBLZXlzLmNsYXVkZTEpIHByb2ZpbGVzWydhbnRocm9waWM6ZGVmYXVsdCddID0geyBwcm92aWRlcjogJ2FudGhyb3BpYycsIG1vZGU6ICd0b2tlbicgfTtcbiAgICBpZiAodGhpcy5zZXR1cEtleXMuY2xhdWRlMikgcHJvZmlsZXNbJ2FudGhyb3BpYzpzZWNvbmRhcnknXSA9IHsgcHJvdmlkZXI6ICdhbnRocm9waWMnLCBtb2RlOiAndG9rZW4nIH07XG4gICAgaWYgKHRoaXMuc2V0dXBLZXlzLmdvb2dsZWFpKSBwcm9maWxlc1snZ29vZ2xlOmRlZmF1bHQnXSA9IHsgcHJvdmlkZXI6ICdnb29nbGUnLCBtb2RlOiAnYXBpX2tleScgfTtcbiAgICBpZiAodGhpcy5zZXR1cEtleXMuYnJhdmUpIGNvbmZpZy50b29scyA9IHsgd2ViOiB7IHNlYXJjaDogeyBhcGlLZXk6IHRoaXMuc2V0dXBLZXlzLmJyYXZlIH0gfSB9O1xuICAgIGlmICh0aGlzLnNldHVwS2V5cy5lbGV2ZW5sYWJzKSBjb25maWcubWVzc2FnZXMgPSB7IHR0czogeyBwcm92aWRlcjogJ2VsZXZlbmxhYnMnLCBlbGV2ZW5sYWJzOiB7IGFwaUtleTogdGhpcy5zZXR1cEtleXMuZWxldmVubGFicyB9IH0gfTtcbiAgICBpZiAodGhpcy5zZXR1cEJvdHMubGVuZ3RoID4gMSkge1xuICAgICAgYWdlbnRzLmxpc3QgPSB0aGlzLnNldHVwQm90cy5tYXAoKGJvdCwgaSkgPT4ge1xuICAgICAgICBjb25zdCBpZCA9IGkgPT09IDAgPyAnbWFpbicgOiAoYm90Lm5hbWUudG9Mb3dlckNhc2UoKS5yZXBsYWNlKC9bXmEtejAtOV0vZywgJy0nKSB8fCBgYm90LSR7aX1gKTtcbiAgICAgICAgY29uc3QgZm9sZGVyID0gJ0FHRU5ULScgKyAoYm90Lm5hbWUgfHwgJ0JPVCcpLnRvVXBwZXJDYXNlKCkucmVwbGFjZSgvW15BLVowLTldL2csICctJyk7XG4gICAgICAgIHJldHVybiB7IGlkLCBuYW1lOiBib3QubmFtZSB8fCBgQm90ICR7aSArIDF9YCwgd29ya3NwYWNlOiBgfi8ub3BlbmNsYXcvd29ya3NwYWNlLyR7Zm9sZGVyfWAgfTtcbiAgICAgIH0pO1xuICAgIH0gZWxzZSBpZiAodGhpcy5zZXR1cEJvdHNbMF0/Lm5hbWUpIHtcbiAgICAgIGNvbnN0IGZvbGRlciA9ICdBR0VOVC0nICsgdGhpcy5zZXR1cEJvdHNbMF0ubmFtZS50b1VwcGVyQ2FzZSgpLnJlcGxhY2UoL1teQS1aMC05XS9nLCAnLScpO1xuICAgICAgKGFnZW50cy5kZWZhdWx0cyBhcyBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPikud29ya3NwYWNlID0gYH4vLm9wZW5jbGF3L3dvcmtzcGFjZS8ke2ZvbGRlcn1gO1xuICAgIH1cbiAgICByZXR1cm4gY29uZmlnO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEV4aXN0aW5nIHBhdGg6IFN0ZXAgMSBcdTIwMTQgTmV0d29yayAoVGFpbHNjYWxlKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlck5ldHdvcmsoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiU2V0IHVwIHlvdXIgcHJpdmF0ZSBuZXR3b3JrXCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiVGFpbHNjYWxlIGNyZWF0ZXMgYW4gZW5jcnlwdGVkIHByaXZhdGUgbmV0d29yayBiZXR3ZWVuIHlvdXIgZGV2aWNlcy4gTm8gcG9ydHMgdG8gb3Blbiwgbm8gVlBOIHRvIGNvbmZpZ3VyZS5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGVsLmNyZWF0ZUVsKFwiaDNcIiwgeyB0ZXh0OiBcIkluc3RhbGwgVGFpbHNjYWxlIG9uIGJvdGggZGV2aWNlc1wiIH0pO1xuXG4gICAgY29uc3Qgc3RlcHMgPSBlbC5jcmVhdGVFbChcIm9sXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtbGlzdFwiIH0pO1xuICAgIGNvbnN0IHMxID0gc3RlcHMuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBzMS5hcHBlbmRUZXh0KFwiSW5zdGFsbCBvbiB5b3VyIFwiKTtcbiAgICBzMS5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiZ2F0ZXdheSBtYWNoaW5lXCIgfSk7XG4gICAgczEuYXBwZW5kVGV4dChcIjogXCIpO1xuICAgIHMxLmNyZWF0ZUVsKFwiYVwiLCB7IHRleHQ6IFwidGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiLCBocmVmOiBcImh0dHBzOi8vdGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiIH0pO1xuICAgIGNvbnN0IHMyID0gc3RlcHMuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBzMi5hcHBlbmRUZXh0KFwiSW5zdGFsbCBvbiBcIik7XG4gICAgczIuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcInRoaXMgZGV2aWNlXCIgfSk7XG4gICAgczIuYXBwZW5kVGV4dChcIjogXCIpO1xuICAgIHMyLmNyZWF0ZUVsKFwiYVwiLCB7IHRleHQ6IFwidGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiLCBocmVmOiBcImh0dHBzOi8vdGFpbHNjYWxlLmNvbS9kb3dubG9hZFwiIH0pO1xuICAgIHN0ZXBzLmNyZWF0ZUVsKFwibGlcIiwgeyB0ZXh0OiBcIlNpZ24gaW4gdG8gdGhlIHNhbWUgVGFpbHNjYWxlIGFjY291bnQgb24gYm90aC5cIiB9KTtcblxuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVmVyaWZ5IGJ5IHJ1bm5pbmcgdGhpcyBvbiB0aGUgZ2F0ZXdheTpcIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goZWwsIFwidGFpbHNjYWxlIHN0YXR1c1wiKTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMDsgdGhpcy5wYXRoID0gbnVsbDsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkJvdGggb24gVGFpbHNjYWxlIFx1MjE5MlwiLCBjbHM6IFwibW9kLWN0YVwiIH0pO1xuICAgIG5leHRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMjsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEV4aXN0aW5nIHBhdGg6IFN0ZXAgMiBcdTIwMTQgR2F0ZXdheSAoVGFpbHNjYWxlIFNlcnZlKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlckdhdGV3YXkoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiRXhwb3NlIHlvdXIgZ2F0ZXdheVwiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIlRhaWxzY2FsZSBTZXJ2ZSBnaXZlcyB5b3VyIGdhdGV3YXkgYSBwcml2YXRlIEhUVFBTIGFkZHJlc3MuIFJ1biBvbiB0aGUgZ2F0ZXdheSBtYWNoaW5lOlwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtZGVzY1wiLFxuICAgIH0pO1xuXG4gICAgZWwuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIjEuIENvbmZpZ3VyZSBPcGVuQ2xhd1wiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goZWwsIFwib3BlbmNsYXcgY29uZmlnIHNldCBnYXRld2F5LmJpbmQgbG9vcGJhY2tcXG5vcGVuY2xhdyBjb25maWcgc2V0IGdhdGV3YXkudGFpbHNjYWxlLm1vZGUgc2VydmVcXG5vcGVuY2xhdyBnYXRld2F5IHJlc3RhcnRcIik7XG5cbiAgICBlbC5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiMi4gU3RhcnQgVGFpbHNjYWxlIHNlcnZlXCIgfSk7XG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgXCJ0YWlsc2NhbGUgc2VydmUgLS1iZyBodHRwOi8vMTI3LjAuMC4xOjE4Nzg5XCIpO1xuXG4gICAgZWwuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIjMuIEdldCB5b3VyIFVSTCBhbmQgdG9rZW5cIiB9KTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KGVsLCBcInRhaWxzY2FsZSBzZXJ2ZSBzdGF0dXNcIik7XG4gICAgdGhpcy5tYWtlQ29weUJveChlbCwgXCJjYXQgfi8ub3BlbmNsYXcvb3BlbmNsYXcuanNvbiB8IGdyZXAgdG9rZW5cIik7XG5cbiAgICBjb25zdCBoaW50ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIpO1xuICAgIGhpbnQuYXBwZW5kVGV4dChcIkNvcHkgdGhlIFwiKTtcbiAgICBoaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiaHR0cHM6Ly95b3VyLW1hY2hpbmUudGFpbFhYWFgudHMubmV0XCIgfSk7XG4gICAgaGludC5hcHBlbmRUZXh0KFwiIFVSTCBhbmQgdGhlIGF1dGggdG9rZW4gZm9yIHRoZSBuZXh0IHN0ZXAuXCIpO1xuXG4gICAgY29uc3QgdHJvdWJsZSA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaW5mb1wiKTtcbiAgICB0cm91YmxlLmFwcGVuZFRleHQoXCJcdUQ4M0RcdURDQTEgXCIpO1xuICAgIHRyb3VibGUuY3JlYXRlRWwoXCJzdHJvbmdcIiwgeyB0ZXh0OiBcIk5vdCB3b3JraW5nP1wiIH0pO1xuICAgIHRyb3VibGUuYXBwZW5kVGV4dChcIiBSdW46IFwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGUsIFwib3BlbmNsYXcgZG9jdG9yIC0tZml4ICYmIG9wZW5jbGF3IGdhdGV3YXkgcmVzdGFydFwiKTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIGNvbnN0IGJ0blJvdyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtYnV0dG9uc1wiKTtcbiAgICBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlx1MjE5MCBiYWNrXCIgfSkuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gMTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICAgIGNvbnN0IG5leHRCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIkkgaGF2ZSB0aGUgVVJMIGFuZCB0b2tlbiBcdTIxOTJcIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICBuZXh0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDM7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTdGVwIDM6IENvbm5lY3QgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSByZW5kZXJDb25uZWN0KGVsOiBIVE1MRWxlbWVudCk6IHZvaWQge1xuICAgIGVsLmNyZWF0ZUVsKFwiaDJcIiwgeyB0ZXh0OiBcIkNvbm5lY3QgdG8geW91ciBnYXRld2F5XCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiUGFzdGUgdGhlIFVSTCBhbmQgdG9rZW4gZnJvbSB0aGUgcHJldmlvdXMgc3RlcC5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIC8vIFVSTCBpbnB1dFxuICAgIGNvbnN0IHVybEdyb3VwID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1maWVsZFwiKTtcbiAgICB1cmxHcm91cC5jcmVhdGVFbChcImxhYmVsXCIsIHsgdGV4dDogXCJHYXRld2F5IFVSTFwiIH0pO1xuICAgIGNvbnN0IHVybElucHV0ID0gdXJsR3JvdXAuY3JlYXRlRWwoXCJpbnB1dFwiLCB7XG4gICAgICB0eXBlOiBcInRleHRcIixcbiAgICAgIHZhbHVlOiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsIHx8IFwiXCIsXG4gICAgICBwbGFjZWhvbGRlcjogXCJodHRwczovL3lvdXItbWFjaGluZS50YWlsMTIzNC50cy5uZXRcIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWlucHV0XCIsXG4gICAgfSk7XG4gICAgY29uc3QgdXJsSGludCA9IHVybEdyb3VwLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiKTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCJUaGUgVVJMIGZyb20gXCIpO1xuICAgIHVybEhpbnQuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogXCJ0YWlsc2NhbGUgc2VydmUgc3RhdHVzXCIgfSk7XG4gICAgdXJsSGludC5hcHBlbmRUZXh0KFwiLiBZb3UgY2FuIHBhc3RlIFwiKTtcbiAgICB1cmxIaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiaHR0cHM6Ly9cIiB9KTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCIgb3IgXCIpO1xuICAgIHVybEhpbnQuY3JlYXRlRWwoXCJjb2RlXCIsIHsgdGV4dDogXCJ3c3M6Ly9cIiB9KTtcbiAgICB1cmxIaW50LmFwcGVuZFRleHQoXCIgXHUyMDE0IGJvdGggd29yay5cIik7XG5cbiAgICAvLyBUb2tlbiBpbnB1dFxuICAgIGNvbnN0IHRva2VuR3JvdXAgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWZpZWxkXCIpO1xuICAgIHRva2VuR3JvdXAuY3JlYXRlRWwoXCJsYWJlbFwiLCB7IHRleHQ6IFwiQXV0aCB0b2tlblwiIH0pO1xuICAgIGNvbnN0IHRva2VuSW5wdXQgPSB0b2tlbkdyb3VwLmNyZWF0ZUVsKFwiaW5wdXRcIiwge1xuICAgICAgdHlwZTogXCJwYXNzd29yZFwiLFxuICAgICAgdmFsdWU6IHRoaXMucGx1Z2luLnNldHRpbmdzLnRva2VuIHx8IFwiXCIsXG4gICAgICBwbGFjZWhvbGRlcjogXCJQYXN0ZSB5b3VyIGdhdGV3YXkgYXV0aCB0b2tlblwiLFxuICAgICAgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaW5wdXRcIixcbiAgICB9KTtcblxuICAgIHRoaXMuc3RhdHVzRWwgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXN0YXR1c1wiKTtcblxuICAgIC8vIFRyb3VibGVzaG9vdGluZyAoaGlkZGVuIHVudGlsIGZhaWx1cmUpXG4gICAgY29uc3QgdHJvdWJsZXNob290ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC10cm91Ymxlc2hvb3RcIik7XG4gICAgdHJvdWJsZXNob290LmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIHRyb3VibGVzaG9vdC5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogXCJUcm91Ymxlc2hvb3RpbmdcIiB9KTtcblxuICAgIGNvbnN0IGNoZWNrcyA9IHRyb3VibGVzaG9vdC5jcmVhdGVFbChcIm9sXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtbGlzdFwiIH0pO1xuXG4gICAgY29uc3QgbGkxID0gY2hlY2tzLmNyZWF0ZUVsKFwibGlcIik7XG4gICAgbGkxLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJJcyBUYWlsc2NhbGUgY29ubmVjdGVkIG9uIHRoaXMgZGV2aWNlP1wiIH0pO1xuICAgIGxpMS5hcHBlbmRUZXh0KFwiIENoZWNrIHRoZSBUYWlsc2NhbGUgaWNvbiBpbiB5b3VyIHN5c3RlbSB0cmF5IC8gbWVudSBiYXIuIElmIGl0J3Mgb2ZmLCB0dXJuIGl0IG9uLlwiKTtcblxuICAgIGNvbnN0IGxpMiA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiRE5TIG5vdCByZXNvbHZpbmc/IChtb3N0IGNvbW1vbiBvbiBtYWNPUylcIiB9KTtcbiAgICBsaTIuYXBwZW5kVGV4dChcIiBPcGVuIHRoZSBcIik7XG4gICAgbGkyLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJUYWlsc2NhbGUgYXBwXCIgfSk7XG4gICAgbGkyLmFwcGVuZFRleHQoXCIgZnJvbSB5b3VyIG1lbnUgYmFyLCB0b2dnbGUgaXQgXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiT0ZGXCIgfSk7XG4gICAgbGkyLmFwcGVuZFRleHQoXCIsIHdhaXQgNSBzZWNvbmRzLCB0b2dnbGUgaXQgXCIpO1xuICAgIGxpMi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiT05cIiB9KTtcbiAgICBsaTIuYXBwZW5kVGV4dChcIi4gVGhpcyByZXNldHMgTWFnaWNETlMsIHdoaWNoIG1hY09TIHNvbWV0aW1lcyBsb3NlcyB0cmFjayBvZi5cIik7XG5cbiAgICBjb25zdCBsaTMgPSBjaGVja3MuY3JlYXRlRWwoXCJsaVwiKTtcbiAgICBsaTMuc2V0VGV4dChcIklzIHRoZSBnYXRld2F5IHJ1bm5pbmc/IE9uIHRoZSBnYXRld2F5IG1hY2hpbmUsIHJ1bjpcIik7XG4gICAgdGhpcy5tYWtlQ29weUJveCh0cm91Ymxlc2hvb3QsIFwib3BlbmNsYXcgZG9jdG9yIC0tZml4ICYmIG9wZW5jbGF3IGdhdGV3YXkgcmVzdGFydFwiKTtcblxuICAgIGNvbnN0IGxpNCA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpNC5zZXRUZXh0KFwiSXMgVGFpbHNjYWxlIFNlcnZlIGFjdGl2ZT8gT24gdGhlIGdhdGV3YXkgbWFjaGluZSwgcnVuOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJ0YWlsc2NhbGUgc2VydmUgc3RhdHVzXCIpO1xuICAgIGNvbnN0IHRzSGludCA9IHRyb3VibGVzaG9vdC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnRcIik7XG4gICAgdHNIaW50LnNldFRleHQoXCJJZiBUYWlsc2NhbGUgU2VydmUgc2hvd3Mgbm90aGluZywgc2V0IGl0IHVwOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJ0YWlsc2NhbGUgc2VydmUgLS1iZyBodHRwOi8vMTI3LjAuMC4xOjE4Nzg5XCIpO1xuXG4gICAgY29uc3QgbGk1ID0gY2hlY2tzLmNyZWF0ZUVsKFwibGlcIik7XG4gICAgbGk1LmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJHYXRld2F5IGNvbmZpZyBicm9rZW4/XCIgfSk7XG4gICAgbGk1LmFwcGVuZFRleHQoXCIgSWYgXCIpO1xuICAgIGxpNS5jcmVhdGVFbChcImNvZGVcIiwgeyB0ZXh0OiBcIm9wZW5jbGF3IGRvY3RvclwiIH0pO1xuICAgIGxpNS5hcHBlbmRUZXh0KCcgc2hvd3MgXCJJbnZhbGlkIGNvbmZpZ1wiIGVycm9ycywgeW91ciBnYXRld2F5IGNvbmZpZyBmaWxlIG1heSBoYXZlIGJlZW4gY29ycnVwdGVkLiBUbyByZXNldCB0byB0aGUgcmVjb21tZW5kZWQgc2V0dXAsIHJ1biB0aGVzZSBvbiB0aGUgZ2F0ZXdheSBtYWNoaW5lOicpO1xuICAgIHRoaXMubWFrZUNvcHlCb3godHJvdWJsZXNob290LCBgY2F0IH4vLm9wZW5jbGF3L29wZW5jbGF3Lmpzb24gfCBweXRob24zIC1jIFwiXG5pbXBvcnQganNvbiwgc3lzXG5jID0ganNvbi5sb2FkKHN5cy5zdGRpbilcbmMuc2V0ZGVmYXVsdCgnZ2F0ZXdheScsIHt9KVsnYmluZCddID0gJ2xvb3BiYWNrJ1xuY1snZ2F0ZXdheSddLnNldGRlZmF1bHQoJ3RhaWxzY2FsZScsIHt9KVsnbW9kZSddID0gJ3NlcnZlJ1xuY1snZ2F0ZXdheSddWyd0YWlsc2NhbGUnXVsncmVzZXRPbkV4aXQnXSA9IEZhbHNlXG5qc29uLmR1bXAoYywgb3BlbihzeXMuYXJndlsxXSwgJ3cnKSwgaW5kZW50PTIpXG5wcmludCgnQ29uZmlnIGZpeGVkOiBiaW5kPWxvb3BiYWNrLCB0YWlsc2NhbGUubW9kZT1zZXJ2ZScpXG5cIiB+Ly5vcGVuY2xhdy9vcGVuY2xhdy5qc29uYCk7XG4gICAgY29uc3QgbGk1aGludCA9IHRyb3VibGVzaG9vdC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWhpbnRcIik7XG4gICAgbGk1aGludC5zZXRUZXh0KFwiVGhlbiByZXN0YXJ0IHRoZSBnYXRld2F5IGFuZCByZS1lbmFibGUgVGFpbHNjYWxlIFNlcnZlOlwiKTtcbiAgICB0aGlzLm1ha2VDb3B5Qm94KHRyb3VibGVzaG9vdCwgXCJvcGVuY2xhdyBnYXRld2F5IHJlc3RhcnQgJiYgdGFpbHNjYWxlIHNlcnZlIC0tYmcgaHR0cDovLzEyNy4wLjAuMToxODc4OVwiKTtcblxuICAgIGNvbnN0IGxpNiA9IGNoZWNrcy5jcmVhdGVFbChcImxpXCIpO1xuICAgIGxpNi5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiU3RpbGwgc3R1Y2s/XCIgfSk7XG4gICAgbGk2LmFwcGVuZFRleHQoXCIgVHJ5IHJlc3RhcnRpbmcgdGhlIFRhaWxzY2FsZSBhcHAgZW50aXJlbHksIG9yIHJlYm9vdCB0aGlzIGRldmljZS4gbWFjT1MgRE5TIGNhbiBnZXQgc3R1Y2sgYW5kIG5lZWRzIGEgZnJlc2ggc3RhcnQuXCIpO1xuXG4gICAgY29uc3QgYnRuUm93ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1idXR0b25zXCIpO1xuICAgIGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiXHUyMTkwIGJhY2tcIiB9KS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyB0aGlzLnN0ZXAgPSAyOyB0aGlzLnJlbmRlclN0ZXAoKTsgfSk7XG5cbiAgICBjb25zdCB0ZXN0QnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJUZXN0IGNvbm5lY3Rpb25cIiwgY2xzOiBcIm1vZC1jdGFcIiB9KTtcbiAgICB0ZXN0QnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICBjb25zdCB1cmwgPSB1cmxJbnB1dC52YWx1ZS50cmltKCk7XG4gICAgICBjb25zdCB0b2tlbiA9IHRva2VuSW5wdXQudmFsdWUudHJpbSgpO1xuXG4gICAgICBpZiAoIXVybCkgeyB0aGlzLnNob3dTdGF0dXMoXCJQYXN0ZSB5b3VyIGdhdGV3YXkgVVJMIGZyb20gdGhlIHByZXZpb3VzIHN0ZXBcIiwgXCJlcnJvclwiKTsgcmV0dXJuOyB9XG4gICAgICBjb25zdCBub3JtYWxpemVkVXJsID0gbm9ybWFsaXplR2F0ZXdheVVybCh1cmwpO1xuICAgICAgaWYgKCFub3JtYWxpemVkVXJsKSB7XG4gICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIlRoYXQgZG9lc24ndCBsb29rIHJpZ2h0LiBQYXN0ZSB0aGUgVVJMIGZyb20gYHRhaWxzY2FsZSBzZXJ2ZSBzdGF0dXNgIChlLmcuIGh0dHBzOi8veW91ci1tYWNoaW5lLnRhaWwxMjM0LnRzLm5ldClcIiwgXCJlcnJvclwiKTsgcmV0dXJuO1xuICAgICAgfVxuICAgICAgaWYgKCF0b2tlbikgeyB0aGlzLnNob3dTdGF0dXMoXCJQYXN0ZSB5b3VyIGF1dGggdG9rZW5cIiwgXCJlcnJvclwiKTsgcmV0dXJuOyB9XG5cbiAgICAgIHRlc3RCdG4uZGlzYWJsZWQgPSB0cnVlO1xuICAgICAgdGVzdEJ0bi50ZXh0Q29udGVudCA9IFwiQ29ubmVjdGluZy4uLlwiO1xuICAgICAgdHJvdWJsZXNob290LmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgdGhpcy5zaG93U3RhdHVzKFwiVGVzdGluZyBjb25uZWN0aW9uLi4uXCIsIFwiaW5mb1wiKTtcblxuICAgICAgLy8gQWx3YXlzIHJlc2V0IHRvIFwibWFpblwiIHNlc3Npb24gdG8gZW5zdXJlIGNsZWFuIGNvbm5lY3Rpb25cbiAgICAgIHVybElucHV0LnZhbHVlID0gbm9ybWFsaXplZFVybDtcbiAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSBub3JtYWxpemVkVXJsO1xuICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MudG9rZW4gPSB0b2tlbjtcbiAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBcIm1haW5cIjtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuXG4gICAgICBjb25zdCBvayA9IGF3YWl0IG5ldyBQcm9taXNlPGJvb2xlYW4+KChyZXNvbHZlKSA9PiB7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHsgdGMuc3RvcCgpOyByZXNvbHZlKGZhbHNlKTsgfSwgODAwMCk7XG4gICAgICAgIGNvbnN0IHRjID0gbmV3IEdhdGV3YXlDbGllbnQoe1xuICAgICAgICAgIHVybDogbm9ybWFsaXplZFVybCwgdG9rZW4sXG4gICAgICAgICAgb25IZWxsbzogKCkgPT4geyBjbGVhclRpbWVvdXQodGltZW91dCk7IHRjLnN0b3AoKTsgcmVzb2x2ZSh0cnVlKTsgfSxcbiAgICAgICAgICBvbkNsb3NlOiAoKSA9PiB7fSxcbiAgICAgICAgfSk7XG4gICAgICAgIHRjLnN0YXJ0KCk7XG4gICAgICB9KTtcblxuICAgICAgdGVzdEJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgdGVzdEJ0bi50ZXh0Q29udGVudCA9IFwiVGVzdCBjb25uZWN0aW9uXCI7XG5cbiAgICAgIGlmIChvaykge1xuICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJcdTI3MTMgQ29ubmVjdGVkIVwiLCBcInN1Y2Nlc3NcIik7XG4gICAgICAgIHNldFRpbWVvdXQoKCkgPT4geyB0aGlzLnN0ZXAgPSA0OyB0aGlzLnJlbmRlclN0ZXAoKTsgfSwgODAwKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIkNvdWxkIG5vdCBjb25uZWN0LiBDaGVjayB0aGUgdHJvdWJsZXNob290aW5nIHN0ZXBzIGJlbG93LlwiLCBcImVycm9yXCIpO1xuICAgICAgICB0cm91Ymxlc2hvb3QucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB9XG4gICAgfSkoKSk7XG4gIH1cblxuICBwcml2YXRlIG1ha2VDb3B5Qm94KHBhcmVudDogSFRNTEVsZW1lbnQsIGNvbW1hbmQ6IHN0cmluZyk6IEhUTUxFbGVtZW50IHtcbiAgICBjb25zdCBib3ggPSBwYXJlbnQuY3JlYXRlRGl2KFwib3BlbmNsYXctY29weS1ib3hcIik7XG4gICAgYm94LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IGNvbW1hbmQgfSk7XG4gICAgY29uc3QgYnRuID0gYm94LmNyZWF0ZVNwYW4oXCJvcGVuY2xhdy1jb3B5LWJ0blwiKTtcbiAgICBidG4udGV4dENvbnRlbnQgPSBcIkNvcHlcIjtcbiAgICBib3guYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgIHZvaWQgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoY29tbWFuZCkudGhlbigoKSA9PiB7XG4gICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNzEzXCI7XG4gICAgICAgIHNldFRpbWVvdXQoKCkgPT4gYnRuLnRleHRDb250ZW50ID0gXCJDb3B5XCIsIDE1MDApO1xuICAgICAgfSk7XG4gICAgfSk7XG4gICAgcmV0dXJuIGJveDtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTdGVwIDQ6IERldmljZSBQYWlyaW5nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgcmVuZGVyUGFpcmluZyhlbDogSFRNTEVsZW1lbnQpOiB2b2lkIHtcbiAgICBlbC5jcmVhdGVFbChcImgyXCIsIHsgdGV4dDogXCJQYWlyIHRoaXMgZGV2aWNlXCIgfSk7XG4gICAgZWwuY3JlYXRlRWwoXCJwXCIsIHtcbiAgICAgIHRleHQ6IFwiRm9yIHNlY3VyaXR5LCBlYWNoIGRldmljZSBuZWVkcyBvbmUtdGltZSBhcHByb3ZhbCBmcm9tIHRoZSBnYXRld2F5LiBUaGlzIGNyZWF0ZXMgYSB1bmlxdWUga2V5cGFpciBmb3IgdGhpcyBkZXZpY2Ugc28gdGhlIGdhdGV3YXkga25vd3MgaXQncyB5b3UuXCIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1kZXNjXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBoYXNLZXlzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuZGV2aWNlSWQgJiYgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZGV2aWNlUHVibGljS2V5O1xuXG4gICAgaWYgKGhhc0tleXMpIHtcbiAgICAgIGNvbnN0IGluZm8gPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWluZm9cIik7XG4gICAgICBpbmZvLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiVGhpcyBkZXZpY2UgYWxyZWFkeSBoYXMgYSBrZXlwYWlyLlwiIH0pO1xuICAgICAgY29uc3QgZGV2aWNlUCA9IGluZm8uY3JlYXRlRWwoXCJwXCIpO1xuICAgICAgZGV2aWNlUC5hcHBlbmRUZXh0KFwiRGV2aWNlIElEOiBcIik7XG4gICAgICBkZXZpY2VQLmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6ICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5kZXZpY2VJZD8uc2xpY2UoMCwgMTIpID8/IFwiXCIpICsgXCIuLi5cIiB9KTtcbiAgICB9XG5cbiAgICB0aGlzLnN0YXR1c0VsID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1zdGF0dXNcIik7XG5cbiAgICAvLyBBcHByb3ZhbCBpbnN0cnVjdGlvbnMgKGFsd2F5cyB2aXNpYmxlKVxuICAgIGNvbnN0IGFwcHJvdmFsSW5mbyA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtbnVtYmVyZWRcIik7XG4gICAgY29uc3QgYTEgPSBhcHByb3ZhbEluZm8uY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1udW1iZXJlZC1pdGVtXCIpO1xuICAgIGExLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJIb3cgYXBwcm92YWwgd29ya3NcIiB9KTtcbiAgICBhMS5jcmVhdGVFbChcInBcIiwgeyB0ZXh0OiBcIkNsaWNrIHRoZSBidXR0b24gYmVsb3cgdG8gc2VuZCBhIHBhaXJpbmcgcmVxdWVzdC4gVGhlbiwgb24geW91ciBnYXRld2F5IG1hY2hpbmUsIHJ1bjpcIiwgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIHRoaXMubWFrZUNvcHlCb3goYTEsIFwib3BlbmNsYXcgZGV2aWNlcyBsaXN0XCIpO1xuICAgIGExLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IFwiWW91J2xsIHNlZSB5b3VyIHBlbmRpbmcgcmVxdWVzdC4gQXBwcm92ZSBpdCB3aXRoOlwiLCBjbHM6IFwib3BlbmNsYXctb25ib2FyZC1oaW50XCIgfSk7XG4gICAgdGhpcy5tYWtlQ29weUJveChhMSwgXCJvcGVuY2xhdyBkZXZpY2VzIGFwcHJvdmUgPHJlcXVlc3RJZD5cIik7XG4gICAgY29uc3QgYTFoaW50ID0gYTEuY3JlYXRlRWwoXCJwXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtaGludFwiIH0pO1xuICAgIGExaGludC5hcHBlbmRUZXh0KFwiUmVwbGFjZSBcIik7XG4gICAgYTFoaW50LmNyZWF0ZUVsKFwiY29kZVwiLCB7IHRleHQ6IFwiPHJlcXVlc3RJZD5cIiB9KTtcbiAgICBhMWhpbnQuYXBwZW5kVGV4dChcIiB3aXRoIHRoZSBJRCBzaG93biBpbiB0aGUgcGVuZGluZyBsaXN0LiBZb3UgY2FuIGFsc28gYXBwcm92ZSBmcm9tIHRoZSBPcGVuQ2xhdyBDb250cm9sIFVJIGRhc2hib2FyZC5cIik7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWJ1dHRvbnNcIik7XG4gICAgYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogXCJcdTIxOTAgYmFja1wiIH0pLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7IHRoaXMuc3RlcCA9IDM7IHRoaXMucmVuZGVyU3RlcCgpOyB9KTtcblxuICAgIGNvbnN0IHBhaXJCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwge1xuICAgICAgdGV4dDogaGFzS2V5cyA/IFwiQ2hlY2sgcGFpcmluZyBzdGF0dXNcIiA6IFwiU2VuZCBwYWlyaW5nIHJlcXVlc3RcIixcbiAgICAgIGNsczogXCJtb2QtY3RhXCIsXG4gICAgfSk7XG4gICAgcGFpckJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgcGFpckJ0bi5kaXNhYmxlZCA9IHRydWU7XG4gICAgICB0aGlzLnNob3dTdGF0dXMoXCJDb25uZWN0aW5nIHRvIGdhdGV3YXkuLi5cIiwgXCJpbmZvXCIpO1xuXG4gICAgICB0cnkge1xuICAgICAgICAvLyBFbnN1cmUgd2UgaGF2ZSBhIHJlYWwgY29ubmVjdGlvbiB0byB0ZXN0IHBhaXJpbmdcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uY29ubmVjdEdhdGV3YXkoKTtcblxuICAgICAgICAvLyBXYWl0IGEgbW9tZW50IGZvciBjb25uZWN0aW9uIHRvIGVzdGFibGlzaFxuICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgMjAwMCkpO1xuXG4gICAgICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheUNvbm5lY3RlZCkge1xuICAgICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIkNvdWxkIG5vdCBjb25uZWN0IHRvIGdhdGV3YXkuIEdvIGJhY2sgYW5kIGNoZWNrIHlvdXIgc2V0dGluZ3MuXCIsIFwiZXJyb3JcIik7XG4gICAgICAgICAgcGFpckJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFRyeSBhIHNpbXBsZSByZXF1ZXN0IHRvIHZlcmlmeSBwYWlyaW5nXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5wbHVnaW4uZ2F0ZXdheSEucmVxdWVzdChcInNlc3Npb25zLmxpc3RcIiwge30pIGFzIHsgc2Vzc2lvbnM/OiB1bmtub3duW10gfSB8IG51bGw7XG4gICAgICAgICAgaWYgKHJlc3VsdD8uc2Vzc2lvbnMpIHtcbiAgICAgICAgICAgIHRoaXMuc2hvd1N0YXR1cyhcIlx1MjcxMyBEZXZpY2UgaXMgcGFpcmVkIGFuZCBhdXRob3JpemVkIVwiLCBcInN1Y2Nlc3NcIik7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHsgdGhpcy5zdGVwID0gNTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0sIDEwMDApO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgfSBjYXRjaCAoZTogdW5rbm93bikge1xuICAgICAgICAgIC8vIElmIHdlIGdldCBhbiBhdXRoIGVycm9yLCBkZXZpY2UgbmVlZHMgYXBwcm92YWxcbiAgICAgICAgICBjb25zdCBtc2cgPSBTdHJpbmcoZSk7XG4gICAgICAgICAgaWYgKG1zZy5pbmNsdWRlcyhcInNjb3BlXCIpIHx8IG1zZy5pbmNsdWRlcyhcImF1dGhcIikgfHwgbXNnLmluY2x1ZGVzKFwicGFpclwiKSkge1xuICAgICAgICAgICAgdGhpcy5zaG93U3RhdHVzKFwiXHUyM0YzIFBhaXJpbmcgcmVxdWVzdCBzZW50ISBOb3cgYXBwcm92ZSBpdCBvbiB5b3VyIGdhdGV3YXkgbWFjaGluZSB1c2luZyB0aGUgY29tbWFuZHMgYWJvdmUuXFxuXFxuV2FpdGluZyBmb3IgYXBwcm92YWwuLi5cIiwgXCJpbmZvXCIpO1xuICAgICAgICAgICAgdGhpcy5zdGFydFBhaXJpbmdQb2xsKHBhaXJCdG4pO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIElmIHdlIGdvdCBoZXJlLCBjb25uZWN0aW9uIHdvcmtzIFx1MjAxNCBtaWdodCBhbHJlYWR5IGJlIHBhaXJlZFxuICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJcdTI3MTMgQ29ubmVjdGlvbiB3b3JraW5nISBQcm9jZWVkaW5nLi4uXCIsIFwic3VjY2Vzc1wiKTtcbiAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7IHRoaXMuc3RlcCA9IDU7IHRoaXMucmVuZGVyU3RlcCgpOyB9LCAxMDAwKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgdGhpcy5zaG93U3RhdHVzKGBFcnJvcjogJHtlfWAsIFwiZXJyb3JcIik7XG4gICAgICAgIHBhaXJCdG4uZGlzYWJsZWQgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9KSgpKTtcblxuICAgIGNvbnN0IHNraXBCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlNraXAgZm9yIG5vd1wiIH0pO1xuICAgIHNraXBCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHsgdGhpcy5zdGVwID0gNTsgdGhpcy5yZW5kZXJTdGVwKCk7IH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBzdGFydFBhaXJpbmdQb2xsKGJ0bjogSFRNTEJ1dHRvbkVsZW1lbnQpOiB2b2lkIHtcbiAgICBsZXQgYXR0ZW1wdHMgPSAwO1xuICAgIHRoaXMucGFpcmluZ1BvbGxUaW1lciA9IHNldEludGVydmFsKCgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgIGF0dGVtcHRzKys7XG4gICAgICBpZiAoYXR0ZW1wdHMgPiA2MCkgeyAvLyAyIG1pbnV0ZXNcbiAgICAgICAgaWYgKHRoaXMucGFpcmluZ1BvbGxUaW1lcikgY2xlYXJJbnRlcnZhbCh0aGlzLnBhaXJpbmdQb2xsVGltZXIpO1xuICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJUaW1lZCBvdXQgd2FpdGluZyBmb3IgYXBwcm92YWwuIFlvdSBjYW4gYXBwcm92ZSBsYXRlciBhbmQgcmUtcnVuIHRoZSBzZXR1cCB3aXphcmQgZnJvbSBzZXR0aW5ncy5cIiwgXCJlcnJvclwiKTtcbiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXk/LnJlcXVlc3QoXCJzZXNzaW9ucy5saXN0XCIsIHt9KSBhcyB7IHNlc3Npb25zPzogdW5rbm93bltdIH0gfCBudWxsO1xuICAgICAgICBpZiAocmVzdWx0Py5zZXNzaW9ucykge1xuICAgICAgICAgIGlmICh0aGlzLnBhaXJpbmdQb2xsVGltZXIpIGNsZWFySW50ZXJ2YWwodGhpcy5wYWlyaW5nUG9sbFRpbWVyKTtcbiAgICAgICAgICB0aGlzLnNob3dTdGF0dXMoXCJcdTI3MTMgRGV2aWNlIGFwcHJvdmVkIVwiLCBcInN1Y2Nlc3NcIik7XG4gICAgICAgICAgc2V0VGltZW91dCgoKSA9PiB7IHRoaXMuc3RlcCA9IDU7IHRoaXMucmVuZGVyU3RlcCgpOyB9LCAxMDAwKTtcbiAgICAgICAgfVxuICAgICAgfSBjYXRjaCB7IC8qIHN0aWxsIHdhaXRpbmcgKi8gfVxuICAgIH0pKCksIDIwMDApO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFN0ZXAgNTogRG9uZSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIHJlbmRlckRvbmUoZWw6IEhUTUxFbGVtZW50KTogdm9pZCB7XG4gICAgZWwuY3JlYXRlRWwoXCJoMlwiLCB7IHRleHQ6IFwiWW91J3JlIGFsbCBzZXQhIFx1RDgzQ1x1REY4OVwiIH0pO1xuICAgIGVsLmNyZWF0ZUVsKFwicFwiLCB7XG4gICAgICB0ZXh0OiBcIk9wZW5DbGF3IGlzIGNvbm5lY3RlZCBhbmQgcmVhZHkuIFlvdXIgdmF1bHQgaXMgbm93IHRoZSBhZ2VudCdzIHdvcmtzcGFjZS5cIixcbiAgICAgIGNsczogXCJvcGVuY2xhdy1vbmJvYXJkLWRlc2NcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IHRpcHMgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLXRpcHNcIik7XG4gICAgdGlwcy5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogXCJXaGF0IHlvdSBjYW4gZG9cIiB9KTtcbiAgICBjb25zdCBsaXN0ID0gdGlwcy5jcmVhdGVFbChcInVsXCIsIHsgY2xzOiBcIm9wZW5jbGF3LW9uYm9hcmQtbGlzdFwiIH0pO1xuICAgIGxpc3QuY3JlYXRlRWwoXCJsaVwiLCB7IHRleHQ6IFwiQ2hhdCB3aXRoIHlvdXIgQUkgYWdlbnQgaW4gdGhlIHNpZGViYXJcIiB9KTtcbiAgICBsaXN0LmNyZWF0ZUVsKFwibGlcIiwgeyB0ZXh0OiBcIlVzZSBDbWQvQ3RybCtQIFx1MjE5MiBcXFwiQXNrIGFib3V0IGN1cnJlbnQgbm90ZVxcXCIgdG8gZGlzY3VzcyBhbnkgbm90ZVwiIH0pO1xuICAgIGxpc3QuY3JlYXRlRWwoXCJsaVwiLCB7IHRleHQ6IFwiVGhlIGFnZW50IGNhbiByZWFkLCBjcmVhdGUsIGFuZCBlZGl0IGZpbGVzIGluIHlvdXIgdmF1bHRcIiB9KTtcbiAgICBsaXN0LmNyZWF0ZUVsKFwibGlcIiwgeyB0ZXh0OiBcIlRvb2wgY2FsbHMgYXBwZWFyIGlubGluZSBcdTIwMTQgY2xpY2sgZmlsZSBwYXRocyB0byBvcGVuIHRoZW1cIiB9KTtcblxuICAgIGNvbnN0IHN5bmNUaXAgPSBlbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1vbmJvYXJkLWluZm9cIik7XG4gICAgc3luY1RpcC5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiXHVEODNEXHVEQ0ExIHN5bmMgdGlwOiBcIiB9KTtcbiAgICBzeW5jVGlwLmNyZWF0ZUVsKFwic3BhblwiLCB7XG4gICAgICB0ZXh0OiBcIkVuYWJsZSBPYnNpZGlhbiBTeW5jIHRvIGFjY2VzcyB5b3VyIGFnZW50IGZyb20gbXVsdGlwbGUgZGV2aWNlcy4gWW91ciBjaGF0IHNldHRpbmdzIGFuZCBkZXZpY2Uga2V5cyBzeW5jIGF1dG9tYXRpY2FsbHkgXHUyMDE0IHNldCB1cCBvbmNlLCB3b3JrcyBldmVyeXdoZXJlLlwiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgY29udHJvbFRpcCA9IGVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW9uYm9hcmQtaW5mb1wiKTtcbiAgICBjb250cm9sVGlwLmNyZWF0ZUVsKFwic3Ryb25nXCIsIHsgdGV4dDogXCJcdUQ4M0RcdUREQTVcdUZFMEYgY29udHJvbCBVSTogXCIgfSk7XG4gICAgY29uc3QgY3RybFNwYW4gPSBjb250cm9sVGlwLmNyZWF0ZUVsKFwic3BhblwiKTtcbiAgICBjdHJsU3Bhbi5zZXRUZXh0KFwiWW91IGNhbiBhbHNvIG1hbmFnZSB5b3VyIGdhdGV3YXkgZnJvbSBhbnkgYnJvd3NlciBvbiB5b3VyIFRhaWxzY2FsZSBuZXR3b3JrLiBKdXN0IG9wZW4geW91ciBnYXRld2F5IFVSTCBpbiBhIGJyb3dzZXIuXCIpO1xuXG4gICAgY29uc3QgYnRuUm93ID0gZWwuY3JlYXRlRGl2KFwib3BlbmNsYXctb25ib2FyZC1idXR0b25zXCIpO1xuICAgIGNvbnN0IGRvbmVCdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlN0YXJ0IGNoYXR0aW5nIFx1MjE5MlwiLCBjbHM6IFwibW9kLWN0YVwiIH0pO1xuICAgIGRvbmVCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLm9uYm9hcmRpbmdDb21wbGV0ZSA9IHRydWU7XG4gICAgICAvLyBBbHdheXMgcmVzZXQgdG8gXCJtYWluXCIgc2Vzc2lvbiB0byBlbnN1cmUgY2xlYW4gY29ubmVjdGlvblxuICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IFwibWFpblwiO1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICB0aGlzLmNsb3NlKCk7XG4gICAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXlDb25uZWN0ZWQpIHZvaWQgdGhpcy5wbHVnaW4uY29ubmVjdEdhdGV3YXkoKTtcbiAgICAgIHZvaWQgdGhpcy5wbHVnaW4uYWN0aXZhdGVWaWV3KCk7XG4gICAgfSkoKSk7XG4gIH1cblxuICBwcml2YXRlIHNob3dTdGF0dXModGV4dDogc3RyaW5nLCB0eXBlOiBcImluZm9cIiB8IFwic3VjY2Vzc1wiIHwgXCJlcnJvclwiKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnN0YXR1c0VsKSByZXR1cm47XG4gICAgdGhpcy5zdGF0dXNFbC5lbXB0eSgpO1xuICAgIHRoaXMuc3RhdHVzRWwuY2xhc3NOYW1lID0gYG9wZW5jbGF3LW9uYm9hcmQtc3RhdHVzIG9wZW5jbGF3LW9uYm9hcmQtc3RhdHVzLSR7dHlwZX1gO1xuICAgIC8vIFN1cHBvcnQgbXVsdGlsaW5lIHdpdGggXFxuXG4gICAgZm9yIChjb25zdCBsaW5lIG9mIHRleHQuc3BsaXQoXCJcXG5cIikpIHtcbiAgICAgIGlmICh0aGlzLnN0YXR1c0VsLmNoaWxkTm9kZXMubGVuZ3RoID4gMCkgdGhpcy5zdGF0dXNFbC5jcmVhdGVFbChcImJyXCIpO1xuICAgICAgdGhpcy5zdGF0dXNFbC5hcHBlbmRUZXh0KGxpbmUpO1xuICAgIH1cbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgQ2hhdCBWaWV3IFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jb25zdCBWSUVXX1RZUEUgPSBcIm9wZW5jbGF3LWNoYXRcIjtcblxuY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgdGFiQmFyRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSB0YWJTZXNzaW9uczogeyBrZXk6IHN0cmluZzsgbGFiZWw6IHN0cmluZzsgcGN0OiBudW1iZXIgfVtdID0gW107XG4gIHByaXZhdGUgcmVuZGVyaW5nVGFicyA9IGZhbHNlO1xuICBwcml2YXRlIHRhYkRlbGV0ZUluUHJvZ3Jlc3MgPSBmYWxzZTtcbiAgcHJpdmF0ZSBpbnB1dEVsITogSFRNTFRleHRBcmVhRWxlbWVudDtcbiAgcHJpdmF0ZSBzZW5kQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgcmVjb25uZWN0QnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgYWJvcnRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIFBlci1zZXNzaW9uIHN0cmVhbSBzdGF0ZSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcbiAgcHJpdmF0ZSBzdHJlYW1zID0gbmV3IE1hcDxzdHJpbmcsIHtcbiAgICBydW5JZDogc3RyaW5nO1xuICAgIHRleHQ6IHN0cmluZyB8IG51bGw7XG4gICAgdG9vbENhbGxzOiBzdHJpbmdbXTtcbiAgICBpdGVtczogU3RyZWFtSXRlbVtdO1xuICAgIHNwbGl0UG9pbnRzOiBudW1iZXJbXTtcbiAgICBsYXN0RGVsdGFUaW1lOiBudW1iZXI7XG4gICAgY29tcGFjdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG4gICAgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG4gIH0+KCk7XG4gIC8qKiBNYXAgcnVuSWQgLT4gc2Vzc2lvbktleSBzbyB3ZSBjYW4gcm91dGUgc3RyZWFtIGV2ZW50cyB0aGF0IGxhY2sgc2Vzc2lvbktleSAqL1xuICBwcml2YXRlIHJ1blRvU2Vzc2lvbiA9IG5ldyBNYXA8c3RyaW5nLCBzdHJpbmc+KCk7XG5cbiAgcHJpdmF0ZSBzdHJlYW1FbDogSFRNTEVsZW1lbnQgfCBudWxsID0gbnVsbDtcblxuICAvKiogR2V0IGN1cnJlbnQgYWN0aXZlIHNlc3Npb24ga2V5ICovXG4gIHByaXZhdGUgZ2V0IGFjdGl2ZVNlc3Npb25LZXkoKTogc3RyaW5nIHsgcmV0dXJuIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgfHwgXCJtYWluXCI7IH1cbiAgLyoqIEdldCBzdHJlYW0gc3RhdGUgZm9yIGFjdGl2ZSB0YWIgKGlmIGFueSkgKi9cbiAgcHJpdmF0ZSBnZXQgYWN0aXZlU3RyZWFtKCkgeyByZXR1cm4gdGhpcy5zdHJlYW1zLmdldCh0aGlzLmFjdGl2ZVNlc3Npb25LZXkpID8/IG51bGw7IH1cblxuICBwcml2YXRlIGNvbnRleHRNZXRlckVsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgY29udGV4dEZpbGxFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGNvbnRleHRMYWJlbEVsITogSFRNTEVsZW1lbnQ7XG4gIG1vZGVsTGFiZWxFbCE6IEhUTUxFbGVtZW50O1xuXG4gIGN1cnJlbnRNb2RlbDogc3RyaW5nID0gXCJcIjtcbiAgY3VycmVudE1vZGVsU2V0QXQ6IG51bWJlciA9IDA7IC8vIHRpbWVzdGFtcCB0byBwcmV2ZW50IHN0YWxlIG92ZXJ3cml0ZXNcbiAgY2FjaGVkU2Vzc2lvbkRpc3BsYXlOYW1lOiBzdHJpbmcgPSBcIlwiO1xuXG4gIC8vIEFnZW50IHN3aXRjaGVyIHN0YXRlXG4gIHByaXZhdGUgYWdlbnRzOiBBZ2VudEluZm9bXSA9IFtdO1xuICBwcml2YXRlIGFjdGl2ZUFnZW50OiBBZ2VudEluZm8gPSB7IGlkOiBcIm1haW5cIiwgbmFtZTogXCJBZ2VudFwiLCBlbW9qaTogXCJcdUQ4M0VcdUREMTZcIiwgY3JlYXR1cmU6IFwiXCIgfTtcbiAgcHJpdmF0ZSBwcm9maWxlQnRuRWw6IEhUTUxFbGVtZW50IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcHJvZmlsZURyb3Bkb3duRWw6IEhUTUxFbGVtZW50IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgdHlwaW5nRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBhdHRhY2hQcmV2aWV3RWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBmaWxlSW5wdXRFbCE6IEhUTUxJbnB1dEVsZW1lbnQ7XG4gIHByaXZhdGUgcGVuZGluZ0F0dGFjaG1lbnRzOiB7IG5hbWU6IHN0cmluZzsgY29udGVudDogc3RyaW5nOyB2YXVsdFBhdGg/OiBzdHJpbmc7IGJhc2U2ND86IHN0cmluZzsgbWltZVR5cGU/OiBzdHJpbmcgfVtdID0gW107XG4gIHByaXZhdGUgc2VuZGluZyA9IGZhbHNlO1xuICBwcml2YXRlIHJlY29yZGluZyA9IGZhbHNlO1xuICBwcml2YXRlIG1lZGlhUmVjb3JkZXI6IE1lZGlhUmVjb3JkZXIgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvcmRlZENodW5rczogQmxvYltdID0gW107XG5cbiAgcHJpdmF0ZSByZWFkb25seSBtaWNTdmcgPSBgPHN2ZyB3aWR0aD1cIjE4XCIgaGVpZ2h0PVwiMThcIiB2aWV3Qm94PVwiMCAwIDI0IDI0XCIgZmlsbD1cIm5vbmVcIiBzdHJva2U9XCJjdXJyZW50Q29sb3JcIiBzdHJva2Utd2lkdGg9XCIyXCIgc3Ryb2tlLWxpbmVjYXA9XCJyb3VuZFwiIHN0cm9rZS1saW5lam9pbj1cInJvdW5kXCI+PHBhdGggZD1cIk0xMiAxYTMgMyAwIDAwLTMgM3Y4YTMgMyAwIDAwNiAwVjRhMyAzIDAgMDAtMy0zelwiLz48cGF0aCBkPVwiTTE5IDEwdjJhNyA3IDAgMDEtMTQgMHYtMlwiLz48bGluZSB4MT1cIjEyXCIgeTE9XCIxOVwiIHgyPVwiMTJcIiB5Mj1cIjIzXCIvPjxsaW5lIHgxPVwiOFwiIHkxPVwiMjNcIiB4Mj1cIjE2XCIgeTI9XCIyM1wiLz48L3N2Zz5gO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlbmRTdmcgPSBgPHN2ZyB3aWR0aD1cIjE4XCIgaGVpZ2h0PVwiMThcIiB2aWV3Qm94PVwiMCAwIDI0IDI0XCIgZmlsbD1cIm5vbmVcIiBzdHJva2U9XCJjdXJyZW50Q29sb3JcIiBzdHJva2Utd2lkdGg9XCIyXCIgc3Ryb2tlLWxpbmVjYXA9XCJyb3VuZFwiIHN0cm9rZS1saW5lam9pbj1cInJvdW5kXCI+PGxpbmUgeDE9XCIyMlwiIHkxPVwiMlwiIHgyPVwiMTFcIiB5Mj1cIjEzXCIvPjxwb2x5Z29uIHBvaW50cz1cIjIyIDIgMTUgMjIgMTEgMTMgMiA5IDIyIDJcIi8+PC9zdmc+YDtcbiAgcHJpdmF0ZSByZWFkb25seSBzdG9wU3ZnID0gYDxzdmcgd2lkdGg9XCIxOFwiIGhlaWdodD1cIjE4XCIgdmlld0JveD1cIjAgMCAyNCAyNFwiIGZpbGw9XCJub25lXCIgc3Ryb2tlPVwicmVkXCIgc3Ryb2tlLXdpZHRoPVwiMi41XCIgc3Ryb2tlLWxpbmVjYXA9XCJyb3VuZFwiIHN0cm9rZS1saW5lam9pbj1cInJvdW5kXCI+PHJlY3QgeD1cIjNcIiB5PVwiM1wiIHdpZHRoPVwiMThcIiBoZWlnaHQ9XCIxOFwiIHJ4PVwiMlwiLz48L3N2Zz5gO1xuICBwcml2YXRlIGJhbm5lckVsITogSFRNTEVsZW1lbnQ7XG5cbiAgLyoqIEdldCB0aGUgc2Vzc2lvbiBrZXkgcHJlZml4IGZvciB0aGUgYWN0aXZlIGFnZW50ICovXG4gIHByaXZhdGUgZ2V0IGFnZW50UHJlZml4KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGBhZ2VudDoke3RoaXMuYWN0aXZlQWdlbnQuaWR9OmA7XG4gIH1cblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBnZXRWaWV3VHlwZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBWSUVXX1RZUEU7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiBcIk9wZW5DbGF3XCI7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFwibWVzc2FnZS1zcXVhcmVcIjtcbiAgfVxuXG4gIGFzeW5jIG9uT3BlbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBjb250YWluZXIgPSB0aGlzLmNvbnRhaW5lckVsLmNoaWxkcmVuWzFdIGFzIEhUTUxFbGVtZW50O1xuICAgIGNvbnRhaW5lci5lbXB0eSgpO1xuICAgIGNvbnRhaW5lci5hZGRDbGFzcyhcIm9wZW5jbGF3LWNoYXQtY29udGFpbmVyXCIpO1xuXG4gICAgLy8gVG9wIGJhciB3aXRoIHRhYnMgKyBwcm9maWxlXG4gICAgY29uc3QgdG9wQmFyID0gY29udGFpbmVyLmNyZWF0ZURpdihcIm9wZW5jbGF3LXRvcC1iYXJcIik7XG5cbiAgICAvLyBUYWIgYmFyIChicm93c2VyLWxpa2UgdGFicylcbiAgICB0aGlzLnRhYkJhckVsID0gdG9wQmFyLmNyZWF0ZURpdihcIm9wZW5jbGF3LXRhYi1iYXJcIik7XG4gICAgdGhpcy50YWJCYXJFbC5hZGRFdmVudExpc3RlbmVyKFwid2hlZWxcIiwgKGUpID0+IHsgZS5wcmV2ZW50RGVmYXVsdCgpOyB0aGlzLnRhYkJhckVsLnNjcm9sbExlZnQgKz0gZS5kZWx0YVk7IH0sIHsgcGFzc2l2ZTogZmFsc2UgfSk7XG5cbiAgICAvLyBBZ2VudCBzd2l0Y2hlciBidXR0b24gKHJpZ2h0IHNpZGUgb2YgdG9wIGJhcilcbiAgICB0aGlzLnByb2ZpbGVCdG5FbCA9IHRvcEJhci5jcmVhdGVEaXYoXCJvcGVuY2xhdy1hZ2VudC1idG5cIik7XG4gICAgdGhpcy5wcm9maWxlQnRuRWwuc2V0QXR0cmlidXRlKFwiYXJpYS1sYWJlbFwiLCBcIlN3aXRjaCBhZ2VudFwiKTtcbiAgICB0aGlzLnVwZGF0ZUFnZW50QnV0dG9uKCk7XG4gICAgdGhpcy5wcm9maWxlQnRuRWwuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsIChlKSA9PiB7IGUuc3RvcFByb3BhZ2F0aW9uKCk7IHRoaXMudG9nZ2xlQWdlbnRTd2l0Y2hlcigpOyB9KTtcblxuICAgIC8vIEFnZW50IHN3aXRjaGVyIGRyb3Bkb3duIChoaWRkZW4gYnkgZGVmYXVsdClcbiAgICB0aGlzLnByb2ZpbGVEcm9wZG93bkVsID0gY29udGFpbmVyLmNyZWF0ZURpdihcIm9wZW5jbGF3LWFnZW50LWRyb3Bkb3duXCIpO1xuICAgIHRoaXMucHJvZmlsZURyb3Bkb3duRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG5cbiAgICAvLyBDbG9zZSBkcm9wZG93biB3aGVuIGNsaWNraW5nIG91dHNpZGVcbiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4geyBpZiAodGhpcy5wcm9maWxlRHJvcGRvd25FbCkgdGhpcy5wcm9maWxlRHJvcGRvd25FbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTsgfSk7XG5cbiAgICAvLyBXZSdsbCByZW5kZXIgdGFicyBhZnRlciBsb2FkaW5nIHNlc3Npb25zXG4gICAgdm9pZCB0aGlzLnJlbmRlclRhYnMoKTtcblxuICAgIC8vIEhpZGRlbiBlbGVtZW50cyBmb3IgY29tcGF0aWJpbGl0eVxuXG4gICAgdGhpcy5jb250ZXh0TWV0ZXJFbCA9IGNyZWF0ZURpdigpO1xuICAgIHRoaXMuY29udGV4dEZpbGxFbCA9IGNyZWF0ZURpdigpO1xuICAgIHRoaXMuY29udGV4dExhYmVsRWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KFwic3BhblwiKTtcbiAgICB0aGlzLm1vZGVsTGFiZWxFbCA9IGNyZWF0ZURpdigpO1xuXG4gICAgLy8gU3RhdHVzIGJhbm5lciAoY29tcGFjdGlvbiwgZXRjLikgXHUyMDE0IGhpZGRlbiBieSBkZWZhdWx0XG4gICAgdGhpcy5iYW5uZXJFbCA9IGNvbnRhaW5lci5jcmVhdGVEaXYoXCJvcGVuY2xhdy1iYW5uZXJcIik7XG4gICAgdGhpcy5iYW5uZXJFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcblxuICAgIC8vIE1lc3NhZ2VzIGFyZWFcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSBjb250YWluZXIuY3JlYXRlRGl2KFwib3BlbmNsYXctbWVzc2FnZXNcIik7XG5cbiAgICAvLyBUeXBpbmcgaW5kaWNhdG9yIChoaWRkZW4gYnkgZGVmYXVsdClcbiAgICB0aGlzLnR5cGluZ0VsID0gY29udGFpbmVyLmNyZWF0ZURpdihcIm9wZW5jbGF3LXR5cGluZ1wiKTtcbiAgICB0aGlzLnR5cGluZ0VsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIGNvbnN0IHR5cGluZ0RvdHMgPSB0aGlzLnR5cGluZ0VsLmNyZWF0ZURpdihcIm9wZW5jbGF3LXR5cGluZy1pbm5lclwiKTtcbiAgICB0eXBpbmdEb3RzLmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIlRoaW5raW5nXCIsIGNsczogXCJvcGVuY2xhdy10eXBpbmctdGV4dFwiIH0pO1xuICAgIGNvbnN0IGRvdHNFbCA9IHR5cGluZ0RvdHMuY3JlYXRlU3BhbihcIm9wZW5jbGF3LXR5cGluZy1kb3RzXCIpO1xuICAgIGRvdHNFbC5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuICAgIGRvdHNFbC5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuICAgIGRvdHNFbC5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuXG4gICAgLy8gSW5wdXQgYXJlYVxuICAgIGNvbnN0IGlucHV0QXJlYSA9IGNvbnRhaW5lci5jcmVhdGVEaXYoXCJvcGVuY2xhdy1pbnB1dC1hcmVhXCIpO1xuICAgIGNvbnN0IGlucHV0Um93ID0gaW5wdXRBcmVhLmNyZWF0ZURpdihcIm9wZW5jbGF3LWlucHV0LXJvd1wiKTtcbiAgICAvLyBCcmFpbiBidXR0b24gKG1vZGVsIHBpY2tlcilcbiAgICBjb25zdCBicmFpbkJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgY2xzOiBcIm9wZW5jbGF3LWJyYWluLWJ0blwiLCBhdHRyOiB7IFwiYXJpYS1sYWJlbFwiOiBcIlN3aXRjaCBtb2RlbFwiIH0gfSk7XG4gICAgc2V0SWNvbihicmFpbkJ0biwgXCJzcGFya2xlc1wiKTtcbiAgICBicmFpbkJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5vcGVuTW9kZWxQaWNrZXIoKSk7XG4gICAgLy8gQXR0YWNoIGJ1dHRvbiArIGhpZGRlbiBmaWxlIGlucHV0XG4gICAgY29uc3QgYXR0YWNoQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctYXR0YWNoLWJ0blwiLCBhdHRyOiB7IFwiYXJpYS1sYWJlbFwiOiBcIkF0dGFjaCBmaWxlXCIgfSB9KTtcbiAgICBzZXRJY29uKGF0dGFjaEJ0biwgXCJwYXBlcmNsaXBcIik7XG4gICAgdGhpcy5maWxlSW5wdXRFbCA9IGlucHV0QXJlYS5jcmVhdGVFbChcImlucHV0XCIsIHtcbiAgICAgIGNsczogXCJvcGVuY2xhdy1maWxlLWlucHV0XCIsXG4gICAgICBhdHRyOiB7IHR5cGU6IFwiZmlsZVwiLCBhY2NlcHQ6IFwiaW1hZ2UvKiwubWQsLnR4dCwuanNvbiwuY3N2LC5wZGYsLnlhbWwsLnltbCwuanMsLnRzLC5weSwuaHRtbCwuY3NzXCIsIG11bHRpcGxlOiBcInRydWVcIiB9LFxuICAgIH0pO1xuICAgIHRoaXMuZmlsZUlucHV0RWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgdGhpcy5maWxlSW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKFwiY2hhbmdlXCIsICgpID0+IHZvaWQgdGhpcy5oYW5kbGVGaWxlU2VsZWN0KCkpO1xuICAgIGF0dGFjaEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5maWxlSW5wdXRFbC5jbGljaygpKTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbChcInRleHRhcmVhXCIsIHtcbiAgICAgIGNsczogXCJvcGVuY2xhdy1pbnB1dFwiLFxuICAgICAgYXR0cjogeyBwbGFjZWhvbGRlcjogXCJNZXNzYWdlLi4uXCIsIHJvd3M6IFwiMVwiIH0sXG4gICAgfSk7XG4gICAgLy8gQXR0YWNobWVudCBwcmV2aWV3IChoaWRkZW4gYnkgZGVmYXVsdClcbiAgICB0aGlzLmF0dGFjaFByZXZpZXdFbCA9IGlucHV0QXJlYS5jcmVhdGVEaXYoXCJvcGVuY2xhdy1hdHRhY2gtcHJldmlld1wiKTtcbiAgICB0aGlzLmF0dGFjaFByZXZpZXdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB0aGlzLmFib3J0QnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyBjbHM6IFwib3BlbmNsYXctYWJvcnQtYnRuXCIsIGF0dHI6IHsgXCJhcmlhLWxhYmVsXCI6IFwiU3RvcFwiIH0gfSk7XG4gICAgc2V0SWNvbih0aGlzLmFib3J0QnRuLCBcInNxdWFyZVwiKTtcbiAgICB0aGlzLmFib3J0QnRuLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIGNvbnN0IHNlbmRXcmFwcGVyID0gaW5wdXRSb3cuY3JlYXRlRGl2KFwib3BlbmNsYXctc2VuZC13cmFwcGVyXCIpO1xuICAgIHRoaXMuc2VuZEJ0biA9IHNlbmRXcmFwcGVyLmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgY2xzOiBcIm9wZW5jbGF3LXNlbmQtYnRuXCIsIGF0dHI6IHsgXCJhcmlhLWxhYmVsXCI6IFwiU2VuZFwiIH0gfSk7XG4gICAgc2V0SWNvbih0aGlzLnNlbmRCdG4sIFwic2VuZFwiKTtcbiAgICB0aGlzLnNlbmRCdG4uYWRkQ2xhc3MoXCJvYy1vcGFjaXR5LWxvd1wiKTtcbiAgICB0aGlzLnJlY29ubmVjdEJ0biA9IHNlbmRXcmFwcGVyLmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgY2xzOiBcIm9wZW5jbGF3LXJlY29ubmVjdC1idG5cIiwgYXR0cjogeyBcImFyaWEtbGFiZWxcIjogXCJSZWNvbm5lY3RcIiB9IH0pO1xuICAgIHNldEljb24odGhpcy5yZWNvbm5lY3RCdG4sIFwicmVmcmVzaC1jd1wiKTtcbiAgICB0aGlzLnJlY29ubmVjdEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB0aGlzLnJlY29ubmVjdEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLnBsdWdpbi5jb25uZWN0R2F0ZXdheSgpO1xuICAgIH0pO1xuICAgIHRoaXMuc3RhdHVzRWwgPSBzZW5kV3JhcHBlci5jcmVhdGVTcGFuKFwib3BlbmNsYXctc3RhdHVzLWRvdFwiKTtcblxuICAgIC8vIEV2ZW50c1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKFwia2V5ZG93blwiLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSBcIkVudGVyXCIpIHtcbiAgICAgICAgLy8gTW9iaWxlOiBFbnRlciBhbHdheXMgY3JlYXRlcyBuZXcgbGluZSAodXNlIHNlbmQgYnV0dG9uIHRvIHNlbmQpXG4gICAgICAgIC8vIERlc2t0b3A6IEVudGVyIHNlbmRzLCBTaGlmdCtFbnRlciBjcmVhdGVzIG5ldyBsaW5lXG4gICAgICAgIGlmIChQbGF0Zm9ybS5pc01vYmlsZSkge1xuICAgICAgICAgIC8vIExldCBFbnRlciBjcmVhdGUgYSBuZXcgbGluZSBuYXR1cmFsbHlcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFlLnNoaWZ0S2V5KSB7XG4gICAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgIHZvaWQgdGhpcy5zZW5kTWVzc2FnZSgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoXCJpbnB1dFwiLCAoKSA9PiB7XG4gICAgICB0aGlzLmF1dG9SZXNpemUoKTtcbiAgICAgIHRoaXMudXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKFwiZm9jdXNcIiwgKCkgPT4ge1xuICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIHRoaXMuaW5wdXRFbC5zY3JvbGxJbnRvVmlldyh7IGJsb2NrOiBcImVuZFwiLCBiZWhhdmlvcjogXCJzbW9vdGhcIiB9KTtcbiAgICAgIH0sIDMwMCk7XG4gICAgfSk7XG4gICAgLy8gQ2xpcGJvYXJkIHBhc3RlOiBjYXB0dXJlIGltYWdlcyBmcm9tIGNsaXBib2FyZFxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKFwicGFzdGVcIiwgKGUpID0+IHtcbiAgICAgIGNvbnN0IGl0ZW1zID0gZS5jbGlwYm9hcmREYXRhPy5pdGVtcztcbiAgICAgIGlmICghaXRlbXMpIHJldHVybjtcbiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBBcnJheS5mcm9tKGl0ZW1zKSkge1xuICAgICAgICBpZiAoaXRlbS50eXBlLnN0YXJ0c1dpdGgoXCJpbWFnZS9cIikpIHtcbiAgICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgY29uc3QgZmlsZSA9IGl0ZW0uZ2V0QXNGaWxlKCk7XG4gICAgICAgICAgaWYgKGZpbGUpIHZvaWQgdGhpcy5oYW5kbGVQYXN0ZWRGaWxlKGZpbGUpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgaWYgKHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCkgfHwgdGhpcy5wZW5kaW5nQXR0YWNobWVudHMubGVuZ3RoID4gMCkge1xuICAgICAgICB2b2lkIHRoaXMuc2VuZE1lc3NhZ2UoKTtcbiAgICAgIH1cbiAgICAgIC8vIFZvaWNlIHJlY29yZGluZyBkaXNhYmxlZCBcdTIwMTQgYmFzZTY0IGluIG1lc3NhZ2UgdGV4dCBibG9hdHMgY29udGV4dFxuICAgIH0pO1xuICAgIHRoaXMuYWJvcnRCdG4uYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHZvaWQgdGhpcy5hYm9ydE1lc3NhZ2UoKSk7XG5cbiAgICAvLyBJbml0aWFsIHN0YXRlXG4gICAgdGhpcy51cGRhdGVTdGF0dXMoKTtcbiAgICB0aGlzLnBsdWdpbi5jaGF0VmlldyA9IHRoaXM7XG4gICAgXG4gICAgLy8gSW5pdCB0b3VjaCBnZXN0dXJlcyBmb3IgbW9iaWxlXG4gICAgdGhpcy5pbml0VG91Y2hHZXN0dXJlcygpO1xuICAgIFxuICAgIGlmICh0aGlzLnBsdWdpbi5nYXRld2F5Q29ubmVjdGVkKSB7XG4gICAgICBhd2FpdCB0aGlzLmxvYWRIaXN0b3J5KCk7XG4gICAgICB2b2lkIHRoaXMubG9hZEFnZW50cygpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMucGx1Z2luLmNoYXRWaWV3ID09PSB0aGlzKSB7XG4gICAgICB0aGlzLnBsdWdpbi5jaGF0VmlldyA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgdXBkYXRlU3RhdHVzKCk6IHZvaWQge1xuICAgIGlmICghdGhpcy5zdGF0dXNFbCkgcmV0dXJuO1xuICAgIHRoaXMuc3RhdHVzRWwucmVtb3ZlQ2xhc3MoXCJjb25uZWN0ZWRcIiwgXCJkaXNjb25uZWN0ZWRcIik7XG4gICAgY29uc3QgY29ubmVjdGVkID0gdGhpcy5wbHVnaW4uZ2F0ZXdheUNvbm5lY3RlZDtcbiAgICB0aGlzLnN0YXR1c0VsLmFkZENsYXNzKGNvbm5lY3RlZCA/IFwiY29ubmVjdGVkXCIgOiBcImRpc2Nvbm5lY3RlZFwiKTtcblxuICAgIC8vIFN3YXAgc2VuZCBidXR0b24gZm9yIHJlY29ubmVjdCB3aGVuIGRpc2Nvbm5lY3RlZFxuICAgIGlmIChjb25uZWN0ZWQpIHtcbiAgICAgIHRoaXMuc2VuZEJ0bi5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIGlmICh0aGlzLnJlY29ubmVjdEJ0bikgdGhpcy5yZWNvbm5lY3RCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB0aGlzLmlucHV0RWwuZGlzYWJsZWQgPSBmYWxzZTtcbiAgICAgIHRoaXMuaW5wdXRFbC5wbGFjZWhvbGRlciA9IFwiTWVzc2FnZS4uLlwiO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLnNlbmRCdG4uYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICBpZiAodGhpcy5yZWNvbm5lY3RCdG4pIHRoaXMucmVjb25uZWN0QnRuLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgdGhpcy5pbnB1dEVsLmRpc2FibGVkID0gdHJ1ZTtcbiAgICAgIHRoaXMuaW5wdXRFbC5wbGFjZWhvbGRlciA9IFwiRGlzY29ubmVjdGVkXCI7XG4gICAgfVxuICB9XG5cbiAgLyoqIEZldGNoIGFsbCBhZ2VudHMgZnJvbSB0aGUgZ2F0ZXdheSBhbmQgbG9hZCB0aGVpciBpZGVudGl0aWVzICovXG4gIGFzeW5jIGxvYWRBZ2VudHMoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICB0cnkge1xuICAgICAgLy8gR2V0IGFnZW50IGxpc3RcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImFnZW50cy5saXN0XCIsIHt9KSBhcyB7IGFnZW50cz86IEFnZW50TGlzdEl0ZW1bXSB9IHwgbnVsbDtcbiAgICAgIGNvbnN0IGFnZW50TGlzdDogQWdlbnRMaXN0SXRlbVtdID0gcmVzdWx0Py5hZ2VudHMgfHwgW107XG4gICAgICBpZiAoYWdlbnRMaXN0Lmxlbmd0aCA9PT0gMCkge1xuICAgICAgICBhZ2VudExpc3QucHVzaCh7IGlkOiBcIm1haW5cIiB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gQnVpbGQgYWdlbnQgaW5mbyBmcm9tIGdhdGV3YXkgZGF0YSBvbmx5IFx1MjAxNCBubyBmaWxlIHBhcnNpbmdcbiAgICAgIGNvbnN0IGFnZW50czogQWdlbnRJbmZvW10gPSBbXTtcbiAgICAgIGZvciAoY29uc3QgYSBvZiBhZ2VudExpc3QpIHtcbiAgICAgICAgYWdlbnRzLnB1c2goe1xuICAgICAgICAgIGlkOiBhLmlkIHx8IFwibWFpblwiLFxuICAgICAgICAgIG5hbWU6IGEubmFtZSB8fCBhLmlkIHx8IFwiQWdlbnRcIixcbiAgICAgICAgICBlbW9qaTogXCJcdUQ4M0VcdUREMTZcIixcbiAgICAgICAgICBjcmVhdHVyZTogXCJcIixcbiAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuYWdlbnRzID0gYWdlbnRzO1xuXG4gICAgICAvLyBTZXQgYWN0aXZlIGFnZW50XG4gICAgICBjb25zdCBzYXZlZElkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWN0aXZlQWdlbnRJZDtcbiAgICAgIGNvbnN0IGFjdGl2ZSA9IGFnZW50cy5maW5kKGEgPT4gYS5pZCA9PT0gc2F2ZWRJZCkgfHwgYWdlbnRzWzBdO1xuICAgICAgaWYgKGFjdGl2ZSkge1xuICAgICAgICB0aGlzLmFjdGl2ZUFnZW50ID0gYWN0aXZlO1xuICAgICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWN0aXZlQWdlbnRJZCAhPT0gYWN0aXZlLmlkKSB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWN0aXZlQWdlbnRJZCA9IGFjdGl2ZS5pZDtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICB0aGlzLnVwZGF0ZUFnZW50QnV0dG9uKCk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS53YXJuKFwiW09ic2lkaWFuQ2xhd10gRmFpbGVkIHRvIGxvYWQgYWdlbnRzOlwiLCBlKTtcbiAgICB9XG4gIH1cblxuICAvKiogVXBkYXRlIHRoZSBhZ2VudCBidXR0b24gXHUyMDE0IGhpZGRlbiBmb3Igc2luZ2xlIGFnZW50LCB2aXNpYmxlIGZvciBtdWx0aSAqL1xuICBwcml2YXRlIHVwZGF0ZUFnZW50QnV0dG9uKCk6IHZvaWQge1xuICAgIGlmICghdGhpcy5wcm9maWxlQnRuRWwpIHJldHVybjtcbiAgICBpZiAodGhpcy5hZ2VudHMubGVuZ3RoIDw9IDEpIHtcbiAgICAgIHRoaXMucHJvZmlsZUJ0bkVsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB0aGlzLnByb2ZpbGVCdG5FbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICBjb25zdCBlbW9qaSA9IHRoaXMuYWN0aXZlQWdlbnQuZW1vamkgfHwgXCJcdUQ4M0VcdUREMTZcIjtcbiAgICB0aGlzLnByb2ZpbGVCdG5FbC5lbXB0eSgpO1xuICAgIHRoaXMucHJvZmlsZUJ0bkVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBlbW9qaSwgY2xzOiBcIm9wZW5jbGF3LWFnZW50LWVtb2ppXCIgfSk7XG4gIH1cblxuICAvKiogU3dpdGNoIHRvIGEgZGlmZmVyZW50IGFnZW50ICovXG4gIHByaXZhdGUgYXN5bmMgc3dpdGNoQWdlbnQoYWdlbnQ6IEFnZW50SW5mbyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmIChhZ2VudC5pZCA9PT0gdGhpcy5hY3RpdmVBZ2VudC5pZCkgcmV0dXJuO1xuICAgIHRoaXMuYWN0aXZlQWdlbnQgPSBhZ2VudDtcbiAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY3RpdmVBZ2VudElkID0gYWdlbnQuaWQ7XG4gICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IFwibWFpblwiOyAvLyByZXNldCB0byBtYWluIHNlc3Npb24gb2YgbmV3IGFnZW50XG4gICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgdGhpcy51cGRhdGVBZ2VudEJ1dHRvbigpO1xuICAgIGF3YWl0IHRoaXMubG9hZEhpc3RvcnkoKTtcbiAgICBhd2FpdCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgfVxuXG4gIC8qKiBUb2dnbGUgdGhlIGFnZW50IHN3aXRjaGVyIGRyb3Bkb3duICovXG4gIHByaXZhdGUgdG9nZ2xlQWdlbnRTd2l0Y2hlcigpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMucHJvZmlsZURyb3Bkb3duRWwpIHJldHVybjtcbiAgICBjb25zdCB2aXNpYmxlID0gIXRoaXMucHJvZmlsZURyb3Bkb3duRWwuaGFzQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgaWYgKHZpc2libGUpIHtcbiAgICAgIHRoaXMucHJvZmlsZURyb3Bkb3duRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIHRoaXMucHJvZmlsZURyb3Bkb3duRWwuZW1wdHkoKTtcblxuICAgIGZvciAoY29uc3QgYWdlbnQgb2YgdGhpcy5hZ2VudHMpIHtcbiAgICAgIGNvbnN0IGlzQWN0aXZlID0gYWdlbnQuaWQgPT09IHRoaXMuYWN0aXZlQWdlbnQuaWQ7XG4gICAgICBjb25zdCBpdGVtID0gdGhpcy5wcm9maWxlRHJvcGRvd25FbC5jcmVhdGVEaXYoeyBjbHM6IGBvcGVuY2xhdy1hZ2VudC1pdGVtJHtpc0FjdGl2ZSA/IFwiIGFjdGl2ZVwiIDogXCJcIn1gIH0pO1xuICAgICAgaXRlbS5jcmVhdGVTcGFuKHsgdGV4dDogYWdlbnQuZW1vamkgfHwgXCJcdUQ4M0VcdUREMTZcIiwgY2xzOiBcIm9wZW5jbGF3LWFnZW50LWl0ZW0tZW1vamlcIiB9KTtcbiAgICAgIGNvbnN0IGluZm8gPSBpdGVtLmNyZWF0ZURpdihcIm9wZW5jbGF3LWFnZW50LWl0ZW0taW5mb1wiKTtcbiAgICAgIGluZm8uY3JlYXRlRGl2KHsgdGV4dDogYWdlbnQubmFtZSwgY2xzOiBcIm9wZW5jbGF3LWFnZW50LWl0ZW0tbmFtZVwiIH0pO1xuICAgICAgaWYgKGFnZW50LmNyZWF0dXJlKSB7XG4gICAgICAgIGluZm8uY3JlYXRlRGl2KHsgdGV4dDogYWdlbnQuY3JlYXR1cmUsIGNsczogXCJvcGVuY2xhdy1hZ2VudC1pdGVtLXN1YlwiIH0pO1xuICAgICAgfVxuICAgICAgaWYgKCFpc0FjdGl2ZSkge1xuICAgICAgICBpdGVtLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5wcm9maWxlRHJvcGRvd25FbCEuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgICAgdm9pZCB0aGlzLnN3aXRjaEFnZW50KGFnZW50KTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5wcm9maWxlRHJvcGRvd25FbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRIaXN0b3J5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSByZXR1cm47XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImNoYXQuaGlzdG9yeVwiLCB7XG4gICAgICAgIHNlc3Npb25LZXk6IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXksXG4gICAgICAgIGxpbWl0OiAyMDAsXG4gICAgICB9KSBhcyB7IG1lc3NhZ2VzPzogSGlzdG9yeU1lc3NhZ2VbXSB9IHwgbnVsbDtcbiAgICAgIGlmIChyZXN1bHQ/Lm1lc3NhZ2VzICYmIEFycmF5LmlzQXJyYXkocmVzdWx0Lm1lc3NhZ2VzKSkge1xuICAgICAgICB0aGlzLm1lc3NhZ2VzID0gcmVzdWx0Lm1lc3NhZ2VzXG4gICAgICAgICAgLmZpbHRlcigobTogSGlzdG9yeU1lc3NhZ2UpID0+IG0ucm9sZSA9PT0gXCJ1c2VyXCIgfHwgbS5yb2xlID09PSBcImFzc2lzdGFudFwiKVxuICAgICAgICAgIC5tYXAoKG06IEhpc3RvcnlNZXNzYWdlKSA9PiB7XG4gICAgICAgICAgICBjb25zdCB7IHRleHQsIGltYWdlcyB9ID0gdGhpcy5leHRyYWN0Q29udGVudChtLmNvbnRlbnQpO1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgcm9sZTogbS5yb2xlIGFzIFwidXNlclwiIHwgXCJhc3Npc3RhbnRcIixcbiAgICAgICAgICAgICAgdGV4dCxcbiAgICAgICAgICAgICAgaW1hZ2VzLFxuICAgICAgICAgICAgICB0aW1lc3RhbXA6IG0udGltZXN0YW1wID8/IERhdGUubm93KCksXG4gICAgICAgICAgICAgIGNvbnRlbnRCbG9ja3M6IEFycmF5LmlzQXJyYXkobS5jb250ZW50KSA/IG0uY29udGVudCA6IHVuZGVmaW5lZCxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgfSlcbiAgICAgICAgICAuZmlsdGVyKChtOiBDaGF0TWVzc2FnZSkgPT4gKG0udGV4dC50cmltKCkgfHwgbS5pbWFnZXMubGVuZ3RoID4gMCkgJiYgIW0udGV4dC5zdGFydHNXaXRoKFwiSEVBUlRCRUFUXCIpKTtcblxuICAgICAgICAvLyBIaWRlIHRoZSBmaXJzdCB1c2VyIG1lc3NhZ2UgKHR5cGljYWxseSB0aGUgL25ldyBvciAvcmVzZXQgc3lzdGVtIHByb21wdClcbiAgICAgICAgaWYgKHRoaXMubWVzc2FnZXMubGVuZ3RoID4gMCAmJiB0aGlzLm1lc3NhZ2VzWzBdLnJvbGUgPT09IFwidXNlclwiKSB7XG4gICAgICAgICAgdGhpcy5tZXNzYWdlcyA9IHRoaXMubWVzc2FnZXMuc2xpY2UoMSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBObyBwb3N0LXByb2Nlc3NpbmcgbmVlZGVkOiBWT0lDRTogcmVmcyBhcmUgaW4gdGhlIGFzc2lzdGFudCBtZXNzYWdlIHRleHQgaXRzZWxmXG5cbiAgICAgICAgYXdhaXQgdGhpcy5yZW5kZXJNZXNzYWdlcygpO1xuICAgICAgICB2b2lkIHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcihcIltPYnNpZGlhbkNsYXddIEZhaWxlZCB0byBsb2FkIGhpc3Rvcnk6XCIsIGUpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgZXh0cmFjdENvbnRlbnQoY29udGVudDogc3RyaW5nIHwgQ29udGVudEJsb2NrW10gfCB1bmRlZmluZWQpOiB7IHRleHQ6IHN0cmluZzsgaW1hZ2VzOiBzdHJpbmdbXSB9IHtcbiAgICBsZXQgdGV4dCA9IFwiXCI7XG4gICAgY29uc3QgaW1hZ2VzOiBzdHJpbmdbXSA9IFtdO1xuXG4gICAgaWYgKHR5cGVvZiBjb250ZW50ID09PSBcInN0cmluZ1wiKSB7XG4gICAgICB0ZXh0ID0gY29udGVudDtcbiAgICB9IGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICAgIGZvciAoY29uc3QgYyBvZiBjb250ZW50KSB7XG4gICAgICAgIGlmIChjLnR5cGUgPT09IFwidGV4dFwiKSB7XG4gICAgICAgICAgdGV4dCArPSAodGV4dCA/IFwiXFxuXCIgOiBcIlwiKSArIGMudGV4dDtcbiAgICAgICAgfSBlbHNlIGlmIChjLnR5cGUgPT09IFwidG9vbF9yZXN1bHRcIikge1xuICAgICAgICAgIC8vIEV4dHJhY3QgdGV4dCBmcm9tIHRvb2xfcmVzdWx0IGNvbnRlbnQgKGUuZy4sIFRUUyBNRURJQTogcGF0aHMpXG4gICAgICAgICAgY29uc3QgdHJDb250ZW50ID0gYy5jb250ZW50O1xuICAgICAgICAgIGlmICh0eXBlb2YgdHJDb250ZW50ID09PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICB0ZXh0ICs9ICh0ZXh0ID8gXCJcXG5cIiA6IFwiXCIpICsgdHJDb250ZW50O1xuICAgICAgICAgIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheSh0ckNvbnRlbnQpKSB7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IHRjIG9mIHRyQ29udGVudCkge1xuICAgICAgICAgICAgICBpZiAodGM/LnR5cGUgPT09IFwidGV4dFwiICYmIHRjLnRleHQpIHRleHQgKz0gKHRleHQgPyBcIlxcblwiIDogXCJcIikgKyB0Yy50ZXh0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIGlmIChjLnR5cGUgPT09IFwiaW1hZ2VfdXJsXCIgJiYgYy5pbWFnZV91cmw/LnVybCkge1xuICAgICAgICAgIGltYWdlcy5wdXNoKGMuaW1hZ2VfdXJsLnVybCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBFeHRyYWN0IHZhdWx0IGltYWdlIHBhdGhzIGZyb20gXCJGaWxlIHNhdmVkIGF0OlwiIGxpbmVzXG4gICAgY29uc3Qgc2F2ZWRBdFJlZ2V4ID0gL0ZpbGUgc2F2ZWQgYXQ6XFxzKiguKz9vcGVuY2xhdy1hdHRhY2htZW50c1xcL1teXFxzXFxuXSspL2c7XG4gICAgbGV0IG1hdGNoO1xuICAgIHdoaWxlICgobWF0Y2ggPSBzYXZlZEF0UmVnZXguZXhlYyh0ZXh0KSkgIT09IG51bGwpIHtcbiAgICAgIC8vIFRyeSB0byByZXNvbHZlIGFzIHZhdWx0LXJlbGF0aXZlIHBhdGhcbiAgICAgIGNvbnN0IGZ1bGxQYXRoID0gbWF0Y2hbMV0udHJpbSgpO1xuICAgICAgY29uc3QgdmF1bHRSZWxhdGl2ZSA9IGZ1bGxQYXRoLmluY2x1ZGVzKFwib3BlbmNsYXctYXR0YWNobWVudHMvXCIpXG4gICAgICAgID8gXCJvcGVuY2xhdy1hdHRhY2htZW50cy9cIiArIGZ1bGxQYXRoLnNwbGl0KFwib3BlbmNsYXctYXR0YWNobWVudHMvXCIpWzFdXG4gICAgICAgIDogbnVsbDtcbiAgICAgIGlmICh2YXVsdFJlbGF0aXZlKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgcmVzb3VyY2VQYXRoID0gdGhpcy5hcHAudmF1bHQuYWRhcHRlci5nZXRSZXNvdXJjZVBhdGgodmF1bHRSZWxhdGl2ZSk7XG4gICAgICAgICAgaWYgKHJlc291cmNlUGF0aCkgaW1hZ2VzLnB1c2gocmVzb3VyY2VQYXRoKTtcbiAgICAgICAgfSBjYXRjaCB7IC8qIGlnbm9yZSAqLyB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gRXh0cmFjdCBpbmxpbmUgZGF0YSBVUklzIGZyb20gdGV4dCAobGVnYWN5KVxuICAgIGNvbnN0IGRhdGFVcmlSZWdleCA9IC8oPzpefFxcbilkYXRhOihpbWFnZVxcL1teO10rKTtiYXNlNjQsW0EtWmEtejAtOSsvPVxcbl0rL2c7XG4gICAgd2hpbGUgKChtYXRjaCA9IGRhdGFVcmlSZWdleC5leGVjKHRleHQpKSAhPT0gbnVsbCkge1xuICAgICAgaW1hZ2VzLnB1c2gobWF0Y2hbMF0ucmVwbGFjZSgvXlxcbi8sIFwiXCIpLnRyaW0oKSk7XG4gICAgfVxuICAgIC8vIFJlbW92ZSBkYXRhIFVSSXMgZnJvbSB0ZXh0IGRpc3BsYXlcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9cXG4/ZGF0YTppbWFnZVxcL1teO10rO2Jhc2U2NCxbQS1aYS16MC05Ky89XFxuXSsvZywgXCJcIikudHJpbSgpO1xuICAgIC8vIFN0cmlwIFtBdHRhY2hlZCBpbWFnZTogLi4uXSBhbmQgXCJGaWxlIHNhdmVkIGF0OlwiIGxpbmVzXG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXlxcW0F0dGFjaGVkIGltYWdlOi4qP1xcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eRmlsZSBzYXZlZCBhdDouKiQvZ20sIFwiXCIpLnRyaW0oKTtcblxuICAgIC8vIFN0cmlwIGdhdGV3YXkgbWV0YWRhdGEgYmxvY2tzIChDb252ZXJzYXRpb24gaW5mbyArIEpTT04gY29kZSBibG9jaylcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9Db252ZXJzYXRpb24gaW5mbyBcXCh1bnRydXN0ZWQgbWV0YWRhdGFcXCk6XFxzKmBgYGpzb25bXFxzXFxTXSo/YGBgXFxzKi9nLCBcIlwiKS50cmltKCk7XG4gICAgLy8gU3RyaXAgYW55IHJlbWFpbmluZyBzdGFuZGFsb25lIG1ldGFkYXRhIEpTT04gYmxvY2tzXG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXmBgYGpzb25cXHMqXFx7XFxzKlwibWVzc2FnZV9pZFwiW1xcc1xcU10qP2BgYFxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCB0aW1lc3RhbXAgcHJlZml4ZXMgbGlrZSBcIltTdW4gMjAyNi0wMi0yMiAyMTo1OCBHTVQrN10gXCJcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eXFxbLio/R01UWystXVxcZCtcXF1cXHMqL2dtLCBcIlwiKS50cmltKCk7XG4gICAgLy8gU3RyaXAgbWVkaWEgYXR0YWNobWVudCBsaW5lc1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15cXFttZWRpYSBhdHRhY2hlZDouKj9cXF1cXHMqL2dtLCBcIlwiKS50cmltKCk7XG4gICAgLy8gU3RyaXAgXCJUbyBzZW5kIGFuIGltYWdlIGJhY2suLi5cIiBpbnN0cnVjdGlvbiBsaW5lc1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15UbyBzZW5kIGFuIGltYWdlIGJhY2suKiQvZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBcIk5PX1JFUExZXCIgcmVzcG9uc2VzXG4gICAgaWYgKHRleHQgPT09IFwiTk9fUkVQTFlcIiB8fCB0ZXh0ID09PSBcIkhFQVJUQkVBVF9PS1wiKSB0ZXh0ID0gXCJcIjtcbiAgICByZXR1cm4geyB0ZXh0LCBpbWFnZXMgfTtcbiAgfVxuXG4gIHByaXZhdGUgdXBkYXRlU2VuZEJ1dHRvbigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKSB8fCB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cmlidXRlKFwiYXJpYS1sYWJlbFwiLCBcIlNlbmRcIik7XG4gICAgICB0aGlzLnNlbmRCdG4ucmVtb3ZlQ2xhc3MoXCJvYy1vcGFjaXR5LWxvd1wiKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5zZW5kQnRuLnNldEF0dHJpYnV0ZShcImFyaWEtbGFiZWxcIiwgXCJTZW5kXCIpO1xuICAgICAgdGhpcy5zZW5kQnRuLmFkZENsYXNzKFwib2Mtb3BhY2l0eS1sb3dcIik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBzdGFydFJlY29yZGluZygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3Qgc3RyZWFtID0gYXdhaXQgbmF2aWdhdG9yLm1lZGlhRGV2aWNlcy5nZXRVc2VyTWVkaWEoeyBhdWRpbzogdHJ1ZSB9KTtcbiAgICAgIHRoaXMucmVjb3JkZWRDaHVua3MgPSBbXTtcblxuICAgICAgLy8gVHJ5IG9wdXMgZmlyc3QsIGZhbGwgYmFjayB0byBkZWZhdWx0XG4gICAgICBjb25zdCBtaW1lVHlwZSA9IE1lZGlhUmVjb3JkZXIuaXNUeXBlU3VwcG9ydGVkKFwiYXVkaW8vd2VibTtjb2RlY3M9b3B1c1wiKVxuICAgICAgICA/IFwiYXVkaW8vd2VibTtjb2RlY3M9b3B1c1wiXG4gICAgICAgIDogTWVkaWFSZWNvcmRlci5pc1R5cGVTdXBwb3J0ZWQoXCJhdWRpby93ZWJtXCIpXG4gICAgICAgID8gXCJhdWRpby93ZWJtXCJcbiAgICAgICAgOiBcIlwiO1xuXG4gICAgICB0aGlzLm1lZGlhUmVjb3JkZXIgPSBuZXcgTWVkaWFSZWNvcmRlcihzdHJlYW0sIG1pbWVUeXBlID8geyBtaW1lVHlwZSB9IDoge30pO1xuICAgICAgdGhpcy5tZWRpYVJlY29yZGVyLmFkZEV2ZW50TGlzdGVuZXIoXCJkYXRhYXZhaWxhYmxlXCIsIChlKSA9PiB7XG4gICAgICAgIGlmIChlLmRhdGEuc2l6ZSA+IDApIHRoaXMucmVjb3JkZWRDaHVua3MucHVzaChlLmRhdGEpO1xuICAgICAgfSk7XG4gICAgICB0aGlzLm1lZGlhUmVjb3JkZXIuYWRkRXZlbnRMaXN0ZW5lcihcInN0b3BcIiwgKCkgPT4ge1xuICAgICAgICBzdHJlYW0uZ2V0VHJhY2tzKCkuZm9yRWFjaCh0ID0+IHQuc3RvcCgpKTtcbiAgICAgICAgdm9pZCB0aGlzLmZpbmlzaFJlY29yZGluZygpO1xuICAgICAgfSk7XG5cbiAgICAgIHRoaXMubWVkaWFSZWNvcmRlci5zdGFydCgpO1xuICAgICAgdGhpcy5yZWNvcmRpbmcgPSB0cnVlO1xuICAgICAgdGhpcy51cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgICB0aGlzLmlucHV0RWwucGxhY2Vob2xkZXIgPSBcIlJlY29yZGluZy4uLiB0YXAgXHUyNUEwIHRvIHN0b3BcIjtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKFwiW09ic2lkaWFuQ2xhd10gTWljIGFjY2VzcyBmYWlsZWQ6XCIsIGUpO1xuICAgICAgbmV3IE5vdGljZShcIk1pY3JvcGhvbmUgYWNjZXNzIGRlbmllZFwiKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIHN0b3BSZWNvcmRpbmcoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMubWVkaWFSZWNvcmRlciAmJiB0aGlzLm1lZGlhUmVjb3JkZXIuc3RhdGUgIT09IFwiaW5hY3RpdmVcIikge1xuICAgICAgdGhpcy5tZWRpYVJlY29yZGVyLnN0b3AoKTtcbiAgICB9XG4gICAgdGhpcy5yZWNvcmRpbmcgPSBmYWxzZTtcbiAgICB0aGlzLnVwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB0aGlzLmlucHV0RWwucGxhY2Vob2xkZXIgPSBcIk1lc3NhZ2UuLi5cIjtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgZmluaXNoUmVjb3JkaW5nKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnJlY29yZGVkQ2h1bmtzLmxlbmd0aCA9PT0gMCkgcmV0dXJuO1xuICAgIGNvbnN0IGJsb2IgPSBuZXcgQmxvYih0aGlzLnJlY29yZGVkQ2h1bmtzLCB7IHR5cGU6IHRoaXMubWVkaWFSZWNvcmRlcj8ubWltZVR5cGUgfHwgXCJhdWRpby93ZWJtXCIgfSk7XG4gICAgdGhpcy5yZWNvcmRlZENodW5rcyA9IFtdO1xuXG4gICAgLy8gQ29udmVydCB0byBiYXNlNjRcbiAgICBjb25zdCBhcnJheUJ1ZiA9IGF3YWl0IGJsb2IuYXJyYXlCdWZmZXIoKTtcbiAgICBjb25zdCBieXRlcyA9IG5ldyBVaW50OEFycmF5KGFycmF5QnVmKTtcbiAgICBsZXQgYmluYXJ5ID0gXCJcIjtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGJ5dGVzLmxlbmd0aDsgaSsrKSBiaW5hcnkgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlc1tpXSk7XG4gICAgY29uc3QgYjY0ID0gYnRvYShiaW5hcnkpO1xuICAgIGNvbnN0IG1pbWUgPSBibG9iLnR5cGUgfHwgXCJhdWRpby93ZWJtXCI7XG5cbiAgICAvLyBVcGxvYWQgdG8gZ2F0ZXdheSBzdGF0aWMgZGlyIHZpYSB0aGUgYWdlbnQgKGV4ZWMpLCBhbmQgc2VuZCBWT0lDRTogcmVmXG4gICAgLy8gRm9yIG5vdzogc2VuZCBhcyBBVURJT19EQVRBIGluIG1lc3NhZ2UgdGV4dCwgYWdlbnQgaGFuZGxlcyB0cmFuc2NyaXB0aW9uXG4gICAgY29uc3QgbWFya2VyID0gYEFVRElPX0RBVEE6JHttaW1lfTtiYXNlNjQsJHtiNjR9YDtcblxuICAgIC8vIFNob3cgdm9pY2UgbWVzc2FnZSBpbiBsb2NhbCBVSVxuICAgIHRoaXMubWVzc2FnZXMucHVzaCh7IHJvbGU6IFwidXNlclwiLCB0ZXh0OiBcIlx1RDgzQ1x1REZBNCBWb2ljZSBtZXNzYWdlXCIsIGltYWdlczogW10sIHRpbWVzdGFtcDogRGF0ZS5ub3coKSB9KTtcbiAgICBhd2FpdCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG5cbiAgICAvLyBTZW5kIHRvIGdhdGV3YXlcbiAgICBjb25zdCBydW5JZCA9IGdlbmVyYXRlSWQoKTtcbiAgICBjb25zdCBzZW5kU2Vzc2lvbktleSA9IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcbiAgICBjb25zdCBzcyA9IHtcbiAgICAgIHJ1bklkLFxuICAgICAgdGV4dDogXCJcIiBhcyBzdHJpbmcgfCBudWxsLFxuICAgICAgdG9vbENhbGxzOiBbXSBhcyBzdHJpbmdbXSxcbiAgICAgIGl0ZW1zOiBbXSBhcyBTdHJlYW1JdGVtW10sXG4gICAgICBzcGxpdFBvaW50czogW10gYXMgbnVtYmVyW10sXG4gICAgICBsYXN0RGVsdGFUaW1lOiAwLFxuICAgICAgY29tcGFjdFRpbWVyOiBudWxsIGFzIFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCxcbiAgICAgIHdvcmtpbmdUaW1lcjogbnVsbCBhcyBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwsXG4gICAgfTtcbiAgICB0aGlzLnN0cmVhbXMuc2V0KHNlbmRTZXNzaW9uS2V5LCBzcyk7XG4gICAgdGhpcy5ydW5Ub1Nlc3Npb24uc2V0KHJ1bklkLCBzZW5kU2Vzc2lvbktleSk7XG4gICAgdGhpcy5hYm9ydEJ0bi5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIGNvbnN0IHRoaW5rVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcbiAgICBpZiAodGhpbmtUZXh0KSB0aGlua1RleHQudGV4dENvbnRlbnQgPSBcIlRoaW5raW5nXCI7XG4gICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkhLnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICBzZXNzaW9uS2V5OiBzZW5kU2Vzc2lvbktleSxcbiAgICAgICAgbWVzc2FnZTogbWFya2VyLFxuICAgICAgICBkZWxpdmVyOiBmYWxzZSxcbiAgICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgdGhpcy5tZXNzYWdlcy5wdXNoKHsgcm9sZTogXCJhc3Npc3RhbnRcIiwgdGV4dDogYEVycm9yOiAke2V9YCwgaW1hZ2VzOiBbXSwgdGltZXN0YW1wOiBEYXRlLm5vdygpIH0pO1xuICAgICAgdGhpcy5zdHJlYW1zLmRlbGV0ZShzZW5kU2Vzc2lvbktleSk7XG4gICAgICB0aGlzLnJ1blRvU2Vzc2lvbi5kZWxldGUocnVuSWQpO1xuICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIGF3YWl0IHRoaXMucmVuZGVyTWVzc2FnZXMoKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBsZXQgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgY29uc3QgaGFzQXR0YWNobWVudHMgPSB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5sZW5ndGggPiAwO1xuICAgIGlmICghdGV4dCAmJiAhaGFzQXR0YWNobWVudHMpIHJldHVybjtcbiAgICBpZiAodGhpcy5zZW5kaW5nKSByZXR1cm47XG4gICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHtcbiAgICAgIG5ldyBOb3RpY2UoXCJOb3QgY29ubmVjdGVkIHRvIE9wZW5DbGF3IGdhdGV3YXlcIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5zZW5kaW5nID0gdHJ1ZTtcbiAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSB0cnVlO1xuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9IFwiXCI7XG4gICAgdGhpcy5hdXRvUmVzaXplKCk7XG5cbiAgICAvLyBCdWlsZCBhdHRhY2htZW50cyBmb3IgZ2F0ZXdheVxuICAgIGxldCBmdWxsTWVzc2FnZSA9IHRleHQ7XG4gICAgY29uc3QgZGlzcGxheVRleHQgPSB0ZXh0O1xuICAgIGNvbnN0IHVzZXJJbWFnZXM6IHN0cmluZ1tdID0gW107XG4gICAgY29uc3QgZ2F0ZXdheUF0dGFjaG1lbnRzOiB7IHR5cGU6IHN0cmluZzsgbWltZVR5cGU6IHN0cmluZzsgY29udGVudDogc3RyaW5nIH1bXSA9IFtdO1xuICAgIGlmICh0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICBmb3IgKGNvbnN0IGF0dCBvZiB0aGlzLnBlbmRpbmdBdHRhY2htZW50cykge1xuICAgICAgICBpZiAoYXR0LmJhc2U2NCAmJiBhdHQubWltZVR5cGUpIHtcbiAgICAgICAgICAvLyBJbWFnZTogc2VuZCB2aWEgYXR0YWNobWVudHMgZmllbGQgKGdhdGV3YXkgc2F2ZXMgdG8gZGlzaylcbiAgICAgICAgICBnYXRld2F5QXR0YWNobWVudHMucHVzaCh7IHR5cGU6IFwiaW1hZ2VcIiwgbWltZVR5cGU6IGF0dC5taW1lVHlwZSwgY29udGVudDogYXR0LmJhc2U2NCB9KTtcbiAgICAgICAgICAvLyBTaG93IHByZXZpZXcgaW4gY2hhdCBoaXN0b3J5XG4gICAgICAgICAgdXNlckltYWdlcy5wdXNoKGBkYXRhOiR7YXR0Lm1pbWVUeXBlfTtiYXNlNjQsJHthdHQuYmFzZTY0fWApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIC8vIFRleHQgZmlsZXM6IGFwcGVuZCB0byBtZXNzYWdlIGFzIGJlZm9yZVxuICAgICAgICAgIGZ1bGxNZXNzYWdlID0gKGZ1bGxNZXNzYWdlID8gZnVsbE1lc3NhZ2UgKyBcIlxcblxcblwiIDogXCJcIikgKyBhdHQuY29udGVudDtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKCF0ZXh0KSB7XG4gICAgICAgIHRleHQgPSBgXHVEODNEXHVEQ0NFICR7dGhpcy5wZW5kaW5nQXR0YWNobWVudHMubWFwKGEgPT4gYS5uYW1lKS5qb2luKFwiLCBcIil9YDtcbiAgICAgICAgZnVsbE1lc3NhZ2UgPSB0ZXh0O1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nQXR0YWNobWVudHMgPSBbXTtcbiAgICAgIHRoaXMuYXR0YWNoUHJldmlld0VsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIH1cblxuICAgIHRoaXMubWVzc2FnZXMucHVzaCh7IHJvbGU6IFwidXNlclwiLCB0ZXh0OiBkaXNwbGF5VGV4dCB8fCB0ZXh0LCBpbWFnZXM6IHVzZXJJbWFnZXMsIHRpbWVzdGFtcDogRGF0ZS5ub3coKSB9KTtcbiAgICBhd2FpdCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG5cbiAgICBjb25zdCBydW5JZCA9IGdlbmVyYXRlSWQoKTtcbiAgICBjb25zdCBzZW5kU2Vzc2lvbktleSA9IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcblxuICAgIC8vIENyZWF0ZSBwZXItc2Vzc2lvbiBzdHJlYW0gc3RhdGVcbiAgICBjb25zdCBzcyA9IHtcbiAgICAgIHJ1bklkLFxuICAgICAgdGV4dDogXCJcIiBhcyBzdHJpbmcgfCBudWxsLFxuICAgICAgdG9vbENhbGxzOiBbXSBhcyBzdHJpbmdbXSxcbiAgICAgIGl0ZW1zOiBbXSBhcyBTdHJlYW1JdGVtW10sXG4gICAgICBzcGxpdFBvaW50czogW10gYXMgbnVtYmVyW10sXG4gICAgICBsYXN0RGVsdGFUaW1lOiAwLFxuICAgICAgY29tcGFjdFRpbWVyOiBudWxsIGFzIFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCxcbiAgICAgIHdvcmtpbmdUaW1lcjogbnVsbCBhcyBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwsXG4gICAgfTtcbiAgICB0aGlzLnN0cmVhbXMuc2V0KHNlbmRTZXNzaW9uS2V5LCBzcyk7XG4gICAgdGhpcy5ydW5Ub1Nlc3Npb24uc2V0KHJ1bklkLCBzZW5kU2Vzc2lvbktleSk7XG5cbiAgICAvLyBTaG93IFVJIGZvciBhY3RpdmUgdGFiXG4gICAgdGhpcy5hYm9ydEJ0bi5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIGNvbnN0IHRoaW5rVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcbiAgICBpZiAodGhpbmtUZXh0KSB0aGlua1RleHQudGV4dENvbnRlbnQgPSBcIlRoaW5raW5nXCI7XG4gICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuXG4gICAgLy8gRmFsbGJhY2s6IGlmIG5vIGV2ZW50cyBhdCBhbGwgYWZ0ZXIgMTVzLCBzaG93IGdlbmVyaWMgc3RhdHVzXG4gICAgc3MuY29tcGFjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICBjb25zdCBjdXJyZW50ID0gdGhpcy5zdHJlYW1zLmdldChzZW5kU2Vzc2lvbktleSk7XG4gICAgICBpZiAoY3VycmVudD8ucnVuSWQgPT09IHJ1bklkICYmICFjdXJyZW50LnRleHQpIHtcbiAgICAgICAgLy8gT25seSB1cGRhdGUgRE9NIGlmIHRoaXMgc2Vzc2lvbiBpcyBzdGlsbCBhY3RpdmUgdGFiXG4gICAgICAgIGlmICh0aGlzLmFjdGl2ZVNlc3Npb25LZXkgPT09IHNlbmRTZXNzaW9uS2V5KSB7XG4gICAgICAgICAgY29uc3QgdHQgPSB0aGlzLnR5cGluZ0VsLnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdHlwaW5nLXRleHRcIik7XG4gICAgICAgICAgaWYgKHR0ICYmIHR0LnRleHRDb250ZW50ID09PSBcIlRoaW5raW5nXCIpIHR0LnRleHRDb250ZW50ID0gXCJTdGlsbCB0aGlua2luZ1wiO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgMTUwMDApO1xuXG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHNlbmRQYXJhbXM6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0ge1xuICAgICAgICBzZXNzaW9uS2V5OiBzZW5kU2Vzc2lvbktleSxcbiAgICAgICAgbWVzc2FnZTogZnVsbE1lc3NhZ2UsXG4gICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICBpZGVtcG90ZW5jeUtleTogcnVuSWQsXG4gICAgICB9O1xuICAgICAgaWYgKGdhdGV3YXlBdHRhY2htZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHNlbmRQYXJhbXMuYXR0YWNobWVudHMgPSBnYXRld2F5QXR0YWNobWVudHM7XG4gICAgICB9XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwgc2VuZFBhcmFtcyk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgaWYgKHNzLmNvbXBhY3RUaW1lcikgY2xlYXJUaW1lb3V0KHNzLmNvbXBhY3RUaW1lcik7XG4gICAgICB0aGlzLm1lc3NhZ2VzLnB1c2goeyByb2xlOiBcImFzc2lzdGFudFwiLCB0ZXh0OiBgRXJyb3I6ICR7ZX1gLCBpbWFnZXM6IFtdLCB0aW1lc3RhbXA6IERhdGUubm93KCkgfSk7XG4gICAgICB0aGlzLnN0cmVhbXMuZGVsZXRlKHNlbmRTZXNzaW9uS2V5KTtcbiAgICAgIHRoaXMucnVuVG9TZXNzaW9uLmRlbGV0ZShydW5JZCk7XG4gICAgICB0aGlzLmFib3J0QnRuLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJNZXNzYWdlcygpO1xuICAgIH0gZmluYWxseSB7XG4gICAgICB0aGlzLnNlbmRpbmcgPSBmYWxzZTtcbiAgICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGZhbHNlO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGFib3J0TWVzc2FnZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBzcyA9IHRoaXMuYWN0aXZlU3RyZWFtO1xuICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkIHx8ICFzcykgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LmFib3J0XCIsIHtcbiAgICAgICAgc2Vzc2lvbktleTogdGhpcy5hY3RpdmVTZXNzaW9uS2V5LFxuICAgICAgICBydW5JZDogc3MucnVuSWQsXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHVwZGF0ZUNvbnRleHRNZXRlcigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJzZXNzaW9ucy5saXN0XCIsIHt9KSBhcyB7IHNlc3Npb25zPzogU2Vzc2lvbkluZm9bXSB9IHwgbnVsbDtcbiAgICAgIGNvbnN0IHNlc3Npb25zOiBTZXNzaW9uSW5mb1tdID0gcmVzdWx0Py5zZXNzaW9ucyB8fCBbXTtcbiAgICAgIC8vIEZpbmQgc2Vzc2lvbiBtYXRjaGluZyBjdXJyZW50IHNlc3Npb25LZXkgKHRyeSBleGFjdCBtYXRjaCwgdGhlbiB3aXRoIGFnZW50IHByZWZpeClcbiAgICAgIGNvbnN0IHNrID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSB8fCBcIm1haW5cIjtcbiAgICAgIGNvbnN0IHNlc3Npb24gPSBzZXNzaW9ucy5maW5kKChzOiBTZXNzaW9uSW5mbykgPT4gcy5rZXkgPT09IHNrKSB8fFxuICAgICAgICBzZXNzaW9ucy5maW5kKChzOiBTZXNzaW9uSW5mbykgPT4gcy5rZXkgPT09IGAke3RoaXMuYWdlbnRQcmVmaXh9JHtza31gKSB8fFxuICAgICAgICBzZXNzaW9ucy5maW5kKChzOiBTZXNzaW9uSW5mbykgPT4gcy5rZXkuZW5kc1dpdGgoYDoke3NrfWApKTtcbiAgICAgIGlmICghc2Vzc2lvbikgcmV0dXJuO1xuICAgICAgY29uc3QgdXNlZCA9IHNlc3Npb24udG90YWxUb2tlbnMgfHwgMDtcbiAgICAgIGNvbnN0IG1heCA9IHNlc3Npb24uY29udGV4dFRva2VucyB8fCAyMDAwMDA7XG4gICAgICBjb25zdCBwY3QgPSBNYXRoLm1pbigxMDAsIE1hdGgucm91bmQoKHVzZWQgLyBtYXgpICogMTAwKSk7XG4gICAgICB0aGlzLmNvbnRleHRGaWxsRWwuc2V0Q3NzU3R5bGVzKHsgd2lkdGg6IHBjdCArIFwiJVwiIH0pO1xuICAgICAgdGhpcy5jb250ZXh0RmlsbEVsLmNsYXNzTmFtZSA9IFwib3BlbmNsYXctY29udGV4dC1maWxsXCIgKyAocGN0ID4gODAgPyBcIiBvcGVuY2xhdy1jb250ZXh0LWhpZ2hcIiA6IHBjdCA+IDYwID8gXCIgb3BlbmNsYXctY29udGV4dC1taWRcIiA6IFwiXCIpO1xuICAgICAgdGhpcy5jb250ZXh0TGFiZWxFbC50ZXh0Q29udGVudCA9IGAke3BjdH0lYDtcbiAgICAgIC8vIFVwZGF0ZSBhY3RpdmUgdGFiIG1ldGVyIGJhclxuICAgICAgY29uc3QgYWN0aXZlRmlsbCA9IHRoaXMudGFiQmFyRWw/LnF1ZXJ5U2VsZWN0b3IoXCIub3BlbmNsYXctdGFiLmFjdGl2ZSAub3BlbmNsYXctdGFiLW1ldGVyLWZpbGxcIikgYXMgSFRNTEVsZW1lbnQ7XG4gICAgICBpZiAoYWN0aXZlRmlsbCkgYWN0aXZlRmlsbC5zZXRDc3NTdHlsZXMoeyB3aWR0aDogcGN0ICsgXCIlXCIgfSk7XG4gICAgICAvLyBVcGRhdGUgbW9kZWwgbGFiZWwgZnJvbSBzZXNzaW9uIGRhdGEgKGJ1dCBkb24ndCBvdmVyd3JpdGUgYSByZWNlbnQgbWFudWFsIHN3aXRjaClcbiAgICAgIGNvbnN0IGZ1bGxNb2RlbCA9IHNlc3Npb24ubW9kZWwgfHwgXCJcIjtcbiAgICAgIGNvbnN0IG1vZGVsQ29vbGRvd24gPSBEYXRlLm5vdygpIC0gdGhpcy5jdXJyZW50TW9kZWxTZXRBdCA8IDE1MDAwO1xuICAgICAgaWYgKGZ1bGxNb2RlbCAmJiBmdWxsTW9kZWwgIT09IHRoaXMuY3VycmVudE1vZGVsICYmICFtb2RlbENvb2xkb3duKSB7XG4gICAgICAgIHRoaXMuY3VycmVudE1vZGVsID0gZnVsbE1vZGVsO1xuICAgICAgICB0aGlzLnVwZGF0ZU1vZGVsUGlsbCgpO1xuICAgICAgfVxuICAgICAgLy8gVXBkYXRlIHNlc3Npb24gZGlzcGxheSBuYW1lIGZyb20gZ2F0ZXdheVxuICAgICAgaWYgKHNlc3Npb24uZGlzcGxheU5hbWUgJiYgc2Vzc2lvbi5kaXNwbGF5TmFtZSAhPT0gdGhpcy5jYWNoZWRTZXNzaW9uRGlzcGxheU5hbWUpIHtcbiAgICAgICAgdGhpcy5jYWNoZWRTZXNzaW9uRGlzcGxheU5hbWUgPSBzZXNzaW9uLmRpc3BsYXlOYW1lO1xuICAgICAgfVxuICAgICAgLy8gRGV0ZWN0IHNlc3Npb24gbGlzdCBjaGFuZ2VzIGFuZCByZS1yZW5kZXIgdGFicyB3aGVuIG5lZWRlZFxuICAgICAgY29uc3QgYWdlbnRQcmVmaXggPSB0aGlzLmFnZW50UHJlZml4O1xuICAgICAgY29uc3QgY3VycmVudFNlc3Npb25LZXlzID0gbmV3IFNldChcbiAgICAgICAgc2Vzc2lvbnMuZmlsdGVyKChzOiBTZXNzaW9uSW5mbykgPT4gcy5rZXkuc3RhcnRzV2l0aChhZ2VudFByZWZpeCkgJiYgIXMua2V5LmluY2x1ZGVzKFwiOmNyb246XCIpICYmICFzLmtleS5pbmNsdWRlcyhcIjpzdWJhZ2VudDpcIikpLm1hcCgoczogU2Vzc2lvbkluZm8pID0+IHMua2V5KVxuICAgICAgKTtcbiAgICAgIGNvbnN0IHRyYWNrZWRLZXlzID0gbmV3IFNldCh0aGlzLnRhYlNlc3Npb25zLm1hcCh0ID0+IGAke2FnZW50UHJlZml4fSR7dC5rZXl9YCkpO1xuICAgICAgY29uc3QgYWRkZWQgPSBbLi4uY3VycmVudFNlc3Npb25LZXlzXS5zb21lKGsgPT4gIXRyYWNrZWRLZXlzLmhhcyhrKSk7XG4gICAgICBjb25zdCByZW1vdmVkID0gWy4uLnRyYWNrZWRLZXlzXS5zb21lKGsgPT4gIWN1cnJlbnRTZXNzaW9uS2V5cy5oYXMoaykpO1xuICAgICAgaWYgKChhZGRlZCB8fCByZW1vdmVkKSAmJiAhdGhpcy50YWJEZWxldGVJblByb2dyZXNzKSB7XG4gICAgICAgIC8vIElmIHZpZXdpbmcgYSBzZXNzaW9uIHRoYXQgbm8gbG9uZ2VyIGV4aXN0cywgc3dpdGNoIGJhY2sgdG8gbWFpblxuICAgICAgICBpZiAocmVtb3ZlZCAmJiAhY3VycmVudFNlc3Npb25LZXlzLmhhcyhgJHthZ2VudFByZWZpeH0ke3NrfWApKSB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IFwibWFpblwiO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcbiAgICAgICAgICBhd2FpdCB0aGlzLmxvYWRIaXN0b3J5KCk7XG4gICAgICAgICAgdGhpcy51cGRhdGVTdGF0dXMoKTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIHsgLyogaWdub3JlICovIH1cbiAgfVxuXG4gIHVwZGF0ZU1vZGVsUGlsbCgpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMubW9kZWxMYWJlbEVsKSByZXR1cm47XG4gICAgY29uc3QgbW9kZWwgPSB0aGlzLmN1cnJlbnRNb2RlbCA/IHRoaXMuc2hvcnRNb2RlbE5hbWUodGhpcy5jdXJyZW50TW9kZWwpIDogXCJtb2RlbFwiO1xuICAgIHRoaXMubW9kZWxMYWJlbEVsLmVtcHR5KCk7XG4gICAgdGhpcy5tb2RlbExhYmVsRWwuY3JlYXRlU3Bhbih7IHRleHQ6IG1vZGVsLCBjbHM6IFwib3BlbmNsYXctY3R4LXBpbGwtdGV4dFwiIH0pO1xuICAgIHRoaXMubW9kZWxMYWJlbEVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIiBcdTI1QkVcIiwgY2xzOiBcIm9wZW5jbGF3LWN0eC1waWxsLWFycm93XCIgfSk7XG4gIH1cblxuICBhc3luYyByZW5kZXJUYWJzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICghdGhpcy50YWJCYXJFbCB8fCB0aGlzLnJlbmRlcmluZ1RhYnMpIHJldHVybjtcbiAgICB0aGlzLnJlbmRlcmluZ1RhYnMgPSB0cnVlO1xuICAgIHRyeSB7IGF3YWl0IHRoaXMuX3JlbmRlclRhYnNJbm5lcigpOyB9IGZpbmFsbHkgeyB0aGlzLnJlbmRlcmluZ1RhYnMgPSBmYWxzZTsgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfcmVuZGVyVGFic0lubmVyKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudGFiQmFyRWwuZW1wdHkoKTtcbiAgICBjb25zdCBjdXJyZW50S2V5ID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSB8fCBcIm1haW5cIjtcblxuICAgIC8vIEZldGNoIHNlc3Npb25zIGZyb20gZ2F0ZXdheVxuICAgIGxldCBzZXNzaW9uczogU2Vzc2lvbkluZm9bXSA9IFtdO1xuICAgIGlmICh0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcInNlc3Npb25zLmxpc3RcIiwge30pIGFzIHsgc2Vzc2lvbnM/OiBTZXNzaW9uSW5mb1tdIH0gfCBudWxsO1xuICAgICAgICBzZXNzaW9ucyA9IHJlc3VsdD8uc2Vzc2lvbnMgfHwgW107XG4gICAgICB9IGNhdGNoIHsgLyogdXNlIGVtcHR5ICovIH1cbiAgICB9XG5cbiAgICAvLyBGaWx0ZXI6IHNob3cgYWxsIGFnZW50IHNlc3Npb25zIGV4Y2VwdCBjcm9uIGFuZCBzdWItYWdlbnRzXG4gICAgY29uc3QgYWdlbnRQcmVmaXggPSB0aGlzLmFnZW50UHJlZml4O1xuICAgIGNvbnN0IGNvbnZTZXNzaW9ucyA9IHNlc3Npb25zLmZpbHRlcihzID0+IHtcbiAgICAgIGlmICghcy5rZXkuc3RhcnRzV2l0aChhZ2VudFByZWZpeCkpIHJldHVybiBmYWxzZTtcbiAgICAgIGlmIChzLmtleS5pbmNsdWRlcyhcIjpjcm9uOlwiKSkgcmV0dXJuIGZhbHNlO1xuICAgICAgaWYgKHMua2V5LmluY2x1ZGVzKFwiOnN1YmFnZW50OlwiKSkgcmV0dXJuIGZhbHNlO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSk7XG5cbiAgICAvLyBCdWlsZCB0YWIgbGlzdCBcdTIwMTQgZW5zdXJlIFwibWFpblwiIGlzIGFsd2F5cyBmaXJzdFxuICAgIHRoaXMudGFiU2Vzc2lvbnMgPSBbXTtcbiAgICBjb25zdCBtYWluU2Vzc2lvbiA9IGNvbnZTZXNzaW9ucy5maW5kKHMgPT4gcy5rZXkgPT09IGAke3RoaXMuYWdlbnRQcmVmaXh9bWFpbmApO1xuICAgIGlmIChtYWluU2Vzc2lvbikge1xuICAgICAgY29uc3QgdXNlZCA9IG1haW5TZXNzaW9uLnRvdGFsVG9rZW5zIHx8IDA7XG4gICAgICBjb25zdCBtYXggPSBtYWluU2Vzc2lvbi5jb250ZXh0VG9rZW5zIHx8IDIwMDAwMDtcbiAgICAgIHRoaXMudGFiU2Vzc2lvbnMucHVzaCh7IGtleTogXCJtYWluXCIsIGxhYmVsOiBcIk1haW5cIiwgcGN0OiBNYXRoLm1pbigxMDAsIE1hdGgucm91bmQoKHVzZWQgLyBtYXgpICogMTAwKSkgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMudGFiU2Vzc2lvbnMucHVzaCh7IGtleTogXCJtYWluXCIsIGxhYmVsOiBcIk1haW5cIiwgcGN0OiAwIH0pO1xuICAgIH1cblxuICAgIC8vIEFkZCBvdGhlciBzZXNzaW9ucyBpbiBjcmVhdGlvbiBvcmRlciAob2xkZXN0IGZpcnN0KVxuICAgIGNvbnN0IG90aGVycyA9IGNvbnZTZXNzaW9uc1xuICAgICAgLmZpbHRlcihzID0+IHMua2V5LnNsaWNlKGFnZW50UHJlZml4Lmxlbmd0aCkgIT09IFwibWFpblwiKVxuICAgICAgLnNvcnQoKGEsIGIpID0+IChhLmNyZWF0ZWRBdCB8fCBhLnVwZGF0ZWRBdCB8fCAwKSAtIChiLmNyZWF0ZWRBdCB8fCBiLnVwZGF0ZWRBdCB8fCAwKSk7XG4gICAgbGV0IG51bSA9IDE7XG4gICAgZm9yIChjb25zdCBzIG9mIG90aGVycykge1xuICAgICAgY29uc3Qgc2sgPSBzLmtleS5zbGljZShhZ2VudFByZWZpeC5sZW5ndGgpO1xuICAgICAgY29uc3QgdXNlZCA9IHMudG90YWxUb2tlbnMgfHwgMDtcbiAgICAgIGNvbnN0IG1heCA9IHMuY29udGV4dFRva2VucyB8fCAyMDAwMDA7XG4gICAgICBjb25zdCBwY3QgPSBNYXRoLm1pbigxMDAsIE1hdGgucm91bmQoKHVzZWQgLyBtYXgpICogMTAwKSk7XG4gICAgICBjb25zdCBsYWJlbCA9IHMubGFiZWwgfHwgcy5kaXNwbGF5TmFtZSB8fCBTdHJpbmcobnVtKTtcbiAgICAgIHRoaXMudGFiU2Vzc2lvbnMucHVzaCh7IGtleTogc2ssIGxhYmVsLCBwY3QgfSk7XG4gICAgICBudW0rKztcbiAgICB9XG5cbiAgICAvLyBSZW5kZXIgZWFjaCB0YWJcbiAgICBmb3IgKGNvbnN0IHRhYiBvZiB0aGlzLnRhYlNlc3Npb25zKSB7XG4gICAgICBjb25zdCBpc0N1cnJlbnQgPSB0YWIua2V5ID09PSBjdXJyZW50S2V5O1xuICAgICAgY29uc3QgdGFiQ2xzID0gYG9wZW5jbGF3LXRhYiR7aXNDdXJyZW50ID8gXCIgYWN0aXZlXCIgOiBcIlwifWA7XG4gICAgICBjb25zdCB0YWJFbCA9IHRoaXMudGFiQmFyRWwuY3JlYXRlRGl2KHsgY2xzOiB0YWJDbHMgfSk7XG5cbiAgICAgIC8vIFJvdzogbGFiZWwgKyBcdTAwRDcgKFx1MDBENyBwdXNoZWQgdG8gZmFyIHJpZ2h0IHZpYSBDU1MpXG4gICAgICBjb25zdCByb3cgPSB0YWJFbC5jcmVhdGVEaXYoeyBjbHM6IFwib3BlbmNsYXctdGFiLXJvd1wiIH0pO1xuICAgICAgY29uc3QgbGFiZWxTcGFuID0gcm93LmNyZWF0ZVNwYW4oeyB0ZXh0OiB0YWIubGFiZWwsIGNsczogXCJvcGVuY2xhdy10YWItbGFiZWxcIiB9KTtcblxuICAgICAgLy8gRG91YmxlLWNsaWNrIHRvIHJlbmFtZSAobm90IG1haW4pXG4gICAgICBpZiAodGFiLmtleSAhPT0gXCJtYWluXCIpIHtcbiAgICAgICAgbGFiZWxTcGFuLnRpdGxlID0gXCJEb3VibGUtY2xpY2sgdG8gcmVuYW1lXCI7XG4gICAgICAgIGxhYmVsU3Bhbi5hZGRFdmVudExpc3RlbmVyKFwiZGJsY2xpY2tcIiwgKGUpID0+IHtcbiAgICAgICAgICBlLnN0b3BQcm9wYWdhdGlvbigpO1xuICAgICAgICAgIGNvbnN0IGlucHV0ID0gY3JlYXRlRWwoXCJpbnB1dFwiLCB7IGNsczogXCJvcGVuY2xhdy10YWItbGFiZWwtaW5wdXRcIiB9KTtcbiAgICAgICAgICBpbnB1dC52YWx1ZSA9IHRhYi5sYWJlbDtcbiAgICAgICAgICBpbnB1dC5tYXhMZW5ndGggPSAzMDtcbiAgICAgICAgICBsYWJlbFNwYW4ucmVwbGFjZVdpdGgoaW5wdXQpO1xuICAgICAgICAgIGlucHV0LmZvY3VzKCk7XG4gICAgICAgICAgaW5wdXQuc2VsZWN0KCk7XG4gICAgICAgICAgY29uc3QgZmluaXNoID0gYXN5bmMgKHNhdmU6IGJvb2xlYW4pID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG5ld05hbWUgPSBpbnB1dC52YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBpZiAoc2F2ZSAmJiBuZXdOYW1lICYmIG5ld05hbWUgIT09IHRhYi5sYWJlbCkge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXk/LnJlcXVlc3QoXCJzZXNzaW9ucy5wYXRjaFwiLCB7XG4gICAgICAgICAgICAgICAgICBrZXk6IGAke3RoaXMuYWdlbnRQcmVmaXh9JHt0YWIua2V5fWAsXG4gICAgICAgICAgICAgICAgICBsYWJlbDogbmV3TmFtZSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB0YWIubGFiZWwgPSBuZXdOYW1lO1xuICAgICAgICAgICAgICB9IGNhdGNoIHsgLyoga2VlcCBvbGQgbmFtZSAqLyB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpbnB1dC5yZXBsYWNlV2l0aChsYWJlbFNwYW4pO1xuICAgICAgICAgICAgbGFiZWxTcGFuLnRleHRDb250ZW50ID0gdGFiLmxhYmVsO1xuICAgICAgICAgICAgdm9pZCB0aGlzLnJlbmRlclRhYnMoKTtcbiAgICAgICAgICB9O1xuICAgICAgICAgIGlucHV0LmFkZEV2ZW50TGlzdGVuZXIoXCJrZXlkb3duXCIsIChldjogS2V5Ym9hcmRFdmVudCkgPT4ge1xuICAgICAgICAgICAgaWYgKGV2LmtleSA9PT0gXCJFbnRlclwiKSB7IGV2LnByZXZlbnREZWZhdWx0KCk7IHZvaWQgZmluaXNoKHRydWUpOyB9XG4gICAgICAgICAgICBpZiAoZXYua2V5ID09PSBcIkVzY2FwZVwiKSB7IGV2LnByZXZlbnREZWZhdWx0KCk7IHZvaWQgZmluaXNoKGZhbHNlKTsgfVxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGlucHV0LmFkZEV2ZW50TGlzdGVuZXIoXCJibHVyXCIsICgpID0+IHZvaWQgZmluaXNoKHRydWUpKTtcbiAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIC8vIFx1MDBENyBidXR0b246IE1haW4gPSByZXNldCwgZXZlcnl0aGluZyBlbHNlID0gY2xvc2UvZGVsZXRlXG4gICAgICBjb25zdCBpc1Jlc2V0T25seSA9IHRhYi5rZXkgPT09IFwibWFpblwiO1xuICAgICAgY29uc3QgY2xvc2VCdG4gPSByb3cuY3JlYXRlU3Bhbih7IHRleHQ6IFwiXHUwMEQ3XCIsIGNsczogXCJvcGVuY2xhdy10YWItY2xvc2VcIiB9KTtcbiAgICAgIGlmIChpc1Jlc2V0T25seSkge1xuICAgICAgICBjbG9zZUJ0bi50aXRsZSA9IFwiUmVzZXQgY29udmVyc2F0aW9uXCI7XG4gICAgICAgIGNsb3NlQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoZSkgPT4geyBlLnN0b3BQcm9wYWdhdGlvbigpOyB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQpIHJldHVybjtcbiAgICAgICAgICAvLyBDb25maXJtIGJlZm9yZSByZXNldFxuICAgICAgICAgIGlmICghdGhpcy5pc0Nsb3NlQ29uZmlybURpc2FibGVkKCkpIHtcbiAgICAgICAgICAgIGNvbnN0IGNvbmZpcm1lZCA9IGF3YWl0IHRoaXMuY29uZmlybVRhYkNsb3NlKFwiUmVzZXQgbWFpbiB0YWI/XCIsIFwiVGhpcyB3aWxsIGNsZWFyIHRoZSBjb252ZXJzYXRpb24uXCIpO1xuICAgICAgICAgICAgaWYgKCFjb25maXJtZWQpIHJldHVybjtcbiAgICAgICAgICB9XG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImNoYXQuc2VuZFwiLCB7XG4gICAgICAgICAgICAgIHNlc3Npb25LZXk6IHRhYi5rZXksXG4gICAgICAgICAgICAgIG1lc3NhZ2U6IFwiL3Jlc2V0XCIsXG4gICAgICAgICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICAgICAgICBpZGVtcG90ZW5jeUtleTogXCJyZXNldC1cIiArIERhdGUubm93KCksXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIG5ldyBOb3RpY2UoYFJlc2V0OiAke3RhYi5sYWJlbH1gKTtcbiAgICAgICAgICAgIGlmICh0YWIua2V5ID09PSBjdXJyZW50S2V5KSB7XG4gICAgICAgICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5yZW5kZXJUYWJzKCk7XG4gICAgICAgICAgfSBjYXRjaCAoZXJyOiB1bmtub3duKSB7XG4gICAgICAgICAgICBuZXcgTm90aWNlKGBSZXNldCBmYWlsZWQ6ICR7ZXJyIGluc3RhbmNlb2YgRXJyb3IgPyBlcnIubWVzc2FnZSA6IFN0cmluZyhlcnIpfWApO1xuICAgICAgICAgIH1cbiAgICAgICAgfSkoKTsgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjbG9zZUJ0bi50aXRsZSA9IFwiQ2xvc2UgdGFiXCI7XG4gICAgICAgIGNsb3NlQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoZSkgPT4geyBlLnN0b3BQcm9wYWdhdGlvbigpOyB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nYXRld2F5Py5jb25uZWN0ZWQgfHwgdGhpcy50YWJEZWxldGVJblByb2dyZXNzKSByZXR1cm47XG4gICAgICAgICAgLy8gQ29uZmlybSBiZWZvcmUgY2xvc2VcbiAgICAgICAgICBpZiAoIXRoaXMuaXNDbG9zZUNvbmZpcm1EaXNhYmxlZCgpKSB7XG4gICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCB0aGlzLmNvbmZpcm1UYWJDbG9zZShcIkNsb3NlIHRhYj9cIiwgYENsb3NlIFwiJHt0YWIubGFiZWx9XCI/IENoYXQgaGlzdG9yeSB3aWxsIGJlIGxvc3QuYCk7XG4gICAgICAgICAgICBpZiAoIWNvbmZpcm1lZCkgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLnRhYkRlbGV0ZUluUHJvZ3Jlc3MgPSB0cnVlO1xuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBkZWxldGVkID0gYXdhaXQgZGVsZXRlU2Vzc2lvbldpdGhGYWxsYmFjayh0aGlzLnBsdWdpbi5nYXRld2F5LCBgJHt0aGlzLmFnZW50UHJlZml4fSR7dGFiLmtleX1gKTtcbiAgICAgICAgICAgIG5ldyBOb3RpY2UoZGVsZXRlZCA/IGBDbG9zZWQ6ICR7dGFiLmxhYmVsfWAgOiBgQ291bGQgbm90IGRlbGV0ZTogJHt0YWIubGFiZWx9YCk7XG4gICAgICAgICAgfSBjYXRjaCAoZXJyOiB1bmtub3duKSB7XG4gICAgICAgICAgICBuZXcgTm90aWNlKGBDbG9zZSBmYWlsZWQ6ICR7ZXJyIGluc3RhbmNlb2YgRXJyb3IgPyBlcnIubWVzc2FnZSA6IFN0cmluZyhlcnIpfWApO1xuICAgICAgICAgIH1cbiAgICAgICAgICAvLyBDbGVhbiB1cCBhbnkgc3RyZWFtIHN0YXRlIGZvciB0aGUgZGVsZXRlZCB0YWJcbiAgICAgICAgICB0aGlzLmZpbmlzaFN0cmVhbSh0YWIua2V5KTtcbiAgICAgICAgICAvLyBTd2l0Y2ggdG8gbWFpbiBpZiB3ZSBjbG9zZWQgdGhlIGFjdGl2ZSB0YWJcbiAgICAgICAgICBpZiAodGFiLmtleSA9PT0gY3VycmVudEtleSkge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IFwibWFpblwiO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgICAgICAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMubG9hZEhpc3RvcnkoKTtcbiAgICAgICAgICAgIHRoaXMucmVzdG9yZVN0cmVhbVVJKCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHRoaXMudGFiRGVsZXRlSW5Qcm9ncmVzcyA9IGZhbHNlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgICAgIGF3YWl0IHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICAgIH0pKCk7IH0pO1xuICAgICAgfVxuXG4gICAgICAvLyBQcm9ncmVzcyBiYXIgKGdyYXkgY29udGFpbmVyLCBibGFjayBmaWxsKVxuICAgICAgY29uc3QgbWV0ZXIgPSB0YWJFbC5jcmVhdGVEaXYoeyBjbHM6IFwib3BlbmNsYXctdGFiLW1ldGVyXCIgfSk7XG4gICAgICBjb25zdCBmaWxsID0gbWV0ZXIuY3JlYXRlRGl2KHsgY2xzOiBcIm9wZW5jbGF3LXRhYi1tZXRlci1maWxsXCIgfSk7XG4gICAgICBmaWxsLnNldENzc1N0eWxlcyh7IHdpZHRoOiB0YWIucGN0ICsgXCIlXCIgfSk7XG5cbiAgICAgIC8vIENsaWNrIHRvIHN3aXRjaFxuICAgICAgaWYgKCFpc0N1cnJlbnQpIHtcbiAgICAgICAgdGFiRWwuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAvLyBDbGVhciBET00gZnJvbSBvbGQgdGFiXG4gICAgICAgICAgdGhpcy5zdHJlYW1FbCA9IG51bGw7XG4gICAgICAgICAgdGhpcy50eXBpbmdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLmFib3J0QnRuLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgICAgIHRoaXMuaGlkZUJhbm5lcigpO1xuXG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHRhYi5rZXk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgICAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgICAgIHRoaXMuY2FjaGVkU2Vzc2lvbkRpc3BsYXlOYW1lID0gdGFiLmxhYmVsO1xuICAgICAgICAgIGF3YWl0IHRoaXMubG9hZEhpc3RvcnkoKTtcblxuICAgICAgICAgIC8vIFJlc3RvcmUgc3RyZWFtIFVJIGlmIG5ldyB0YWIgaGFzIGFuIGFjdGl2ZSBzdHJlYW1cbiAgICAgICAgICB0aGlzLnJlc3RvcmVTdHJlYW1VSSgpO1xuXG4gICAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgICAgICB2b2lkIHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgICAgIHRoaXMudXBkYXRlU3RhdHVzKCk7XG4gICAgICAgIH0pKCkpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vICsgYnV0dG9uIHRvIGFkZCBuZXcgdGFiXG4gICAgY29uc3QgYWRkQnRuID0gdGhpcy50YWJCYXJFbC5jcmVhdGVEaXYoeyBjbHM6IFwib3BlbmNsYXctdGFiIG9wZW5jbGF3LXRhYi1hZGRcIiB9KTtcbiAgICBhZGRCdG4uY3JlYXRlU3Bhbih7IHRleHQ6IFwiK1wiLCBjbHM6IFwib3BlbmNsYXctdGFiLWxhYmVsXCIgfSk7XG4gICAgYWRkQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAvLyBBdXRvLW5hbWU6IGZpbmQgbmV4dCBudW1iZXJcbiAgICAgIGNvbnN0IG51bXMgPSB0aGlzLnRhYlNlc3Npb25zLm1hcCh0ID0+IHBhcnNlSW50KHQubGFiZWwpKS5maWx0ZXIobiA9PiAhaXNOYU4obikpO1xuICAgICAgY29uc3QgbmV4dE51bSA9IG51bXMubGVuZ3RoID4gMCA/IE1hdGgubWF4KC4uLm51bXMpICsgMSA6IDE7XG4gICAgICBjb25zdCBzZXNzaW9uS2V5ID0gYHRhYi0ke25leHROdW19YDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXk/LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICAgIHNlc3Npb25LZXk6IHNlc3Npb25LZXksXG4gICAgICAgICAgbWVzc2FnZTogXCIvbmV3XCIsXG4gICAgICAgICAgZGVsaXZlcjogZmFsc2UsXG4gICAgICAgICAgaWRlbXBvdGVuY3lLZXk6IFwibmV3dGFiLVwiICsgRGF0ZS5ub3coKSxcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IG5ldyBQcm9taXNlKHIgPT4gc2V0VGltZW91dChyLCA1MDApKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5Py5yZXF1ZXN0KFwic2Vzc2lvbnMucGF0Y2hcIiwge1xuICAgICAgICAgICAga2V5OiBgJHt0aGlzLmFnZW50UHJlZml4fSR7c2Vzc2lvbktleX1gLFxuICAgICAgICAgICAgbGFiZWw6IFN0cmluZyhuZXh0TnVtKSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBjYXRjaCB7IC8qIGxhYmVsIG9wdGlvbmFsICovIH1cbiAgICAgICAgLy8gU3dpdGNoIHRvIGl0IC0gY2xlYXIgb2xkIHRhYidzIHN0cmVhbSBVSVxuICAgICAgICB0aGlzLnN0cmVhbUVsID0gbnVsbDtcbiAgICAgICAgdGhpcy50eXBpbmdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgdGhpcy5oaWRlQmFubmVyKCk7XG5cbiAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgaWYgKHRoaXMucGx1Z2luLnNldHRpbmdzLnN0cmVhbUl0ZW1zTWFwKSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zdHJlYW1JdGVtc01hcCA9IHt9O1xuICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICAgIGF3YWl0IHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgICBhd2FpdCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgICBuZXcgTm90aWNlKGBOZXcgdGFiOiAke25leHROdW19YCk7XG4gICAgICB9IGNhdGNoIChlcnI6IHVua25vd24pIHtcbiAgICAgICAgbmV3IE5vdGljZShgRmFpbGVkIHRvIGNyZWF0ZSB0YWI6ICR7ZXJyIGluc3RhbmNlb2YgRXJyb3IgPyBlcnIubWVzc2FnZSA6IFN0cmluZyhlcnIpfWApO1xuICAgICAgfVxuICAgIH0pKCkpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbmZpcm0gY2xvc2UgZGlhbG9nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgaXNDbG9zZUNvbmZpcm1EaXNhYmxlZCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oXCJvcGVuY2xhdy1jb25maXJtLWNsb3NlLWRpc2FibGVkXCIpID09PSBcInRydWVcIjtcbiAgfVxuXG4gIHByaXZhdGUgY29uZmlybVRhYkNsb3NlKHRpdGxlOiBzdHJpbmcsIG1zZzogc3RyaW5nKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgY29uc3QgbW9kYWwgPSBuZXcgQ29uZmlybUNsb3NlTW9kYWwodGhpcy5hcHAsIHRpdGxlLCBtc2csIChyZXN1bHQsIGRvbnRBc2spID0+IHtcbiAgICAgICAgaWYgKHJlc3VsdCAmJiBkb250QXNrKSB7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oXCJvcGVuY2xhdy1jb25maXJtLWNsb3NlLWRpc2FibGVkXCIsIFwidHJ1ZVwiKTtcbiAgICAgICAgfVxuICAgICAgICByZXNvbHZlKHJlc3VsdCk7XG4gICAgICB9KTtcbiAgICAgIG1vZGFsLm9wZW4oKTtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBUb3VjaCBnZXN0dXJlcyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGluaXRUb3VjaEdlc3R1cmVzKCk6IHZvaWQge1xuICAgIGxldCB0b3VjaFN0YXJ0WCA9IDA7XG4gICAgbGV0IHRvdWNoU3RhcnRZID0gMDtcbiAgICBsZXQgcHVsbGluZyA9IGZhbHNlO1xuXG4gICAgdGhpcy5tZXNzYWdlc0VsLmFkZEV2ZW50TGlzdGVuZXIoXCJ0b3VjaHN0YXJ0XCIsIChlOiBUb3VjaEV2ZW50KSA9PiB7XG4gICAgICB0b3VjaFN0YXJ0WCA9IGUudG91Y2hlc1swXS5jbGllbnRYO1xuICAgICAgdG91Y2hTdGFydFkgPSBlLnRvdWNoZXNbMF0uY2xpZW50WTtcbiAgICAgIHB1bGxpbmcgPSBmYWxzZTtcbiAgICB9LCB7IHBhc3NpdmU6IHRydWUgfSk7XG5cbiAgICB0aGlzLm1lc3NhZ2VzRWwuYWRkRXZlbnRMaXN0ZW5lcihcInRvdWNobW92ZVwiLCAoZTogVG91Y2hFdmVudCkgPT4ge1xuICAgICAgY29uc3QgZGVsdGFZID0gZS50b3VjaGVzWzBdLmNsaWVudFkgLSB0b3VjaFN0YXJ0WTtcbiAgICAgIGlmICh0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wIDw9IDAgJiYgZGVsdGFZID4gNjApIHtcbiAgICAgICAgcHVsbGluZyA9IHRydWU7XG4gICAgICB9XG4gICAgfSwgeyBwYXNzaXZlOiB0cnVlIH0pO1xuXG4gICAgdGhpcy5tZXNzYWdlc0VsLmFkZEV2ZW50TGlzdGVuZXIoXCJ0b3VjaGVuZFwiLCAoZTogVG91Y2hFdmVudCkgPT4ge1xuICAgICAgY29uc3QgZGVsdGFYID0gZS5jaGFuZ2VkVG91Y2hlc1swXS5jbGllbnRYIC0gdG91Y2hTdGFydFg7XG4gICAgICBjb25zdCBkZWx0YVkgPSBlLmNoYW5nZWRUb3VjaGVzWzBdLmNsaWVudFkgLSB0b3VjaFN0YXJ0WTtcblxuICAgICAgLy8gUHVsbC10by1yZWZyZXNoXG4gICAgICBpZiAocHVsbGluZykge1xuICAgICAgICBwdWxsaW5nID0gZmFsc2U7XG4gICAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICAgIHZvaWQgdGhpcy5sb2FkSGlzdG9yeSgpLnRoZW4oKCkgPT4gdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKSk7XG4gICAgICAgIG5ldyBOb3RpY2UoXCJSZWZyZXNoZWRcIik7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gU3dpcGUgYmV0d2VlbiB0YWJzXG4gICAgICBpZiAoTWF0aC5hYnMoZGVsdGFYKSA+IDgwICYmIE1hdGguYWJzKGRlbHRhWCkgPiBNYXRoLmFicyhkZWx0YVkpICogMS41KSB7XG4gICAgICAgIGNvbnN0IGN1cnJlbnRJZHggPSB0aGlzLnRhYlNlc3Npb25zLmZpbmRJbmRleCh0ID0+IHQua2V5ID09PSB0aGlzLmFjdGl2ZVNlc3Npb25LZXkpO1xuICAgICAgICBpZiAoY3VycmVudElkeCA8IDApIHJldHVybjtcbiAgICAgICAgY29uc3QgbmV4dElkeCA9IGRlbHRhWCA8IDAgPyBjdXJyZW50SWR4ICsgMSA6IGN1cnJlbnRJZHggLSAxO1xuICAgICAgICBpZiAobmV4dElkeCA+PSAwICYmIG5leHRJZHggPCB0aGlzLnRhYlNlc3Npb25zLmxlbmd0aCkge1xuICAgICAgICAgIGNvbnN0IHRhYiA9IHRoaXMudGFiU2Vzc2lvbnNbbmV4dElkeF07XG4gICAgICAgICAgdGhpcy5zdHJlYW1FbCA9IG51bGw7XG4gICAgICAgICAgdGhpcy50eXBpbmdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLmFib3J0QnRuLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgICAgIHRoaXMuaGlkZUJhbm5lcigpO1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB0YWIua2V5O1xuICAgICAgICAgIHZvaWQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgICAgICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuICAgICAgICAgIHRoaXMuY2FjaGVkU2Vzc2lvbkRpc3BsYXlOYW1lID0gdGFiLmxhYmVsO1xuICAgICAgICAgIHZvaWQgdGhpcy5sb2FkSGlzdG9yeSgpO1xuICAgICAgICAgIHZvaWQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgICAgICB2b2lkIHRoaXMucmVuZGVyVGFicygpO1xuICAgICAgICAgIHRoaXMudXBkYXRlU3RhdHVzKCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCB7IHBhc3NpdmU6IHRydWUgfSk7XG4gIH1cblxuICBwcml2YXRlIGNvbnRleHRDb2xvcihwY3Q6IG51bWJlcik6IHN0cmluZyB7XG4gICAgaWYgKHBjdCA+IDgwKSByZXR1cm4gXCIjYzQ0XCI7XG4gICAgaWYgKHBjdCA+IDYwKSByZXR1cm4gXCIjZDRhODQzXCI7XG4gICAgaWYgKHBjdCA+IDMwKSByZXR1cm4gXCIjN2E3XCI7XG4gICAgcmV0dXJuIFwiIzVhNVwiO1xuICB9XG5cbiAgYXN5bmMgcmVzZXRDdXJyZW50VGFiKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSByZXR1cm47XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImNoYXQuc2VuZFwiLCB7XG4gICAgICAgIHNlc3Npb25LZXk6IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXksXG4gICAgICAgIG1lc3NhZ2U6IFwiL3Jlc2V0XCIsXG4gICAgICAgIGRlbGl2ZXI6IGZhbHNlLFxuICAgICAgICBpZGVtcG90ZW5jeUtleTogXCJyZXNldC1cIiArIERhdGUubm93KCksXG4gICAgICB9KTtcbiAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zdHJlYW1JdGVtc01hcCkgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXAgPSB7fTtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICBhd2FpdCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJUYWJzKCk7XG4gICAgICBuZXcgTm90aWNlKFwiVGFiIHJlc2V0XCIpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIG5ldyBOb3RpY2UoYFJlc2V0IGZhaWxlZDogJHtlfWApO1xuICAgIH1cbiAgfVxuXG4gIG9wZW5Nb2RlbFBpY2tlcigpOiB2b2lkIHtcbiAgICBuZXcgTW9kZWxQaWNrZXJNb2RhbCh0aGlzLmFwcCwgdGhpcy5wbHVnaW4sIHRoaXMpLm9wZW4oKTtcbiAgfVxuXG4gIGFzeW5jIGNvbXBhY3RTZXNzaW9uKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICghdGhpcy5wbHVnaW4uZ2F0ZXdheT8uY29ubmVjdGVkKSByZXR1cm47XG4gICAgdHJ5IHtcbiAgICAgIHRoaXMuc2hvd0Jhbm5lcihcIkNvbXBhY3RpbmcgY29udGV4dC4uLlwiKTtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImNoYXQuc2VuZFwiLCB7XG4gICAgICAgIHNlc3Npb25LZXk6IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXksXG4gICAgICAgIG1lc3NhZ2U6IFwiL2NvbXBhY3RcIixcbiAgICAgICAgZGVsaXZlcjogZmFsc2UsXG4gICAgICAgIGlkZW1wb3RlbmN5S2V5OiBcImNvbXBhY3QtXCIgKyBEYXRlLm5vdygpLFxuICAgICAgfSk7XG4gICAgICAvLyBQb2xsIGNvbnRleHQgbWV0ZXIgdG8gYW5pbWF0ZSB0aGUgZGVjcmVhc2VcbiAgICAgIGNvbnN0IHBvbGxJbnRlcnZhbCA9IHNldEludGVydmFsKCgpID0+IHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgIH0pKCksIDIwMDApO1xuICAgICAgc2V0VGltZW91dCgoKSA9PiB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGNsZWFySW50ZXJ2YWwocG9sbEludGVydmFsKTtcbiAgICAgICAgdGhpcy5oaWRlQmFubmVyKCk7XG4gICAgICAgIGF3YWl0IHRoaXMubG9hZEhpc3RvcnkoKTtcbiAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVDb250ZXh0TWV0ZXIoKTtcbiAgICAgIH0pKCksIDEyMDAwKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcbiAgICAgIG5ldyBOb3RpY2UoYENvbXBhY3QgZmFpbGVkOiAke2V9YCk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgbmV3U2Vzc2lvbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5nYXRld2F5LnJlcXVlc3QoXCJjaGF0LnNlbmRcIiwge1xuICAgICAgICBzZXNzaW9uS2V5OiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgICBtZXNzYWdlOiBcIi9uZXdcIixcbiAgICAgICAgZGVsaXZlcjogZmFsc2UsXG4gICAgICAgIGlkZW1wb3RlbmN5S2V5OiBcIm5ldy1cIiArIERhdGUubm93KCksXG4gICAgICB9KTtcbiAgICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zdHJlYW1JdGVtc01hcCkgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXAgPSB7fTtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgICBhd2FpdCB0aGlzLnVwZGF0ZUNvbnRleHRNZXRlcigpO1xuICAgICAgbmV3IE5vdGljZShcIk5ldyBzZXNzaW9uIHN0YXJ0ZWRcIik7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgbmV3IE5vdGljZShgTmV3IHNlc3Npb24gZmFpbGVkOiAke2V9YCk7XG4gICAgfVxuICB9XG5cbiAgc2hvcnRNb2RlbE5hbWUoZnVsbElkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIC8vIFwiYW50aHJvcGljL2NsYXVkZS1vcHVzLTQtNlwiIC0+IFwib3B1cy00LTZcIiAoc2VsZWN0ZWQgZGlzcGxheSlcbiAgICAvLyBTdHJpcCBwcm92aWRlciBwcmVmaXgsIHN0cmlwIFwiY2xhdWRlLVwiIHByZWZpeCBmb3IgYnJldml0eVxuICAgIGNvbnN0IG1vZGVsID0gZnVsbElkLmluY2x1ZGVzKFwiL1wiKSA/IGZ1bGxJZC5zcGxpdChcIi9cIilbMV0gOiBmdWxsSWQ7XG4gICAgcmV0dXJuIG1vZGVsLnJlcGxhY2UoL15jbGF1ZGUtLywgXCJcIik7XG4gIH1cblxuXG5cblxuXG4gIGFzeW5jIGhhbmRsZUZpbGVTZWxlY3QoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZmlsZXMgPSB0aGlzLmZpbGVJbnB1dEVsLmZpbGVzO1xuICAgIGlmICghZmlsZXMgfHwgZmlsZXMubGVuZ3RoID09PSAwKSByZXR1cm47XG5cbiAgICBmb3IgKGNvbnN0IGZpbGUgb2YgQXJyYXkuZnJvbShmaWxlcykpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGlzSW1hZ2UgPSBmaWxlLnR5cGUuc3RhcnRzV2l0aChcImltYWdlL1wiKTtcbiAgICAgICAgY29uc3QgaXNUZXh0ID0gZmlsZS50eXBlLnN0YXJ0c1dpdGgoXCJ0ZXh0L1wiKSB8fFxuICAgICAgICAgIFtcImFwcGxpY2F0aW9uL2pzb25cIiwgXCJhcHBsaWNhdGlvbi95YW1sXCIsIFwiYXBwbGljYXRpb24veG1sXCIsIFwiYXBwbGljYXRpb24vamF2YXNjcmlwdFwiXS5pbmNsdWRlcyhmaWxlLnR5cGUpIHx8XG4gICAgICAgICAgL1xcLihtZHx0eHR8anNvbnxjc3Z8eWFtbHx5bWx8anN8dHN8cHl8aHRtbHxjc3N8eG1sfHRvbWx8aW5pfHNofGxvZykkL2kudGVzdChmaWxlLm5hbWUpO1xuXG4gICAgICAgIGlmIChpc0ltYWdlKSB7XG4gICAgICAgICAgY29uc3QgcmVzaXplZCA9IGF3YWl0IHRoaXMucmVzaXplSW1hZ2UoZmlsZSwgMjA0OCwgMC44NSk7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nQXR0YWNobWVudHMucHVzaCh7XG4gICAgICAgICAgICBuYW1lOiBmaWxlLm5hbWUsXG4gICAgICAgICAgICBjb250ZW50OiBgW0F0dGFjaGVkIGltYWdlOiAke2ZpbGUubmFtZX1dYCxcbiAgICAgICAgICAgIGJhc2U2NDogcmVzaXplZC5iYXNlNjQsXG4gICAgICAgICAgICBtaW1lVHlwZTogcmVzaXplZC5taW1lVHlwZSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIGlmIChpc1RleHQpIHtcbiAgICAgICAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgZmlsZS50ZXh0KCk7XG4gICAgICAgICAgY29uc3QgdHJ1bmNhdGVkID0gY29udGVudC5sZW5ndGggPiAxMDAwMCA/IGNvbnRlbnQuc2xpY2UoMCwgMTAwMDApICsgXCJcXG4uLi4odHJ1bmNhdGVkKVwiIDogY29udGVudDtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdBdHRhY2htZW50cy5wdXNoKHtcbiAgICAgICAgICAgIG5hbWU6IGZpbGUubmFtZSxcbiAgICAgICAgICAgIGNvbnRlbnQ6IGBGaWxlOiAke2ZpbGUubmFtZX1cXG5cXGBcXGBcXGBcXG4ke3RydW5jYXRlZH1cXG5cXGBcXGBcXGBgLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLnB1c2goe1xuICAgICAgICAgICAgbmFtZTogZmlsZS5uYW1lLFxuICAgICAgICAgICAgY29udGVudDogYFtBdHRhY2hlZCBmaWxlOiAke2ZpbGUubmFtZX0gKCR7ZmlsZS50eXBlIHx8IFwidW5rbm93biB0eXBlXCJ9LCAke01hdGgucm91bmQoZmlsZS5zaXplLzEwMjQpfUtCKV1gLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoYEZhaWxlZCB0byBhdHRhY2ggJHtmaWxlLm5hbWV9OiAke2V9YCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gVXBkYXRlIHByZXZpZXdcbiAgICB0aGlzLnJlbmRlckF0dGFjaFByZXZpZXcoKTtcbiAgICB0aGlzLmZpbGVJbnB1dEVsLnZhbHVlID0gXCJcIjtcbiAgfVxuXG4gIGFzeW5jIGhhbmRsZVBhc3RlZEZpbGUoZmlsZTogRmlsZSk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBleHQgPSBmaWxlLnR5cGUuc3BsaXQoXCIvXCIpWzFdIHx8IFwicG5nXCI7XG4gICAgICBjb25zdCByZXNpemVkID0gYXdhaXQgdGhpcy5yZXNpemVJbWFnZShmaWxlLCAyMDQ4LCAwLjg1KTtcbiAgICAgIHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLnB1c2goe1xuICAgICAgICBuYW1lOiBgY2xpcGJvYXJkLiR7ZXh0fWAsXG4gICAgICAgIGNvbnRlbnQ6IGBbQXR0YWNoZWQgaW1hZ2U6IGNsaXBib2FyZC4ke2V4dH1dYCxcbiAgICAgICAgYmFzZTY0OiByZXNpemVkLmJhc2U2NCxcbiAgICAgICAgbWltZVR5cGU6IHJlc2l6ZWQubWltZVR5cGUsXG4gICAgICB9KTtcbiAgICAgIHRoaXMucmVuZGVyQXR0YWNoUHJldmlldygpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIG5ldyBOb3RpY2UoYEZhaWxlZCB0byBwYXN0ZSBpbWFnZTogJHtlfWApO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgcmVzaXplSW1hZ2UoZmlsZTogRmlsZSwgbWF4U2lkZTogbnVtYmVyLCBxdWFsaXR5OiBudW1iZXIpOiBQcm9taXNlPHsgYmFzZTY0OiBzdHJpbmc7IG1pbWVUeXBlOiBzdHJpbmcgfT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBjb25zdCBpbWcgPSBuZXcgSW1hZ2UoKTtcbiAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoZmlsZSk7XG4gICAgICBpbWcub25sb2FkID0gKCkgPT4ge1xuICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7XG4gICAgICAgIGxldCB7IHdpZHRoLCBoZWlnaHQgfSA9IGltZztcbiAgICAgICAgaWYgKHdpZHRoID4gbWF4U2lkZSB8fCBoZWlnaHQgPiBtYXhTaWRlKSB7XG4gICAgICAgICAgY29uc3Qgc2NhbGUgPSBtYXhTaWRlIC8gTWF0aC5tYXgod2lkdGgsIGhlaWdodCk7XG4gICAgICAgICAgd2lkdGggPSBNYXRoLnJvdW5kKHdpZHRoICogc2NhbGUpO1xuICAgICAgICAgIGhlaWdodCA9IE1hdGgucm91bmQoaGVpZ2h0ICogc2NhbGUpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJjYW52YXNcIik7XG4gICAgICAgIGNhbnZhcy53aWR0aCA9IHdpZHRoO1xuICAgICAgICBjYW52YXMuaGVpZ2h0ID0gaGVpZ2h0O1xuICAgICAgICBjb25zdCBjdHggPSBjYW52YXMuZ2V0Q29udGV4dChcIjJkXCIpO1xuICAgICAgICBpZiAoIWN0eCkgeyByZWplY3QobmV3IEVycm9yKFwiTm8gY2FudmFzIGNvbnRleHRcIikpOyByZXR1cm47IH1cbiAgICAgICAgY3R4LmRyYXdJbWFnZShpbWcsIDAsIDAsIHdpZHRoLCBoZWlnaHQpO1xuICAgICAgICBjb25zdCBkYXRhVXJsID0gY2FudmFzLnRvRGF0YVVSTChcImltYWdlL2pwZWdcIiwgcXVhbGl0eSk7XG4gICAgICAgIGNvbnN0IGJhc2U2NCA9IGRhdGFVcmwuc3BsaXQoXCIsXCIpWzFdO1xuICAgICAgICByZXNvbHZlKHsgYmFzZTY0LCBtaW1lVHlwZTogXCJpbWFnZS9qcGVnXCIgfSk7XG4gICAgICB9O1xuICAgICAgaW1nLm9uZXJyb3IgPSAoKSA9PiB7IFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsgcmVqZWN0KG5ldyBFcnJvcihcIkZhaWxlZCB0byBsb2FkIGltYWdlXCIpKTsgfTtcbiAgICAgIGltZy5zcmMgPSB1cmw7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIHJlbmRlckF0dGFjaFByZXZpZXcoKTogdm9pZCB7XG4gICAgdGhpcy5hdHRhY2hQcmV2aWV3RWwuZW1wdHkoKTtcbiAgICBpZiAodGhpcy5wZW5kaW5nQXR0YWNobWVudHMubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aGlzLmF0dGFjaFByZXZpZXdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdGhpcy5hdHRhY2hQcmV2aWV3RWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBhdHQgPSB0aGlzLnBlbmRpbmdBdHRhY2htZW50c1tpXTtcbiAgICAgIGNvbnN0IGNoaXAgPSB0aGlzLmF0dGFjaFByZXZpZXdFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1hdHRhY2gtY2hpcFwiKTtcblxuICAgICAgLy8gU2hvdyB0aHVtYm5haWwgZm9yIGltYWdlc1xuICAgICAgaWYgKGF0dC5iYXNlNjQgJiYgYXR0Lm1pbWVUeXBlKSB7XG4gICAgICAgIGNvbnN0IHNyYyA9IGBkYXRhOiR7YXR0Lm1pbWVUeXBlfTtiYXNlNjQsJHthdHQuYmFzZTY0fWA7XG4gICAgICAgIGNoaXAuY3JlYXRlRWwoXCJpbWdcIiwgeyBjbHM6IFwib3BlbmNsYXctYXR0YWNoLXRodW1iXCIsIGF0dHI6IHsgc3JjIH0gfSk7XG4gICAgICB9IGVsc2UgaWYgKGF0dC52YXVsdFBhdGgpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCBzcmMgPSB0aGlzLmFwcC52YXVsdC5hZGFwdGVyLmdldFJlc291cmNlUGF0aChhdHQudmF1bHRQYXRoKTtcbiAgICAgICAgICBpZiAoc3JjKSBjaGlwLmNyZWF0ZUVsKFwiaW1nXCIsIHsgY2xzOiBcIm9wZW5jbGF3LWF0dGFjaC10aHVtYlwiLCBhdHRyOiB7IHNyYyB9IH0pO1xuICAgICAgICB9IGNhdGNoIHsgLyogaWdub3JlICovIH1cbiAgICAgIH1cblxuICAgICAgY2hpcC5jcmVhdGVTcGFuKHsgdGV4dDogYXR0Lm5hbWUsIGNsczogXCJvcGVuY2xhdy1hdHRhY2gtbmFtZVwiIH0pO1xuICAgICAgY29uc3QgcmVtb3ZlQnRuID0gY2hpcC5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiXHUyNzE1XCIsIGNsczogXCJvcGVuY2xhdy1hdHRhY2gtcmVtb3ZlXCIgfSk7XG4gICAgICBjb25zdCBpZHggPSBpO1xuICAgICAgcmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICAgIHRoaXMucGVuZGluZ0F0dGFjaG1lbnRzLnNwbGljZShpZHgsIDEpO1xuICAgICAgICB0aGlzLnJlbmRlckF0dGFjaFByZXZpZXcoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYnVpbGRUb29sTGFiZWwodG9vbE5hbWU6IHN0cmluZywgYXJnczogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gfCB1bmRlZmluZWQpOiB7IGxhYmVsOiBzdHJpbmc7IHVybD86IHN0cmluZyB9IHtcbiAgICBjb25zdCBhID0gYXJncyA/PyB7fTtcbiAgICBzd2l0Y2ggKHRvb2xOYW1lKSB7XG4gICAgICBjYXNlIFwiZXhlY1wiOiB7XG4gICAgICAgIGNvbnN0IGNtZCA9IHN0cihhPy5jb21tYW5kKTtcbiAgICAgICAgY29uc3Qgc2hvcnQgPSBjbWQubGVuZ3RoID4gNjAgPyBjbWQuc2xpY2UoMCwgNjApICsgXCJcdTIwMjZcIiA6IGNtZDtcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0RcdUREMjcgJHtzaG9ydCB8fCBcIlJ1bm5pbmcgY29tbWFuZFwifWAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJyZWFkXCI6IGNhc2UgXCJSZWFkXCI6IHtcbiAgICAgICAgY29uc3QgcCA9IHN0cihhPy5wYXRoLCBzdHIoYT8uZmlsZV9wYXRoKSk7XG4gICAgICAgIGNvbnN0IG5hbWUgPSBwLnNwbGl0KFwiL1wiKS5wb3AoKSB8fCBcImZpbGVcIjtcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0RcdURDQzQgUmVhZGluZyAke25hbWV9YCB9O1xuICAgICAgfVxuICAgICAgY2FzZSBcIndyaXRlXCI6IGNhc2UgXCJXcml0ZVwiOiB7XG4gICAgICAgIGNvbnN0IHAgPSBzdHIoYT8ucGF0aCwgc3RyKGE/LmZpbGVfcGF0aCkpO1xuICAgICAgICBjb25zdCBuYW1lID0gcC5zcGxpdChcIi9cIikucG9wKCkgfHwgXCJmaWxlXCI7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHUyNzBGXHVGRTBGIFdyaXRpbmcgJHtuYW1lfWAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJlZGl0XCI6IGNhc2UgXCJFZGl0XCI6IHtcbiAgICAgICAgY29uc3QgcCA9IHN0cihhPy5wYXRoLCBzdHIoYT8uZmlsZV9wYXRoKSk7XG4gICAgICAgIGNvbnN0IG5hbWUgPSBwLnNwbGl0KFwiL1wiKS5wb3AoKSB8fCBcImZpbGVcIjtcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdTI3MEZcdUZFMEYgRWRpdGluZyAke25hbWV9YCB9O1xuICAgICAgfVxuICAgICAgY2FzZSBcIndlYl9zZWFyY2hcIjoge1xuICAgICAgICBjb25zdCBxID0gc3RyKGE/LnF1ZXJ5KTtcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0RcdUREMEQgU2VhcmNoaW5nIFwiJHtxLmxlbmd0aCA+IDQwID8gcS5zbGljZSgwLCA0MCkgKyBcIlx1MjAyNlwiIDogcX1cImAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJ3ZWJfZmV0Y2hcIjoge1xuICAgICAgICBjb25zdCByYXdVcmwgPSBzdHIoYT8udXJsKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCBkb21haW4gPSBuZXcgVVJMKHJhd1VybCkuaG9zdG5hbWU7XG4gICAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0NcdURGMTAgRmV0Y2hpbmcgJHtkb21haW59YCwgdXJsOiByYXdVcmwgfTtcbiAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0NcdURGMTAgRmV0Y2hpbmcgcGFnZWAsIHVybDogcmF3VXJsIHx8IHVuZGVmaW5lZCB9O1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICBjYXNlIFwiYnJvd3NlclwiOlxuICAgICAgICByZXR1cm4geyBsYWJlbDogXCJcdUQ4M0NcdURGMTAgVXNpbmcgYnJvd3NlclwiIH07XG4gICAgICBjYXNlIFwiaW1hZ2VcIjpcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IFwiXHVEODNEXHVEQzQxXHVGRTBGIFZpZXdpbmcgaW1hZ2VcIiB9O1xuICAgICAgY2FzZSBcIm1lbW9yeV9zZWFyY2hcIjoge1xuICAgICAgICBjb25zdCBxID0gc3RyKGE/LnF1ZXJ5KTtcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IGBcdUQ4M0VcdURERTAgU2VhcmNoaW5nIFwiJHtxLmxlbmd0aCA+IDQwID8gcS5zbGljZSgwLCA0MCkgKyBcIlx1MjAyNlwiIDogcX1cImAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJtZW1vcnlfZ2V0XCI6IHtcbiAgICAgICAgY29uc3QgcCA9IHN0cihhPy5wYXRoKTtcbiAgICAgICAgY29uc3QgbmFtZSA9IHAuc3BsaXQoXCIvXCIpLnBvcCgpIHx8IFwibWVtb3J5XCI7XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBgXHVEODNFXHVEREUwIFJlYWRpbmcgJHtuYW1lfWAgfTtcbiAgICAgIH1cbiAgICAgIGNhc2UgXCJtZXNzYWdlXCI6XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBcIlx1RDgzRFx1RENBQyBTZW5kaW5nIG1lc3NhZ2VcIiB9O1xuICAgICAgY2FzZSBcInR0c1wiOlxuICAgICAgICByZXR1cm4geyBsYWJlbDogXCJcdUQ4M0RcdUREMEEgU3BlYWtpbmdcIiB9O1xuICAgICAgY2FzZSBcInNlc3Npb25zX3NwYXduXCI6XG4gICAgICAgIHJldHVybiB7IGxhYmVsOiBcIlx1RDgzRVx1REQxNiBTcGF3bmluZyBzdWItYWdlbnRcIiB9O1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIHsgbGFiZWw6IHRvb2xOYW1lID8gYFx1MjZBMSAke3Rvb2xOYW1lfWAgOiBcIldvcmtpbmdcIiB9O1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXBwZW5kVG9vbENhbGwobGFiZWw6IHN0cmluZywgdXJsPzogc3RyaW5nLCBhY3RpdmUgPSBmYWxzZSk6IHZvaWQge1xuICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcImRpdlwiKTtcbiAgICBlbC5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LXRvb2wtaXRlbVwiICsgKGFjdGl2ZSA/IFwiIG9wZW5jbGF3LXRvb2wtYWN0aXZlXCIgOiBcIlwiKTtcbiAgICBpZiAodXJsKSB7XG4gICAgICBjb25zdCBsaW5rID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcImFcIik7XG4gICAgICBsaW5rLmhyZWYgPSB1cmw7XG4gICAgICBsaW5rLnRleHRDb250ZW50ID0gbGFiZWw7XG4gICAgICBsaW5rLmNsYXNzTmFtZSA9IFwib3BlbmNsYXctdG9vbC1saW5rXCI7XG4gICAgICBsaW5rLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoZSkgPT4ge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHdpbmRvdy5vcGVuKHVybCwgXCJfYmxhbmtcIik7XG4gICAgICB9KTtcbiAgICAgIGVsLmFwcGVuZENoaWxkKGxpbmspO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25zdCBzcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcInNwYW5cIik7XG4gICAgICBzcGFuLnRleHRDb250ZW50ID0gbGFiZWw7XG4gICAgICBlbC5hcHBlbmRDaGlsZChzcGFuKTtcbiAgICB9XG4gICAgaWYgKGFjdGl2ZSkge1xuICAgICAgY29uc3QgZG90cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJzcGFuXCIpO1xuICAgICAgZG90cy5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LXRvb2wtZG90c1wiO1xuICAgICAgZG90cy5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuICAgICAgZG90cy5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuICAgICAgZG90cy5jcmVhdGVTcGFuKFwib3BlbmNsYXctZG90XCIpO1xuICAgICAgZWwuYXBwZW5kQ2hpbGQoZG90cyk7XG4gICAgfVxuICAgIHRoaXMubWVzc2FnZXNFbC5hcHBlbmRDaGlsZChlbCk7XG4gICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuICB9XG5cbiAgcHJpdmF0ZSBkZWFjdGl2YXRlTGFzdFRvb2xJdGVtKCk6IHZvaWQge1xuICAgIGNvbnN0IGl0ZW1zID0gdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3JBbGwoXCIub3BlbmNsYXctdG9vbC1hY3RpdmVcIik7XG4gICAgY29uc3QgbGFzdCA9IGl0ZW1zW2l0ZW1zLmxlbmd0aCAtIDFdO1xuICAgIGlmIChsYXN0KSB7XG4gICAgICBsYXN0LnJlbW92ZUNsYXNzKFwib3BlbmNsYXctdG9vbC1hY3RpdmVcIik7XG4gICAgICBjb25zdCBkb3RzID0gbGFzdC5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LXRvb2wtZG90c1wiKTtcbiAgICAgIGlmIChkb3RzKSBkb3RzLnJlbW92ZSgpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgcGxheVRUU0F1ZGlvKF9hdWRpb1BhdGg6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIExvY2FsIGZpbGUgc3lzdGVtIGFjY2VzcyBub3QgYXZhaWxhYmxlIGluIHRoZSBPYnNpZGlhbiBwbHVnaW4gc2FuZGJveC5cbiAgICAvLyBBdWRpbyBpcyBzdHJlYW1lZCB2aWEgZ2F0ZXdheSBIVFRQIHVzaW5nIHJlbmRlckF1ZGlvUGxheWVyIGluc3RlYWQuXG4gIH1cblxuICBwcml2YXRlIHNob3dCYW5uZXIodGV4dDogc3RyaW5nKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLmJhbm5lckVsKSByZXR1cm47XG4gICAgdGhpcy5iYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7XG4gICAgdGhpcy5iYW5uZXJFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgfVxuXG4gIHByaXZhdGUgaGlkZUJhbm5lcigpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuYmFubmVyRWwpIHJldHVybjtcbiAgICB0aGlzLmJhbm5lckVsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICB9XG5cbiAgLyoqIFJlc29sdmUgd2hpY2ggc2Vzc2lvbiBhIHN0cmVhbS9hZ2VudCBldmVudCBiZWxvbmdzIHRvICovXG4gIHByaXZhdGUgcmVzb2x2ZVN0cmVhbVNlc3Npb24ocGF5bG9hZDogR2F0ZXdheVBheWxvYWQpOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBUcnkgc2Vzc2lvbktleSBvbiBwYXlsb2FkIGZpcnN0XG4gICAgY29uc3Qgc2sgPSBzdHIocGF5bG9hZC5zZXNzaW9uS2V5KTtcbiAgICBpZiAoc2spIHtcbiAgICAgIC8vIE5vcm1hbGl6ZTogc3RyaXAgYWdlbnQ6bWFpbjogcHJlZml4XG4gICAgICBjb25zdCBwcmVmaXggPSB0aGlzLmFnZW50UHJlZml4O1xuICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IHNrLnN0YXJ0c1dpdGgocHJlZml4KSA/IHNrLnNsaWNlKHByZWZpeC5sZW5ndGgpIDogc2s7XG4gICAgICBpZiAodGhpcy5zdHJlYW1zLmhhcyhub3JtYWxpemVkKSkgcmV0dXJuIG5vcm1hbGl6ZWQ7XG4gICAgfVxuICAgIC8vIEZhbGwgYmFjayB0byBydW5JZCBtYXBwaW5nXG4gICAgY29uc3QgZGF0YSA9IHBheWxvYWQuZGF0YSBhcyBHYXRld2F5UGF5bG9hZCB8IHVuZGVmaW5lZDtcbiAgICBjb25zdCBydW5JZCA9IHN0cihwYXlsb2FkLnJ1bklkLCBzdHIoZGF0YT8ucnVuSWQpKTtcbiAgICBpZiAocnVuSWQgJiYgdGhpcy5ydW5Ub1Nlc3Npb24uaGFzKHJ1bklkKSkgcmV0dXJuIHRoaXMucnVuVG9TZXNzaW9uLmdldChydW5JZCkhO1xuICAgIC8vIExhc3QgcmVzb3J0OiBpZiBvbmx5IG9uZSBzdHJlYW0gaXMgYWN0aXZlLCB1c2UgdGhhdFxuICAgIGlmICh0aGlzLnN0cmVhbXMuc2l6ZSA9PT0gMSkgcmV0dXJuIHRoaXMuc3RyZWFtcy5rZXlzKCkubmV4dCgpLnZhbHVlITtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIGhhbmRsZVN0cmVhbUV2ZW50KHBheWxvYWQ6IEdhdGV3YXlQYXlsb2FkKTogdm9pZCB7XG4gICAgY29uc3Qgc3RyZWFtID0gc3RyKHBheWxvYWQuc3RyZWFtKTtcbiAgICBjb25zdCBzdGF0ZSA9IHN0cihwYXlsb2FkLnN0YXRlKTtcbiAgICBjb25zdCBwYXlsb2FkRGF0YSA9IHBheWxvYWQuZGF0YSBhcyBHYXRld2F5UGF5bG9hZCB8IHVuZGVmaW5lZDtcblxuICAgIGNvbnN0IHNlc3Npb25LZXkgPSB0aGlzLnJlc29sdmVTdHJlYW1TZXNzaW9uKHBheWxvYWQpO1xuICAgIGNvbnN0IGlzQWN0aXZlVGFiID0gc2Vzc2lvbktleSA9PT0gdGhpcy5hY3RpdmVTZXNzaW9uS2V5O1xuXG4gICAgLy8gQ29tcGFjdGlvbiBjYW4gYXJyaXZlIHdpdGhvdXQgYW4gYWN0aXZlIHN0cmVhbVxuICAgIGlmICghc2Vzc2lvbktleSB8fCAhdGhpcy5zdHJlYW1zLmhhcyhzZXNzaW9uS2V5KSkge1xuICAgICAgaWYgKHN0cmVhbSA9PT0gXCJjb21wYWN0aW9uXCIgfHwgc3RhdGUgPT09IFwiY29tcGFjdGluZ1wiKSB7XG4gICAgICAgIGNvbnN0IGNQaGFzZSA9IHN0cihwYXlsb2FkRGF0YT8ucGhhc2UpO1xuICAgICAgICBpZiAoaXNBY3RpdmVUYWIgfHwgIXNlc3Npb25LZXkpIHtcbiAgICAgICAgICBpZiAoY1BoYXNlID09PSBcImVuZFwiKSB7XG4gICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMuaGlkZUJhbm5lcigpLCAyMDAwKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5zaG93QmFubmVyKFwiQ29tcGFjdGluZyBjb250ZXh0Li4uXCIpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHNzID0gdGhpcy5zdHJlYW1zLmdldChzZXNzaW9uS2V5KSE7XG4gICAgY29uc3QgdHlwaW5nVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcblxuICAgIC8vIEFnZW50IFwiYXNzaXN0YW50XCIgZXZlbnRzID0gYWdlbnQgaXMgYWN0aXZlbHkgd29ya2luZ1xuICAgIGlmIChzdGF0ZSA9PT0gXCJhc3Npc3RhbnRcIikge1xuICAgICAgY29uc3QgdGltZVNpbmNlRGVsdGEgPSBEYXRlLm5vdygpIC0gc3MubGFzdERlbHRhVGltZTtcbiAgICAgIGlmIChzcy50ZXh0ICYmIHRpbWVTaW5jZURlbHRhID4gMTUwMCkge1xuICAgICAgICBpZiAoIXNzLndvcmtpbmdUaW1lcikge1xuICAgICAgICAgIHNzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMuc3RyZWFtcy5oYXMoc2Vzc2lvbktleSkpIHtcbiAgICAgICAgICAgICAgaWYgKGlzQWN0aXZlVGFiICYmIHRoaXMudHlwaW5nRWwuaGFzQ2xhc3MoXCJvYy1oaWRkZW5cIikpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwaW5nVGV4dCkgdHlwaW5nVGV4dC50ZXh0Q29udGVudCA9IFwiV29ya2luZ1wiO1xuICAgICAgICAgICAgICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHNzLndvcmtpbmdUaW1lciA9IG51bGw7XG4gICAgICAgICAgfSwgNTAwKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIGlmICghc3MudGV4dCAmJiAhc3MubGFzdERlbHRhVGltZSAmJiBpc0FjdGl2ZVRhYikge1xuICAgICAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoc3RhdGUgPT09IFwibGlmZWN5Y2xlXCIpIHtcbiAgICAgIGlmICghc3MudGV4dCAmJiBpc0FjdGl2ZVRhYiAmJiB0eXBpbmdUZXh0KSB7XG4gICAgICAgIHR5cGluZ1RleHQudGV4dENvbnRlbnQgPSBcIlRoaW5raW5nXCI7XG4gICAgICAgIHRoaXMudHlwaW5nRWwucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gSGFuZGxlIGV4cGxpY2l0IHRvb2wgZXZlbnRzXG4gICAgY29uc3QgdG9vbE5hbWUgPSBzdHIocGF5bG9hZERhdGE/Lm5hbWUsIHN0cihwYXlsb2FkRGF0YT8udG9vbE5hbWUsIHN0cihwYXlsb2FkLnRvb2xOYW1lLCBzdHIocGF5bG9hZC5uYW1lKSkpKTtcbiAgICBjb25zdCBwaGFzZSA9IHN0cihwYXlsb2FkRGF0YT8ucGhhc2UsIHN0cihwYXlsb2FkLnBoYXNlKSk7XG5cbiAgICBpZiAoKHN0cmVhbSA9PT0gXCJ0b29sXCIgfHwgdG9vbE5hbWUpICYmIChwaGFzZSA9PT0gXCJzdGFydFwiIHx8IHN0YXRlID09PSBcInRvb2xfdXNlXCIpKSB7XG4gICAgICBpZiAoc3MuY29tcGFjdFRpbWVyKSB7IGNsZWFyVGltZW91dChzcy5jb21wYWN0VGltZXIpOyBzcy5jb21wYWN0VGltZXIgPSBudWxsOyB9XG4gICAgICBpZiAoc3Mud29ya2luZ1RpbWVyKSB7IGNsZWFyVGltZW91dChzcy53b3JraW5nVGltZXIpOyBzcy53b3JraW5nVGltZXIgPSBudWxsOyB9XG4gICAgICBpZiAoc3MudGV4dCkge1xuICAgICAgICBzcy5zcGxpdFBvaW50cy5wdXNoKHNzLnRleHQubGVuZ3RoKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgbGFiZWwsIHVybCB9ID0gdGhpcy5idWlsZFRvb2xMYWJlbCh0b29sTmFtZSwgKHBheWxvYWREYXRhPy5hcmdzIHx8IHBheWxvYWQuYXJncykgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj4gfCB1bmRlZmluZWQpO1xuICAgICAgc3MudG9vbENhbGxzLnB1c2gobGFiZWwpO1xuICAgICAgc3MuaXRlbXMucHVzaCh7IHR5cGU6IFwidG9vbFwiLCBsYWJlbCwgdXJsIH0gYXMgU3RyZWFtSXRlbSk7XG4gICAgICBpZiAoaXNBY3RpdmVUYWIpIHtcbiAgICAgICAgdGhpcy5hcHBlbmRUb29sQ2FsbChsYWJlbCwgdXJsLCB0cnVlKTtcbiAgICAgICAgaWYgKHR5cGluZ1RleHQpIHR5cGluZ1RleHQudGV4dENvbnRlbnQgPSBsYWJlbDtcbiAgICAgICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKChzdHJlYW0gPT09IFwidG9vbFwiIHx8IHRvb2xOYW1lKSAmJiBwaGFzZSA9PT0gXCJyZXN1bHRcIikge1xuICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgIHRoaXMuZGVhY3RpdmF0ZUxhc3RUb29sSXRlbSgpO1xuICAgICAgICBpZiAodHlwaW5nVGV4dCkgdHlwaW5nVGV4dC50ZXh0Q29udGVudCA9IFwiVGhpbmtpbmdcIjtcbiAgICAgICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoc3RyZWFtID09PSBcImNvbXBhY3Rpb25cIiB8fCBzdGF0ZSA9PT0gXCJjb21wYWN0aW5nXCIpIHtcbiAgICAgIGlmIChwaGFzZSA9PT0gXCJlbmRcIikge1xuICAgICAgICBpZiAoaXNBY3RpdmVUYWIpIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5oaWRlQmFubmVyKCksIDIwMDApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgc3MudG9vbENhbGxzLnB1c2goXCJDb21wYWN0aW5nIG1lbW9yeVwiKTtcbiAgICAgICAgc3MuaXRlbXMucHVzaCh7IHR5cGU6IFwidG9vbFwiLCBsYWJlbDogXCJDb21wYWN0aW5nIG1lbW9yeVwiIH0pO1xuICAgICAgICBpZiAoaXNBY3RpdmVUYWIpIHtcbiAgICAgICAgICB0aGlzLmFwcGVuZFRvb2xDYWxsKFwiQ29tcGFjdGluZyBtZW1vcnlcIik7XG4gICAgICAgICAgdGhpcy50eXBpbmdFbC5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgICAgICB0aGlzLnNob3dCYW5uZXIoXCJDb21wYWN0aW5nIGNvbnRleHQuLi5cIik7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBoYW5kbGVDaGF0RXZlbnQocGF5bG9hZDogR2F0ZXdheVBheWxvYWQpOiB2b2lkIHtcbiAgICAvLyBSZXNvbHZlIHdoaWNoIHNlc3Npb24gdGhpcyBldmVudCBiZWxvbmdzIHRvXG4gICAgY29uc3QgcGF5bG9hZFNrID0gc3RyKHBheWxvYWQuc2Vzc2lvbktleSk7XG4gICAgY29uc3QgcHJlZml4ID0gdGhpcy5hZ2VudFByZWZpeDtcbiAgICBsZXQgZXZlbnRTZXNzaW9uS2V5OiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICAvLyBUcnkgdG8gbWF0Y2ggYWdhaW5zdCBrbm93biBzZXNzaW9uc1xuICAgIGZvciAoY29uc3Qgc2sgb2YgWy4uLnRoaXMuc3RyZWFtcy5rZXlzKCksIHRoaXMuYWN0aXZlU2Vzc2lvbktleV0pIHtcbiAgICAgIGlmIChwYXlsb2FkU2sgPT09IHNrIHx8IHBheWxvYWRTayA9PT0gYCR7cHJlZml4fSR7c2t9YCB8fCBwYXlsb2FkU2suZW5kc1dpdGgoYDoke3NrfWApKSB7XG4gICAgICAgIGV2ZW50U2Vzc2lvbktleSA9IHNrO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG4gICAgLy8gSWYgbm8gc3RyZWFtIG1hdGNoLCBjaGVjayBpZiBpdCdzIGZvciB0aGUgYWN0aXZlIHRhYiAocGFzc2l2ZSBkZXZpY2UgY2FzZSlcbiAgICBpZiAoIWV2ZW50U2Vzc2lvbktleSkge1xuICAgICAgY29uc3QgYWN0aXZlID0gdGhpcy5hY3RpdmVTZXNzaW9uS2V5O1xuICAgICAgaWYgKHBheWxvYWRTayA9PT0gYWN0aXZlIHx8IHBheWxvYWRTayA9PT0gYCR7cHJlZml4fSR7YWN0aXZlfWAgfHwgcGF5bG9hZFNrLmVuZHNXaXRoKGA6JHthY3RpdmV9YCkpIHtcbiAgICAgICAgZXZlbnRTZXNzaW9uS2V5ID0gYWN0aXZlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuOyAvLyBOb3QgZm9yIGFueSBrbm93biBzZXNzaW9uXG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qgc3MgPSB0aGlzLnN0cmVhbXMuZ2V0KGV2ZW50U2Vzc2lvbktleSk7XG4gICAgY29uc3QgaXNBY3RpdmVUYWIgPSBldmVudFNlc3Npb25LZXkgPT09IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcbiAgICBjb25zdCBjaGF0U3RhdGUgPSBzdHIocGF5bG9hZC5zdGF0ZSk7XG5cbiAgICAvLyBObyBhY3RpdmUgc3RyZWFtIGZvciB0aGlzIHNlc3Npb24gKHBhc3NpdmUgZGV2aWNlKTogc3RpbGwgcmVmcmVzaCBoaXN0b3J5XG4gICAgaWYgKCFzcyAmJiAoY2hhdFN0YXRlID09PSBcImZpbmFsXCIgfHwgY2hhdFN0YXRlID09PSBcImFib3J0ZWRcIiB8fCBjaGF0U3RhdGUgPT09IFwiZXJyb3JcIikpIHtcbiAgICAgIGlmIChpc0FjdGl2ZVRhYikge1xuICAgICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcbiAgICAgICAgdm9pZCB0aGlzLmxvYWRIaXN0b3J5KCk7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKGNoYXRTdGF0ZSA9PT0gXCJkZWx0YVwiICYmIHNzKSB7XG4gICAgICBpZiAoc3MuY29tcGFjdFRpbWVyKSB7IGNsZWFyVGltZW91dChzcy5jb21wYWN0VGltZXIpOyBzcy5jb21wYWN0VGltZXIgPSBudWxsOyB9XG4gICAgICBpZiAoc3Mud29ya2luZ1RpbWVyKSB7IGNsZWFyVGltZW91dChzcy53b3JraW5nVGltZXIpOyBzcy53b3JraW5nVGltZXIgPSBudWxsOyB9XG4gICAgICBzcy5sYXN0RGVsdGFUaW1lID0gRGF0ZS5ub3coKTtcbiAgICAgIGNvbnN0IHRleHQgPSB0aGlzLmV4dHJhY3REZWx0YVRleHQocGF5bG9hZC5tZXNzYWdlIGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+IHwgc3RyaW5nIHwgdW5kZWZpbmVkKTtcbiAgICAgIGlmICh0ZXh0KSB7XG4gICAgICAgIHNzLnRleHQgPSB0ZXh0O1xuICAgICAgICBpZiAoaXNBY3RpdmVUYWIpIHtcbiAgICAgICAgICB0aGlzLnR5cGluZ0VsLmFkZENsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgICAgICAgIHRoaXMuaGlkZUJhbm5lcigpO1xuICAgICAgICAgIHRoaXMudXBkYXRlU3RyZWFtQnViYmxlKCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKGNoYXRTdGF0ZSA9PT0gXCJmaW5hbFwiKSB7XG4gICAgICBjb25zdCBpdGVtcyA9IHNzID8gWy4uLnNzLml0ZW1zXSA6IFtdO1xuICAgICAgdGhpcy5maW5pc2hTdHJlYW0oZXZlbnRTZXNzaW9uS2V5KTtcblxuICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgIHZvaWQgdGhpcy5sb2FkSGlzdG9yeSgpLnRoZW4oYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGF3YWl0IHRoaXMucmVuZGVyTWVzc2FnZXMoKTtcbiAgICAgICAgICB2b2lkIHRoaXMudXBkYXRlQ29udGV4dE1ldGVyKCk7XG4gICAgICAgICAgaWYgKGl0ZW1zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIGNvbnN0IGxhc3RBc3Npc3RhbnQgPSBbLi4udGhpcy5tZXNzYWdlc10ucmV2ZXJzZSgpLmZpbmQobSA9PiBtLnJvbGUgPT09IFwiYXNzaXN0YW50XCIpO1xuICAgICAgICAgICAgaWYgKGxhc3RBc3Npc3RhbnQpIHtcbiAgICAgICAgICAgICAgY29uc3Qga2V5ID0gU3RyaW5nKGxhc3RBc3Npc3RhbnQudGltZXN0YW1wKTtcbiAgICAgICAgICAgICAgaWYgKCF0aGlzLnBsdWdpbi5zZXR0aW5ncy5zdHJlYW1JdGVtc01hcCkgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXAgPSB7fTtcbiAgICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc3RyZWFtSXRlbXNNYXBba2V5XSA9IGl0ZW1zO1xuICAgICAgICAgICAgICB2b2lkIHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBOb3QgYWN0aXZlIHRhYjoganVzdCBjbGVhbiB1cCwgaGlzdG9yeSB3aWxsIGxvYWQgd2hlbiB1c2VyIHN3aXRjaGVzIHRvIGl0XG4gICAgICB9XG4gICAgfSBlbHNlIGlmIChjaGF0U3RhdGUgPT09IFwiYWJvcnRlZFwiKSB7XG4gICAgICBpZiAoaXNBY3RpdmVUYWIgJiYgc3M/LnRleHQpIHtcbiAgICAgICAgdGhpcy5tZXNzYWdlcy5wdXNoKHsgcm9sZTogXCJhc3Npc3RhbnRcIiwgdGV4dDogc3MudGV4dCwgaW1hZ2VzOiBbXSwgdGltZXN0YW1wOiBEYXRlLm5vdygpIH0pO1xuICAgICAgfVxuICAgICAgdGhpcy5maW5pc2hTdHJlYW0oZXZlbnRTZXNzaW9uS2V5KTtcbiAgICAgIGlmIChpc0FjdGl2ZVRhYikgdm9pZCB0aGlzLnJlbmRlck1lc3NhZ2VzKCk7XG4gICAgfSBlbHNlIGlmIChjaGF0U3RhdGUgPT09IFwiZXJyb3JcIikge1xuICAgICAgaWYgKGlzQWN0aXZlVGFiKSB7XG4gICAgICAgIHRoaXMubWVzc2FnZXMucHVzaCh7XG4gICAgICAgICAgcm9sZTogXCJhc3Npc3RhbnRcIixcbiAgICAgICAgICB0ZXh0OiBgRXJyb3I6ICR7c3RyKHBheWxvYWQuZXJyb3JNZXNzYWdlLCBcInVua25vd24gZXJyb3JcIil9YCxcbiAgICAgICAgICBpbWFnZXM6IFtdLFxuICAgICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICB0aGlzLmZpbmlzaFN0cmVhbShldmVudFNlc3Npb25LZXkpO1xuICAgICAgaWYgKGlzQWN0aXZlVGFiKSB2b2lkIHRoaXMucmVuZGVyTWVzc2FnZXMoKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGZpbmlzaFN0cmVhbShzZXNzaW9uS2V5Pzogc3RyaW5nKTogdm9pZCB7XG4gICAgY29uc3Qgc2sgPSBzZXNzaW9uS2V5ID8/IHRoaXMuYWN0aXZlU2Vzc2lvbktleTtcbiAgICBjb25zdCBzcyA9IHRoaXMuc3RyZWFtcy5nZXQoc2spO1xuICAgIGlmIChzcykge1xuICAgICAgaWYgKHNzLmNvbXBhY3RUaW1lcikgY2xlYXJUaW1lb3V0KHNzLmNvbXBhY3RUaW1lcik7XG4gICAgICBpZiAoc3Mud29ya2luZ1RpbWVyKSBjbGVhclRpbWVvdXQoc3Mud29ya2luZ1RpbWVyKTtcbiAgICAgIHRoaXMucnVuVG9TZXNzaW9uLmRlbGV0ZShzcy5ydW5JZCk7XG4gICAgICB0aGlzLnN0cmVhbXMuZGVsZXRlKHNrKTtcbiAgICB9XG4gICAgLy8gT25seSBjbGVhciBET00gaWYgdGhpcyBpcyB0aGUgYWN0aXZlIHRhYlxuICAgIGlmIChzayA9PT0gdGhpcy5hY3RpdmVTZXNzaW9uS2V5KSB7XG4gICAgICB0aGlzLmhpZGVCYW5uZXIoKTtcbiAgICAgIHRoaXMuc3RyZWFtRWwgPSBudWxsO1xuICAgICAgdGhpcy5hYm9ydEJ0bi5hZGRDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICAgIHRoaXMudHlwaW5nRWwuYWRkQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG4gICAgICBjb25zdCB0eXBpbmdUZXh0ID0gdGhpcy50eXBpbmdFbC5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LXR5cGluZy10ZXh0XCIpO1xuICAgICAgaWYgKHR5cGluZ1RleHQpIHR5cGluZ1RleHQudGV4dENvbnRlbnQgPSBcIlRoaW5raW5nXCI7XG4gICAgfVxuICB9XG5cbiAgLyoqIFJlc3RvcmUgc3RyZWFtIFVJICh0eXBpbmcsIHRvb2wgY2FsbHMsIHN0cmVhbSBidWJibGUpIGZvciB0aGUgYWN0aXZlIHRhYiBhZnRlciBhIHRhYiBzd2l0Y2ggKi9cbiAgcHJpdmF0ZSByZXN0b3JlU3RyZWFtVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgc3MgPSB0aGlzLmFjdGl2ZVN0cmVhbTtcbiAgICBpZiAoIXNzKSByZXR1cm47XG5cbiAgICAvLyBTaG93IGFib3J0IGJ1dHRvblxuICAgIHRoaXMuYWJvcnRCdG4ucmVtb3ZlQ2xhc3MoXCJvYy1oaWRkZW5cIik7XG5cbiAgICAvLyBSZXN0b3JlIHRvb2wgY2FsbCBpdGVtcyBpbiB0aGUgRE9NXG4gICAgZm9yIChjb25zdCBpdGVtIG9mIHNzLml0ZW1zKSB7XG4gICAgICBpZiAoaXRlbS50eXBlID09PSBcInRvb2xcIikge1xuICAgICAgICB0aGlzLmFwcGVuZFRvb2xDYWxsKGl0ZW0ubGFiZWwsIGl0ZW0udXJsKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBSZXN0b3JlIHN0cmVhbSB0ZXh0IGJ1YmJsZSBpZiB3ZSBoYXZlIGRlbHRhIHRleHRcbiAgICBpZiAoc3MudGV4dCkge1xuICAgICAgdGhpcy51cGRhdGVTdHJlYW1CdWJibGUoKTtcbiAgICAgIC8vIElmIHRleHQgaXMgc3RyZWFtaW5nLCBzaG93IHdvcmtpbmcgaW5kaWNhdG9yICh0ZXh0IGV4aXN0cyBidXQgbWlnaHQgc3RpbGwgYmUgY29taW5nKVxuICAgICAgY29uc3QgdHlwaW5nVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcbiAgICAgIGlmICh0eXBpbmdUZXh0KSB0eXBpbmdUZXh0LnRleHRDb250ZW50ID0gXCJXb3JraW5nXCI7XG4gICAgICB0aGlzLnR5cGluZ0VsLnJlbW92ZUNsYXNzKFwib2MtaGlkZGVuXCIpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBObyB0ZXh0IHlldCwgc2hvdyB0aGlua2luZ1xuICAgICAgY29uc3QgdHlwaW5nVGV4dCA9IHRoaXMudHlwaW5nRWwucXVlcnlTZWxlY3RvcihcIi5vcGVuY2xhdy10eXBpbmctdGV4dFwiKTtcbiAgICAgIGlmICh0eXBpbmdUZXh0KSB0eXBpbmdUZXh0LnRleHRDb250ZW50ID0gXCJUaGlua2luZ1wiO1xuICAgICAgdGhpcy50eXBpbmdFbC5yZW1vdmVDbGFzcyhcIm9jLWhpZGRlblwiKTtcbiAgICB9XG5cbiAgICB0aGlzLnNjcm9sbFRvQm90dG9tKCk7XG4gIH1cblxuICBwcml2YXRlIGluc2VydFN0cmVhbUl0ZW1zQmVmb3JlTGFzdEFzc2lzdGFudChpdGVtczogU3RyZWFtSXRlbVtdKTogdm9pZCB7XG4gICAgaWYgKGl0ZW1zLmxlbmd0aCA9PT0gMCkgcmV0dXJuO1xuICAgIGNvbnN0IGJ1YmJsZXMgPSB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvckFsbChcIi5vcGVuY2xhdy1tc2ctYXNzaXN0YW50XCIpO1xuICAgIGNvbnN0IGxhc3RCdWJibGUgPSBidWJibGVzW2J1YmJsZXMubGVuZ3RoIC0gMV07XG4gICAgaWYgKCFsYXN0QnViYmxlKSByZXR1cm47XG5cbiAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgaXRlbXMpIHtcbiAgICAgIGNvbnN0IGVsID0gdGhpcy5jcmVhdGVTdHJlYW1JdGVtRWwoaXRlbSk7XG4gICAgICBsYXN0QnViYmxlLnBhcmVudEVsZW1lbnQ/Lmluc2VydEJlZm9yZShlbCwgbGFzdEJ1YmJsZSk7XG4gICAgfVxuICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTtcbiAgfVxuXG4gIHByaXZhdGUgY3JlYXRlU3RyZWFtSXRlbUVsKGl0ZW06IFN0cmVhbUl0ZW0pOiBIVE1MRWxlbWVudCB7XG4gICAgaWYgKGl0ZW0udHlwZSA9PT0gXCJ0b29sXCIpIHtcbiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcImRpdlwiKTtcbiAgICAgIGVsLmNsYXNzTmFtZSA9IFwib3BlbmNsYXctdG9vbC1pdGVtXCI7XG4gICAgICBpZiAoaXRlbS51cmwpIHtcbiAgICAgICAgY29uc3QgbGluayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJhXCIpO1xuICAgICAgICBsaW5rLmhyZWYgPSBpdGVtLnVybDtcbiAgICAgICAgbGluay50ZXh0Q29udGVudCA9IGl0ZW0ubGFiZWw7XG4gICAgICAgIGxpbmsuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy10b29sLWxpbmtcIjtcbiAgICAgICAgbGluay5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKGUpID0+IHsgZS5wcmV2ZW50RGVmYXVsdCgpOyB3aW5kb3cub3BlbihpdGVtLnVybCwgXCJfYmxhbmtcIik7IH0pO1xuICAgICAgICBlbC5hcHBlbmRDaGlsZChsaW5rKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGVsLnRleHRDb250ZW50ID0gaXRlbS5sYWJlbDtcbiAgICAgIH1cbiAgICAgIHJldHVybiBlbDtcbiAgICB9IGVsc2Uge1xuICAgICAgY29uc3QgZGV0YWlscyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJkZXRhaWxzXCIpO1xuICAgICAgZGV0YWlscy5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LWludGVybWVkaWFyeVwiO1xuICAgICAgY29uc3Qgc3VtbWFyeSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoXCJzdW1tYXJ5XCIpO1xuICAgICAgc3VtbWFyeS5jbGFzc05hbWUgPSBcIm9wZW5jbGF3LWludGVybWVkaWFyeS1zdW1tYXJ5XCI7XG4gICAgICBjb25zdCBwcmV2aWV3ID0gaXRlbS50ZXh0Lmxlbmd0aCA+IDYwID8gaXRlbS50ZXh0LnNsaWNlKDAsIDYwKSArIFwiLi4uXCIgOiBpdGVtLnRleHQ7XG4gICAgICBzdW1tYXJ5LnRleHRDb250ZW50ID0gcHJldmlldztcbiAgICAgIGRldGFpbHMuYXBwZW5kQ2hpbGQoc3VtbWFyeSk7XG4gICAgICBjb25zdCBjb250ZW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudChcImRpdlwiKTtcbiAgICAgIGNvbnRlbnQuY2xhc3NOYW1lID0gXCJvcGVuY2xhdy1pbnRlcm1lZGlhcnktY29udGVudFwiO1xuICAgICAgY29udGVudC50ZXh0Q29udGVudCA9IGl0ZW0udGV4dDtcbiAgICAgIGRldGFpbHMuYXBwZW5kQ2hpbGQoY29udGVudCk7XG4gICAgICByZXR1cm4gZGV0YWlscztcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGNsZWFuVGV4dCh0ZXh0OiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL0NvbnZlcnNhdGlvbiBpbmZvIFxcKHVudHJ1c3RlZCBtZXRhZGF0YVxcKTpcXHMqYGBganNvbltcXHNcXFNdKj9gYGBcXHMqL2csIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eYGBganNvblxccypcXHtcXHMqXCJtZXNzYWdlX2lkXCJbXFxzXFxTXSo/YGBgXFxzKi9nbSwgXCJcIikudHJpbSgpO1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15cXFsuKj9HTVRbKy1dXFxkK1xcXVxccyovZ20sIFwiXCIpLnRyaW0oKTtcbiAgICB0ZXh0ID0gdGV4dC5yZXBsYWNlKC9eXFxbbWVkaWEgYXR0YWNoZWQ6Lio/XFxdXFxzKi9nbSwgXCJcIikudHJpbSgpO1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15UbyBzZW5kIGFuIGltYWdlIGJhY2suKiQvZ20sIFwiXCIpLnRyaW0oKTtcbiAgICAvLyBTdHJpcCBUVFMgZGlyZWN0aXZlcyBhbmQgTUVESUE6IHBhdGhzIChyZW5kZXJlZCBhcyBhdWRpbyBwbGF5ZXJzIHNlcGFyYXRlbHkpXG4gICAgdGV4dCA9IHRleHQucmVwbGFjZSgvXlxcW1xcW2F1ZGlvX2FzX3ZvaWNlXFxdXFxdXFxzKi9nbSwgXCJcIikudHJpbSgpO1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15NRURJQTpcXC9bXlxcbl0rJC9nbSwgXCJcIikudHJpbSgpO1xuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15WT0lDRTpbXlxcc1xcbl0rJC9nbSwgXCJcIikudHJpbSgpO1xuICAgIC8vIFN0cmlwIGluYm91bmQgdm9pY2UgZGF0YSAoc2hvd24gYXMgXCJcdUQ4M0NcdURGQTQgVm9pY2UgbWVzc2FnZVwiIGluIFVJKVxuICAgIHRleHQgPSB0ZXh0LnJlcGxhY2UoL15BVURJT19EQVRBOlteXFxuXSskL2dtLCBcIlwiKS50cmltKCk7XG4gICAgaWYgKHRleHQgPT09IFwiXHVEODNDXHVERkE0IFZvaWNlIG1lc3NhZ2VcIikgdGV4dCA9IFwiXHVEODNDXHVERkE0IFZvaWNlIG1lc3NhZ2VcIjsgLy8ga2VlcCB0aGUgbGFiZWxcbiAgICBpZiAodGV4dCA9PT0gXCJOT19SRVBMWVwiIHx8IHRleHQgPT09IFwiSEVBUlRCRUFUX09LXCIpIHJldHVybiBcIlwiO1xuICAgIHJldHVybiB0ZXh0O1xuICB9XG5cbiAgLyoqIEV4dHJhY3QgVk9JQ0U6cGF0aCByZWZlcmVuY2VzIGZyb20gbWVzc2FnZSB0ZXh0ICovXG4gIHByaXZhdGUgZXh0cmFjdFZvaWNlUmVmcyh0ZXh0OiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gICAgY29uc3QgcmVmczogc3RyaW5nW10gPSBbXTtcbiAgICBjb25zdCByZSA9IC9eVk9JQ0U6KFteXFxzXFxuXStcXC4oPzptcDN8b3B1c3xvZ2d8d2F2fG00YXxtcDQpKSQvZ207XG4gICAgbGV0IG1hdGNoOiBSZWdFeHBFeGVjQXJyYXkgfCBudWxsO1xuICAgIHdoaWxlICgobWF0Y2ggPSByZS5leGVjKHRleHQpKSAhPT0gbnVsbCkge1xuICAgICAgcmVmcy5wdXNoKG1hdGNoWzFdLnRyaW0oKSk7XG4gICAgfVxuICAgIHJldHVybiByZWZzO1xuICB9XG5cbiAgLyoqIEJ1aWxkIEhUVFAgVVJMIGZvciBhIHZvaWNlIGZpbGUgc2VydmVkIGJ5IHRoZSBnYXRld2F5ICovXG4gIHByaXZhdGUgYnVpbGRWb2ljZVVybCh2b2ljZVBhdGg6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgLy8gR2F0ZXdheSBVUkwgaXMgd3M6Ly8gb3Igd3NzOi8vIFx1MjAxNCBjb252ZXJ0IHRvIGh0dHA6Ly8gb3IgaHR0cHM6Ly9cbiAgICBjb25zdCBnd1VybCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgfHwgXCJcIjtcbiAgICBjb25zdCBodHRwVXJsID0gZ3dVcmwucmVwbGFjZSgvXndzKHM/KTpcXC9cXC8vLCBcImh0dHAkMTovL1wiKTtcbiAgICByZXR1cm4gYCR7aHR0cFVybH0vJHt2b2ljZVBhdGh9YDtcbiAgfVxuXG4gIC8qKiBSZW5kZXIgYW4gaW5saW5lIGF1ZGlvIHBsYXllciB0aGF0IGZldGNoZXMgYXVkaW8gdmlhIGdhdGV3YXkgSFRUUCAqL1xuICBwcml2YXRlIHJlbmRlckF1ZGlvUGxheWVyKGNvbnRhaW5lcjogSFRNTEVsZW1lbnQsIHZvaWNlUmVmOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCBwbGF5ZXJFbCA9IGNvbnRhaW5lci5jcmVhdGVEaXYoXCJvcGVuY2xhdy1hdWRpby1wbGF5ZXJcIik7XG4gICAgY29uc3QgcGxheUJ0biA9IHBsYXllckVsLmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgY2xzOiBcIm9wZW5jbGF3LWF1ZGlvLXBsYXktYnRuXCIsIHRleHQ6IFwiXHUyNUI2IHZvaWNlIG1lc3NhZ2VcIiB9KTtcbiAgICBjb25zdCBwcm9ncmVzc0VsID0gcGxheWVyRWwuY3JlYXRlRGl2KFwib3BlbmNsYXctYXVkaW8tcHJvZ3Jlc3NcIik7XG4gICAgY29uc3QgYmFyRWwgPSBwcm9ncmVzc0VsLmNyZWF0ZURpdihcIm9wZW5jbGF3LWF1ZGlvLWJhclwiKTtcblxuICAgIGxldCBhdWRpbzogSFRNTEF1ZGlvRWxlbWVudCB8IG51bGwgPSBudWxsO1xuXG4gICAgcGxheUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGF1ZGlvICYmICFhdWRpby5wYXVzZWQpIHtcbiAgICAgICAgYXVkaW8ucGF1c2UoKTtcbiAgICAgICAgcGxheUJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNUI2IHZvaWNlIG1lc3NhZ2VcIjtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBpZiAoIWF1ZGlvKSB7XG4gICAgICAgIHBsYXlCdG4udGV4dENvbnRlbnQgPSBcIlx1MjNGMyBsb2FkaW5nLi4uXCI7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgdXJsID0gdGhpcy5idWlsZFZvaWNlVXJsKHZvaWNlUmVmKTtcbiAgICAgICAgICBjb25zb2xlLmRlYnVnKFwiW09ic2lkaWFuQ2xhd10gTG9hZGluZyBhdWRpbyBmcm9tOlwiLCB1cmwpO1xuICAgICAgICAgIGF1ZGlvID0gbmV3IEF1ZGlvKHVybCk7XG5cbiAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZTx2b2lkPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBjb25zdCB0aW1lciA9IHNldFRpbWVvdXQoKCkgPT4gcmVqZWN0KG5ldyBFcnJvcihcInRpbWVvdXRcIikpLCAxMDAwMCk7XG4gICAgICAgICAgICBhdWRpbyEuYWRkRXZlbnRMaXN0ZW5lcihcImNhbnBsYXl0aHJvdWdoXCIsICgpID0+IHsgY2xlYXJUaW1lb3V0KHRpbWVyKTsgcmVzb2x2ZSgpOyB9LCB7IG9uY2U6IHRydWUgfSk7XG4gICAgICAgICAgICBhdWRpbyEuYWRkRXZlbnRMaXN0ZW5lcihcImVycm9yXCIsICgpID0+IHsgY2xlYXJUaW1lb3V0KHRpbWVyKTsgcmVqZWN0KG5ldyBFcnJvcihcImxvYWQgZXJyb3JcIikpOyB9LCB7IG9uY2U6IHRydWUgfSk7XG4gICAgICAgICAgICBhdWRpbyEubG9hZCgpO1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgYXVkaW8uYWRkRXZlbnRMaXN0ZW5lcihcInRpbWV1cGRhdGVcIiwgKCkgPT4ge1xuICAgICAgICAgICAgaWYgKGF1ZGlvICYmIGF1ZGlvLmR1cmF0aW9uKSBiYXJFbC5zZXRDc3NTdHlsZXMoeyB3aWR0aDogYCR7KGF1ZGlvLmN1cnJlbnRUaW1lIC8gYXVkaW8uZHVyYXRpb24pICogMTAwfSVgIH0pO1xuICAgICAgICAgIH0pO1xuICAgICAgICAgIGF1ZGlvLmFkZEV2ZW50TGlzdGVuZXIoXCJlbmRlZFwiLCAoKSA9PiB7XG4gICAgICAgICAgICBwbGF5QnRuLnRleHRDb250ZW50ID0gXCJcdTI1QjYgdm9pY2UgbWVzc2FnZVwiO1xuICAgICAgICAgICAgYmFyRWwuc2V0Q3NzU3R5bGVzKHsgd2lkdGg6IFwiMCVcIiB9KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJbT2JzaWRpYW5DbGF3XSBBdWRpbyBsb2FkIGZhaWxlZDpcIiwgZSk7XG4gICAgICAgICAgcGxheUJ0bi50ZXh0Q29udGVudCA9IFwiXHUyNkEwIGF1ZGlvIHVuYXZhaWxhYmxlXCI7XG4gICAgICAgICAgcGxheUJ0bi5kaXNhYmxlZCA9IHRydWU7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHBsYXlCdG4udGV4dENvbnRlbnQgPSBcIlx1MjNGOCBwbGF5aW5nLi4uXCI7XG4gICAgICBhdWRpby5wbGF5KCkuY2F0Y2goKCkgPT4geyBwbGF5QnRuLnRleHRDb250ZW50ID0gXCJcdTI2QTAgYXVkaW8gdW5hdmFpbGFibGVcIjsgcGxheUJ0bi5kaXNhYmxlZCA9IHRydWU7IH0pO1xuICAgIH0pKCkpO1xuICB9XG5cbiAgcHJpdmF0ZSBleHRyYWN0RGVsdGFUZXh0KG1zZzogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gfCBzdHJpbmcgfCB1bmRlZmluZWQpOiBzdHJpbmcge1xuICAgIGlmICh0eXBlb2YgbXNnID09PSBcInN0cmluZ1wiKSByZXR1cm4gbXNnO1xuICAgIGlmICghbXNnKSByZXR1cm4gXCJcIjtcbiAgICAvLyBHYXRld2F5IHNlbmRzIHtyb2xlLCBjb250ZW50LCB0aW1lc3RhbXB9IHdoZXJlIGNvbnRlbnQgaXMgW3t0eXBlOlwidGV4dFwiLCB0ZXh0OlwiLi4uXCJ9XVxuICAgIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2c7XG4gICAgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICAgIGxldCB0ZXh0ID0gXCJcIjtcbiAgICAgIGZvciAoY29uc3QgYmxvY2sgb2YgY29udGVudCkge1xuICAgICAgICBpZiAodHlwZW9mIGJsb2NrID09PSBcInN0cmluZ1wiKSB7IHRleHQgKz0gYmxvY2s7IH1cbiAgICAgICAgZWxzZSBpZiAoYmxvY2sgJiYgdHlwZW9mIGJsb2NrID09PSBcIm9iamVjdFwiICYmIFwidGV4dFwiIGluIGJsb2NrKSB7IHRleHQgKz0gKHRleHQgPyBcIlxcblwiIDogXCJcIikgKyBTdHJpbmcoKGJsb2NrIGFzIHsgdGV4dDogc3RyaW5nIH0pLnRleHQpOyB9XG4gICAgICB9XG4gICAgICByZXR1cm4gdGV4dDtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBjb250ZW50ID09PSBcInN0cmluZ1wiKSByZXR1cm4gY29udGVudDtcbiAgICByZXR1cm4gc3RyKG1zZy50ZXh0KTtcbiAgfVxuXG4gIHByaXZhdGUgdXBkYXRlU3RyZWFtQnViYmxlKCk6IHZvaWQge1xuICAgIGNvbnN0IHNzID0gdGhpcy5hY3RpdmVTdHJlYW07XG4gICAgY29uc3QgdmlzaWJsZVRleHQgPSBzcz8udGV4dDtcbiAgICBpZiAoIXZpc2libGVUZXh0KSByZXR1cm47XG4gICAgaWYgKCF0aGlzLnN0cmVhbUVsKSB7XG4gICAgICB0aGlzLnN0cmVhbUVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW1zZyBvcGVuY2xhdy1tc2ctYXNzaXN0YW50IG9wZW5jbGF3LXN0cmVhbWluZ1wiKTtcbiAgICAgIHRoaXMuc2Nyb2xsVG9Cb3R0b20oKTsgLy8gU2Nyb2xsIG9uY2Ugd2hlbiBidWJibGUgZmlyc3QgYXBwZWFyc1xuICAgIH1cbiAgICB0aGlzLnN0cmVhbUVsLmVtcHR5KCk7XG4gICAgdGhpcy5zdHJlYW1FbC5jcmVhdGVEaXYoeyB0ZXh0OiB2aXNpYmxlVGV4dCwgY2xzOiBcIm9wZW5jbGF3LW1zZy10ZXh0XCIgfSk7XG4gICAgLy8gRG9uJ3QgYXV0by1zY3JvbGwgZHVyaW5nIHRleHQgc3RyZWFtaW5nIFx1MjAxNCBsZXQgdXNlciByZWFkIGZyb20gdGhlIHRvcFxuICB9XG5cbiAgYXN5bmMgcmVuZGVyTWVzc2FnZXMoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG4gICAgZm9yIChjb25zdCBtc2cgb2YgdGhpcy5tZXNzYWdlcykge1xuICAgICAgaWYgKG1zZy5yb2xlID09PSBcImFzc2lzdGFudFwiKSB7XG4gICAgICAgIGNvbnN0IGhhc0NvbnRlbnRUb29scyA9IG1zZy5jb250ZW50QmxvY2tzPy5zb21lKChiOiBDb250ZW50QmxvY2spID0+IGIudHlwZSA9PT0gXCJ0b29sX3VzZVwiIHx8IGIudHlwZSA9PT0gXCJ0b29sQ2FsbFwiKSB8fCBmYWxzZTtcblxuICAgICAgICBpZiAoaGFzQ29udGVudFRvb2xzICYmIG1zZy5jb250ZW50QmxvY2tzKSB7XG4gICAgICAgICAgLy8gUmVuZGVyIGludGVybGVhdmVkIHRleHQgKyB0b29sIGJsb2NrcyBkaXJlY3RseVxuICAgICAgICAgIGZvciAoY29uc3QgYmxvY2sgb2YgbXNnLmNvbnRlbnRCbG9ja3MpIHtcbiAgICAgICAgICAgIGlmIChibG9jay50eXBlID09PSBcInRleHRcIiAmJiBibG9jay50ZXh0Py50cmltKCkpIHtcbiAgICAgICAgICAgICAgY29uc3QgYmxvY2tBdWRpbyA9IHRoaXMuZXh0cmFjdFZvaWNlUmVmcyhibG9jay50ZXh0KTtcbiAgICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHRoaXMuY2xlYW5UZXh0KGJsb2NrLnRleHQpO1xuICAgICAgICAgICAgICAvLyBSZW5kZXIgdGV4dCBidWJibGUgaWYgdGhlcmUncyB2aXNpYmxlIHRleHRcbiAgICAgICAgICAgICAgaWYgKGNsZWFuZWQpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBidWJibGUgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KFwib3BlbmNsYXctbXNnIG9wZW5jbGF3LW1zZy1hc3Npc3RhbnRcIik7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGF3YWl0IE1hcmtkb3duUmVuZGVyZXIucmVuZGVyKHRoaXMuYXBwLCBjbGVhbmVkLCBidWJibGUsIFwiXCIsIHRoaXMpO1xuICAgICAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgYnViYmxlLmNyZWF0ZURpdih7IHRleHQ6IGNsZWFuZWQsIGNsczogXCJvcGVuY2xhdy1tc2ctdGV4dFwiIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBBdWRpbyBwbGF5ZXJzIGluc2lkZSB0ZXh0IGJ1YmJsZVxuICAgICAgICAgICAgICAgIGZvciAoY29uc3QgYXAgb2YgYmxvY2tBdWRpbykge1xuICAgICAgICAgICAgICAgICAgdGhpcy5yZW5kZXJBdWRpb1BsYXllcihidWJibGUsIGFwKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gZWxzZSBpZiAoYmxvY2tBdWRpby5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgLy8gTm8gdmlzaWJsZSB0ZXh0IGJ1dCBoYXMgYXVkaW8gXHUyMDE0IGNyZWF0ZSBhIGJ1YmJsZSBqdXN0IGZvciB0aGUgcGxheWVyXG4gICAgICAgICAgICAgICAgY29uc3QgYnViYmxlID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdihcIm9wZW5jbGF3LW1zZyBvcGVuY2xhdy1tc2ctYXNzaXN0YW50XCIpO1xuICAgICAgICAgICAgICAgIGZvciAoY29uc3QgYXAgb2YgYmxvY2tBdWRpbykge1xuICAgICAgICAgICAgICAgICAgdGhpcy5yZW5kZXJBdWRpb1BsYXllcihidWJibGUsIGFwKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSBpZiAoYmxvY2sudHlwZSA9PT0gXCJ0b29sX3VzZVwiIHx8IGJsb2NrLnR5cGUgPT09IFwidG9vbENhbGxcIikge1xuICAgICAgICAgICAgICBjb25zdCB7IGxhYmVsLCB1cmwgfSA9IHRoaXMuYnVpbGRUb29sTGFiZWwoYmxvY2submFtZSB8fCBcIlwiLCBibG9jay5pbnB1dCB8fCBibG9jay5hcmd1bWVudHMgfHwge30pO1xuICAgICAgICAgICAgICBjb25zdCBlbCA9IHRoaXMuY3JlYXRlU3RyZWFtSXRlbUVsKHsgdHlwZTogXCJ0b29sXCIsIGxhYmVsLCB1cmwgfSBhcyBTdHJlYW1JdGVtKTtcbiAgICAgICAgICAgICAgdGhpcy5tZXNzYWdlc0VsLmFwcGVuZENoaWxkKGVsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgfVxuICAgICAgY29uc3QgY2xzID0gbXNnLnJvbGUgPT09IFwidXNlclwiID8gXCJvcGVuY2xhdy1tc2ctdXNlclwiIDogXCJvcGVuY2xhdy1tc2ctYXNzaXN0YW50XCI7XG4gICAgICBjb25zdCBidWJibGUgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KGBvcGVuY2xhdy1tc2cgJHtjbHN9YCk7XG4gICAgICAvLyBSZW5kZXIgaW1hZ2VzXG4gICAgICBpZiAobXNnLmltYWdlcyAmJiBtc2cuaW1hZ2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgY29uc3QgaW1nQ29udGFpbmVyID0gYnViYmxlLmNyZWF0ZURpdihcIm9wZW5jbGF3LW1zZy1pbWFnZXNcIik7XG4gICAgICAgIGZvciAoY29uc3Qgc3JjIG9mIG1zZy5pbWFnZXMpIHtcbiAgICAgICAgICBjb25zdCBpbWcgPSBpbWdDb250YWluZXIuY3JlYXRlRWwoXCJpbWdcIiwge1xuICAgICAgICAgICAgY2xzOiBcIm9wZW5jbGF3LW1zZy1pbWdcIixcbiAgICAgICAgICAgIGF0dHI6IHsgc3JjLCBsb2FkaW5nOiBcImxhenlcIiB9LFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGltZy5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgICAgICAgLy8gT3BlbiBmdWxsLXNpemUgaW4gYSBtb2RhbC1saWtlIG92ZXJsYXlcbiAgICAgICAgICAgIGNvbnN0IG92ZXJsYXkgPSBkb2N1bWVudC5ib2R5LmNyZWF0ZURpdihcIm9wZW5jbGF3LWltZy1vdmVybGF5XCIpO1xuICAgICAgICAgICAgb3ZlcmxheS5jcmVhdGVFbChcImltZ1wiLCB7IGF0dHI6IHsgc3JjIH0gfSk7XG4gICAgICAgICAgICBvdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiBvdmVybGF5LnJlbW92ZSgpKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgLy8gQ29tYmluZSBhdWRpbyBwYXRocyBmcm9tIG1lc3NhZ2UgbWV0YWRhdGEgKyB0ZXh0IGNvbnRlbnRcbiAgICAgIGNvbnN0IGFsbEF1ZGlvID0gbXNnLnRleHQgPyB0aGlzLmV4dHJhY3RWb2ljZVJlZnMobXNnLnRleHQpIDogW107XG5cbiAgICAgIC8vIFJlbmRlciB0ZXh0XG4gICAgICBpZiAobXNnLnRleHQpIHtcbiAgICAgICAgY29uc3QgZGlzcGxheVRleHQgPSBtc2cucm9sZSA9PT0gXCJhc3Npc3RhbnRcIiA/IHRoaXMuY2xlYW5UZXh0KG1zZy50ZXh0KSA6IG1zZy50ZXh0O1xuICAgICAgICBpZiAoZGlzcGxheVRleHQpIHtcbiAgICAgICAgICBpZiAobXNnLnJvbGUgPT09IFwiYXNzaXN0YW50XCIpIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGF3YWl0IE1hcmtkb3duUmVuZGVyZXIucmVuZGVyKHRoaXMuYXBwLCBkaXNwbGF5VGV4dCwgYnViYmxlLCBcIlwiLCB0aGlzKTtcbiAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICBidWJibGUuY3JlYXRlRGl2KHsgdGV4dDogZGlzcGxheVRleHQsIGNsczogXCJvcGVuY2xhdy1tc2ctdGV4dFwiIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBidWJibGUuY3JlYXRlRGl2KHsgdGV4dDogZGlzcGxheVRleHQsIGNsczogXCJvcGVuY2xhdy1tc2ctdGV4dFwiIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvLyBSZW5kZXIgYXVkaW8gcGxheWVycyBmb3Igdm9pY2UgbWVzc2FnZXNcbiAgICAgIGZvciAoY29uc3QgYXAgb2YgYWxsQXVkaW8pIHtcbiAgICAgICAgdGhpcy5yZW5kZXJBdWRpb1BsYXllcihidWJibGUsIGFwKTtcbiAgICAgIH1cbiAgICB9XG4gICAgdGhpcy5zY3JvbGxUb0JvdHRvbSgpO1xuICB9XG5cbiAgcHJpdmF0ZSBzY3JvbGxUb0JvdHRvbSgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5tZXNzYWdlc0VsKSB7XG4gICAgICAvLyBVc2UgcmVxdWVzdEFuaW1hdGlvbkZyYW1lIHRvIGVuc3VyZSBET00gaGFzIHVwZGF0ZWRcbiAgICAgIHJlcXVlc3RBbmltYXRpb25GcmFtZSgoKSA9PiB7XG4gICAgICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhdXRvUmVzaXplKCk6IHZvaWQge1xuICAgIHRoaXMuaW5wdXRFbC5zZXRDc3NTdHlsZXMoeyBoZWlnaHQ6IFwiYXV0b1wiIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5zZXRDc3NTdHlsZXMoeyBoZWlnaHQ6IE1hdGgubWluKHRoaXMuaW5wdXRFbC5zY3JvbGxIZWlnaHQsIDE1MCkgKyBcInB4XCIgfSk7XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIE1haW4gUGx1Z2luIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzOiBPcGVuQ2xhd1NldHRpbmdzID0gREVGQVVMVF9TRVRUSU5HUztcbiAgZ2F0ZXdheTogR2F0ZXdheUNsaWVudCB8IG51bGwgPSBudWxsO1xuICBnYXRld2F5Q29ubmVjdGVkID0gZmFsc2U7XG4gIGNoYXRWaWV3OiBPcGVuQ2xhd0NoYXRWaWV3IHwgbnVsbCA9IG51bGw7XG5cbiAgYXN5bmMgb25sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMubG9hZFNldHRpbmdzKCk7XG5cbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhWSUVXX1RZUEUsIChsZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKSk7XG5cbiAgICAvLyBSaWJib24gaWNvblxuICAgIHRoaXMuYWRkUmliYm9uSWNvbihcIm1lc3NhZ2Utc3F1YXJlXCIsIFwiT3BlbkNsYXcgY2hhdFwiLCAoKSA9PiB7XG4gICAgICB2b2lkIHRoaXMuYWN0aXZhdGVWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBDb21tYW5kc1xuICAgIHRoaXMuYWRkQ29tbWFuZCh7XG4gICAgICBpZDogXCJ0b2dnbGUtY2hhdFwiLFxuICAgICAgbmFtZTogXCJUb2dnbGUgY2hhdCBzaWRlYmFyXCIsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLmFjdGl2YXRlVmlldygpLFxuICAgIH0pO1xuXG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiBcImFzay1hYm91dC1ub3RlXCIsXG4gICAgICBuYW1lOiBcIkFzayBhYm91dCBjdXJyZW50IG5vdGVcIixcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB2b2lkIHRoaXMuYXNrQWJvdXROb3RlKCksXG4gICAgfSk7XG5cbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6IFwicmVjb25uZWN0XCIsXG4gICAgICBuYW1lOiBcIlJlY29ubmVjdCB0byBnYXRld2F5XCIsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLmNvbm5lY3RHYXRld2F5KCksXG4gICAgfSk7XG5cbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6IFwic2V0dXBcIixcbiAgICAgIG5hbWU6IFwiUnVuIHNldHVwIHdpemFyZFwiLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IG5ldyBPbmJvYXJkaW5nTW9kYWwodGhpcy5hcHAsIHRoaXMpLm9wZW4oKSxcbiAgICB9KTtcblxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBTaG93IG9uYm9hcmRpbmcgb24gZmlyc3QgcnVuLCBvdGhlcndpc2UgYXV0by1jb25uZWN0IGFuZCBvcGVuIGNoYXRcbiAgICBpZiAoIXRoaXMuc2V0dGluZ3Mub25ib2FyZGluZ0NvbXBsZXRlKSB7XG4gICAgICAvLyBTbWFsbCBkZWxheSBzbyBPYnNpZGlhbiBmaW5pc2hlcyBsb2FkaW5nXG4gICAgICBzZXRUaW1lb3V0KCgpID0+IG5ldyBPbmJvYXJkaW5nTW9kYWwodGhpcy5hcHAsIHRoaXMpLm9wZW4oKSwgNTAwKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdm9pZCB0aGlzLmNvbm5lY3RHYXRld2F5KCk7XG4gICAgICAvLyBBdXRvLW9wZW4gY2hhdCBzaWRlYmFyIGFmdGVyIHdvcmtzcGFjZSBpcyByZWFkeVxuICAgICAgdGhpcy5hcHAud29ya3NwYWNlLm9uTGF5b3V0UmVhZHkoKCkgPT4ge1xuICAgICAgICB2b2lkIHRoaXMuYWN0aXZhdGVWaWV3KCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICBvbnVubG9hZCgpOiB2b2lkIHtcbiAgICB0aGlzLmdhdGV3YXk/LnN0b3AoKTtcbiAgICB0aGlzLmdhdGV3YXkgPSBudWxsO1xuICAgIHRoaXMuZ2F0ZXdheUNvbm5lY3RlZCA9IGZhbHNlO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuc2V0dGluZ3MgPSBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX1NFVFRJTkdTLCBhd2FpdCB0aGlzLmxvYWREYXRhKCkpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEodGhpcy5zZXR0aW5ncyk7XG4gIH1cblxuICBhc3luYyBjb25uZWN0R2F0ZXdheSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmdhdGV3YXk/LnN0b3AoKTtcbiAgICB0aGlzLmdhdGV3YXlDb25uZWN0ZWQgPSBmYWxzZTtcbiAgICB0aGlzLmNoYXRWaWV3Py51cGRhdGVTdGF0dXMoKTtcblxuICAgIGNvbnN0IHJhd1VybCA9IHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybC50cmltKCk7XG4gICAgaWYgKCFyYXdVcmwpIHJldHVybjtcblxuICAgIC8vIE5vcm1hbGl6ZSBVUkwgKGFjY2VwdCBodHRwczovLyBhbmQgaHR0cDovLyBhcyB3ZWxsKVxuICAgIGNvbnN0IHVybCA9IG5vcm1hbGl6ZUdhdGV3YXlVcmwocmF3VXJsKTtcbiAgICBpZiAoIXVybCkge1xuICAgICAgbmV3IE5vdGljZShcIk9wZW5DbGF3OiBJbnZhbGlkIGdhdGV3YXkgVVJMLiBVc2UgeW91ciBUYWlsc2NhbGUgU2VydmUgVVJMIChlLmcuIHdzczovL3lvdXItbWFjaGluZS50YWlsMTIzNC50cy5uZXQpXCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFBlcnNpc3QgdGhlIG5vcm1hbGl6ZWQgZm9ybSBpZiBpdCBjaGFuZ2VkXG4gICAgaWYgKHVybCAhPT0gcmF3VXJsKSB7XG4gICAgICB0aGlzLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB1cmw7XG4gICAgICBhd2FpdCB0aGlzLnNhdmVTZXR0aW5ncygpO1xuICAgIH1cblxuICAgIC8vIEdldCBvciBjcmVhdGUgZGV2aWNlIGlkZW50aXR5IGZvciBzY29wZSBhdXRob3JpemF0aW9uXG4gICAgbGV0IGRldmljZUlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSB8IHVuZGVmaW5lZDtcbiAgICB0cnkge1xuICAgICAgZGV2aWNlSWRlbnRpdHkgPSBhd2FpdCBnZXRPckNyZWF0ZURldmljZUlkZW50aXR5KFxuICAgICAgICAoKSA9PiB0aGlzLmxvYWREYXRhKCksXG4gICAgICAgIChkYXRhKSA9PiB0aGlzLnNhdmVEYXRhKGRhdGEpXG4gICAgICApO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUud2FybihcIltPYnNpZGlhbkNsYXddIERldmljZSBpZGVudGl0eSBjcmVhdGlvbiBmYWlsZWQsIGNvbm5lY3Rpbmcgd2l0aG91dCBzY29wZXM6XCIsIGUpO1xuICAgIH1cblxuICAgIHRoaXMuZ2F0ZXdheSA9IG5ldyBHYXRld2F5Q2xpZW50KHtcbiAgICAgIHVybCxcbiAgICAgIHRva2VuOiB0aGlzLnNldHRpbmdzLnRva2VuLnRyaW0oKSB8fCB1bmRlZmluZWQsXG4gICAgICBkZXZpY2VJZGVudGl0eSxcbiAgICAgIG9uSGVsbG86ICgpID0+IHtcbiAgICAgICAgdGhpcy5nYXRld2F5Q29ubmVjdGVkID0gdHJ1ZTtcbiAgICAgICAgdGhpcy5jaGF0Vmlldz8udXBkYXRlU3RhdHVzKCk7XG4gICAgICAgIHZvaWQgdGhpcy5jaGF0Vmlldz8ubG9hZEhpc3RvcnkoKTtcbiAgICAgICAgdm9pZCB0aGlzLmNoYXRWaWV3Py5yZW5kZXJUYWJzKCk7XG4gICAgICAgIHZvaWQgdGhpcy5jaGF0Vmlldz8ubG9hZEFnZW50cygpO1xuICAgICAgICAvLyBSZXN0b3JlIHBlcnNpc3RlZCBtb2RlbCBzZWxlY3Rpb25cbiAgICAgICAgaWYgKHRoaXMuc2V0dGluZ3MuY3VycmVudE1vZGVsICYmIHRoaXMuY2hhdFZpZXcpIHtcbiAgICAgICAgICB0aGlzLmNoYXRWaWV3LmN1cnJlbnRNb2RlbCA9IHRoaXMuc2V0dGluZ3MuY3VycmVudE1vZGVsO1xuICAgICAgICAgIHRoaXMuY2hhdFZpZXcudXBkYXRlTW9kZWxQaWxsKCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBvbkNsb3NlOiAoaW5mbykgPT4ge1xuICAgICAgICB0aGlzLmdhdGV3YXlDb25uZWN0ZWQgPSBmYWxzZTtcbiAgICAgICAgdGhpcy5jaGF0Vmlldz8udXBkYXRlU3RhdHVzKCk7XG4gICAgICAgIC8vIFNob3cgcGFpcmluZyBpbnN0cnVjdGlvbnMgaWYgbmVlZGVkXG4gICAgICAgIGlmIChpbmZvLnJlYXNvbi5pbmNsdWRlcyhcInBhaXJpbmcgcmVxdWlyZWRcIikgfHwgaW5mby5yZWFzb24uaW5jbHVkZXMoXCJkZXZpY2UgaWRlbnRpdHkgcmVxdWlyZWRcIikpIHtcbiAgICAgICAgICBuZXcgTm90aWNlKFwiT3BlbkNsYXc6IERldmljZSBwYWlyaW5nIHJlcXVpcmVkLiBSdW4gJ29wZW5jbGF3IGRldmljZXMgYXBwcm92ZScgb24geW91ciBnYXRld2F5IG1hY2hpbmUuXCIsIDEwMDAwKTtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIG9uRXZlbnQ6IChldnQpID0+IHtcbiAgICAgICAgaWYgKGV2dC5ldmVudCA9PT0gXCJjaGF0XCIpIHtcbiAgICAgICAgICB0aGlzLmNoYXRWaWV3Py5oYW5kbGVDaGF0RXZlbnQoZXZ0LnBheWxvYWQpO1xuICAgICAgICB9IGVsc2UgaWYgKGV2dC5ldmVudCA9PT0gXCJzdHJlYW1cIiB8fCBldnQuZXZlbnQgPT09IFwiYWdlbnRcIikge1xuICAgICAgICAgIHRoaXMuY2hhdFZpZXc/LmhhbmRsZVN0cmVhbUV2ZW50KGV2dC5wYXlsb2FkKTtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIHRoaXMuZ2F0ZXdheS5zdGFydCgpO1xuICB9XG5cbiAgYXN5bmMgYWN0aXZhdGVWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGV4aXN0aW5nID0gdGhpcy5hcHAud29ya3NwYWNlLmdldExlYXZlc09mVHlwZShWSUVXX1RZUEUpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5yZXZlYWxMZWFmKGV4aXN0aW5nWzBdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgY29uc3QgbGVhZiA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmIChsZWFmKSB7XG4gICAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRSwgYWN0aXZlOiB0cnVlIH0pO1xuICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBhc2tBYm91dE5vdGUoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZmlsZSA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gICAgaWYgKCFmaWxlKSB7XG4gICAgICBuZXcgTm90aWNlKFwiTm8gYWN0aXZlIG5vdGVcIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMuYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgaWYgKCFjb250ZW50LnRyaW0oKSkge1xuICAgICAgbmV3IE5vdGljZShcIk5vdGUgaXMgZW1wdHlcIik7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5hY3RpdmF0ZVZpZXcoKTtcblxuICAgIGlmICghdGhpcy5jaGF0VmlldyB8fCAhdGhpcy5nYXRld2F5Py5jb25uZWN0ZWQpIHtcbiAgICAgIG5ldyBOb3RpY2UoXCJOb3QgY29ubmVjdGVkIHRvIE9wZW5DbGF3XCIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IG1lc3NhZ2UgPSBgSGVyZSBpcyBteSBjdXJyZW50IG5vdGUgXCIke2ZpbGUuYmFzZW5hbWV9XCI6XFxuXFxuJHtjb250ZW50fVxcblxcbldoYXQgY2FuIHlvdSB0ZWxsIG1lIGFib3V0IHRoaXM/YDtcbiAgICBjb25zdCBpbnB1dEVsID0gdGhpcy5jaGF0Vmlldy5jb250YWluZXJFbC5xdWVyeVNlbGVjdG9yKFwiLm9wZW5jbGF3LWlucHV0XCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gICAgaWYgKGlucHV0RWwpIHtcbiAgICAgIGlucHV0RWwudmFsdWUgPSBtZXNzYWdlO1xuICAgICAgaW5wdXRFbC5mb2N1cygpO1xuICAgIH1cbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgQ29uZmlybSBNb2RhbCBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuXG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBNb2RlbCBQaWNrZXIgTW9kYWwgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbmNsYXNzIE1vZGVsUGlja2VyTW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIGNoYXRWaWV3OiBPcGVuQ2xhd0NoYXRWaWV3O1xuICBwcml2YXRlIG1vZGVsczogTW9kZWxJbmZvW10gPSBbXTtcbiAgcHJpdmF0ZSBjdXJyZW50TW9kZWw6IHN0cmluZyA9IFwiXCI7XG4gIHByaXZhdGUgc2VsZWN0ZWRQcm92aWRlcjogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4sIGNoYXRWaWV3OiBPcGVuQ2xhd0NoYXRWaWV3KSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgICB0aGlzLmNoYXRWaWV3ID0gY2hhdFZpZXc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5tb2RhbEVsLmFkZENsYXNzKFwib3BlbmNsYXctcGlja2VyXCIpO1xuICAgIHRoaXMuY29udGVudEVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LXBpY2tlci1sb2FkaW5nXCIpLnRleHRDb250ZW50ID0gXCJMb2FkaW5nIG1vZGVscy4uLlwiO1xuXG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXk/LnJlcXVlc3QoXCJtb2RlbHMubGlzdFwiLCB7fSkgYXMgeyBtb2RlbHM/OiBNb2RlbEluZm9bXSB9IHwgdW5kZWZpbmVkO1xuICAgICAgdGhpcy5tb2RlbHMgPSByZXN1bHQ/Lm1vZGVscyB8fCBbXTtcbiAgICB9IGNhdGNoIHsgdGhpcy5tb2RlbHMgPSBbXTsgfVxuXG4gICAgLy8gTm9ybWFsaXplIGN1cnJlbnRNb2RlbCB0byBhbHdheXMgYmUgcHJvdmlkZXIvaWQgZm9ybWF0XG4gICAgdGhpcy5jdXJyZW50TW9kZWwgPSB0aGlzLmNoYXRWaWV3LmN1cnJlbnRNb2RlbCB8fCBcIlwiO1xuICAgIGlmICh0aGlzLmN1cnJlbnRNb2RlbCAmJiAhdGhpcy5jdXJyZW50TW9kZWwuaW5jbHVkZXMoXCIvXCIpKSB7XG4gICAgICBjb25zdCBtYXRjaCA9IHRoaXMubW9kZWxzLmZpbmQoKG06IE1vZGVsSW5mbykgPT4gbS5pZCA9PT0gdGhpcy5jdXJyZW50TW9kZWwpO1xuICAgICAgaWYgKG1hdGNoKSB0aGlzLmN1cnJlbnRNb2RlbCA9IGAke21hdGNoLnByb3ZpZGVyfS8ke21hdGNoLmlkfWA7XG4gICAgfVxuXG4gICAgLy8gQXV0by1zZWxlY3QgcHJvdmlkZXIgb2YgY3VycmVudCBtb2RlbFxuICAgIGlmICh0aGlzLmN1cnJlbnRNb2RlbC5pbmNsdWRlcyhcIi9cIikpIHtcbiAgICAgIHRoaXMuc2VsZWN0ZWRQcm92aWRlciA9IHRoaXMuY3VycmVudE1vZGVsLnNwbGl0KFwiL1wiKVswXTtcbiAgICB9XG5cbiAgICAvLyBJZiBvbmx5IG9uZSBwcm92aWRlciwgc2tpcCBzdHJhaWdodCB0byBtb2RlbHNcbiAgICBjb25zdCBwcm92aWRlcnMgPSBuZXcgU2V0KHRoaXMubW9kZWxzLm1hcCgobTogTW9kZWxJbmZvKSA9PiBtLnByb3ZpZGVyKSk7XG4gICAgaWYgKHByb3ZpZGVycy5zaXplID09PSAxKSB7XG4gICAgICB0aGlzLnJlbmRlck1vZGVscyhbLi4ucHJvdmlkZXJzXVswXSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMucmVuZGVyUHJvdmlkZXJzKCk7XG4gICAgfVxuICB9XG5cbiAgb25DbG9zZSgpOiB2b2lkIHsgdGhpcy5jb250ZW50RWwuZW1wdHkoKTsgfVxuXG4gIHByaXZhdGUgcmVuZGVyUHJvdmlkZXJzKCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGVudEVsIH0gPSB0aGlzO1xuICAgIGNvbnRlbnRFbC5lbXB0eSgpO1xuXG4gICAgLy8gR3JvdXAgbW9kZWxzIGJ5IHByb3ZpZGVyXG4gICAgY29uc3QgcHJvdmlkZXJNYXAgPSBuZXcgTWFwPHN0cmluZywgTW9kZWxJbmZvW10+KCk7XG4gICAgZm9yIChjb25zdCBtIG9mIHRoaXMubW9kZWxzKSB7XG4gICAgICBjb25zdCBwID0gbS5wcm92aWRlciB8fCBcInVua25vd25cIjtcbiAgICAgIGlmICghcHJvdmlkZXJNYXAuaGFzKHApKSBwcm92aWRlck1hcC5zZXQocCwgW10pO1xuICAgICAgcHJvdmlkZXJNYXAuZ2V0KHApIS5wdXNoKG0pO1xuICAgIH1cblxuICAgIC8vIEN1cnJlbnQgcHJvdmlkZXIgZnJvbSBjdXJyZW50TW9kZWxcbiAgICBjb25zdCBjdXJyZW50UHJvdmlkZXIgPSB0aGlzLmN1cnJlbnRNb2RlbC5pbmNsdWRlcyhcIi9cIikgPyB0aGlzLmN1cnJlbnRNb2RlbC5zcGxpdChcIi9cIilbMF0gOiBcIlwiO1xuXG4gICAgY29uc3QgbGlzdCA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItbGlzdFwiKTtcblxuICAgIGZvciAoY29uc3QgW3Byb3ZpZGVyLCBtb2RlbHNdIG9mIHByb3ZpZGVyTWFwKSB7XG4gICAgICBjb25zdCBpc0N1cnJlbnQgPSBwcm92aWRlciA9PT0gY3VycmVudFByb3ZpZGVyO1xuICAgICAgY29uc3Qgcm93ID0gbGlzdC5jcmVhdGVEaXYoeyBjbHM6IGBvcGVuY2xhdy1waWNrZXItcm93JHtpc0N1cnJlbnQgPyBcIiBhY3RpdmVcIiA6IFwiXCJ9YCB9KTtcblxuICAgICAgY29uc3QgbGVmdCA9IHJvdy5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItcm93LWxlZnRcIik7XG4gICAgICBpZiAoaXNDdXJyZW50KSBsZWZ0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIlx1MjVDRiBcIiwgY2xzOiBcIm9wZW5jbGF3LXBpY2tlci1kb3RcIiB9KTtcbiAgICAgIGxlZnQuY3JlYXRlU3Bhbih7IHRleHQ6IHByb3ZpZGVyLCBjbHM6IFwib3BlbmNsYXctcGlja2VyLXByb3ZpZGVyLW5hbWVcIiB9KTtcblxuICAgICAgY29uc3QgcmlnaHQgPSByb3cuY3JlYXRlRGl2KFwib3BlbmNsYXctcGlja2VyLXJvdy1yaWdodFwiKTtcbiAgICAgIHJpZ2h0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBgJHttb2RlbHMubGVuZ3RofSBtb2RlbCR7bW9kZWxzLmxlbmd0aCAhPT0gMSA/IFwic1wiIDogXCJcIn1gLCBjbHM6IFwib3BlbmNsYXctcGlja2VyLW1ldGFcIiB9KTtcbiAgICAgIHJpZ2h0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIiBcdTIxOTJcIiwgY2xzOiBcIm9wZW5jbGF3LXBpY2tlci1hcnJvd1wiIH0pO1xuXG4gICAgICByb3cuYWRkRXZlbnRMaXN0ZW5lcihcImNsaWNrXCIsICgpID0+IHtcbiAgICAgICAgdGhpcy5zZWxlY3RlZFByb3ZpZGVyID0gcHJvdmlkZXI7XG4gICAgICAgIHRoaXMucmVuZGVyTW9kZWxzKHByb3ZpZGVyKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIEZvb3RlclxuICAgIGNvbnN0IGZvb3RlciA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItaGludCBvcGVuY2xhdy1waWNrZXItZm9vdGVyXCIpO1xuICAgIGZvb3Rlci5hcHBlbmRUZXh0KFwiV2FudCBtb3JlIG1vZGVscz8gXCIpO1xuICAgIGZvb3Rlci5jcmVhdGVFbChcImFcIiwgeyB0ZXh0OiBcIkFkZCB0aGVtIGluIHlvdXIgZ2F0ZXdheSBjb25maWcuXCIsIGhyZWY6IFwiaHR0cHM6Ly9kb2NzLm9wZW5jbGF3LmFpL2dhdGV3YXkvY29uZmlndXJhdGlvbiNjaG9vc2UtYW5kLWNvbmZpZ3VyZS1tb2RlbHNcIiB9KTtcbiAgfVxuXG4gIHByaXZhdGUgcmVuZGVyTW9kZWxzKHByb3ZpZGVyOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuZW1wdHkoKTtcblxuICAgIC8vIEJhY2sgYnV0dG9uXG4gICAgY29uc3QgcHJvdmlkZXJzID0gbmV3IFNldCh0aGlzLm1vZGVscy5tYXAoKG06IE1vZGVsSW5mbykgPT4gbS5wcm92aWRlcikpO1xuICAgIGlmIChwcm92aWRlcnMuc2l6ZSA+IDEpIHtcbiAgICAgIGNvbnN0IGhlYWRlciA9IGNvbnRlbnRFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItaGVhZGVyXCIpO1xuICAgICAgY29uc3QgYmFja0J0biA9IGhlYWRlci5jcmVhdGVFbChcImJ1dHRvblwiLCB7IGNsczogXCJvcGVuY2xhdy1waWNrZXItYmFja1wiLCB0ZXh0OiBcIlx1MjE5MCBcIiArIHByb3ZpZGVyIH0pO1xuICAgICAgYmFja0J0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5yZW5kZXJQcm92aWRlcnMoKSk7XG4gICAgfVxuXG4gICAgY29uc3QgbW9kZWxzID0gdGhpcy5tb2RlbHMuZmlsdGVyKChtOiBNb2RlbEluZm8pID0+IG0ucHJvdmlkZXIgPT09IHByb3ZpZGVyKTtcbiAgICBjb25zdCBsaXN0ID0gY29udGVudEVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LXBpY2tlci1saXN0IG9wZW5jbGF3LXBpY2tlci1tb2RlbC1saXN0XCIpO1xuXG4gICAgZm9yIChjb25zdCBtIG9mIG1vZGVscykge1xuICAgICAgY29uc3QgZnVsbElkID0gYCR7bS5wcm92aWRlcn0vJHttLmlkfWA7XG4gICAgICBjb25zdCBpc0N1cnJlbnQgPSBmdWxsSWQgPT09IHRoaXMuY3VycmVudE1vZGVsO1xuICAgICAgY29uc3Qgcm93ID0gbGlzdC5jcmVhdGVEaXYoeyBjbHM6IGBvcGVuY2xhdy1waWNrZXItcm93JHtpc0N1cnJlbnQgPyBcIiBhY3RpdmVcIiA6IFwiXCJ9YCB9KTtcblxuICAgICAgY29uc3QgbGVmdCA9IHJvdy5jcmVhdGVEaXYoXCJvcGVuY2xhdy1waWNrZXItcm93LWxlZnRcIik7XG4gICAgICBpZiAoaXNDdXJyZW50KSBsZWZ0LmNyZWF0ZVNwYW4oeyB0ZXh0OiBcIlx1MjVDRiBcIiwgY2xzOiBcIm9wZW5jbGF3LXBpY2tlci1kb3RcIiB9KTtcbiAgICAgIGxlZnQuY3JlYXRlU3Bhbih7IHRleHQ6IG0ubmFtZSB8fCBtLmlkIH0pO1xuXG4gICAgICAvLyBBbHdheXMgY2xpY2thYmxlIC0gZXZlbiB0aGUgY3VycmVudCBtb2RlbCAodXNlciBtaWdodCB3YW50IHRvIHJlLXNlbGVjdCBpdClcbiAgICAgIHJvdy5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBpZiAoIXRoaXMucGx1Z2luLmdhdGV3YXk/LmNvbm5lY3RlZCkgcmV0dXJuO1xuICAgICAgICByb3cuYWRkQ2xhc3MoXCJvcGVuY2xhdy1waWNrZXItc2VsZWN0aW5nXCIpO1xuICAgICAgICByb3cudGV4dENvbnRlbnQgPSBcIlN3aXRjaGluZy4uLlwiO1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLmdhdGV3YXkucmVxdWVzdChcImNoYXQuc2VuZFwiLCB7XG4gICAgICAgICAgICBzZXNzaW9uS2V5OiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgICAgICAgbWVzc2FnZTogYC9tb2RlbCAke2Z1bGxJZH1gLFxuICAgICAgICAgICAgZGVsaXZlcjogZmFsc2UsXG4gICAgICAgICAgICBpZGVtcG90ZW5jeUtleTogXCJtb2RlbC1cIiArIERhdGUubm93KCksXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgdGhpcy5jaGF0Vmlldy5jdXJyZW50TW9kZWwgPSBmdWxsSWQ7XG4gICAgICAgICAgdGhpcy5jaGF0Vmlldy5jdXJyZW50TW9kZWxTZXRBdCA9IERhdGUubm93KCk7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuY3VycmVudE1vZGVsID0gZnVsbElkO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIHRoaXMuY2hhdFZpZXcudXBkYXRlTW9kZWxQaWxsKCk7XG4gICAgICAgICAgbmV3IE5vdGljZShgTW9kZWw6ICR7bS5uYW1lIHx8IG0uaWR9YCk7XG4gICAgICAgICAgdGhpcy5jbG9zZSgpO1xuICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgbmV3IE5vdGljZShgRmFpbGVkOiAke2V9YCk7XG4gICAgICAgICAgdGhpcy5yZW5kZXJNb2RlbHMocHJvdmlkZXIpO1xuICAgICAgICB9XG4gICAgICB9KSgpKTtcbiAgICB9XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbmZpcm0gTW9kYWwgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbmNsYXNzIF9Db25maXJtTW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHByaXZhdGUgY29uZmlnOiB7IHRpdGxlOiBzdHJpbmc7IG1lc3NhZ2U6IHN0cmluZzsgY29uZmlybVRleHQ6IHN0cmluZzsgb25Db25maXJtOiAoKSA9PiB2b2lkIH07XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIGNvbmZpZzogeyB0aXRsZTogc3RyaW5nOyBtZXNzYWdlOiBzdHJpbmc7IGNvbmZpcm1UZXh0OiBzdHJpbmc7IG9uQ29uZmlybTogKCkgPT4gdm9pZCB9KSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLmNvbmZpZyA9IGNvbmZpZztcbiAgfVxuXG4gIG9uT3BlbigpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuYWRkQ2xhc3MoXCJvcGVuY2xhdy1jb25maXJtLW1vZGFsXCIpO1xuICAgIGNvbnRlbnRFbC5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogdGhpcy5jb25maWcudGl0bGUsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLXRpdGxlXCIgfSk7XG4gICAgY29udGVudEVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IHRoaXMuY29uZmlnLm1lc3NhZ2UsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLW1lc3NhZ2VcIiB9KTtcbiAgICBjb25zdCBidG5Sb3cgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctY29uZmlybS1idXR0b25zXCIpO1xuICAgIGNvbnN0IGNhbmNlbEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiQ2FuY2VsXCIsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLWNhbmNlbFwiIH0pO1xuICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICBjb25zdCBjb25maXJtQnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogdGhpcy5jb25maWcuY29uZmlybVRleHQsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLW9rXCIgfSk7XG4gICAgY29uZmlybUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgdGhpcy5jbG9zZSgpO1xuICAgICAgdGhpcy5jb25maWcub25Db25maXJtKCk7XG4gICAgfSk7XG4gIH1cblxuICBvbkNsb3NlKCk6IHZvaWQge1xuICAgIHRoaXMuY29udGVudEVsLmVtcHR5KCk7XG4gIH1cbn1cblxuLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbmZpcm0gQ2xvc2UgTW9kYWwgKHdpdGggXCJkb24ndCBhc2sgYWdhaW5cIikgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbmNsYXNzIENvbmZpcm1DbG9zZU1vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwcml2YXRlIHRpdGxlOiBzdHJpbmc7XG4gIHByaXZhdGUgbWVzc2FnZTogc3RyaW5nO1xuICBwcml2YXRlIGNhbGxiYWNrOiAocmVzdWx0OiBib29sZWFuLCBkb250QXNrOiBib29sZWFuKSA9PiB2b2lkO1xuICBwcml2YXRlIGNoZWNrYm94RWwhOiBIVE1MSW5wdXRFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCB0aXRsZTogc3RyaW5nLCBtZXNzYWdlOiBzdHJpbmcsIGNhbGxiYWNrOiAocmVzdWx0OiBib29sZWFuLCBkb250QXNrOiBib29sZWFuKSA9PiB2b2lkKSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLnRpdGxlID0gdGl0bGU7XG4gICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICB0aGlzLmNhbGxiYWNrID0gY2FsbGJhY2s7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmFkZENsYXNzKFwib3BlbmNsYXctY29uZmlybS1tb2RhbFwiKTtcbiAgICBjb250ZW50RWwuY3JlYXRlRWwoXCJoM1wiLCB7IHRleHQ6IHRoaXMudGl0bGUsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLXRpdGxlXCIgfSk7XG4gICAgY29udGVudEVsLmNyZWF0ZUVsKFwicFwiLCB7IHRleHQ6IHRoaXMubWVzc2FnZSwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tbWVzc2FnZVwiIH0pO1xuICAgIFxuICAgIGNvbnN0IGNoZWNrUm93ID0gY29udGVudEVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LWNvbmZpcm0tY2hlY2tcIik7XG4gICAgdGhpcy5jaGVja2JveEVsID0gY2hlY2tSb3cuY3JlYXRlRWwoXCJpbnB1dFwiLCB7IHR5cGU6IFwiY2hlY2tib3hcIiB9KTtcbiAgICB0aGlzLmNoZWNrYm94RWwuaWQgPSBcImNvbmZpcm0tZG9udC1hc2tcIjtcbiAgICBjaGVja1Jvdy5jcmVhdGVFbChcImxhYmVsXCIsIHsgdGV4dDogXCJEb24ndCBhc2sgbWUgYWdhaW5cIiwgYXR0cjogeyBmb3I6IFwiY29uZmlybS1kb250LWFza1wiIH0gfSk7XG5cbiAgICBjb25zdCBidG5Sb3cgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctY29uZmlybS1idXR0b25zXCIpO1xuICAgIGNvbnN0IGNhbmNlbEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiQ2FuY2VsXCIsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLWNhbmNlbFwiIH0pO1xuICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgdGhpcy5jYWxsYmFjayhmYWxzZSwgZmFsc2UpO1xuICAgICAgdGhpcy5jbG9zZSgpO1xuICAgIH0pO1xuICAgIGNvbnN0IGNvbmZpcm1CdG4gPSBidG5Sb3cuY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiB0aGlzLnRpdGxlLnN0YXJ0c1dpdGgoXCJSZXNldFwiKSA/IFwiUmVzZXRcIiA6IFwiQ2xvc2VcIiwgY2xzOiBcIm9wZW5jbGF3LWNvbmZpcm0tb2tcIiB9KTtcbiAgICBjb25maXJtQnRuLmFkZEV2ZW50TGlzdGVuZXIoXCJjbGlja1wiLCAoKSA9PiB7XG4gICAgICB0aGlzLmNhbGxiYWNrKHRydWUsIHRoaXMuY2hlY2tib3hFbC5jaGVja2VkKTtcbiAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICB9KTtcbiAgfVxuXG4gIG9uQ2xvc2UoKTogdm9pZCB7XG4gICAgdGhpcy5jb250ZW50RWwuZW1wdHkoKTtcbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgVGV4dCBJbnB1dCBNb2RhbCBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuY2xhc3MgX1RleHRJbnB1dE1vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwcml2YXRlIGNvbmZpZzogeyB0aXRsZTogc3RyaW5nOyBwbGFjZWhvbGRlcjogc3RyaW5nOyBjb25maXJtVGV4dDogc3RyaW5nOyBpbml0aWFsVmFsdWU/OiBzdHJpbmc7IG9uQ29uZmlybTogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQgfTtcbiAgcHJpdmF0ZSBpbnB1dEVsITogSFRNTElucHV0RWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgY29uZmlnOiB7IHRpdGxlOiBzdHJpbmc7IHBsYWNlaG9sZGVyOiBzdHJpbmc7IGNvbmZpcm1UZXh0OiBzdHJpbmc7IGluaXRpYWxWYWx1ZT86IHN0cmluZzsgb25Db25maXJtOiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCB9KSB7XG4gICAgc3VwZXIoYXBwKTtcbiAgICB0aGlzLmNvbmZpZyA9IGNvbmZpZztcbiAgfVxuXG4gIG9uT3BlbigpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuYWRkQ2xhc3MoXCJvcGVuY2xhdy1jb25maXJtLW1vZGFsXCIpO1xuICAgIGNvbnRlbnRFbC5jcmVhdGVFbChcImgzXCIsIHsgdGV4dDogdGhpcy5jb25maWcudGl0bGUsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLXRpdGxlXCIgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gY29udGVudEVsLmNyZWF0ZUVsKFwiaW5wdXRcIiwge1xuICAgICAgdHlwZTogXCJ0ZXh0XCIsXG4gICAgICBwbGFjZWhvbGRlcjogdGhpcy5jb25maWcucGxhY2Vob2xkZXIsXG4gICAgICBjbHM6IFwib3BlbmNsYXctdGV4dC1pbnB1dFwiLFxuICAgIH0pO1xuICAgIGlmICh0aGlzLmNvbmZpZy5pbml0aWFsVmFsdWUpIHRoaXMuaW5wdXRFbC52YWx1ZSA9IHRoaXMuY29uZmlnLmluaXRpYWxWYWx1ZTtcbiAgICB0aGlzLmlucHV0RWwuZm9jdXMoKTtcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcihcImtleWRvd25cIiwgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gXCJFbnRlclwiKSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5zdWJtaXQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICBjb25zdCBidG5Sb3cgPSBjb250ZW50RWwuY3JlYXRlRGl2KFwib3BlbmNsYXctY29uZmlybS1idXR0b25zXCIpO1xuICAgIGNvbnN0IGNhbmNlbEJ0biA9IGJ0blJvdy5jcmVhdGVFbChcImJ1dHRvblwiLCB7IHRleHQ6IFwiQ2FuY2VsXCIsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLWNhbmNlbFwiIH0pO1xuICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICBjb25zdCBjb25maXJtQnRuID0gYnRuUm93LmNyZWF0ZUVsKFwiYnV0dG9uXCIsIHsgdGV4dDogdGhpcy5jb25maWcuY29uZmlybVRleHQsIGNsczogXCJvcGVuY2xhdy1jb25maXJtLW9rXCIgfSk7XG4gICAgY29uZmlybUJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4gdGhpcy5zdWJtaXQoKSk7XG4gIH1cblxuICBwcml2YXRlIHN1Ym1pdCgpOiB2b2lkIHtcbiAgICBjb25zdCB2YWx1ZSA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF2YWx1ZSkgcmV0dXJuO1xuICAgIHRoaXMuY2xvc2UoKTtcbiAgICB0aGlzLmNvbmZpZy5vbkNvbmZpcm0odmFsdWUpO1xuICB9XG5cbiAgb25DbG9zZSgpOiB2b2lkIHtcbiAgICB0aGlzLmNvbnRlbnRFbC5lbXB0eSgpO1xuICB9XG59XG5cbi8vIFx1MjUwMFx1MjUwMFx1MjUwMCBBdHRhY2htZW50IFBpY2tlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuY2xhc3MgX0F0dGFjaG1lbnRNb2RhbCBleHRlbmRzIEZ1enp5U3VnZ2VzdE1vZGFsPFRGaWxlPiB7XG4gIHByaXZhdGUgZmlsZXM6IFRGaWxlW107XG4gIHByaXZhdGUgb25DaG9vc2U6IChmaWxlOiBURmlsZSkgPT4gdm9pZDtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgZmlsZXM6IFRGaWxlW10sIG9uQ2hvb3NlOiAoZmlsZTogVEZpbGUpID0+IHZvaWQpIHtcbiAgICBzdXBlcihhcHApO1xuICAgIHRoaXMuZmlsZXMgPSBmaWxlcztcbiAgICB0aGlzLm9uQ2hvb3NlID0gb25DaG9vc2U7XG4gICAgdGhpcy5zZXRQbGFjZWhvbGRlcihcIlNlYXJjaCBmaWxlcyB0byBhdHRhY2guLi5cIik7XG4gIH1cblxuICBnZXRJdGVtcygpOiBURmlsZVtdIHtcbiAgICByZXR1cm4gdGhpcy5maWxlcztcbiAgfVxuXG4gIGdldEl0ZW1UZXh0KGZpbGU6IFRGaWxlKTogc3RyaW5nIHtcbiAgICByZXR1cm4gZmlsZS5wYXRoO1xuICB9XG5cbiAgb25DaG9vc2VJdGVtKGZpbGU6IFRGaWxlKTogdm9pZCB7XG4gICAgdGhpcy5vbkNob29zZShmaWxlKTtcbiAgfVxufVxuXG4vLyBcdTI1MDBcdTI1MDBcdTI1MDAgU2V0dGluZ3MgVGFiIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG5jbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpLnNldE5hbWUoXCJDaGF0XCIpLnNldEhlYWRpbmcoKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTZXR1cCBXaXphcmQgKHRvcCwgbW9zdCBwcm9taW5lbnQpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IHdpemFyZFNlY3Rpb24gPSBjb250YWluZXJFbC5jcmVhdGVEaXYoXCJvcGVuY2xhdy1zZXR0aW5ncy13aXphcmRcIik7XG4gICAgY29uc3Qgd2l6YXJkRGVzYyA9IHdpemFyZFNlY3Rpb24uY3JlYXRlRGl2KFwib3BlbmNsYXctc2V0dGluZ3Mtd2l6YXJkLWRlc2NcIik7XG4gICAgd2l6YXJkRGVzYy5jcmVhdGVFbChcInN0cm9uZ1wiLCB7IHRleHQ6IFwiU2V0dXAgd2l6YXJkXCIgfSk7XG4gICAgd2l6YXJkRGVzYy5jcmVhdGVFbChcInBcIiwge1xuICAgICAgdGV4dDogXCJUaGUgZWFzaWVzdCB3YXkgdG8gY29ubmVjdC4gV2Fsa3MgeW91IHRocm91Z2ggVGFpbHNjYWxlLCBnYXRld2F5IHNldHVwLCBhbmQgZGV2aWNlIHBhaXJpbmcgc3RlcCBieSBzdGVwLlwiLFxuICAgICAgY2xzOiBcInNldHRpbmctaXRlbS1kZXNjcmlwdGlvblwiLFxuICAgIH0pO1xuICAgIGNvbnN0IHdpemFyZEJ0biA9IHdpemFyZFNlY3Rpb24uY3JlYXRlRWwoXCJidXR0b25cIiwgeyB0ZXh0OiBcIlJ1biBzZXR1cCB3aXphcmRcIiwgY2xzOiBcIm1vZC1jdGEgb3BlbmNsYXctc2V0dGluZ3Mtd2l6YXJkLWJ0blwiIH0pO1xuICAgIHdpemFyZEJ0bi5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIiwgKCkgPT4ge1xuICAgICAgbmV3IE9uYm9hcmRpbmdNb2RhbCh0aGlzLmFwcCwgdGhpcy5wbHVnaW4pLm9wZW4oKTtcbiAgICB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTdGF0dXMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG4gICAgY29uc3Qgc3RhdHVzU2VjdGlvbiA9IGNvbnRhaW5lckVsLmNyZWF0ZURpdihcIm9wZW5jbGF3LXNldHRpbmdzLXN0YXR1c1wiKTtcbiAgICBjb25zdCBjb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi5nYXRld2F5Q29ubmVjdGVkO1xuICAgIHN0YXR1c1NlY3Rpb24uY3JlYXRlU3Bhbih7IGNsczogYG9wZW5jbGF3LXNldHRpbmdzLWRvdCAke2Nvbm5lY3RlZCA/IFwiY29ubmVjdGVkXCIgOiBcImRpc2Nvbm5lY3RlZFwifWAgfSk7XG4gICAgc3RhdHVzU2VjdGlvbi5jcmVhdGVTcGFuKHsgdGV4dDogY29ubmVjdGVkID8gXCJDb25uZWN0ZWRcIiA6IFwiRGlzY29ubmVjdGVkXCIsIGNsczogXCJvcGVuY2xhdy1zZXR0aW5ncy1zdGF0dXMtdGV4dFwiIH0pO1xuICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKSB7XG4gICAgICBzdGF0dXNTZWN0aW9uLmNyZWF0ZVNwYW4oe1xuICAgICAgICB0ZXh0OiBgIFx1MjAxNCAke3RoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwucmVwbGFjZSgvXndzcz86XFwvXFwvLywgXCJcIil9YCxcbiAgICAgICAgY2xzOiBcIm9wZW5jbGF3LXNldHRpbmdzLXN0YXR1cy11cmxcIixcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIFx1MjUwMFx1MjUwMFx1MjUwMCBTZXNzaW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKS5zZXROYW1lKFwiU2Vzc2lvblwiKS5zZXRIZWFkaW5nKCk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKFwiQ29udmVyc2F0aW9uXCIpXG4gICAgICAuc2V0RGVzYyhcIkN1cnJlbnQgY29udmVyc2F0aW9uIGtleS4gVXNlIFxcXCJtYWluXFxcIiBmb3IgdGhlIGRlZmF1bHQgc2Vzc2lvbi5cIilcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKFwiTWFpblwiKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZSB8fCBcIm1haW5cIjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApXG4gICAgICAuYWRkQnV0dG9uKChidG4pID0+XG4gICAgICAgIGJ0blxuICAgICAgICAgIC5zZXRCdXR0b25UZXh0KFwiUmVzZXQgdG8gbWFpblwiKVxuICAgICAgICAgIC5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSBcIm1haW5cIjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgICAgdGhpcy5kaXNwbGF5KCk7IC8vIHJlZnJlc2ggdGhlIHNldHRpbmdzIFVJXG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5jb25uZWN0R2F0ZXdheSgpO1xuICAgICAgICAgICAgbmV3IE5vdGljZShcIlJlc2V0IHRvIG1haW4gY29udmVyc2F0aW9uXCIpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIEJlaGF2aW9yIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoXCJDb25maXJtIGJlZm9yZSBjbG9zaW5nIHRhYnNcIilcbiAgICAgIC5zZXREZXNjKFwiU2hvdyBhIGNvbmZpcm1hdGlvbiBkaWFsb2cgYmVmb3JlIGNsb3Npbmcgb3IgcmVzZXR0aW5nIHRhYnNcIilcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlXG4gICAgICAgICAgLnNldFZhbHVlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKFwib3BlbmNsYXctY29uZmlybS1jbG9zZS1kaXNhYmxlZFwiKSAhPT0gXCJ0cnVlXCIpXG4gICAgICAgICAgLm9uQ2hhbmdlKCh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oXCJvcGVuY2xhdy1jb25maXJtLWNsb3NlLWRpc2FibGVkXCIsIHZhbHVlID8gXCJmYWxzZVwiIDogXCJ0cnVlXCIpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwXHUyNTAwIENvbm5lY3Rpb24gKEFkdmFuY2VkKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbCkuc2V0TmFtZShcIkNvbm5lY3Rpb25cIikuc2V0RGVzYyhcIlRoZXNlIGFyZSBzZXQgYXV0b21hdGljYWxseSBieSB0aGUgc2V0dXAgd2l6YXJkLiBFZGl0IG1hbnVhbGx5IG9ubHkgaWYgeW91IGtub3cgd2hhdCB5b3UncmUgZG9pbmcuXCIpLnNldEhlYWRpbmcoKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoXCJHYXRld2F5IFVSTFwiKVxuICAgICAgLnNldERlc2MoXCJUYWlsc2NhbGUgU2VydmUgVVJMIChlLmcuIHdzczovL3lvdXItbWFjaGluZS50YWlsMTIzNC50cy5uZXQpXCIpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcihcIndzczovL3lvdXItbWFjaGluZS50YWlsMTIzNC50cy5uZXRcIilcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICBjb25zdCBub3JtYWxpemVkID0gbm9ybWFsaXplR2F0ZXdheVVybCh2YWx1ZSk7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsID0gbm9ybWFsaXplZCB8fCB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZShcIkF1dGggdG9rZW5cIilcbiAgICAgIC5zZXREZXNjKFwiR2F0ZXdheSBhdXRoIHRva2VuXCIpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9IFwicGFzc3dvcmRcIjtcbiAgICAgICAgcmV0dXJuIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoXCJUb2tlblwiKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy50b2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy50b2tlbiA9IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSk7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoXCJSZWNvbm5lY3RcIilcbiAgICAgIC5zZXREZXNjKFwiUmUtZXN0YWJsaXNoIHRoZSBnYXRld2F5IGNvbm5lY3Rpb25cIilcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoXCJSZWNvbm5lY3RcIikub25DbGljaygoKSA9PiB7XG4gICAgICAgICAgdm9pZCB0aGlzLnBsdWdpbi5jb25uZWN0R2F0ZXdheSgpO1xuICAgICAgICAgIG5ldyBOb3RpY2UoXCJPcGVuQ2xhdzogUmVjb25uZWN0aW5nLi4uXCIpO1xuICAgICAgICB9KVxuICAgICAgKTtcbiAgfVxufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxzQkFjTztBQU9QLFNBQVMsSUFBSSxHQUFZLFdBQVcsSUFBWTtBQUM5QyxTQUFPLE9BQU8sTUFBTSxXQUFXLElBQUk7QUFDckM7QUF1QkEsSUFBTSxtQkFBcUM7QUFBQSxFQUN6QyxZQUFZO0FBQUEsRUFDWixPQUFPO0FBQUEsRUFDUCxZQUFZO0FBQUEsRUFDWixvQkFBb0I7QUFDdEI7QUFLQSxTQUFTLG9CQUFvQixLQUE0QjtBQUN2RCxNQUFJLE1BQU0sSUFBSSxLQUFLO0FBQ25CLE1BQUksSUFBSSxXQUFXLFVBQVU7QUFBRyxVQUFNLFdBQVcsSUFBSSxNQUFNLENBQUM7QUFBQSxXQUNuRCxJQUFJLFdBQVcsU0FBUztBQUFHLFVBQU0sVUFBVSxJQUFJLE1BQU0sQ0FBQztBQUMvRCxNQUFJLENBQUMsSUFBSSxXQUFXLE9BQU8sS0FBSyxDQUFDLElBQUksV0FBVyxRQUFRO0FBQUcsV0FBTztBQUVsRSxTQUFPLElBQUksUUFBUSxRQUFRLEVBQUU7QUFDL0I7QUFFQSxTQUFTLFlBQVksT0FBMkI7QUFDOUMsTUFBSSxTQUFTO0FBQ2IsYUFBVyxLQUFLO0FBQU8sY0FBVSxPQUFPLGFBQWEsQ0FBQztBQUN0RCxTQUFPLEtBQUssTUFBTSxFQUFFLFFBQVEsT0FBTyxHQUFHLEVBQUUsUUFBUSxPQUFPLEdBQUcsRUFBRSxRQUFRLFFBQVEsRUFBRTtBQUNoRjtBQUVBLFNBQVMsY0FBYyxHQUF1QjtBQUM1QyxRQUFNLFNBQVMsRUFBRSxRQUFRLE1BQU0sR0FBRyxFQUFFLFFBQVEsTUFBTSxHQUFHLElBQUksSUFBSSxRQUFRLElBQUssRUFBRSxTQUFTLEtBQU0sQ0FBQztBQUM1RixRQUFNLFNBQVMsS0FBSyxNQUFNO0FBQzFCLFFBQU0sUUFBUSxJQUFJLFdBQVcsT0FBTyxN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
