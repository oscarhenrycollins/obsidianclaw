import {
  App,
  ItemView,
  MarkdownRenderer,
  Notice,
  Plugin,
  PluginSettingTab,
  Setting,
  WorkspaceLeaf,
} from "obsidian";

// ─── Settings ────────────────────────────────────────────────────────

interface OpenClawSettings {
  gatewayUrl: string;
  token: string;
  sessionKey: string;
}

const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: "ws://127.0.0.1:18789",
  token: "",
  sessionKey: "main",
};

// ─── Gateway Client ──────────────────────────────────────────────────

type GatewayEventHandler = (event: { event: string; payload: any; seq?: number }) => void;
type GatewayHelloHandler = (payload: any) => void;
type GatewayCloseHandler = (info: { code: number; reason: string }) => void;

interface GatewayClientOpts {
  url: string;
  token?: string;
  onEvent?: GatewayEventHandler;
  onHello?: GatewayHelloHandler;
  onClose?: GatewayCloseHandler;
}

function uuid(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
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

  constructor(opts: GatewayClientOpts) {
    this.opts = opts;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  start(): void {
    this.closed = false;
    this.connect();
  }

  stop(): void {
    this.closed = true;
    this.ws?.close();
    this.ws = null;
    this.flushPending(new Error("client stopped"));
  }

  async request(method: string, params?: any): Promise<any> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("not connected");
    }
    const id = uuid();
    const msg = { type: "req", id, method, params };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws!.send(JSON.stringify(msg));
    });
  }

  private connect(): void {
    if (this.closed) return;
    this.ws = new WebSocket(this.opts.url);
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
    setTimeout(() => this.connect(), delay);
  }

  private flushPending(err: Error): void {
    for (const [, p] of this.pending) p.reject(err);
    this.pending.clear();
  }

  private queueConnect(): void {
    this.connectNonce = null;
    this.connectSent = false;
    if (this.connectTimer !== null) clearTimeout(this.connectTimer);
    this.connectTimer = setTimeout(() => this.sendConnect(), 750);
  }

  private sendConnect(): void {
    if (this.connectSent) return;
    this.connectSent = true;
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }

    const auth = this.opts.token ? { token: this.opts.token } : undefined;
    const params = {
      minProtocol: 3,
      maxProtocol: 3,
      client: {
        id: "obsidianclaw",
        version: "0.1.0",
        platform: "obsidian",
        mode: "webchat",
      },
      role: "operator",
      scopes: ["operator.admin"],
      auth,
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

    // Header
    const header = container.createDiv("openclaw-chat-header");
    this.statusEl = header.createSpan("openclaw-status-dot");
    header.createSpan({ text: "OpenClaw", cls: "openclaw-header-title" });

    // Messages area
    this.messagesEl = container.createDiv("openclaw-messages");

    // Input area
    const inputArea = container.createDiv("openclaw-input-area");
    this.inputEl = inputArea.createEl("textarea", {
      cls: "openclaw-input",
      attr: { placeholder: "Message your AI...", rows: "1" },
    });
    const btnGroup = inputArea.createDiv("openclaw-btn-group");
    this.abortBtn = btnGroup.createEl("button", { text: "Stop", cls: "openclaw-abort-btn" });
    this.abortBtn.style.display = "none";
    this.sendBtn = btnGroup.createEl("button", { text: "Send", cls: "openclaw-send-btn" });

    // Events
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
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
          .map((m: any) => ({
            role: m.role as "user" | "assistant",
            text: this.extractText(m.content),
            timestamp: m.timestamp ?? Date.now(),
          }))
          .filter((m: ChatMessage) => m.text.trim());
        await this.renderMessages();
      }
    } catch (e) {
      console.error("[ObsidianClaw] Failed to load history:", e);
    }
  }

  private extractText(content: any): string {
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      return content
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text)
        .join("\n");
    }
    return "";
  }

  async sendMessage(): Promise<void> {
    const text = this.inputEl.value.trim();
    if (!text || this.sending) return;
    if (!this.plugin.gateway?.connected) {
      new Notice("Not connected to OpenClaw gateway");
      return;
    }

    this.sending = true;
    this.sendBtn.disabled = true;
    this.inputEl.value = "";
    this.autoResize();

    // Add user message
    this.messages.push({ role: "user", text, timestamp: Date.now() });
    await this.renderMessages();

    const runId = uuid();
    this.streamRunId = runId;
    this.streamText = "";
    this.abortBtn.style.display = "";

    try {
      await this.plugin.gateway.request("chat.send", {
        sessionKey: this.plugin.settings.sessionKey,
        message: text,
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

  handleChatEvent(payload: any): void {
    if (payload.sessionKey !== this.plugin.settings.sessionKey) return;

    if (payload.state === "delta") {
      const text = this.extractText(payload.message);
      if (typeof text === "string") {
        this.streamText = text;
        this.updateStreamBubble();
      }
    } else if (payload.state === "final") {
      this.finishStream();
      // Reload history to get the final formatted message
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

    // Command: toggle chat
    this.addCommand({
      id: "toggle-chat",
      name: "Toggle chat sidebar",
      callback: () => this.activateView(),
    });

    // Command: ask about current note
    this.addCommand({
      id: "ask-about-note",
      name: "Ask about current note",
      callback: () => this.askAboutNote(),
    });

    // Command: reconnect
    this.addCommand({
      id: "reconnect",
      name: "Reconnect to gateway",
      callback: () => this.connectGateway(),
    });

    this.addSettingTab(new OpenClawSettingTab(this.app, this));

    // Auto-connect
    this.connectGateway();
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

  connectGateway(): void {
    this.gateway?.stop();
    this.gatewayConnected = false;
    this.chatView?.updateStatus();

    const url = this.settings.gatewayUrl.trim();
    if (!url) return;

    this.gateway = new GatewayClient({
      url,
      token: this.settings.token.trim() || undefined,
      onHello: () => {
        this.gatewayConnected = true;
        this.chatView?.updateStatus();
        this.chatView?.loadHistory();
        new Notice("OpenClaw connected");
      },
      onClose: () => {
        this.gatewayConnected = false;
        this.chatView?.updateStatus();
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

    // Add to input so user can modify before sending
    if (this.chatView) {
      const inputEl = this.chatView.containerEl.querySelector(".openclaw-input") as HTMLTextAreaElement;
      if (inputEl) {
        inputEl.value = message;
        inputEl.focus();
      }
    }
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

    containerEl.createEl("h2", { text: "OpenClaw Settings" });

    new Setting(containerEl)
      .setName("Gateway URL")
      .setDesc("WebSocket URL of your OpenClaw gateway (e.g., ws://127.0.0.1:18789 or ws://100.x.x.x:18789 via Tailscale)")
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
      .setDesc("Gateway authentication token (leave empty if no auth is configured)")
      .addText((text) =>
        text
          .setPlaceholder("Token")
          .setValue(this.plugin.settings.token)
          .onChange(async (value) => {
            this.plugin.settings.token = value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Session Key")
      .setDesc("Which session to chat in (default: main)")
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
      .setDesc("Reconnect to the gateway with current settings")
      .addButton((btn) =>
        btn.setButtonText("Reconnect").onClick(() => {
          this.plugin.connectGateway();
        })
      );
  }
}
