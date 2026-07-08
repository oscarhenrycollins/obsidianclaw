import { Modal, Notice, Plugin } from 'obsidian'
import {
  GatewayClient,
  isLoopbackUrl,
  normalizeGatewayUrl,
} from './gateway-client'
import { getOrCreateDeviceIdentity } from './crypto'
import { OpenClawChatView, VIEW_TYPE } from './chat-view'
import { OpenClawSettingTab } from './settings-tab'
import type { OpenClawSettings, DeviceIdentity } from './types'

// ─── Settings ────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: '',
  token: '',
  sessionKey: 'main',
}

// ─── Welcome Modal ─────────────────────────────────────────────────────

class WelcomeModal extends Modal {
  onOpen(): void {
    this.contentEl.createEl('h2', { text: 'Welcome to OcO' })
    this.contentEl.createEl('p', {
      text: "This plugin connects Obsidian to your OpenClaw AI agent. Your vault becomes the agent's workspace.",
      cls: 'openclaw-onboard-desc',
    })
    this.contentEl.createEl('p', {
      text: 'Go to Settings → OcO → Connection to enter your gateway URL and token.',
      cls: 'openclaw-onboard-desc',
    })
    const btnRow = this.contentEl.createDiv('openclaw-onboard-buttons')
    btnRow
      .createEl('button', {
        text: 'Got it',
        cls: 'mod-cta',
      })
      .addEventListener('click', () => this.close())
  }
}

// ─── Main Plugin ─────────────────────────────────────────────────────

export default class OpenClawPlugin extends Plugin {
  settings: OpenClawSettings = DEFAULT_SETTINGS
  gateway: GatewayClient | null = null
  gatewayConnected = false
  lastGatewayConnectError = ''
  private chatViews = new Set<OpenClawChatView>()
  activeChatView: OpenClawChatView | null = null
  // Consecutive close events with no successful hello in between.
  // After a few in a row, we surface the patch hint - a likely sign the
  // gateway is rejecting our origin during the websocket handshake.
  private handshakeFailuresInARow = 0
  private patchHintShownThisSession = false
  private welcomeTimer: number | null = null

  /** Register an open chat view so gateway events can reach it. */
  registerChatView(view: OpenClawChatView): void {
    this.chatViews.add(view)
    this.activeChatView = view
  }

  /** Unregister a closed chat view. */
  unregisterChatView(view: OpenClawChatView): void {
    this.chatViews.delete(view)
    if (this.activeChatView === view) {
      // Pick another active view, or null if none remain
      const next = this.chatViews.values().next()
      this.activeChatView = next.done ? null : next.value
    }
  }

  /** Invoke a callback on every registered chat view. */
  broadcastToChatViews(fn: (view: OpenClawChatView) => void): void {
    for (const view of this.chatViews) {
      fn(view)
    }
  }

  async onload(): Promise<void> {
    await this.loadSettings()

    this.registerView(VIEW_TYPE, (leaf) => new OpenClawChatView(leaf, this))

    // Ribbon icon
    this.addRibbonIcon('message-square', 'OcO chat', () => {
      void this.openChatInNewTab()
    })

    // Commands
    this.addCommand({
      id: 'open-chat-tab',
      name: 'Open chat in new tab',
      callback: () => void this.openChatInNewTab(),
    })

    this.addCommand({
      id: 'ask-about-note',
      name: 'Ask about current note',
      callback: () => void this.askAboutNote(),
    })

    this.addCommand({
      id: 'reconnect',
      name: 'Reconnect to gateway',
      callback: () => void this.connectGateway(),
    })

    this.addSettingTab(new OpenClawSettingTab(this.app, this))

    // Show welcome on first run; otherwise auto-connect only (no auto-open)
    if (!this.settings.gatewayUrl) {
      this.welcomeTimer = window.setTimeout(
        () => new WelcomeModal(this.app).open(),
        500
      )
    } else {
      void this.connectGateway()
    }
  }

  onunload(): void {
    if (this.welcomeTimer !== null) {
      window.clearTimeout(this.welcomeTimer)
      this.welcomeTimer = null
    }
    this.gateway?.stop()
    this.gateway = null
    this.gatewayConnected = false
  }

  async loadSettings(): Promise<void> {
    const data = (await this.loadData()) as Partial<OpenClawSettings> | null
    this.settings = Object.assign({}, DEFAULT_SETTINGS, data ?? {})
  }

  getCloseConfirmDisabled(): boolean {
    return this.settings.confirmCloseDisabled === true
  }

  setCloseConfirmDisabled(disabled: boolean): void {
    this.settings.confirmCloseDisabled = disabled
    void this.saveSettings()
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings)
  }

  async connectGateway(): Promise<void> {
    this.gateway?.stop()
    this.gatewayConnected = false
    this.lastGatewayConnectError = ''
    this.broadcastToChatViews((v) => v.updateStatus())

    const rawUrl = this.settings.gatewayUrl.trim()
    if (!rawUrl) return

    // Normalize URL (accept https:// and http:// as well)
    const url = normalizeGatewayUrl(rawUrl)
    if (!url) {
      new Notice(
        'OcO: Invalid gateway URL. Use ws://127.0.0.1:18789 (or your custom address).'
      )
      return
    }

    // Persist the normalized form if it changed
    if (url !== rawUrl) {
      this.settings.gatewayUrl = url
      await this.saveSettings()
    }

    // Warn when connecting to a remote host without transport encryption
    if (!isLoopbackUrl(url) && !url.startsWith('wss://')) {
      new Notice(
        'OcO: Using an unencrypted websocket (ws://) to a remote host. Use wss:// or a private tunnel.',
        8000
      )
    }

    // Get or create device identity for scope authorization
    let deviceIdentity: DeviceIdentity | undefined
    try {
      deviceIdentity = await getOrCreateDeviceIdentity(
        () => this.loadData(),
        (data) => this.saveData(data)
      )
    } catch (e) {
      console.warn(
        '[OcO] Device identity creation failed, connecting without scopes:',
        e
      )
      new Notice(
        'OcO: Could not create device identity. Device pairing will not be available.',
        8000
      )
    }

    this.gateway = new GatewayClient({
      url,
      token: this.settings.token.trim() || undefined,
      deviceIdentity,
      onHello: () => {
        this.gatewayConnected = true
        this.lastGatewayConnectError = ''
        this.handshakeFailuresInARow = 0
        this.broadcastToChatViews((v) => v.updateStatus())
        this.broadcastToChatViews((v) => v.hidePairingBanner()) // Dismiss pairing banner on successful connection
        this.broadcastToChatViews((v) => void v.loadHistory())
        this.broadcastToChatViews((v) => void v.renderTabs())
        this.broadcastToChatViews((v) => void v.loadAgents())
        this.broadcastToChatViews((v) => void v.loadDefaults())
        // Restore persisted model selection
        if (this.settings.currentModel) {
          this.broadcastToChatViews((v) => {
            v.currentModel = this.settings.currentModel!
            v.updateModelPill()
          })
        }
      },
      onClose: (info) => {
        const wasConnected = this.gatewayConnected
        this.gatewayConnected = false
        this.broadcastToChatViews((v) => v.updateStatus())
        // Show pairing banner if needed
        const reason = info.reason.toLowerCase()
        if (
          reason.includes('pair') ||
          reason.includes('device') ||
          reason.includes('approval') ||
          reason.includes('scope') ||
          reason.includes('auth')
        ) {
          this.broadcastToChatViews((v) => v.showPairingBanner())
        }
        // Track handshake-only failures (closed without ever reaching onHello).
        // 3+ in a row with no descriptive reason is a strong hint the gateway
        // rejected our origin at the websocket upgrade - show the patch tip once.
        if (!wasConnected) {
          this.handshakeFailuresInARow += 1
          const lacksReason = !info.reason || info.reason.trim() === ''
          if (
            this.handshakeFailuresInARow >= 3 &&
            lacksReason &&
            !this.patchHintShownThisSession
          ) {
            this.patchHintShownThisSession = true
            new Notice(
              'OcO: handshake keeps failing. Apply the origin patch (see README) or check Settings → OcO → Connection.',
              12000
            )
          }
        }
      },
      onConnectError: (message) => {
        this.lastGatewayConnectError = message
      },
      onEvent: (evt) => {
        if (evt.event === 'chat') {
          this.broadcastToChatViews((v) => v.handleChatEvent(evt.payload))
        } else if (evt.event === 'stream' || evt.event === 'agent') {
          this.broadcastToChatViews((v) => v.handleStreamEvent(evt.payload))
        }
      },
    })

    this.gateway.start()
  }

  async openChatInNewTab(): Promise<void> {
    const leaf = this.app.workspace.getLeaf('tab')
    await leaf.setViewState({ type: VIEW_TYPE, active: true })
    this.app.workspace.setActiveLeaf(leaf, { focus: true })
  }

  async askAboutNote(): Promise<void> {
    const file = this.app.workspace.getActiveFile()
    if (!file) {
      new Notice('No active note')
      return
    }

    const content = await this.app.vault.read(file)
    if (!content.trim()) {
      new Notice('Note is empty')
      return
    }

    let target = this.activeChatView
    if (!target) {
      await this.openChatInNewTab()
      // Give the view a moment to instantiate and register itself
      await new Promise((r) => window.setTimeout(r, 50))
      target = this.activeChatView
    } else {
      // Focus the existing leaf
      const leaf = this.app.workspace
        .getLeavesOfType(VIEW_TYPE)
        .find((l) => (l.view as OpenClawChatView) === target)
      if (leaf) this.app.workspace.setActiveLeaf(leaf, { focus: true })
    }

    if (!target || !this.gateway?.connected) {
      new Notice('Not connected to OcO')
      return
    }

    const MAX_NOTE_CHARS = 12000
    const trimmedContent =
      content.length > MAX_NOTE_CHARS
        ? content.slice(0, MAX_NOTE_CHARS) +
          '\n\n[Note truncated: exceeds size limit]'
        : content

    const message = `Here is my current note "${file.basename}":\n\n${trimmedContent}\n\nWhat can you tell me about this?`
    const inputEl = target.containerEl.querySelector(
      '.openclaw-input'
    ) as HTMLTextAreaElement
    if (inputEl) {
      inputEl.value = message
      inputEl.focus()
      // Trigger the input handler so the textarea auto-resizes and the send
      // button reflects the new content.
      inputEl.dispatchEvent(new Event('input'))
    }
  }
}
