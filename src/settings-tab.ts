import { App, Notice, PluginSettingTab, Setting } from 'obsidian'
import { isLoopbackUrl, normalizeGatewayUrl } from './gateway-client'
import type OpenClawPlugin from './main'

export class OpenClawSettingTab extends PluginSettingTab {
  plugin: OpenClawPlugin

  constructor(app: App, plugin: OpenClawPlugin) {
    super(app, plugin)
    this.plugin = plugin
  }

  display(): void {
    const { containerEl } = this
    containerEl.empty()

    new Setting(containerEl).setName('Chat').setHeading()

    // ─── Connection hint ───────────────────────────────────────────
    const hintSection = containerEl.createDiv('openclaw-settings-wizard')
    hintSection.createEl('p', {
      text: 'Set your gateway URL and token below, then click Reconnect.',
      cls: 'setting-item-description',
    })

    // ─── Status ──────────────────────────────────────────────────
    const statusSection = containerEl.createDiv('openclaw-settings-status')
    const connected = this.plugin.gatewayConnected
    statusSection.createSpan({
      cls: `openclaw-settings-dot ${connected ? 'connected' : 'disconnected'}`,
    })
    statusSection.createSpan({
      text: connected ? 'Connected' : 'Disconnected',
      cls: 'openclaw-settings-status-text',
    })
    if (this.plugin.settings.gatewayUrl) {
      statusSection.createSpan({
        text: ` - ${this.plugin.settings.gatewayUrl.replace(/^wss?:\/\//, '')}`,
        cls: 'openclaw-settings-status-url',
      })
    }

    // ─── Session ──────────────────────────────────────────────────
    new Setting(containerEl).setName('Session').setHeading()

    new Setting(containerEl)
      .setName('Conversation')
      .setDesc('Current conversation key. Use "main" for the default session.')
      .addText((text) =>
        text
          .setPlaceholder('Main')
          .setValue(this.plugin.settings.sessionKey)
          .onChange(async (value) => {
            this.plugin.settings.sessionKey = value || 'main'
            await this.plugin.saveSettings()
            this.plugin.broadcastToChatViews((v) => v.syncFromSettings())
          })
      )
      .addButton((btn) =>
        btn.setButtonText('Reset to main').onClick(async () => {
          this.plugin.settings.sessionKey = 'main'
          await this.plugin.saveSettings()
          this.display() // refresh the settings UI
          this.plugin.broadcastToChatViews((v) => v.syncFromSettings())
          new Notice('Reset to main conversation')
        })
      )

    // ─── Behavior ─────────────────────────────────────────────────
    new Setting(containerEl)
      .setName('Confirm before closing tabs')
      .setDesc('Show a confirmation dialog before closing or resetting tabs')
      .addToggle((toggle) =>
        toggle
          .setValue(!this.plugin.getCloseConfirmDisabled())
          .onChange((value) => {
            this.plugin.setCloseConfirmDisabled(!value)
          })
      )

    // ─── Connection (Advanced) ────────────────────────────────────
    new Setting(containerEl)
      .setName('Connection')
      .setDesc("Edit manually if you know what you're doing.")
      .setHeading()

    new Setting(containerEl)
      .setName('Gateway URL')
      .setDesc('Gateway URL (e.g. ws://127.0.0.1:18789)')
      .addText((text) =>
        text
          .setPlaceholder('ws://127.0.0.1:18789')
          .setValue(this.plugin.settings.gatewayUrl)
          .onChange(async (value) => {
            const normalized = normalizeGatewayUrl(value)
            this.plugin.settings.gatewayUrl = normalized || value
            await this.plugin.saveSettings()
            if (
              normalized &&
              !isLoopbackUrl(normalized) &&
              !normalized.startsWith('wss://')
            ) {
              new Notice(
                'OcO: ws:// to a remote host sends your token unencrypted. Use wss:// or a private tunnel.',
                8000
              )
            }
          })
      )

    new Setting(containerEl)
      .setName('Auth token')
      .setDesc('Gateway auth token')
      .addText((text) => {
        text.inputEl.type = 'password'
        return text
          .setPlaceholder('Token')
          .setValue(this.plugin.settings.token)
          .onChange(async (value) => {
            this.plugin.settings.token = value
            await this.plugin.saveSettings()
          })
      })

    new Setting(containerEl)
      .setName('Reconnect')
      .setDesc('Re-establish the gateway connection')
      .addButton((btn) =>
        btn.setButtonText('Reconnect').onClick(() => {
          void this.plugin.connectGateway()
          new Notice('OcO: Reconnecting...')
        })
      )
  }
}
