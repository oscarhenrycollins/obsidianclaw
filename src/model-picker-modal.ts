import { App, Modal, Notice } from 'obsidian'
import type { ModelInfo } from './types'
import type OpenClawPlugin from './main'
import type { OpenClawChatView } from './chat-view'

export class ModelPickerModal extends Modal {
  plugin: OpenClawPlugin
  chatView: OpenClawChatView
  private models: ModelInfo[] = []
  private currentModel: string = ''
  private selectedProvider: string | null = null

  constructor(app: App, plugin: OpenClawPlugin, chatView: OpenClawChatView) {
    super(app)
    this.plugin = plugin
    this.chatView = chatView
  }

  async onOpen(): Promise<void> {
    this.modalEl.addClass('openclaw-picker')
    this.contentEl.createDiv('openclaw-picker-loading').textContent =
      'Loading models...'

    try {
      const result = (await this.plugin.gateway?.request('models.list', {})) as
        { models?: ModelInfo[] } | undefined
      this.models = result?.models || []
    } catch {
      this.models = []
    }

    // Normalize currentModel to always be provider/id format
    this.currentModel = this.chatView.currentModel || ''
    if (this.currentModel && !this.currentModel.includes('/')) {
      const match = this.models.find(
        (m: ModelInfo) => m.id === this.currentModel
      )
      if (match) this.currentModel = `${match.provider}/${match.id}`
    }

    // Auto-select provider of current model
    if (this.currentModel.includes('/')) {
      this.selectedProvider = this.currentModel.split('/')[0]
    }

    // If only one provider, skip straight to models
    const providers = new Set(this.models.map((m: ModelInfo) => m.provider))
    if (providers.size === 1) {
      this.renderModels([...providers][0])
    } else {
      this.renderProviders()
    }
  }

  onClose(): void {
    this.contentEl.empty()
  }

  private renderProviders(): void {
    const { contentEl } = this
    contentEl.empty()

    // Group models by provider
    const providerMap = new Map<string, ModelInfo[]>()
    for (const m of this.models) {
      const p = m.provider || 'unknown'
      if (!providerMap.has(p)) providerMap.set(p, [])
      providerMap.get(p)!.push(m)
    }

    // Current provider from currentModel
    const currentProvider = this.currentModel.includes('/')
      ? this.currentModel.split('/')[0]
      : ''

    const list = contentEl.createDiv('openclaw-picker-list')

    for (const [provider, models] of providerMap) {
      const isCurrent = provider === currentProvider
      const row = list.createDiv({
        cls: `openclaw-picker-row${isCurrent ? ' active' : ''}`,
      })

      const left = row.createDiv('openclaw-picker-row-left')
      if (isCurrent) left.createSpan({ text: '● ', cls: 'openclaw-picker-dot' })
      left.createSpan({ text: provider, cls: 'openclaw-picker-provider-name' })

      const right = row.createDiv('openclaw-picker-row-right')
      right.createSpan({
        text: `${models.length} model${models.length !== 1 ? 's' : ''}`,
        cls: 'openclaw-picker-meta',
      })
      right.createSpan({ text: ' →', cls: 'openclaw-picker-arrow' })

      row.addEventListener('click', () => {
        this.selectedProvider = provider
        this.renderModels(provider)
      })
    }

    // Footer
    const footer = contentEl.createDiv(
      'openclaw-picker-hint openclaw-picker-footer'
    )
    footer.appendText('Want more models? ')
    footer.createEl('a', {
      text: 'Add them in your gateway config.',
      href: 'https://docs.openclaw.ai/gateway/configuration#choose-and-configure-models',
    })
  }

  private renderModels(provider: string): void {
    const { contentEl } = this
    contentEl.empty()

    // Back button
    const providers = new Set(this.models.map((m: ModelInfo) => m.provider))
    if (providers.size > 1) {
      const header = contentEl.createDiv('openclaw-picker-header')
      const backBtn = header.createEl('button', {
        cls: 'openclaw-picker-back',
        text: '← ' + provider,
      })
      backBtn.addEventListener('click', () => this.renderProviders())
    }

    const models = this.models.filter((m: ModelInfo) => m.provider === provider)
    const list = contentEl.createDiv(
      'openclaw-picker-list openclaw-picker-model-list'
    )

    for (const m of models) {
      const fullId = `${m.provider}/${m.id}`
      const isCurrent = fullId === this.currentModel
      const row = list.createDiv({
        cls: `openclaw-picker-row${isCurrent ? ' active' : ''}`,
      })

      const left = row.createDiv('openclaw-picker-row-left')
      if (isCurrent) left.createSpan({ text: '● ', cls: 'openclaw-picker-dot' })
      left.createSpan({ text: m.name || m.id })

      // Always clickable - even the current model (user might want to re-select it)
      row.addEventListener(
        'click',
        () =>
          void (async () => {
            if (!this.plugin.gateway?.connected) return
            row.addClass('openclaw-picker-selecting')
            row.textContent = 'Switching...'
            try {
              await this.plugin.gateway.request('chat.send', {
                sessionKey: this.plugin.settings.sessionKey,
                message: `/model ${fullId}`,
                deliver: false,
                idempotencyKey: 'model-' + Date.now(),
              })
              this.chatView.currentModel = fullId
              this.chatView.currentModelSetAt = Date.now()
              this.plugin.settings.currentModel = fullId
              await this.plugin.saveSettings()
              this.chatView.updateModelPill()
              new Notice(`Model: ${m.name || m.id}`)
              this.close()
            } catch (e) {
              new Notice(`Failed: ${e}`)
              this.renderModels(provider)
            }
          })()
      )
    }
  }
}
