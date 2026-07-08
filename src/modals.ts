import { App, Modal } from 'obsidian'

class ConfirmCloseModal extends Modal {
  private title: string
  private message: string
  private callback: (result: boolean, dontAsk: boolean) => void
  private checkboxEl!: HTMLInputElement
  private resolved = false

  constructor(
    app: App,
    title: string,
    message: string,
    callback: (result: boolean, dontAsk: boolean) => void
  ) {
    super(app)
    this.title = title
    this.message = message
    this.callback = callback
  }

  onOpen(): void {
    const { contentEl } = this
    contentEl.addClass('openclaw-confirm-modal')
    contentEl.createEl('h3', {
      text: this.title,
      cls: 'openclaw-confirm-title',
    })
    contentEl.createEl('p', {
      text: this.message,
      cls: 'openclaw-confirm-message',
    })

    const checkRow = contentEl.createDiv('openclaw-confirm-check')
    this.checkboxEl = checkRow.createEl('input', { type: 'checkbox' })
    this.checkboxEl.id = 'confirm-dont-ask'
    checkRow.createEl('label', {
      text: "Don't ask me again",
      attr: { for: 'confirm-dont-ask' },
    })

    const btnRow = contentEl.createDiv('openclaw-confirm-buttons')
    const cancelBtn = btnRow.createEl('button', {
      text: 'Cancel',
      cls: 'openclaw-confirm-cancel',
    })
    cancelBtn.addEventListener('click', () => {
      this.resolve(false, false)
      this.close()
    })
    const confirmBtn = btnRow.createEl('button', {
      text: this.title.startsWith('Reset') ? 'Reset' : 'Close',
      cls: 'openclaw-confirm-ok',
    })
    confirmBtn.addEventListener('click', () => {
      this.resolve(true, this.checkboxEl.checked)
      this.close()
    })
  }

  private resolve(result: boolean, dontAsk: boolean): void {
    if (this.resolved) return
    this.resolved = true
    this.callback(result, dontAsk)
  }

  onClose(): void {
    this.contentEl.empty()
    // Escape or overlay click = cancel
    this.resolve(false, false)
  }
}

export { ConfirmCloseModal }
