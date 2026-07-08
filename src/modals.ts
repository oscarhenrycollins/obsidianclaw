import { App, Modal, FuzzySuggestModal, TFile } from 'obsidian'

class _ConfirmModal extends Modal {
  private config: {
    title: string
    message: string
    confirmText: string
    onConfirm: () => void
  }

  constructor(
    app: App,
    config: {
      title: string
      message: string
      confirmText: string
      onConfirm: () => void
    }
  ) {
    super(app)
    this.config = config
  }

  onOpen(): void {
    const { contentEl } = this
    contentEl.addClass('openclaw-confirm-modal')
    contentEl.createEl('h3', {
      text: this.config.title,
      cls: 'openclaw-confirm-title',
    })
    contentEl.createEl('p', {
      text: this.config.message,
      cls: 'openclaw-confirm-message',
    })
    const btnRow = contentEl.createDiv('openclaw-confirm-buttons')
    const cancelBtn = btnRow.createEl('button', {
      text: 'Cancel',
      cls: 'openclaw-confirm-cancel',
    })
    cancelBtn.addEventListener('click', () => this.close())
    const confirmBtn = btnRow.createEl('button', {
      text: this.config.confirmText,
      cls: 'openclaw-confirm-ok',
    })
    confirmBtn.addEventListener('click', () => {
      this.close()
      this.config.onConfirm()
    })
  }

  onClose(): void {
    this.contentEl.empty()
  }
}

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

class _TextInputModal extends Modal {
  private config: {
    title: string
    placeholder: string
    confirmText: string
    initialValue?: string
    onConfirm: (value: string) => void
  }
  private inputEl!: HTMLInputElement

  constructor(
    app: App,
    config: {
      title: string
      placeholder: string
      confirmText: string
      initialValue?: string
      onConfirm: (value: string) => void
    }
  ) {
    super(app)
    this.config = config
  }

  onOpen(): void {
    const { contentEl } = this
    contentEl.addClass('openclaw-confirm-modal')
    contentEl.createEl('h3', {
      text: this.config.title,
      cls: 'openclaw-confirm-title',
    })
    this.inputEl = contentEl.createEl('input', {
      type: 'text',
      placeholder: this.config.placeholder,
      cls: 'openclaw-text-input',
    })
    if (this.config.initialValue) this.inputEl.value = this.config.initialValue
    this.inputEl.focus()
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault()
        this.submit()
      }
    })
    const btnRow = contentEl.createDiv('openclaw-confirm-buttons')
    const cancelBtn = btnRow.createEl('button', {
      text: 'Cancel',
      cls: 'openclaw-confirm-cancel',
    })
    cancelBtn.addEventListener('click', () => this.close())
    const confirmBtn = btnRow.createEl('button', {
      text: this.config.confirmText,
      cls: 'openclaw-confirm-ok',
    })
    confirmBtn.addEventListener('click', () => this.submit())
  }

  private submit(): void {
    const value = this.inputEl.value.trim()
    if (!value) return
    this.close()
    this.config.onConfirm(value)
  }

  onClose(): void {
    this.contentEl.empty()
  }
}

class _AttachmentModal extends FuzzySuggestModal<TFile> {
  private files: TFile[]
  private onChoose: (file: TFile) => void

  constructor(app: App, files: TFile[], onChoose: (file: TFile) => void) {
    super(app)
    this.files = files
    this.onChoose = onChoose
    this.setPlaceholder('Search files to attach...')
  }

  getItems(): TFile[] {
    return this.files
  }

  getItemText(file: TFile): string {
    return file.path
  }

  onChooseItem(file: TFile): void {
    this.onChoose(file)
  }
}

export { _ConfirmModal, ConfirmCloseModal, _TextInputModal, _AttachmentModal }
