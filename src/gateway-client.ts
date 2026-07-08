import { str } from './lib'
import { generateId, buildSignaturePayload, signDevicePayload } from './crypto'
import type { GatewayClientOpts, GatewayMessage, GatewayPayload } from './types'

/** Normalize a gateway URL: accepts ws://, wss://, http://, https:// and returns ws:// or wss://. Returns null if invalid. */
export function normalizeGatewayUrl(raw: string): string | null {
  let url = raw.trim()
  if (url.startsWith('https://')) url = 'wss://' + url.slice(8)
  else if (url.startsWith('http://')) url = 'ws://' + url.slice(7)
  if (!url.startsWith('ws://') && !url.startsWith('wss://')) return null
  // Strip trailing slash for consistency
  return url.replace(/\/+$/, '')
}

/**
 * Check whether a normalized gateway URL points to a loopback address.
 * This is used to warn users when they are about to send credentials over an
 * unencrypted websocket to a remote host.
 */
export function isLoopbackUrl(url: string): boolean {
  try {
    const parsed = new URL(url)
    const host = parsed.hostname
    return (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '[::1]'
    )
  } catch {
    return false
  }
}

/**
 * Delete a session via gateway, with fallback for unprefixed store keys.
 * The gateway stores channel sessions (telegram:, discord:, etc.) without the
 * agent:main: prefix, but sessions.list returns them prefixed. Sending the
 * prefixed key to sessions.delete succeeds ({ok:true}) but returns deleted:false
 * because the key lookup misses the unprefixed store entry.
 * Fix: if the first attempt returns deleted:false and the key has an agent prefix,
 * retry with the raw suffix (the actual store key).
 */
export async function deleteSessionWithFallback(
  gateway: GatewayClient,
  key: string,
  deleteTranscript = true
): Promise<boolean> {
  const result = (await gateway.request('sessions.delete', {
    key,
    deleteTranscript,
  })) as { deleted?: boolean } | null
  if (result?.deleted) return true

  // Fallback: strip agent:<id>: prefix and retry with raw key
  const match = key.match(/^agent:[^:]+:(.+)$/)
  if (match) {
    const rawKey = match[1]
    const retry = (await gateway.request('sessions.delete', {
      key: rawKey,
      deleteTranscript,
    })) as { deleted?: boolean } | null
    return !!retry?.deleted
  }
  return false
}

export class GatewayClient {
  private ws: WebSocket | null = null
  private pending = new Map<
    string,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >()
  private closed = false
  private connectSent = false
  private connectNonce: string | null = null
  private backoffMs = 800
  private opts: GatewayClientOpts
  private connectTimer: number | null = null
  private reconnectTimer: number | null = null
  private reconnectAttempts = 0
  private pendingTimeouts = new Map<string, number>()
  private static readonly MAX_RECONNECT_ATTEMPTS = 12

  constructor(opts: GatewayClientOpts) {
    this.opts = opts
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  start(): void {
    this.closed = false
    this.doConnect()
  }

  stop(): void {
    this.closed = true
    if (this.connectTimer !== null) {
      window.clearTimeout(this.connectTimer)
      this.connectTimer = null
    }
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    for (const [, t] of this.pendingTimeouts) window.clearTimeout(t)
    this.pendingTimeouts.clear()
    this.ws?.close()
    this.ws = null
    this.flushPending(new Error('client stopped'))
  }

  async request(method: string, params?: unknown): Promise<unknown> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('not connected')
    }
    const id = generateId()
    const msg = { type: 'req', id, method, params }
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      // Timeout requests after 30s
      const t = window.setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id)
          reject(new Error('request timeout'))
        }
      }, 30000)
      this.pendingTimeouts.set(id, t)
      this.ws!.send(JSON.stringify(msg))
    })
  }

  private doConnect(): void {
    if (this.closed) return

    // Normalize and validate URL
    const url = normalizeGatewayUrl(this.opts.url)
    if (!url) {
      console.error(
        '[OcO] Invalid gateway URL: must be a valid ws://, wss://, http://, or https:// URL'
      )
      return
    }

    this.ws = new WebSocket(url)
    this.ws.addEventListener('open', () => this.queueConnect())
    this.ws.addEventListener('message', (e) => this.handleMessage(str(e.data)))
    this.ws.addEventListener('close', (e) => {
      this.ws = null
      this.flushPending(new Error(`closed (${e.code})`))
      this.opts.onClose?.({ code: e.code, reason: e.reason || '' })
      this.scheduleReconnect()
    })
    this.ws.addEventListener('error', (_e) => {
      this.opts.onConnectError?.('websocket error')
    })
  }

  private scheduleReconnect(): void {
    if (this.closed) return
    if (this.reconnectAttempts >= GatewayClient.MAX_RECONNECT_ATTEMPTS) {
      const message = `giving up after ${this.reconnectAttempts} failed connection attempts`
      console.error('[OcO]', message)
      this.opts.onConnectError?.(message)
      return
    }
    const delay = this.backoffMs
    this.backoffMs = Math.min(this.backoffMs * 1.7, 15000)
    this.reconnectAttempts += 1
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      this.doConnect()
    }, delay)
  }

  private flushPending(err: Error): void {
    for (const [id, p] of this.pending) {
      const t = this.pendingTimeouts.get(id)
      if (t) window.clearTimeout(t)
      p.reject(err)
    }
    this.pending.clear()
    this.pendingTimeouts.clear()
  }

  private queueConnect(): void {
    this.connectNonce = null
    this.connectSent = false
    if (this.connectTimer !== null) window.clearTimeout(this.connectTimer)
    this.connectTimer = window.setTimeout(() => void this.sendConnect(), 750)
  }

  private async sendConnect(): Promise<void> {
    if (this.connectSent) return
    this.connectSent = true
    if (this.connectTimer !== null) {
      window.clearTimeout(this.connectTimer)
      this.connectTimer = null
    }

    const CLIENT_ID = 'gateway-client'
    const CLIENT_MODE = 'ui'
    const ROLE = 'operator'
    const SCOPES = ['operator.admin', 'operator.write', 'operator.read']

    const auth = this.opts.token ? { token: this.opts.token } : undefined

    // Build device fingerprint if identity is available
    let device:
      | {
          id: string
          publicKey: string
          signature: string
          signedAt: number
          nonce?: string
        }
      | undefined = undefined
    const identity = this.opts.deviceIdentity
    if (identity) {
      try {
        const signedAtMs = Date.now()
        const nonce = this.connectNonce ?? null
        const payload = buildSignaturePayload({
          deviceId: identity.deviceId,
          clientId: CLIENT_ID,
          clientMode: CLIENT_MODE,
          role: ROLE,
          scopes: SCOPES,
          signedAtMs,
          token: this.opts.token ?? null,
          nonce,
        })
        const signature = await signDevicePayload(identity, payload)
        device = {
          id: identity.deviceId,
          publicKey: identity.publicKey,
          signature,
          signedAt: signedAtMs,
          nonce: nonce ?? undefined,
        }
      } catch (e) {
        console.error('[OcO] Device signing failed:', e)
      }
    }

    const params = {
      minProtocol: 4,
      maxProtocol: 4,
      client: {
        id: CLIENT_ID,
        version: '0.1.0',
        platform: 'obsidian',
        mode: CLIENT_MODE,
      },
      role: ROLE,
      scopes: SCOPES,
      auth,
      device,
      caps: ['tool-events'],
    }

    void this.request('connect', params)
      .then((payload) => {
        this.backoffMs = 800
        this.reconnectAttempts = 0
        this.opts.onHello?.(payload as GatewayPayload)
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err)
        this.opts.onConnectError?.(message)
        this.ws?.close(4008, message.slice(0, 120) || 'connect failed')
      })
  }

  private handleMessage(raw: string): void {
    let msg: GatewayMessage
    try {
      msg = JSON.parse(raw) as GatewayMessage
    } catch {
      return
    }

    if (msg.type === 'event') {
      if (msg.event === 'connect.challenge') {
        const nonce = msg.payload?.nonce
        if (typeof nonce === 'string') {
          this.connectNonce = nonce
          void this.sendConnect()
        }
        return
      }
      if (msg.event)
        this.opts.onEvent?.({
          event: msg.event,
          payload: msg.payload ?? {},
          seq: msg.seq,
        })
      return
    }

    if (msg.type === 'res') {
      const msgId = msg.id ?? ''
      const p = this.pending.get(msgId)
      if (!p) return
      this.pending.delete(msgId)
      const t = this.pendingTimeouts.get(msgId)
      if (t) {
        window.clearTimeout(t)
        this.pendingTimeouts.delete(msgId)
      }
      if (msg.ok) {
        p.resolve(msg.payload)
      } else {
        p.reject(new Error(msg.error?.message ?? 'request failed'))
      }
    }
  }
}
