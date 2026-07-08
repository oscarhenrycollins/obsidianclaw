// ─── Domain Types ──────────────────────────────────────────────────────

export type StreamItem =
  | { type: 'tool'; label: string; url?: string; textPos?: number }
  | { type: 'text'; text: string }

export interface AgentInfo {
  id: string
  name: string
  emoji: string
  creature: string
}

export interface OpenClawSettings {
  gatewayUrl: string
  token: string
  sessionKey: string
  activeAgentId?: string // currently selected agent id
  currentModel?: string // persisted model selection (provider/model format)
  deviceId?: string
  devicePublicKey?: string
  devicePrivateKey?: string
  /** Saved tab order (non-Home tab keys) */
  tabOrder?: string[]
  /** Suppress the close/reset confirmation modal when true. */
  confirmCloseDisabled?: boolean
}

export interface DeviceIdentity {
  deviceId: string
  publicKey: string
  privateKey: string
  cryptoKey: CryptoKey
}

// ─── Gateway Types ───────────────────────────────────────────────────

export interface GatewayPayload {
  [key: string]: unknown
}

export interface GatewayMessage {
  type: string
  id?: string
  event?: string
  payload?: GatewayPayload
  ok?: boolean
  error?: { message?: string }
  seq?: number
}

export interface SessionInfo {
  key: string
  label?: string
  displayName?: string
  model?: string
  totalTokens?: number
  contextTokens?: number
  createdAt?: number
  updatedAt?: number
  thinkingLevel?: string
  verboseLevel?: string
  thinkingDefault?: string
  verboseDefault?: string
}

export interface AgentListItem {
  id?: string
  name?: string
}

export interface ModelInfo {
  id: string
  name?: string
  provider: string
}

export interface ContentBlock {
  type: string
  text?: string
  content?: string | ContentBlock[]
  name?: string
  input?: Record<string, unknown>
  arguments?: Record<string, unknown>
  image_url?: { url: string }
}

export interface HistoryMessage {
  role: string
  content: string | ContentBlock[]
  timestamp?: number
}

// ─── Gateway Client ──────────────────────────────────────────────────

export type GatewayEventHandler = (event: {
  event: string
  payload: GatewayPayload
  seq?: number
}) => void
export type GatewayHelloHandler = (payload: GatewayPayload) => void
export type GatewayCloseHandler = (info: {
  code: number
  reason: string
}) => void
export type GatewayConnectErrorHandler = (message: string) => void

export interface GatewayClientOpts {
  url: string
  token?: string
  deviceIdentity?: DeviceIdentity
  onEvent?: GatewayEventHandler
  onHello?: GatewayHelloHandler
  onClose?: GatewayCloseHandler
  onConnectError?: GatewayConnectErrorHandler
}

// ─── Chat Message Types ──────────────────────────────────────────────

export interface ChatMessage {
  role: 'user' | 'assistant'
  text: string
  images: string[] // data URIs or URLs
  timestamp: number
  contentBlocks?: ContentBlock[] // raw content array from history (preserves tool_use interleaving)
  voiceRefs?: string[] // VOICE:filename.b64 refs for audio playback via gateway
}

export interface SuggestItem {
  path: string
  display: string
}
