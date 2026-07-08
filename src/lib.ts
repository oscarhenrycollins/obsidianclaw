// Pure helpers with NO `obsidian` import — safe to unit-test with node:test.
// Anything that touches App/TFile/DOM stays in main.ts; logic that's easy to
// get subtly wrong lives here so it can be tested in isolation.

/** Safely extract a string from an unknown value (avoids [object Object] coercion). */
export function str(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback
}

/** Best-effort image MIME from a vault file extension (for base64 sends). */
export function imageMimeFromExt(ext: string): string {
  const e = ext.toLowerCase()
  if (e === 'jpg' || e === 'jpeg') return 'image/jpeg'
  if (e === 'svg') return 'image/svg+xml'
  return `image/${e}`
}

const SAFE_URL_SCHEMES = ['http:', 'https:']

/**
 * Validate a URL string that originated from an untrusted source (e.g. the
 * gateway) before rendering it as a clickable link or opening it externally.
 * Only `http:` and `https:` are permitted. Returns the normalized URL if safe,
 * otherwise null. This prevents a compromised gateway from pushing
 * javascript: or custom-scheme links into Obsidian's renderer context.
 */
export function safeGatewayUrl(raw: unknown): string | null {
  const url = str(raw)
  if (!url) return null
  try {
    const parsed = new URL(url)
    if (!SAFE_URL_SCHEMES.includes(parsed.protocol)) return null
    if (
      parsed.href.split('').some((c) => /\s/.test(c) || c.charCodeAt(0) <= 0x1f)
    )
      return null
    return parsed.href
  } catch {
    return null
  }
}
