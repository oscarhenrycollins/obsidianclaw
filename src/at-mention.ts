// Pure @-mention + attachment logic with NO `obsidian` import — unit-tested
// in at-mention.test.ts. main.ts maps real `TFile`/`File` objects onto these.

/** File-type buckets the chat input treats differently. */
export type FileKind = 'image' | 'text' | 'binary'

const TEXT_MIME = [
  'application/json',
  'application/yaml',
  'application/xml',
  'application/javascript',
]
const TEXT_EXT =
  /\.(md|txt|json|csv|yaml|yml|js|ts|py|html|css|xml|toml|ini|sh|log)$/i
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i

/** Clip text content to `max` chars, appending a marker when clipped. */
export function truncate(content: string, max = 10000): string {
  return content.length > max
    ? content.slice(0, max) + '\n...(truncated)'
    : content
}

/** Wrap text-file content in a fenced block under a `File:` header. */
export function wrapTextContent(label: string, content: string): string {
  return `File: ${label}\n\`\`\`\n${content}\n\`\`\``
}

/**
 * Build a text-file attachment with a metadata header: the (vault-relative)
 * label, original line count, and a truncation note when the body was clipped.
 * Gives the receiving agent enough to tell files apart and to know whether it's
 * seeing the whole file. `label` should be the vault path when available.
 */
export function formatTextAttachment(
  label: string,
  content: string,
  max = 40000
): string {
  const lines = content.split('\n').length
  const clipped = content.length > max
  const meta = `${lines} line${lines === 1 ? '' : 's'}${clipped ? `, truncated to ${max} chars` : ''}`
  return wrapTextContent(`${label} (${meta})`, truncate(content, max))
}

/** A parsed chunk of a stored message: plain text, or a file attachment block. */
export type MessageSegment =
  { type: 'text'; text: string } | { type: 'file'; label: string; body: string }

/**
 * Split a stored message into text and file-attachment segments, inverting
 * `wrapTextContent`/`formatTextAttachment`. A `File: <label>\n```\n…\n``` `
 * block becomes a `file` segment (so the UI can collapse it behind a toggle
 * instead of dumping the whole file into the history); everything else is
 * `text`. Empty/whitespace-only spans between blocks are dropped. Matching is
 * non-greedy, so a code fence inside the file body would close it early — an
 * accepted limitation that mirrors the naive fence used when wrapping.
 */
export function splitFileBlocks(text: string): MessageSegment[] {
  const segments: MessageSegment[] = []
  const re = /(^|\n)File: ([^\n]+)\n```\n([\s\S]*?)\n```/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const pre = text.slice(last, m.index).trim()
    if (pre) segments.push({ type: 'text', text: pre })
    segments.push({ type: 'file', label: m[2], body: m[3] })
    last = m.index + m[0].length
  }
  const rest = text.slice(last).trim()
  if (rest) segments.push({ type: 'text', text: rest })
  return segments
}

/** Bucket a file by mime type, falling back to extension, then binary. */
export function classifyFile({
  name,
  mimeType,
}: {
  name: string
  mimeType: string
}): FileKind {
  if (mimeType.startsWith('image/') || IMAGE_EXT.test(name)) return 'image'
  if (
    mimeType.startsWith('text/') ||
    TEXT_MIME.includes(mimeType) ||
    TEXT_EXT.test(name)
  )
    return 'text'
  return 'binary'
}

/**
 * Detect an active `@`-mention ending at `cursor`.
 *
 * Returns the query (text after `@`, up to the cursor) and the index of the
 * `@`, or null when there's no mention. A mention only triggers when the `@`
 * sits at a word boundary (start of text or after whitespace), so `email@x`
 * doesn't fire; `@@` is treated as a literal escape and doesn't fire either.
 */
export function detectMention(
  text: string,
  cursor: number
): { query: string; start: number } | null {
  if (cursor <= 0) return null
  let start = cursor
  while (start > 0 && !/\s/.test(text[start - 1])) start--
  const word = text.slice(start, cursor)
  if (word[0] !== '@' || word[1] === '@') return null
  return { query: word.slice(1), start }
}

/**
 * Replace the `@query` span (the `@` at `start` plus `queryLen` chars) with
 * `insert`, returning the new textarea value and where the caret should land
 * (right after the inserted text). Pure so the cursor math is unit-tested.
 */
export function replaceMention(
  value: string,
  start: number,
  queryLen: number,
  insert: string
): { value: string; caret: number } {
  const end = start + 1 + queryLen
  return {
    value: value.slice(0, start) + insert + value.slice(end),
    caret: start + insert.length,
  }
}

/**
 * Reconcile inline @-mention attachments against the textarea text: keep an
 * inline attachment only while its exact `@<path>` token is still present.
 * Non-inline (chip) attachments and inline ones without a token are always
 * kept. Returns a new array; never mutates the input. This is how deleting the
 * inline text "un-attaches" a file.
 */
export function reconcileMentions<
  T extends { inline?: boolean; token?: string },
>(value: string, attachments: T[]): T[] {
  return attachments.filter(
    (a) => !(a.inline && a.token && !value.includes(a.token))
  )
}

/**
 * Rank vault files for the mention dropdown.
 *
 * With no query, returns the most-recently-modified files. With a query,
 * keeps only files the `score` fn matches (returns non-null), sorted by score
 * descending and recency as the tiebreak. The `score` fn is injected so this
 * stays `obsidian`-free — `main.ts` backs it with `prepareQuery`/`fuzzySearch`.
 */
export function rankMentions<T extends { path: string; mtime: number }>(
  files: T[],
  query: string,
  score: (query: string, path: string) => number | null,
  limit = 50
): T[] {
  if (!query) {
    return [...files].sort((a, b) => b.mtime - a.mtime).slice(0, limit)
  }
  const scored: { file: T; s: number }[] = []
  for (const file of files) {
    const s = score(query, file.path)
    if (s !== null) scored.push({ file, s })
  }
  scored.sort((a, b) => b.s - a.s || b.file.mtime - a.file.mtime)
  return scored.slice(0, limit).map((x) => x.file)
}
