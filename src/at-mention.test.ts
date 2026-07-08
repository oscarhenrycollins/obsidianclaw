import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import {
  truncate,
  wrapTextContent,
  formatTextAttachment,
  splitFileBlocks,
  classifyFile,
  detectMention,
  rankMentions,
  replaceMention,
  reconcileMentions,
} from './at-mention'

// ─── truncate ────────────────────────────────────────────────────────

test('truncate leaves short content untouched', () => {
  assert.equal(truncate('hello', 10000), 'hello')
  assert.equal(truncate('', 10000), '')
})

test('truncate boundary: exactly at limit is untouched', () => {
  const s = 'a'.repeat(10000)
  assert.equal(truncate(s, 10000), s)
})

test('truncate boundary: one over limit gets clipped + marker', () => {
  const s = 'a'.repeat(10001)
  const out = truncate(s, 10000)
  assert.equal(out, 'a'.repeat(10000) + '\n...(truncated)')
})

// ─── wrapTextContent ─────────────────────────────────────────────────

test('wrapTextContent fences content under a File: header', () => {
  assert.equal(
    wrapTextContent('notes.md', 'line1\nline2'),
    'File: notes.md\n```\nline1\nline2\n```'
  )
})

// ─── formatTextAttachment ────────────────────────────────────────────

test('formatTextAttachment: header carries the label and line count', () => {
  assert.equal(
    formatTextAttachment('idea/spec.md', 'a\nb\nc'),
    'File: idea/spec.md (3 lines)\n```\na\nb\nc\n```'
  )
})

test('formatTextAttachment: singular line is not pluralized', () => {
  assert.equal(
    formatTextAttachment('one.md', 'just one line'),
    'File: one.md (1 line)\n```\njust one line\n```'
  )
})

test('formatTextAttachment: notes truncation in the header and clips the body', () => {
  const content = 'x'.repeat(10001)
  const out = formatTextAttachment('big.md', content, 10000)
  assert.equal(
    out,
    'File: big.md (1 line, truncated to 10000 chars)\n```\n' +
      'x'.repeat(10000) +
      '\n...(truncated)\n```'
  )
})

// ─── splitFileBlocks ─────────────────────────────────────────────────

test('splitFileBlocks: plain text is one text segment', () => {
  assert.deepEqual(splitFileBlocks('just a question'), [
    { type: 'text', text: 'just a question' },
  ])
})

test('splitFileBlocks: blank text yields no segments', () => {
  assert.deepEqual(splitFileBlocks('   \n  '), [])
})

test('splitFileBlocks: separates a mention from its attached file block', () => {
  const msg = formatTextAttachment('idea/spec.md', 'a\nb\nc')
  assert.deepEqual(splitFileBlocks(`@idea/spec.md summary please\n\n${msg}`), [
    { type: 'text', text: '@idea/spec.md summary please' },
    { type: 'file', label: 'idea/spec.md (3 lines)', body: 'a\nb\nc' },
  ])
})

test('splitFileBlocks: handles two attached files in one message', () => {
  const msg = `look\n\n${formatTextAttachment('a.md', 'aaa')}\n\n${formatTextAttachment('b.md', 'bbb')}`
  assert.deepEqual(splitFileBlocks(msg), [
    { type: 'text', text: 'look' },
    { type: 'file', label: 'a.md (1 line)', body: 'aaa' },
    { type: 'file', label: 'b.md (1 line)', body: 'bbb' },
  ])
})

test('splitFileBlocks: a file block with no surrounding text yields just the file', () => {
  assert.deepEqual(splitFileBlocks(formatTextAttachment('only.md', 'x')), [
    { type: 'file', label: 'only.md (1 line)', body: 'x' },
  ])
})

// ─── classifyFile ────────────────────────────────────────────────────

test('classifyFile detects images by mime', () => {
  assert.equal(classifyFile({ name: 'p.png', mimeType: 'image/png' }), 'image')
  assert.equal(classifyFile({ name: 'p', mimeType: 'image/jpeg' }), 'image')
})

test('classifyFile detects text by mime', () => {
  assert.equal(classifyFile({ name: 'x', mimeType: 'text/plain' }), 'text')
  assert.equal(
    classifyFile({ name: 'x', mimeType: 'application/json' }),
    'text'
  )
})

test('classifyFile detects images by extension when mime is empty', () => {
  // Vault files give us an extension but no mime type.
  assert.equal(classifyFile({ name: 'diagram.PNG', mimeType: '' }), 'image')
  assert.equal(classifyFile({ name: 'photo.jpeg', mimeType: '' }), 'image')
  assert.equal(classifyFile({ name: 'icon.svg', mimeType: '' }), 'image')
})

test('classifyFile detects text by extension when mime is empty', () => {
  assert.equal(classifyFile({ name: 'README.md', mimeType: '' }), 'text')
  assert.equal(classifyFile({ name: 'Config.YAML', mimeType: '' }), 'text')
  assert.equal(classifyFile({ name: 'script.ts', mimeType: '' }), 'text')
})

test('classifyFile falls back to binary', () => {
  assert.equal(classifyFile({ name: 'a.bin', mimeType: '' }), 'binary')
  assert.equal(
    classifyFile({ name: 'a.pdf', mimeType: 'application/pdf' }),
    'binary'
  )
})

// ─── detectMention ───────────────────────────────────────────────────

test('detectMention: bare @ at start opens an empty query', () => {
  assert.deepEqual(detectMention('@', 1), { query: '', start: 0 })
})

test('detectMention: @ after whitespace yields the query', () => {
  assert.deepEqual(detectMention('hello @pro', 10), { query: 'pro', start: 6 })
})

test('detectMention: @ after a newline triggers', () => {
  assert.deepEqual(detectMention('a\n@x', 4), { query: 'x', start: 2 })
})

test('detectMention: query is sliced to the cursor, not end of word', () => {
  assert.deepEqual(detectMention('@foobar', 4), { query: 'foo', start: 0 })
})

test('detectMention: mid-word @ (email) does not trigger', () => {
  assert.equal(detectMention('email@domain', 12), null)
})

test('detectMention: @@ is a literal escape, not a trigger', () => {
  assert.equal(detectMention('@@', 2), null)
  assert.equal(detectMention('@@foo', 5), null)
  assert.equal(detectMention('hi @@b', 6), null)
})

test('detectMention: whitespace closes the mention', () => {
  assert.equal(detectMention('@foo bar', 8), null)
  assert.deepEqual(detectMention('@foo bar', 4), { query: 'foo', start: 0 })
})

test('detectMention: picks the nearest @ before the cursor', () => {
  assert.deepEqual(detectMention('hi @a @b', 8), { query: 'b', start: 6 })
})

test('detectMention: cursor at 0 never triggers', () => {
  assert.equal(detectMention('@anything', 0), null)
})

// ─── replaceMention ──────────────────────────────────────────────────

test('replaceMention: swaps the @query span for the inserted token', () => {
  // "see @no" — @ at 4, query "no" (len 2)
  const out = replaceMention('see @no', 4, 2, '@work/notes.md ')
  assert.equal(out.value, 'see @work/notes.md ')
  assert.equal(out.caret, 'see @work/notes.md '.length)
})

test('replaceMention: preserves text after the mention and sets caret after the insert', () => {
  // "a @q b" — @ at 2, query "q" (len 1)
  const out = replaceMention('a @q b', 2, 1, '@x.md ')
  assert.equal(out.value, 'a @x.md  b') // inserted "@x.md " then the original " b"
  assert.equal(out.caret, 'a @x.md '.length) // caret sits right after the insert
})

test('replaceMention: empty query (bare @) still replaces just the @', () => {
  const out = replaceMention('@', 0, 0, '@notes.md ')
  assert.equal(out.value, '@notes.md ')
  assert.equal(out.caret, '@notes.md '.length)
})

// ─── reconcileMentions ───────────────────────────────────────────────

type Att = { name: string; inline?: boolean; token?: string }
const chip: Att = { name: 'pasted.png' }
const md: Att = { name: 'notes.md', inline: true, token: '@work/notes.md' }
const img: Att = {
  name: 'diagram.png',
  inline: true,
  token: '@art/diagram.png',
}

test('reconcileMentions: keeps inline attachments whose token is still in the text', () => {
  const value = 'review @work/notes.md and @art/diagram.png please'
  assert.deepEqual(reconcileMentions(value, [md, img]), [md, img])
})

test('reconcileMentions: drops inline attachments whose token was deleted', () => {
  const value = 'review @work/notes.md please' // diagram token removed
  assert.deepEqual(reconcileMentions(value, [md, img]), [md])
})

test('reconcileMentions: dropping all inline tokens leaves an empty list', () => {
  assert.deepEqual(reconcileMentions('nothing here', [md, img]), [])
})

test('reconcileMentions: always keeps non-inline (chip) attachments', () => {
  // chip has no token; it must survive regardless of the textarea text.
  assert.deepEqual(reconcileMentions('', [chip, md]), [chip])
})

test('reconcileMentions: keeps an inline attachment that has no token (defensive)', () => {
  const tokenless: Att = { name: 'x.md', inline: true }
  assert.deepEqual(reconcileMentions('', [tokenless]), [tokenless])
})

test('reconcileMentions: returns the same items (no mutation of inputs)', () => {
  const input = [md, img]
  const out = reconcileMentions('@work/notes.md @art/diagram.png', input)
  assert.notEqual(out, input) // new array
  assert.deepEqual(input, [md, img]) // input untouched
})

// ─── rankMentions ────────────────────────────────────────────────────

const files = [
  { path: 'old/notes.md', mtime: 100 },
  { path: 'new/project.md', mtime: 300 },
  { path: 'mid/proposal.md', mtime: 200 },
]

// A deterministic stand-in for Obsidian's fuzzySearch: returns a score when
// the query is a substring of the path, else null (no match).
const substr = (q: string, path: string): number | null =>
  path.includes(q) ? path.length : null

test('rankMentions: empty query returns all, most-recent first', () => {
  const out = rankMentions(files, '', substr).map((f) => f.path)
  assert.deepEqual(out, ['new/project.md', 'mid/proposal.md', 'old/notes.md'])
})

test('rankMentions: empty query respects the limit', () => {
  const out = rankMentions(files, '', substr, 2).map((f) => f.path)
  assert.deepEqual(out, ['new/project.md', 'mid/proposal.md'])
})

test('rankMentions: query filters out non-matches', () => {
  const out = rankMentions(files, 'pro', substr).map((f) => f.path)
  // "project.md" and "proposal.md" match "pro"; "notes.md" does not.
  assert.deepEqual(out.sort(), ['mid/proposal.md', 'new/project.md'])
})

test('rankMentions: query sorts by score desc, then recency', () => {
  // Equal scores -> recency breaks the tie (newer first).
  const equalScore = (q: string, path: string): number | null =>
    path.includes(q) ? 1 : null
  const out = rankMentions(files, 'p', equalScore).map((f) => f.path)
  // Only the two paths containing "p" match; newer (project) before older.
  assert.deepEqual(out, ['new/project.md', 'mid/proposal.md'])
})

test('rankMentions: higher score wins over recency', () => {
  const byScore = (q: string, path: string): number | null =>
    path.includes(q) ? (path === 'old/notes.md' ? 99 : 1) : null
  const out = rankMentions(files, 'o', byScore).map((f) => f.path)
  assert.equal(out[0], 'old/notes.md') // oldest, but top score
})
