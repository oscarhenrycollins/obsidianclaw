import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { str } from './lib'

test('str returns strings unchanged', () => {
  assert.equal(str('hello'), 'hello')
  assert.equal(str(''), '')
})

test('str falls back for non-strings', () => {
  assert.equal(str(undefined), '')
  assert.equal(str(null), '')
  assert.equal(str(42), '')
  assert.equal(str({}), '')
  assert.equal(str(123, 'n/a'), 'n/a')
})
