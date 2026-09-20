/**
 * A project_file path may not reach another project's upload directory.
 *
 * `/app/recon/wordlists` is shared: shipped lists sit directly in it and every
 * project's uploads land at `<root>/<projectId>/<name>`. Allowing the whole
 * tree made "inside an allowed root" answer a different question from "this
 * project may read it".
 *
 * Why it matters more than a file read, in the words of the Python copy of the
 * rule: ffuf sends each wordlist LINE as a URL path and records which ones
 * responded, so a wordlist pointed at another project's uploaded file gets that
 * file's contents reflected into this scan's graph and output.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { filterReconSettings, MAX_KEYS_PER_CALL } from './filter'
import { field, fieldsWhere } from './registry'
import { checkHeader, isInsideProjectFileRoot } from './validators'

const MINE = 'cm0000000000000000000000'
const THEIRS = 'cm1111111111111111111111'

describe('the shared upload root is scoped to one project', () => {
  test("another project's upload is not readable", () => {
    expect(isInsideProjectFileRoot(`/app/recon/wordlists/${THEIRS}/creds.txt`, MINE)).toBe(false)
  })

  test('my own upload is readable', () => {
    expect(isInsideProjectFileRoot(`/app/recon/wordlists/${MINE}/creds.txt`, MINE)).toBe(true)
  })

  test('a shipped list sitting directly in the root is readable by anyone', () => {
    expect(isInsideProjectFileRoot('/app/recon/wordlists/jhaddix-all.txt', MINE)).toBe(true)
    expect(isInsideProjectFileRoot('/app/recon/wordlists/vhost-common.txt', '')).toBe(true)
  })

  test('with no project id no upload directory is readable', () => {
    expect(isInsideProjectFileRoot(`/app/recon/wordlists/${MINE}/creds.txt`, '')).toBe(false)
  })

  test('traversal out of my directory into another one is refused', () => {
    expect(
      isInsideProjectFileRoot(`/app/recon/wordlists/${MINE}/../${THEIRS}/creds.txt`, MINE)
    ).toBe(false)
  })

  test('a prefix that merely starts with my id is not my directory', () => {
    expect(isInsideProjectFileRoot(`/app/recon/wordlists/${MINE}-evil/x.txt`, MINE)).toBe(false)
  })

  test('the other roots hold shipped files and stay readable', () => {
    for (const root of ['/usr/share/seclists', '/usr/share/wordlists', '/app/custom_templates']) {
      expect(isInsideProjectFileRoot(`${root}/a/b/c.txt`, ''), root).toBe(true)
    }
  })

  test('escaping the roots entirely is still refused', () => {
    expect(isInsideProjectFileRoot('/etc/shadow', MINE)).toBe(false)
    expect(isInsideProjectFileRoot('/app/recon/../../etc/shadow', MINE)).toBe(false)
  })
})

describe('the write path enforces it on every path-valued field', () => {
  const PATH_FIELDS = fieldsWhere(f => f.validator === 'project_file' && f.mcp === 'settable')

  test('there is at least one such field, or this test proves nothing', () => {
    expect(PATH_FIELDS.length).toBeGreaterThan(0)
  })

  test.each(PATH_FIELDS.map(f => [f.key, f.type] as const))(
    "%s refuses another project's upload",
    (key, type) => {
      const path = `/app/recon/wordlists/${THEIRS}/creds.txt`
      const value = type === 'string-list' ? [path] : path
      const r = filterReconSettings({ [key]: value }, { projectId: MINE })
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.error).toContain(key)
    }
  )

  test.each(PATH_FIELDS.map(f => [f.key, f.type] as const))(
    '%s accepts my own upload',
    (key, type) => {
      const path = `/app/recon/wordlists/${MINE}/mine.txt`
      const value = type === 'string-list' ? [path] : path
      expect(filterReconSettings({ [key]: value }, { projectId: MINE }).ok).toBe(true)
    }
  )
})

describe('a header with no value is refused', () => {
  // The caller believes they are identifying their traffic to the target's blue
  // team, and the target drops a valueless header on the floor.
  test('a name with an empty value is not a header', () => {
    expect(checkHeader('X-Scan-Id:')).toBe('has no value')
    expect(checkHeader('X-Scan-Id:    ')).toBe('has no value')
  })

  test('a header longer than the usual server limit is refused here', () => {
    expect(checkHeader(`X-Scan-Id: ${'a'.repeat(5000)}`)).toMatch(/longer than 4096/)
  })

  test('an ordinary header still passes', () => {
    expect(checkHeader('X-Scan-Id: whitehat-7f3a')).toBeNull()
  })
})

describe('a write with too many keys is refused', () => {
  // Per-value bounds do not bound a call: over 700 columns, free-text ones at
  // 20,000 characters each.
  test('the cap names the limit and the count', () => {
    const settings = Object.fromEntries(
      fieldsWhere(f => f.type === 'boolean' && f.mcp === 'settable')
        .slice(0, MAX_KEYS_PER_CALL + 1)
        .map(f => [f.key, true])
    )
    expect(Object.keys(settings).length).toBe(MAX_KEYS_PER_CALL + 1)
    const r = filterReconSettings(settings)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(new RegExp(`at most ${MAX_KEYS_PER_CALL}`))
  })

  test('a batch at the cap still goes through', () => {
    const settings = Object.fromEntries(
      fieldsWhere(f => f.type === 'boolean' && f.mcp === 'settable')
        .slice(0, MAX_KEYS_PER_CALL)
        .map(f => [f.key, true])
    )
    expect(filterReconSettings(settings).ok).toBe(true)
  })
})

describe('a Bytes column is never described as a writable string', () => {
  // roeDocumentData is `Bytes?` in Prisma and was `tighten_only` with a
  // free_text validator, so a string write passed every check here and then
  // threw a raw Prisma type error out of the tool instead of being refused by
  // name. Every column whose Prisma type cannot round-trip through JSON-RPC
  // has to be closed, not validated.
  test('roeDocumentData is closed', () => {
    const doc = field('roeDocumentData')
    expect(doc).toBeDefined()
    expect(doc!.mcp).toBe('never')
    expect(doc!.readable).toBe(false)
  })

  test('it is refused by name on both write modes', () => {
    for (const mode of ['update', 'create'] as const) {
      const r = filterReconSettings({ roeDocumentData: 'not bytes' }, { mode })
      expect(r.ok, mode).toBe(false)
      if (!r.ok) expect(r.error).toContain('roeDocumentData')
    }
  })

  test('no open column has a Prisma type JSON-RPC cannot carry', () => {
    const open = fieldsWhere(f => f.mcp !== 'never' && f.prisma_type.startsWith('Bytes'))
    expect(open.map(f => f.key)).toEqual([])
  })
})
