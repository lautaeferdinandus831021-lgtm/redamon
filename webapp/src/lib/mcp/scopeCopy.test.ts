/**
 * The scope copy and its presentation grouping.
 *
 * The control here is fail-closed: every scope must appear in exactly one group.
 * A scope added next month is ungrouped, this goes red, and nobody can ship a
 * checkbox that renders nowhere.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, test, expect } from 'vitest'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { MCP_SCOPE_COPY, SCOPE_GROUPS } from './scopeCopy'

describe('the copy', () => {
  test('every scope has a label and a blurb', () => {
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s], `no copy for ${s}`).toBeDefined()
      expect(MCP_SCOPE_COPY[s].label.length, `${s} has no label`).toBeGreaterThan(0)
      expect(MCP_SCOPE_COPY[s].blurb.length, `${s} has no blurb`).toBeGreaterThan(20)
    }
  })

  test('a blurb stays table-safe, because it becomes one markdown cell', () => {
    // The generated API reference prints each blurb into a single table cell.
    // A newline or a raw pipe would break the table.
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a newline`).not.toMatch(/\r?\n/)
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a raw pipe`).not.toContain('|')
    }
  })

  test('detail is UI-only, so it may be as long as it needs to be', () => {
    // Nothing asserts its length; this asserts it EXISTS where the UI needs it.
    expect(MCP_SCOPE_COPY['kali:exec'].detail).toBeDefined()
    expect(MCP_SCOPE_COPY['kali:exec'].detail!.length).toBeGreaterThan(300)
  })

  test('the exec copy states what it really grants: a shell, unscoped', () => {
    // This used to promise "a fixed allowlist of read-only tools" and "not a
    // shell". kali_exec is now at parity with the in-app agent - bash -c, full
    // toolset, no allowlist, no per-command scope check - so that copy was
    // understating the permission an operator ticks, which is the dangerous
    // direction for a consent screen.
    const c = MCP_SCOPE_COPY['kali:exec']
    expect(c.blurb).toContain('SHELL')
    expect(c.blurb).toContain('no allowlist')
    expect(c.detail!).toContain('no human clicking a confirmation')
    expect(c.detail!).toContain('NOT checked against this')
    expect(c.detail!).toContain('not sufficient on its own')
    expect(c.detail!).not.toContain('read-only tools')
    expect(c.learnMore).toHaveLength(2)
  })

  test('it is flagged as a danger scope', () => {
    // It is the most powerful permission on the surface; the UI must style it
    // as such rather than as one checkbox among many.
    expect(MCP_SCOPE_COPY['kali:exec'].danger).toBe(true)
  })

  test('every learnMore link points at the wiki over https', () => {
    for (const s of MCP_SCOPES) {
      for (const link of MCP_SCOPE_COPY[s].learnMore ?? []) {
        expect(link.text.length, `${s} has an unlabelled link`).toBeGreaterThan(0)
        expect(link.href, `${s} link is not an https wiki URL`).toMatch(/^https:\/\/github\.com\/.+\/wiki\//)
      }
    }
  })
})

describe('the grouping', () => {
  test('every scope appears in EXACTLY one group', () => {
    const seen = new Map<string, number>()
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) seen.set(s, (seen.get(s) ?? 0) + 1)
    }
    for (const s of MCP_SCOPES) {
      expect(
        seen.get(s) ?? 0,
        `${s} appears in ${seen.get(s) ?? 0} groups. Add it to exactly one SCOPE_GROUPS entry.`
      ).toBe(1)
    }
  })

  test('no group names a scope that does not exist', () => {
    const known = new Set<string>(MCP_SCOPES)
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) {
        expect(known.has(s), `group ${g.id} names unknown scope ${s}`).toBe(true)
      }
    }
  })

  test('every group has a label and a hint', () => {
    for (const g of SCOPE_GROUPS) {
      expect(g.label.length, `${g.id} has no label`).toBeGreaterThan(0)
      expect(g.hint.length, `${g.id} has no hint`).toBeGreaterThan(0)
      expect(g.scopes.length, `${g.id} is empty`).toBeGreaterThan(0)
    }
  })

  test('the read group changes nothing, so it carries no danger scope', () => {
    const read = SCOPE_GROUPS.find(g => g.id === 'read')!
    expect(read.tone).toBe('neutral')
    for (const s of read.scopes) {
      expect(MCP_SCOPE_COPY[s].danger, `${s} is a danger scope in the neutral group`).not.toBe(true)
    }
  })

  test('kali:exec is set apart in its own tier, not treated as a ninth checkbox', () => {
    const exec = SCOPE_GROUPS.find(g => g.tone === 'exec')!
    expect(exec.scopes).toEqual(['kali:exec'])
    // And it is last, so it reads as a different kind of thing.
    expect(SCOPE_GROUPS[SCOPE_GROUPS.length - 1].id).toBe(exec.id)
  })

  test('MCP_SCOPES itself is NOT reordered to match the groups', () => {
    // That array is the enforcement list and drives the generated reference's
    // permission table; the grouping is presentation beside it.
    const flattened = SCOPE_GROUPS.flatMap(g => g.scopes)
    expect(flattened).not.toEqual([...MCP_SCOPES])
    expect([...flattened].sort()).toEqual([...MCP_SCOPES].sort() as McpScope[])
  })
})

/**
 * Every `learnMore` link points into the wiki by heading anchor, and NOTHING
 * connects the two. Renaming a heading in MCP-Server.md silently 404s a link in
 * the consent screen - the one place an operator goes to understand what they
 * are granting.
 *
 * Found for real: `kali_toolbox`'s section was renamed from "what is installed,
 * not what is permitted" to "what the sandbox carries" when the allowlist was
 * removed, and the link kept pointing at the old slug. Nothing failed.
 */
describe('wiki anchors resolve', () => {
  const WIKI_DIR =
    process.env.MCP_DOCS_WIKI_DIR ||
    fileURLToPath(new URL('../../../../whitehat.wiki/', import.meta.url))

  /**
   * A real checkout, not merely the directory: the main repo records the wiki as
   * a submodule pointer, so a fresh clone leaves whitehat.wiki/ EMPTY and every
   * anchor would read as broken.
   */
  const hasWiki = () => existsSync(path.join(WIKI_DIR, 'Home.md'))

  /** GitHub's heading -> anchor rule: lowercase, drop punctuation, spaces to -. */
  const slug = (heading: string) =>
    heading
      .replace(/^#+\s*/, '')
      .trim()
      .toLowerCase()
      .replace(/`/g, '')
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')

  const anchorsIn = (page: string) =>
    new Set(
      readFileSync(path.join(WIKI_DIR, page), 'utf8')
        .split('\n')
        .filter(l => l.startsWith('#'))
        .map(slug)
    )

  test.skipIf(!hasWiki())('every scope learnMore anchor exists in its wiki page', () => {
    const byPage = new Map<string, Set<string>>()
    const broken: string[] = []

    for (const scope of MCP_SCOPES) {
      for (const link of MCP_SCOPE_COPY[scope].learnMore ?? []) {
        const m = /\/wiki\/([A-Za-z0-9._-]+)#([^"'`\s]+)$/.exec(link.href)
        if (!m) continue
        const [, page, anchor] = m
        const file = `${page}.md`
        if (!existsSync(path.join(WIKI_DIR, file))) {
          broken.push(`${scope}: ${file} does not exist`)
          continue
        }
        if (!byPage.has(file)) byPage.set(file, anchorsIn(file))
        if (!byPage.get(file)!.has(anchor)) {
          broken.push(`${scope}: ${file}#${anchor} matches no heading`)
        }
      }
    }
    expect(broken, 'a consent-screen link points at a heading that no longer exists').toEqual([])
  })
})
