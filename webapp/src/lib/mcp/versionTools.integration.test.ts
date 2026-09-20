/** @vitest-environment node */
/**
 * Strategy rows 8 and 9 (L4, real Postgres): the version tools against real rows.
 *
 * ROW 8. `list_scan_versions` and `assertVersionInProject` both reach Postgres
 * through `$queryRaw`, because `octet_length(snapshot)` is the only way to learn
 * whether a version still has its bytes without fetching a gzipped whole-graph
 * dump to find out. Raw SQL is not type-checked and not exercised by any mocked
 * test: a malformed column name would throw at runtime and break every version
 * tool, with the unit suite entirely green.
 *
 * ROW 9. `compare_scan_versions` gunzips, parses and diffs REAL stored bytes.
 * The unit tests hand it a plain object through a stubbed
 * `snapshotToGraphPayload`, so the serialise/deserialise round trip, the muted
 * filtering inside that conversion, and the secret-stripping over a real
 * `ReconDelta` are all unproven there. The delta's identity keys embed secret
 * VALUES by construction (`Secret` is keyed on `[value, file]`), so "no
 * credential leaves this surface" has to be proved over real bytes, not a mock.
 *
 * Both sides of every comparison here are STORED versions, so nothing touches
 * Neo4j and no snapshot slot is taken.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network whitehat-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://whitehat:<pw>@postgres:5432/whitehat' \
 *     --entrypoint sh whitehat-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/mcp/versionTools.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { serializeSnapshot } from '@/lib/scanSnapshot'
import { compareScanVersions, listScanVersions } from './versionTools'
import { assertVersionInProject } from './childAccess'
import { McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import type { McpContext } from './tools'

const HAS_DB = process.env.DATABASE_URL !== undefined

let prisma: PrismaClient
let userId = ''
let otherUserId = ''
let projectId = ''
let v1 = ''
let v2 = ''
let vNoBytes = ''
let vCurrent = ''

const ctx = (uid: string): McpContext => ({
  token: {
    tokenId: 't-int', userId: uid, tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'integration', scopes: ['recon:read'] as never,
  },
})

/** A snapshot in the shape `snapshotToGraphPayload` consumes. */
const snap = (nodes: { labels: string[]; properties: Record<string, unknown> }[]) => ({
  nodes: nodes.map((n, i) => ({ ...n, _exportId: `x${i}` })),
  relationships: [],
})

/** The literal secret value that must never survive into a response. */
const SECRET_VALUE = 'AKIAIOSFODNN7EXAMPLE'

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const stamp = Date.now()
  const user = await prisma.user.create({
    data: { email: `mcp-version-int-${stamp}@example.invalid`, name: 'mcp int', password: 'x' },
  })
  userId = user.id
  const other = await prisma.user.create({
    data: { email: `mcp-version-other-${stamp}@example.invalid`, name: 'other', password: 'x' },
  })
  otherUserId = other.id

  const project = await prisma.project.create({
    data: { name: 'mcp version integration', userId, targetDomain: 'example.invalid' },
  })
  projectId = project.id

  // v1: two ports. v2: adds one port, one Secret carrying a real value, and a
  // MUTED vulnerability that the render conversion must drop.
  const a = await prisma.scanVersion.create({
    data: {
      projectId, seq: 1, label: 'Scan 1', isCurrent: false, nodeCount: 2, linkCount: 0,
      snapshot: new Uint8Array(serializeSnapshot(snap([
        { labels: ['Port'], properties: { number: 443, ip_address: '10.0.0.1' } },
        { labels: ['Port'], properties: { number: 80, ip_address: '10.0.0.1' } },
      ]) as never)),
    },
  })
  v1 = a.id

  const b = await prisma.scanVersion.create({
    data: {
      projectId, seq: 2, label: 'Scan 2', isCurrent: false, nodeCount: 5, linkCount: 0,
      snapshot: new Uint8Array(serializeSnapshot(snap([
        { labels: ['Port'], properties: { number: 443, ip_address: '10.0.0.1' } },
        { labels: ['Port'], properties: { number: 80, ip_address: '10.0.0.1' } },
        { labels: ['Port'], properties: { number: 8080, ip_address: '10.0.0.1' } },
        { labels: ['Secret'], properties: { value: SECRET_VALUE, file: 'app.js', sample: 'AKIA***' } },
        { labels: ['Vulnerability', 'Muted'], properties: { id: 'v-muted', name: 'noisy' } },
      ]) as never)),
    },
  })
  v2 = b.id

  const c = await prisma.scanVersion.create({
    data: { projectId, seq: 3, label: 'Trimmed', isCurrent: false, snapshot: null },
  })
  vNoBytes = c.id

  const d = await prisma.scanVersion.create({
    data: { projectId, seq: 4, label: 'Current', isCurrent: true, snapshot: null },
  })
  vCurrent = d.id
}, 60_000)

afterAll(async () => {
  if (!HAS_DB || !prisma) return
  try { await prisma.project.delete({ where: { id: projectId } }) } catch { /* cascade */ }
  for (const id of [userId, otherUserId]) {
    try { await prisma.user.delete({ where: { id } }) } catch { /* ignore */ }
  }
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('ROW 8: the raw SQL runs against a real Postgres', () => {
  test('list_scan_versions returns rows with hasSnapshot derived from octet_length', async () => {
    __resetRateLimiter()
    const r = await listScanVersions(ctx(userId), projectId)
    expect(r.total).toBe(4)
    const bySeq = Object.fromEntries(r.versions.map(v => [v.seq, v]))
    expect(bySeq[1].hasSnapshot).toBe(true)
    expect(bySeq[2].hasSnapshot).toBe(true)
    // Trimmed and current both carry no bytes.
    expect(bySeq[3].hasSnapshot).toBe(false)
    expect(bySeq[4].hasSnapshot).toBe(false)
    expect(bySeq[4].isCurrent).toBe(true)
  })

  test('the snapshot bytes themselves never come back', async () => {
    __resetRateLimiter()
    const serialised = JSON.stringify(await listScanVersions(ctx(userId), projectId))
    expect(serialised).not.toContain(SECRET_VALUE)
    // `hasSnapshot` is a boolean ABOUT the bytes; the bytes themselves must have
    // no field at all. octet_length is what makes that possible.
    expect(serialised).not.toMatch(/"snapshot"\s*:/)
  })

  test('assertVersionInProject resolves an owned version', async () => {
    const v = await assertVersionInProject(userId, projectId, v2)
    expect(v.seq).toBe(2)
    expect(v.hasSnapshot).toBe(true)
    expect(v.snapshotBytes).toBeGreaterThan(0)
  })

  test('a version id from outside the project is refused', async () => {
    // Cross-tenant: the whole reason childAccess exists. `findUnique` on a bare
    // cuid resolves across tenants, and a ScanVersion is a gzipped dump of an
    // entire attack-surface graph.
    const outsider = await prisma.project.create({
      data: { name: 'other project', userId: otherUserId, targetDomain: 'other.invalid' },
    })
    const theirs = await prisma.scanVersion.create({
      data: { projectId: outsider.id, seq: 1, label: 'Theirs', snapshot: null },
    })
    await expect(assertVersionInProject(userId, projectId, theirs.id))
      .rejects.toBeInstanceOf(McpAccessDenied)
    await prisma.project.delete({ where: { id: outsider.id } })
  })

  test('a version that does not exist is the same refusal', async () => {
    await expect(assertVersionInProject(userId, projectId, 'no-such-version'))
      .rejects.toBeInstanceOf(McpAccessDenied)
  })
})

describe.skipIf(!HAS_DB)('ROW 9: the delta over real gzipped bytes', () => {
  test('it computes totals and lenses from stored snapshots', async () => {
    __resetRateLimiter()
    const r = await compareScanVersions(ctx(userId), projectId, { from: v1, to: v2 })
    expect(r.from.seq).toBe(1)
    expect(r.to.seq).toBe(2)
    // One new Port, and one new Secret. The MUTED vulnerability must NOT appear:
    // snapshotToGraphPayload drops it at render time, which is why a suppressed
    // finding is never reported as "newly discovered".
    expect(r.lenses.newlyExposedPorts).toBe(1)
    expect(r.totals.added).toBe(2)
    // The real payload conversion derives a Port's display name from its own
    // properties, so a sample carries `8080/tcp` rather than an empty string.
    // Type and name only: no property bag, and nothing that could be a secret.
    expect(r.samples.newlyExposedPorts).toEqual([{ type: 'Port', name: '8080/tcp' }])
  })

  test('NO secret value survives, not even inside an identity key', async () => {
    // `identityKey` builds a Secret's key from [value, file], so the delta's
    // `key`, `sourceKey` and `targetKey` embed secret material by construction.
    __resetRateLimiter()
    const serialised = JSON.stringify(
      await compareScanVersions(ctx(userId), projectId, { from: v1, to: v2 }))
    expect(serialised).not.toContain(SECRET_VALUE)
    expect(serialised).not.toContain('Secret::')
    expect(serialised).not.toContain('app.js')
    expect(serialised).not.toContain('"properties"')
  })

  test('a muted finding is not reported as newly discovered', async () => {
    __resetRateLimiter()
    const r = await compareScanVersions(ctx(userId), projectId, { from: v1, to: v2 })
    expect(JSON.stringify(r)).not.toContain('v-muted')
  })

  test('a version whose bytes were trimmed names retention, not "not found"', async () => {
    __resetRateLimiter()
    await expect(compareScanVersions(ctx(userId), projectId, { from: vNoBytes, to: v2 }))
      .rejects.toThrow(/trimmed by retention/i)
  })

  test('the CURRENT version id says to pass "current" instead', async () => {
    // Its snapshot is null by design, so "empty snapshot" would send a caller
    // hunting for a data problem that does not exist.
    __resetRateLimiter()
    await expect(compareScanVersions(ctx(userId), projectId, { from: vCurrent, to: v2 }))
      .rejects.toThrow(/Pass "current" for that side/)
  })

  test('another user cannot compare this project at all', async () => {
    __resetRateLimiter()
    await expect(compareScanVersions(ctx(otherUserId), projectId, { from: v1, to: v2 }))
      .rejects.toBeInstanceOf(McpAccessDenied)
  })
})
