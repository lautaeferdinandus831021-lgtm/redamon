/** @vitest-environment node */
/**
 * Strategy row 7 (L4, real Postgres): the idempotency key against a real
 * unique constraint.
 *
 * The unit tests mock Prisma, so they prove the tool's branching and nothing
 * about the constraint the branching depends on. `idempotencyKey` is
 * `String? @unique` on `EngagementAuthorization`, and a `@unique` that was
 * never pushed to the database leaves every mocked test green while two retries
 * of the same loop tick create two projects and two authorization records
 * against somebody else's estate.
 *
 * So both halves are exercised here: the pre-check path and the lost-race path,
 * the second by firing concurrent calls at the real database.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network whitehat-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://whitehat:<pw>@postgres:5432/whitehat' \
 *     --entrypoint sh whitehat-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/mcp/engagementTools.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { createProject } from './engagementTools'
import type { McpContext } from './tools'

const HAS_DB = process.env.DATABASE_URL !== undefined

let prisma: PrismaClient
let userId: string

const SUFFIX = `row7-${Date.now()}`

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId, tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['project:create', 'engagement:authorize'] as never,
  },
})

const AUTH = {
  documentSha256: 'c'.repeat(64),
  documentKind: 'hackerone_program',
  programHandle: 'row7',
  issuedAt: '2026-01-01T00:00:00.000Z',
}

const args = (key: string) => ({
  name: 'row7',
  engagementKind: 'third_party',
  targetDomain: 'example.invalid',
  roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
  authorization: AUTH,
  idempotencyKey: key,
})

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const user = await prisma.user.create({
    data: { email: `${SUFFIX}@test.invalid`, name: 'row7' },
  })
  userId = user.id
})

afterAll(async () => {
  if (!HAS_DB) return
  await prisma.$executeRawUnsafe(
    `DELETE FROM engagement_authorization_archive WHERE project_id IN
       (SELECT id FROM projects WHERE user_id = $1)`,
    userId
  ).catch(() => 0)
  // The append-only trigger refuses an unguarded delete, and these rows are
  // test fixtures rather than evidence, so they go with the archive exemption.
  await prisma.$transaction(async tx => {
    await tx.$executeRawUnsafe(`SELECT set_config('whitehat.archiving_project', '', true)`)
    for (const p of await tx.project.findMany({ where: { userId }, select: { id: true } })) {
      await tx.$executeRawUnsafe(
        `SELECT set_config('whitehat.archiving_project', $1, true)`, p.id
      )
      await tx.$executeRawUnsafe(
        `DELETE FROM engagement_authorizations WHERE project_id = $1`, p.id
      )
    }
  }).catch(() => undefined)
  await prisma.project.deleteMany({ where: { userId } })
  await prisma.user.delete({ where: { id: userId } })
  await prisma.$disconnect()
})

beforeEach(() => { __resetRateLimiter() })

describe.skipIf(!HAS_DB)('row 7: a retried create makes one project, not two', () => {
  test('a sequential retry returns the first project', async () => {
    const key = `${SUFFIX}-sequential`
    const first = await createProject(ctx(), args(key))
    expect(first.created).toBe(true)

    __resetRateLimiter()
    const second = await createProject(ctx(), args(key))
    expect(second.created).toBe(false)
    expect(second.projectId).toBe(first.projectId)

    expect(await prisma.engagementAuthorization.count({ where: { idempotencyKey: key } })).toBe(1)
  })

  test('concurrent retries settle on one project', async () => {
    // The pre-check is a read and the constraint is on the write, so this is
    // the race the pre-check alone cannot win.
    const key = `${SUFFIX}-concurrent`
    const results = await Promise.all([
      createProject(ctx(), args(key)),
      createProject(ctx(), args(key)),
      createProject(ctx(), args(key)),
    ])

    const ids = new Set(results.map(r => r.projectId))
    expect(ids.size).toBe(1)
    expect(results.filter(r => r.created)).toHaveLength(1)
    expect(await prisma.engagementAuthorization.count({ where: { idempotencyKey: key } })).toBe(1)
  })

  test('the constraint the tool relies on actually exists in the database', async () => {
    // If this is missing, both tests above could pass by luck of timing.
    const rows = await prisma.$queryRawUnsafe<Array<{ indexdef: string }>>(
      `SELECT indexdef FROM pg_indexes WHERE tablename = 'engagement_authorizations'`
    )
    expect(rows.some(r => /UNIQUE/i.test(r.indexdef) && /idempotency_key/.test(r.indexdef)))
      .toBe(true)
  })

  test('a different key creates a different project', async () => {
    const a = await createProject(ctx(), args(`${SUFFIX}-a`))
    __resetRateLimiter()
    const b = await createProject(ctx(), args(`${SUFFIX}-b`))
    expect(a.projectId).not.toBe(b.projectId)
  })
})
