/** @vitest-environment node */
/**
 * Strategy row 6 (L4, real Postgres): the archive path, against real SQL.
 *
 * Every statement here is raw. `$executeRawUnsafe` is not type-checked, is not
 * covered by the datamodel, and expects a ROW COUNT back, so
 * `SELECT set_config(...)` is exactly the shape that throws at runtime while
 * every mocked test stays green. The failure is not cosmetic: the session flag
 * is what exempts this transaction from the append-only trigger, so if that
 * statement throws, the whole archive fails, and a `Restrict` foreign key then
 * makes the project permanently undeletable.
 *
 * The append-only trigger is the other half. A mock cannot tell us whether it
 * exists or whether its exemption actually works, and "the trigger silently was
 * never created" is the way this control fails in practice.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network whitehat-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://whitehat:<pw>@postgres:5432/whitehat' \
 *     --entrypoint sh whitehat-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/engagementArchive.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { archiveProjectAuthorizations } from './engagementArchive'

const HAS_DB = process.env.DATABASE_URL !== undefined

let prisma: PrismaClient
let userId: string
let projectId: string
/**
 * Every project this file created, including the ones its own tests delete.
 * The archive outlives the project by design, so cleaning it up by joining
 * back to `projects` misses exactly the rows the archive test produced.
 */
const created: string[] = []

const SUFFIX = `row6-${Date.now()}`

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const user = await prisma.user.create({
    data: { email: `${SUFFIX}@test.invalid`, name: 'row6' },
  })
  userId = user.id
})

afterAll(async () => {
  if (!HAS_DB) return
  // The archive has no Prisma model, so its rows are cleaned up in SQL.
  for (const id of created) {
    await prisma.$executeRawUnsafe(
      `DELETE FROM engagement_authorization_archive WHERE project_id = $1`, id
    ).catch(() => 0)
  }
  // The append-only trigger refuses an unguarded delete, and these are test
  // fixtures rather than evidence, so they go through the same per-project
  // exemption the archive uses.
  for (const p of await prisma.project.findMany({ where: { userId }, select: { id: true } })) {
    await prisma.$transaction(async tx => {
      await tx.$executeRawUnsafe(
        `SELECT set_config('whitehat.archiving_project', $1, true)`, p.id
      )
      await tx.$executeRawUnsafe(
        `DELETE FROM engagement_authorizations WHERE project_id = $1`, p.id
      )
    }).catch(() => undefined)
  }
  await prisma.project.deleteMany({ where: { userId } })
  await prisma.user.delete({ where: { id: userId } })
  await prisma.$disconnect()
})

beforeEach(async () => {
  if (!HAS_DB) return
  const project = await prisma.project.create({
    data: {
      name: `row6 ${Date.now()}`,
      userId,
      targetDomain: 'example.invalid',
      engagementKind: 'third_party',
      roeEnabled: true,
      roeGlobalMaxRps: 3,
    },
    select: { id: true },
  })
  projectId = project.id
  created.push(project.id)
})

async function seedAuthorization() {
  return prisma.engagementAuthorization.create({
    data: {
      projectId,
      documentSha256: 'b'.repeat(64),
      documentKind: 'hackerone_program',
      sourceUrl: 'https://example.invalid/program',
      programHandle: 'row6',
      issuedAt: new Date('2026-01-01T00:00:00.000Z'),
      recordedVia: 'ui',
      summary: 'row 6',
    },
    select: { id: true },
  })
}

async function archiveRows(id: string): Promise<Array<Record<string, unknown>>> {
  return prisma.$queryRawUnsafe(
    `SELECT id, archived_reason FROM engagement_authorization_archive WHERE project_id = $1`,
    id
  )
}

describe.skipIf(!HAS_DB)('row 6: a project with authorization records can still be deleted', () => {
  test('the record moves to the archive and the project deletes', async () => {
    const auth = await seedAuthorization()

    const result = await archiveProjectAuthorizations(projectId)
    expect(result.error).toBeUndefined()
    expect(result.archived).toBe(1)

    const archived = await archiveRows(projectId)
    expect(archived).toHaveLength(1)
    expect(archived[0].id).toBe(auth.id)
    expect(archived[0].archived_reason).toBe('project_deleted')

    // The Restrict foreign key is the real assertion: this delete is what would
    // have failed had the archive not emptied the table.
    await expect(prisma.project.delete({ where: { id: projectId } })).resolves.toBeTruthy()
  })

  test('a second archive of the same project is a no-op, not an error', async () => {
    await seedAuthorization()
    await archiveProjectAuthorizations(projectId)
    const again = await archiveProjectAuthorizations(projectId)
    expect(again).toEqual({ archived: 0 })
  })

  test('a project with no records archives nothing and never touches the table', async () => {
    const result = await archiveProjectAuthorizations(projectId)
    expect(result).toEqual({ archived: 0 })
  })

  test('the reason is recorded, so an investigator knows why the row moved', async () => {
    await seedAuthorization()
    await archiveProjectAuthorizations(projectId, 'project_reset')
    const archived = await archiveRows(projectId)
    expect(archived[0].archived_reason).toBe('project_reset')
  })
})

describe.skipIf(!HAS_DB)('row 5: the append-only trigger exists and holds', () => {
  test('the trigger is installed', async () => {
    const rows = await prisma.$queryRawUnsafe<Array<{ tgname: string }>>(
      `SELECT tgname FROM pg_trigger
        WHERE tgrelid = 'engagement_authorizations'::regclass AND NOT tgisinternal`
    )
    expect(rows.map(r => r.tgname)).toContain('engagement_authorizations_append_only')
  })

  test('an UPDATE is refused', async () => {
    const auth = await seedAuthorization()
    await expect(
      prisma.$executeRawUnsafe(
        `UPDATE engagement_authorizations SET summary = 'rewritten' WHERE id = $1`,
        auth.id
      )
    ).rejects.toThrow()
    const still = await prisma.engagementAuthorization.findUnique({ where: { id: auth.id } })
    expect(still?.summary).toBe('row 6')
  })

  test('an unguarded DELETE is refused', async () => {
    const auth = await seedAuthorization()
    await expect(
      prisma.$executeRawUnsafe(`DELETE FROM engagement_authorizations WHERE id = $1`, auth.id)
    ).rejects.toThrow()
    expect(await prisma.engagementAuthorization.count({ where: { projectId } })).toBe(1)
  })

  test('the exemption is scoped to one project, not to any archive run', async () => {
    // A flag naming a DIFFERENT project must not let this one's rows go.
    const auth = await seedAuthorization()
    await expect(
      prisma.$transaction(async tx => {
        await tx.$executeRawUnsafe(
          `SELECT set_config('whitehat.archiving_project', $1, true)`,
          'some-other-project'
        )
        return tx.$executeRawUnsafe(
          `DELETE FROM engagement_authorizations WHERE id = $1`,
          auth.id
        )
      })
    ).rejects.toThrow()
  })
})
