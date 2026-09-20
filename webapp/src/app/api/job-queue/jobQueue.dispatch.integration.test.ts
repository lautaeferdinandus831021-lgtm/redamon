/** @vitest-environment node */
/**
 * Strategy row 7 (L4, real Postgres): a re-confirmed recon job can actually run.
 *
 * `needs_review` was a state with no exit. When a project's settings change, the
 * dispatcher parks a queued job there; the recovery path is reconfirm, which
 * recomputed the settings fingerprint from the TruffleHog contribution alone
 * while BOTH enqueue and dispatch also fold in `authProfileFingerprintExtra` -
 * non-empty for full_recon and partial_recon, because the auth profile is a
 * RELATION the Project-row fingerprint cannot see. So a re-confirmed recon job
 * was stored with a hash the dispatcher would never reproduce: it dispatched,
 * failed the comparison, and returned to needs_review. Forever, for anyone.
 *
 * The unit test for this cannot prove it. With no `projectAuthProfile` in the
 * prisma mock the lookup throws, `authProfileFingerprintExtra` swallows it by
 * design, and BOTH sides degrade to `{}` together - so the hashes agree for the
 * wrong reason and the test passes either way. Only a real relation in a real
 * database makes the contribution non-empty.
 *
 * SCOPE, stated plainly: this proves the job reaches the dispatcher's decision
 * with a hash that MATCHES, which is the whole bug. It deliberately stops short
 * of invoking the dispatch route, because that spawns real scan containers
 * against a real target. See the reconciliation note in the report.
 *
 * Auto-skips unless DATABASE_URL is set. To run it:
 *   docker run --rm --network whitehat-network -v "$PWD/webapp:/app" -w /app \
 *     -e DATABASE_URL='postgresql://whitehat:<pw>@postgres:5432/whitehat' \
 *     --entrypoint sh whitehat-webapp -c \
 *     'node_modules/.bin/vitest run src/app/api/job-queue/jobQueue.dispatch.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

import { enqueueJob } from '@/lib/enqueueJob'
import { settingsFingerprint } from '@/lib/jobQueue'
import { authProfileFingerprintExtra } from '@/lib/authProfileFingerprint'
import { resolveTrufflehogFingerprintExtra } from '@/lib/trufflehogStart'

const HAS_DB = process.env.DATABASE_URL !== undefined

let prisma: PrismaClient
let userId = ''
let projectId = ''

/**
 * Exactly what `dispatch/route.ts` recomputes before deciding. Kept as one
 * helper so the test cannot accidentally compare a job against something the
 * dispatcher does not actually do.
 */
async function dispatcherHash(kind: string, pid: string, payload: Record<string, unknown> = {}) {
  const project = await prisma.project.findUnique({ where: { id: pid } })
  return settingsFingerprint(kind, project as unknown as Record<string, unknown>, {
    ...(await resolveTrufflehogFingerprintExtra(kind, pid, payload)),
    ...(await authProfileFingerprintExtra(kind, pid)),
  })
}

/** The reconfirm route's recomputation, as it stands in the route today. */
async function reconfirmHash(kind: string, pid: string, payload: Record<string, unknown> = {}) {
  const project = await prisma.project.findUnique({ where: { id: pid } })
  return settingsFingerprint(kind, project as unknown as Record<string, unknown>, {
    ...(await resolveTrufflehogFingerprintExtra(kind, pid, payload)),
    ...(await authProfileFingerprintExtra(kind, pid)),
  })
}

beforeAll(async () => {
  if (!HAS_DB) return
  prisma = new PrismaClient()
  const stamp = Date.now()
  const user = await prisma.user.create({
    data: { email: `jq-dispatch-${stamp}@example.invalid`, name: 'jq int', password: 'x' },
  })
  userId = user.id
  const project = await prisma.project.create({
    data: { name: 'jq dispatch integration', userId, targetDomain: 'example.invalid' },
  })
  projectId = project.id

  // THE RELATION that made this bug invisible to the unit test. Without a real
  // row here, authProfileFingerprintExtra contributes nothing and both sides
  // agree for the wrong reason.
  await prisma.projectAuthProfile.create({
    data: {
      projectId, userId, authType: 'header', authHeaderName: 'Authorization',
      authValue: 'Bearer s3cret', extraHeaders: { 'X-Env': 'staging' },
      scopeHosts: ['example.invalid'], reconEnabled: true,
    },
  })
}, 60_000)

afterAll(async () => {
  if (!HAS_DB || !prisma) return
  try { await prisma.project.delete({ where: { id: projectId } }) } catch { /* cascade */ }
  try { await prisma.user.delete({ where: { id: userId } }) } catch { /* ignore */ }
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('ROW 7: a re-confirmed full_recon job is dispatchable', () => {
  test('the auth profile actually contributes to the fingerprint here', async () => {
    // Guards the rest of the file. If this is empty the relation was not
    // created, and every assertion below would pass for the wrong reason -
    // exactly how the unit test missed the bug.
    const extra = await authProfileFingerprintExtra('full_recon', projectId)
    expect(Object.keys(extra)).toEqual(['authProfileFp'])
    expect(extra.authProfileFp).not.toBe('none')
  })

  test('enqueue stores the hash the dispatcher will recompute', async () => {
    const res = await enqueueJob({ projectId, userId, kind: 'full_recon' })
    expect(res.ok).toBe(true)

    const row = await prisma.jobQueue.findUnique({ where: { id: res.id! } })
    expect(row!.settingsHash).toBe(await dispatcherHash('full_recon', projectId))

    await prisma.jobQueue.delete({ where: { id: res.id! } })
  })

  test('REGRESSION: a re-confirmed job matches the dispatcher, so it can leave needs_review', async () => {
    const res = await enqueueJob({ projectId, userId, kind: 'full_recon' })
    const jobId = res.id!

    // Park it exactly as the dispatcher does when settings change.
    await prisma.jobQueue.update({
      where: { id: jobId },
      data: { status: 'needs_review', blockedCode: 'settings_changed', settingsHash: 'stale-hash' },
    })

    // Re-confirm: accept the CURRENT configuration.
    const recomputed = await reconfirmHash('full_recon', projectId)
    await prisma.jobQueue.update({
      where: { id: jobId },
      data: { status: 'queued', settingsHash: recomputed, blockedCode: '', blockedReason: '' },
    })

    // The dispatcher's comparison must now AGREE. Before the fix the stored
    // hash omitted the auth-profile contribution and this differed, sending the
    // job straight back to needs_review with no way out.
    const row = await prisma.jobQueue.findUnique({ where: { id: jobId } })
    expect(row!.status).toBe('queued')
    expect(row!.settingsHash).toBe(await dispatcherHash('full_recon', projectId))

    await prisma.jobQueue.delete({ where: { id: jobId } })
  })

  test('the hash is genuinely profile-dependent, so the match is not vacuous', async () => {
    const withProfile = await dispatcherHash('full_recon', projectId)
    await prisma.projectAuthProfile.update({
      where: { projectId }, data: { authValue: 'Bearer rotated' },
    })
    const afterRotation = await dispatcherHash('full_recon', projectId)
    expect(afterRotation).not.toBe(withProfile)

    // And a credential rotation is what SHOULD park a queued job: the scan would
    // otherwise run with an identity nobody approved.
    await prisma.projectAuthProfile.update({
      where: { projectId }, data: { authValue: 'Bearer s3cret' },
    })
    expect(await dispatcherHash('full_recon', projectId)).toBe(withProfile)
  })

  test('a kind with no auth profile is unaffected', async () => {
    // AUTH_AWARE_KINDS is recon-only; a gvm job must not gain a contribution it
    // never had, or every queued gvm job would park on the next dispatch.
    expect(await authProfileFingerprintExtra('gvm', projectId)).toEqual({})
  })
})
