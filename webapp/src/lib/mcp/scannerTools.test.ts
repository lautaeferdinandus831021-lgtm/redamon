/**
 * get_scan_status: the other six scanners.
 *
 * Same two rules as every other read here. An unreachable orchestrator is
 * "unknown", never "idle" - reporting "not running" for "cannot tell" is how an
 * agent concludes a surface is clean when the scan that would have found
 * something never reported. And the raw state is masked, because it carries
 * `container_id` and raw exception text that embeds the deployment's absolute
 * host paths.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a),
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { getScanStatus, SCANNER_NAMES } from './scannerTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

/** The run-list shape. `scanner` decides which of the two comes back. */
type RunList = {
  runs: Record<string, unknown>[]
  returned: number
  total: number
  truncated?: boolean
}
const asRuns = (r: unknown) => r as RunList

const returns = (body: unknown) =>
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => body })

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  returns({ status: 'idle' })
})

describe('scanner selection', () => {
  test('all six are reachable and hit their own endpoint', async () => {
    const paths: Record<string, string> = {
      gvm: '/gvm/p1/status',
      github_hunt: '/github-hunt/p1/status',
      supply_chain: '/supply-chain/p1/status',
      trufflehog: '/trufflehog/p1/all',
      ai_attack: '/ai-attack-surface/p1/all',
      partial_recon: '/recon/p1/partial/all',
    }
    expect(SCANNER_NAMES.sort()).toEqual(Object.keys(paths).sort())

    for (const [scanner, path] of Object.entries(paths)) {
      __resetRateLimiter()
      h.orchestratorFetch.mockClear()
      returns({ status: 'idle', runs: [] })
      await getScanStatus(ctx(), 'p1', scanner)
      expect(String(h.orchestratorFetch.mock.calls[0][0]), scanner).toContain(path)
    }
  })

  test('an unknown scanner names the valid ones and points at get_recon_status', async () => {
    await expect(getScanStatus(ctx(), 'p1', 'nmap')).rejects.toThrow(/One of: /)
    await expect(getScanStatus(ctx(), 'p1', 'full_recon')).rejects.toThrow(/get_recon_status/)
  })

  test('every call carries an explicit timeout, never the inherited default', async () => {
    await getScanStatus(ctx(), 'p1', 'gvm')
    expect(h.orchestratorFetch.mock.calls[0][2]).toMatchObject({ timeoutMs: expect.any(Number) })
  })
})

describe('scope and ownership', () => {
  test('it needs recon:read', async () => {
    await expect(getScanStatus(ctx([]), 'p1', 'gvm')).rejects.toBeInstanceOf(McpScopeError)
  })

  test("another user's project is refused before the orchestrator is called", async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(getScanStatus(ctx(), 'p1', 'gvm')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('a dependency failure is "unknown", never "idle"', () => {
  test('an unreachable orchestrator fails', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(getScanStatus(ctx(), 'p1', 'gvm')).rejects.toThrow(/unknown/i)
  })

  test('a non-200 fails too', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 502, json: async () => ({}) })
    await expect(getScanStatus(ctx(), 'p1', 'supply_chain')).rejects.toThrow(/unknown/i)
  })

  // REGRESSION: same shape as the activity helper. A 200 whose `runs` key is
  // absent was read as zero runs, so "is the TruffleHog scan running" answered
  // no during one.
  test('REGRESSION: a 200 with no runs key is "unknown", not zero runs', async () => {
    returns({})
    await expect(getScanStatus(ctx(), 'p1', 'trufflehog')).rejects.toThrow(/unknown/i)
  })

  test('an unparseable body fails rather than reporting an empty scan', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => { throw new Error('nope') } })
    await expect(getScanStatus(ctx(), 'p1', 'trufflehog')).rejects.toThrow(/unknown/i)
  })
})

describe('the raw orchestrator body is masked', () => {
  test('container id and exception text never reach the caller', async () => {
    returns({
      status: 'error',
      container_id: 'a1b2c3d4e5f6',
      error: 'invalid mount config for type "bind": bind source path does not exist: '
           + '/home/operator/deploy/whitehat/recon',
    })
    const r = await getScanStatus(ctx(), 'p1', 'gvm')
    const s = JSON.stringify(r)
    expect(s).not.toContain('/home/operator')
    expect(s).not.toContain('a1b2c3d4e5f6')
    expect(s).not.toMatch(/bind source path/)
    // The FACT of failure still reaches the caller.
    expect((r.scan as Record<string, unknown>).failed).toBe(true)
  })

  test('the same masking applies to every run in a run list', async () => {
    returns({
      runs: [
        { status: 'running', container_id: 'deadbeef', tool_id: 'github' },
        { status: 'error', error: '/home/operator/secret/path' },
      ],
    })
    const s = JSON.stringify(await getScanStatus(ctx(), 'p1', 'trufflehog'))
    expect(s).not.toContain('deadbeef')
    expect(s).not.toContain('/home/operator')
  })
})

describe('the two shapes', () => {
  test('a single-state scanner returns one scan', async () => {
    returns({ status: 'running', current_phase: 'analysis', started_at: '2026-09-14T10:00:00Z' })
    const r = await getScanStatus(ctx(), 'p1', 'gvm')
    expect(r.scan).toMatchObject({ status: 'running', currentPhase: 'analysis', failed: false })
    expect(r).not.toHaveProperty('runs')
  })

  test('a run-list scanner returns runs, and TruffleHog findings come free', async () => {
    returns({ runs: [{ status: 'completed', run_id: 'github', findings_count: 12 }] })
    const r = await getScanStatus(ctx(), 'p1', 'trufflehog')
    expect(asRuns(r).runs[0]).toMatchObject({ status: 'completed', runId: 'github', findingsCount: 12 })
    expect(asRuns(r).total).toBe(1)
  })

  test('a run list is capped and says so', async () => {
    returns({ runs: Array.from({ length: 120 }, (_, i) => ({ status: 'completed', run_id: `r${i}` })) })
    const r = await getScanStatus(ctx(), 'p1', 'ai_attack')
    expect(asRuns(r).returned).toBe(50)
    expect(asRuns(r).total).toBe(120)
    expect(asRuns(r).truncated).toBe(true)
  })

  test('no runs is an honest empty list, not an error', async () => {
    returns({ runs: [] })
    const r = await getScanStatus(ctx(), 'p1', 'partial_recon')
    expect(asRuns(r).runs).toEqual([])
    expect(asRuns(r).total).toBe(0)
  })
})
