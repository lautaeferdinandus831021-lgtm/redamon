/**
 * Deep-debug: replay the EXACT persisted bytes of every seeded LATS demo
 * scenario (internal/lats_seed_demo.py) through the REAL UI pipeline —
 * restore fold -> graph build -> tidy-tree layout — and assert each one
 * produces a valid, correct card and canvas. Catches any mismatch between what
 * the backend persists and what the UI renders, for all 7 states at once.
 *
 * Fixture is exported from the DB to webapp/.lats_demo_fixture.json:
 *   docker exec whitehat-postgres psql ... > webapp/.lats_demo_fixture.json
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/AIAssistantDrawer/latsDemoReplay.test.ts
 */

import { readFileSync, existsSync } from 'fs'
import { resolve } from 'path'
import { describe, test, expect } from 'vitest'
import { foldLatsRestoreMarkers } from './hooks/latsChatState'
import { buildLatsGraph } from './useLatsGraph'
import { latsTreeLayout } from './latsTreeLayout'
import type { ChatItem, LatsSearchItem } from './types'

type Msg = { type: 'lats_start' | 'lats_tree_update' | 'lats_complete'; data: any }
type Scenario = { title: string; messages: Msg[] }

// Debug harness: reads the export produced by internal/lats_seed_demo.py +
// the psql dump into webapp/.lats_demo_fixture.json. Skips cleanly (CI-safe)
// when that ephemeral fixture is absent.
const FIXTURE_PATH = resolve(process.cwd(), '.lats_demo_fixture.json')
const FIXTURE: Scenario[] = existsSync(FIXTURE_PATH)
  ? JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))
  : []
const suite = FIXTURE.length ? describe : describe.skip

// Rebuild the card exactly as useConversationRestoration does: turn each
// persisted lats_* row into a marker, wrap with a couple of non-LATS messages
// to prove passthrough/placement, and fold.
function restore(scenario: Scenario): { items: ChatItem[]; card: LatsSearchItem } {
  const before = { type: 'message', id: 'u', role: 'user', content: 'go', timestamp: new Date('2020-01-01T00:00:00Z') } as any
  const after = { type: 'message', id: 'a', role: 'assistant', content: 'done', timestamp: new Date('2020-01-01T01:00:00Z') } as any
  const markers = scenario.messages.map((m, i) => ({
    _latsEvent: m.type, payload: m.data,
    timestamp: new Date(Date.UTC(2020, 0, 1, 0, 1, i)),
  })) as any[]
  const items = foldLatsRestoreMarkers([before, ...markers, after])
  const card = items.find(i => i.type === 'lats_search') as LatsSearchItem
  return { items, card }
}

suite('LATS seeded scenarios — replay through the real UI pipeline', () => {
  test('fixture has all 7 scenarios', () => {
    expect(FIXTURE.length).toBe(7)
  })

  for (const scenario of FIXTURE) {
    describe(scenario.title, () => {
      const { items, card } = restore(scenario)

      test('restores to exactly one card, placed between the messages', () => {
        expect(card).toBeTruthy()
        expect(items.filter(i => i.type === 'lats_search')).toHaveLength(1)
        // card sits between the user msg (index 0) and assistant msg (last) — C1
        expect(items[0].type).toBe('message')
        expect(items[items.length - 1].type).toBe('message')
        expect(items.findIndex(i => i.type === 'lats_search')).toBe(1)
      })

      test('history has exactly one frame per tree_update', () => {
        const nUpdates = scenario.messages.filter(m => m.type === 'lats_tree_update').length
        expect(card.history).toHaveLength(nUpdates)
      })

      test('status/outcome reflect the events', () => {
        const hasComplete = scenario.messages.some(m => m.type === 'lats_complete')
        expect(card.status).toBe(hasComplete ? 'complete' : 'running')
        if (hasComplete) {
          const outcome = scenario.messages.find(m => m.type === 'lats_complete')!.data.outcome
          expect(card.outcome).toBe(outcome)
        }
      })

      test('graph builds: no duplicate node/edge ids, every edge endpoint exists', () => {
        const { nodes, edges } = buildLatsGraph(card.latest)
        expect(new Set(nodes.map(n => n.id)).size).toBe(nodes.length)     // React key safety
        expect(new Set(edges.map(e => e.id)).size).toBe(edges.length)
        const ids = new Set(nodes.map(n => n.id))
        for (const e of edges) {
          expect(ids.has(e.source)).toBe(true)
          expect(ids.has(e.target)).toBe(true)
        }
        // one edge per non-root node
        const nonRoot = card.latest.nodes.filter(n => n.parent_id !== null).length
        expect(edges.length).toBe(nonRoot)
      })

      test('layout: every node positioned, no two share a coordinate', () => {
        const pos = latsTreeLayout(card.latest.nodes)
        expect(pos).toHaveLength(card.latest.nodes.length)
        const keys = pos.map(p => `${p.x},${p.y}`)
        expect(new Set(keys).size).toBe(keys.length)
      })

      test('best_trajectory ids all exist in the tree', () => {
        const ids = new Set(card.latest.nodes.map(n => n.id))
        for (const id of card.latest.best_trajectory) expect(ids.has(id)).toBe(true)
      })

      test('every node view carries the full field set', () => {
        for (const n of card.latest.nodes) {
          for (const k of ['id', 'parent_id', 'depth', 'label', 'tool_name', 'status',
            'value', 'local_value', 'visits', 'verdict', 'error_class', 'finding_confidence',
            'exploit_succeeded', 'duration_ms', 'observation', 'reflection', 'is_dangerous', 'step_id']) {
            expect(n).toHaveProperty(k)
          }
        }
      })
    })
  }
})

// ---- scenario-specific invariants (keyed by title) ----
function cardFor(match: string): LatsSearchItem {
  return restore(FIXTURE.find(s => s.title.includes(match))!).card
}

suite('LATS scenarios — state-specific invariants', () => {
  test('takeover ends terminal with a crowned foothold on the best line', () => {
    const c = cardFor('account takeover')
    expect(c.outcome).toBe('terminal_success')
    const terminal = c.latest.nodes.filter(n => n.status === 'terminal' && n.exploit_succeeded)
    expect(terminal.length).toBe(1)
    expect(c.latest.best_trajectory).toContain(terminal[0].id)
  })

  test('collapsed: every child pruned, no terminal', () => {
    const c = cardFor('branch collapsed')
    expect(c.outcome).toBe('branch_collapsed')
    const children = c.latest.nodes.filter(n => n.parent_id !== null)
    expect(children.every(n => n.status === 'pruned')).toBe(true)
    expect(c.latest.nodes.some(n => n.status === 'terminal')).toBe(false)
  })

  test('budget: hit the rollout cap, deep, no foothold', () => {
    const c = cardFor('budget exhausted')
    expect(c.outcome).toBe('budget_exhausted')
    expect(c.latest.rollouts).toBe(c.latest.budget.max_rollouts)
    expect(Math.max(...c.latest.nodes.map(n => n.depth))).toBeGreaterThanOrEqual(6)
    expect(c.latest.nodes.some(n => n.exploit_succeeded)).toBe(false)
  })

  test('running: still executing, no complete', () => {
    const c = cardFor('search in progress')
    expect(c.status).toBe('running')
    expect(c.latest.nodes.some(n => n.status === 'executing')).toBe(true)
  })

  test('shadow: observe-only flag set on the snapshot', () => {
    const c = cardFor('shadow')
    expect(c.shadow_mode).toBe(true)
    expect(c.latest.shadow_mode).toBe(true)
  })

  test('dangerous: a dangerous probe is flagged for confirmation', () => {
    const c = cardFor('dangerous probe')
    expect(c.latest.nodes.some(n => n.is_dangerous && n.status === 'executing')).toBe(true)
  })

  test('deep: chain reaches depth 5 and the golden line runs root->leaf', () => {
    const c = cardFor('deep 6-stage')
    expect(Math.max(...c.latest.nodes.map(n => n.depth))).toBe(5)
    expect(c.latest.best_trajectory).toHaveLength(6)
  })
})
