import { test, expect, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * End-to-end pass over every filterable page in the graph table dropdown.
 *
 * The unit suites drive each table with mocked data; this drives the real
 * stack - real Cypher, real Neo4j rows, the real preferences column - because
 * three things only break here: a column whose live values are a shape the
 * fixtures never had (Neo4j temporals, `{low, high}` integers), a filter that
 * does not survive a real page load, and a page that never renders its Filters
 * button at all under production data.
 *
 * Requires the stack to be up. Run: npx playwright test
 */

const PROJECT = process.env.WHITEHAT_PROJECT || '9417780d1f864e928fbe9091a'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'

/** Every entry of the table dropdown that carries per-column filters. */
const VIEWS = [
  'nodeDetails', 'all', 'jsRecon', 'aiSurface', 'aiRisk', 'killChain', 'blastRadius',
  'takeover', 'secrets', 'netInitAccess', 'graphql', 'webInitAccess',
  'paramMatrix', 'sharedInfra', 'dnsEmail', 'threatIntel', 'jsDepSignals',
  'supplyChainSca', 'dnsDrift', 'webCachePoison',
] as const

/** Reported at the end so an all-empty project cannot look like an all-pass. */
const coverage: { view: string; outcome: string }[] = []

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  // The onboarding gate and the star banner are full-screen overlays keyed off
  // localStorage. Pre-accepting them is the only way to reach the table at all.
  await context.addInitScript(() => {
    localStorage.setItem('whitehat-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('whitehat-github-star-dismissed', '1')
  })
})

/** Wipe stored filters so a previous run cannot pre-narrow a table. */
test.beforeAll(async ({ playwright, baseURL }) => {
  const api = await playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { cookie: `whitehat-auth=${mintToken(USER)}` },
  })
  const res = await api.patch('/api/user/preferences', {
    data: { featureKey: 'tableFilters', value: {} },
  })
  expect(res.ok(), 'could not reset stored filters - is the stack up?').toBeTruthy()
  await api.dispose()
})

async function openView(page: Page, view: string) {
  await page.goto(`/graph?project=${PROJECT}&table=${view}`)
  // The graph page mounts a lot; the table area settling is the real signal.
  await page.waitForLoadState('networkidle')
}

function filtersButton(page: Page) {
  return page.getByRole('button', { name: /^Filters/ }).first()
}

function chips(page: Page) {
  return page.locator('[aria-label^="Remove filter:"]')
}

async function bodyRowCount(page: Page): Promise<number> {
  return page.locator('tbody tr').count()
}

/**
 * Expand column cards until one offers a facet checkbox, then tick the first.
 * Returns the chip text, or null when no column on this page is pickable
 * (every column unique, or the sheet is empty).
 */
async function applyFirstAvailableFilter(page: Page): Promise<string | null> {
  const cards = page.getByRole('button', { name: /^Filter by / })
  const count = Math.min(await cards.count(), 10)

  for (let i = 0; i < count; i++) {
    const card = cards.nth(i)
    if ((await card.getAttribute('aria-expanded')) === 'false') await card.click()

    const boxes = page.locator('input[type="checkbox"]')
    // The `not` toggle for text search is a checkbox too; facet rows carry a value label.
    const facets = page.locator('label').filter({ has: page.locator('input[type="checkbox"]') })
      .filter({ hasNotText: /^not$/ })
    if (await facets.count() > 0 && await boxes.count() > 0) {
      // The save is debounced; wait for the write rather than for a fixed time,
      // so the reload below is testing persistence and not the clock.
      const saved = page.waitForResponse(
        r => r.url().includes('/api/user/preferences') && r.request().method() === 'PATCH',
        { timeout: 10_000 },
      )
      await facets.first().locator('input[type="checkbox"]').check()
      const chip = chips(page).first()
      await expect(chip).toBeVisible()
      await saved
      return (await chip.getAttribute('aria-label'))!.replace('Remove filter: ', '')
    }
    if ((await card.getAttribute('aria-expanded')) === 'true') await card.click()
  }
  return null
}

for (const view of VIEWS) {
  test(`${view}: filters apply and survive a reload`, async ({ page }) => {
    await openView(page, view)

    const btn = filtersButton(page)
    if (await btn.count() === 0) {
      coverage.push({ view, outcome: 'no Filters button (page rendered no filterable table)' })
      test.skip(true, `${view} has no filter control on this project`)
      return
    }

    if (await btn.isDisabled()) {
      // Correct behaviour for an empty sheet - assert it rather than skipping
      // silently, so "no data" cannot masquerade as "feature works".
      await expect(btn).toBeDisabled()
      coverage.push({ view, outcome: 'no rows on this project - button correctly disabled' })
      test.skip(true, `${view} has no rows on this project`)
      return
    }

    const before = await bodyRowCount(page)
    expect(before, 'enabled Filters button but no rows').toBeGreaterThan(0)

    await btn.click()
    await expect(page.getByPlaceholder('Find a column…')).toBeVisible()

    const chipText = await applyFirstAvailableFilter(page)
    if (!chipText) {
      coverage.push({ view, outcome: `${before} rows, no pickable facet column` })
      test.skip(true, `${view} offers no facet column`)
      return
    }

    const after = await bodyRowCount(page)
    expect(after, 'a filter must never widen the result').toBeLessThanOrEqual(before)

    // The point of the whole exercise: still there after a full reload.
    await openView(page, view)
    await expect(chips(page).first()).toHaveAttribute('aria-label', `Remove filter: ${chipText}`)
    expect(await bodyRowCount(page)).toBe(after)

    // And removable, permanently.
    const cleared = page.waitForResponse(
      r => r.url().includes('/api/user/preferences') && r.request().method() === 'PATCH',
      { timeout: 10_000 },
    )
    await chips(page).first().click()
    await expect(chips(page)).toHaveCount(0)
    await cleared
    await openView(page, view)
    await expect(chips(page)).toHaveCount(0)
    expect(await bodyRowCount(page)).toBe(before)

    coverage.push({ view, outcome: `${before} -> ${after} rows via "${chipText}", persisted` })
  })
}

test('Node Inspector: each node type keeps its own filters', async ({ page }) => {
  await openView(page, 'nodeDetails')

  // Scoped to the Node Inspector toolbar: the page has another listbox button
  // (the scan-version selector), and picking that one would silently test
  // version switching instead of node types.
  const toolbar = page.locator('[class*="toolbar"]')
    .filter({ has: page.getByRole('button', { name: /^Filters/ }) })
    .first()
  const typeButton = toolbar.locator('button[aria-haspopup="listbox"]').first()
  await typeButton.click()
  const options = page.getByRole('option')
  const typeCount = await options.count()
  expect(typeCount, 'expected node types, not scan versions').toBeGreaterThan(0)
  test.skip(typeCount < 2, 'need at least two node types')

  const firstType = (await options.nth(0).textContent())!.trim()
  const secondType = (await options.nth(1).textContent())!.trim()
  await options.nth(0).click()

  await filtersButton(page).click()
  const chipText = await applyFirstAvailableFilter(page)
  test.skip(!chipText, 'no facet column on the first node type')
  await expect(chips(page)).toHaveCount(1)

  // Switching type must drop it from view entirely...
  await typeButton.click()
  await page.getByRole('option').nth(1).click()
  await expect(chips(page)).toHaveCount(0)

  // ...and switching back must bring it back, from storage.
  await openView(page, 'nodeDetails')
  await typeButton.click()
  await page.getByRole('option').nth(0).click()
  await expect(chips(page).first()).toHaveAttribute('aria-label', `Remove filter: ${chipText}`)

  coverage.push({
    view: 'nodeDetails (per-type)',
    outcome: `"${chipText}" on ${firstType} absent on ${secondType}, restored on return`,
  })
})

test.afterAll(() => {
  // eslint-disable-next-line no-console
  console.log('\n=== filter coverage ===')
  for (const c of coverage) console.log(`  ${c.view.padEnd(22)} ${c.outcome}`)
})
