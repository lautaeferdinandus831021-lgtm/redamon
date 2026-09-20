import { test, expect, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * Every filterable page, in a real browser, regardless of what the project
 * happens to contain.
 *
 * filters.spec.ts is the honest run against live data - and on any given
 * project most sheets are empty, so most of it skips. This file serves the
 * rows itself so that each page is actually rendered, filtered, reloaded and
 * checked. What that buys over the jsdom suites is the parts jsdom does not
 * have: the production bundle, real CSS (an overlay that covers the panel), a
 * real navigation, and the preferences round trip through Postgres.
 *
 * Requires the stack to be up. Run: npx playwright test filtersSynthetic
 */

const PROJECT = process.env.WHITEHAT_PROJECT || '9417780d1f864e928fbe9091a'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'

interface View {
  view: string
  /** Analytics slug in the URL the page requests. */
  endpoint: string
  /** A real column key on that sheet, and its panel header. */
  key: string
  header: string
  /** Set for the sheeted tables, which answer with `{ sheets: {...} }`. */
  sheet?: string
  /** Fields the table dereferences without a null guard. */
  base?: Record<string, unknown>
}

const VIEWS: View[] = [
  { view: 'killChain', endpoint: 'killChain', key: 'subdomain', header: 'Subdomain' },
  { view: 'blastRadius', endpoint: 'blastRadius', key: 'techName', header: 'Technology' },
  { view: 'takeover', endpoint: 'takeover', key: 'hostname', header: 'Hostname',
    base: { verdict: 'likely', sources: [] } },
  { view: 'secrets', endpoint: 'secrets', key: 'origin', header: 'Origin' },
  { view: 'netInitAccess', endpoint: 'netInitAccess', key: 'ipAddress', header: 'IP' },
  { view: 'graphql', endpoint: 'graphql', key: 'endpointUrl', header: 'Endpoint' },
  { view: 'webInitAccess', endpoint: 'webInitAccess', key: 'baseUrl', header: 'BaseURL',
    base: { headerGrid: {}, authEndpoints: [], findings: [] } },
  { view: 'paramMatrix', endpoint: 'paramMatrix', key: 'paramName', header: 'Parameter' },
  { view: 'sharedInfra', endpoint: 'sharedInfra', key: 'clusterType', header: 'Type' },
  { view: 'dnsEmail', endpoint: 'dnsEmail', key: 'domain', header: 'Domain' },
  { view: 'threatIntel', endpoint: 'threatIntel', key: 'assetType', header: 'Type' },
  { view: 'jsDepSignals', endpoint: 'supplyChain', key: 'findingType', header: 'Type' },
  { view: 'dnsDrift', endpoint: 'dnsDrift', key: 'domain', header: 'Domain',
    base: {
      historicResolutions: [], externalDomains: [], currentIps: [], currentAsns: [],
      currentCountries: [], asnDrift: [], countryDrift: [], danglingSubs: [],
    } },
  { view: 'webCachePoison', endpoint: 'webCachePoison', key: 'endpointUrl', header: 'Endpoint' },
  { view: 'aiSurface', endpoint: 'aiSurface', key: 'baseUrl', header: 'Base URL', sheet: 'llmEndpoints' },
  { view: 'aiRisk', endpoint: 'aiRisk', key: 'name', header: 'Finding', sheet: 'findings' },
  { view: 'supplyChainSca', endpoint: 'supplyChainSca', key: 'name', header: 'Package', sheet: 'verdicts',
    base: { repos: [], baseUrls: [], sboms: [], aliases: [] } },
]

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('whitehat-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('whitehat-github-star-dismissed', '1')
  })
})

test.beforeAll(async ({ playwright, baseURL }) => {
  const api = await playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { cookie: `whitehat-auth=${mintToken(USER)}` },
  })
  expect((await api.patch('/api/user/preferences', {
    data: { featureKey: 'tableFilters', value: {} },
  })).ok()).toBeTruthy()
  await api.dispose()
})

/** Three rows: two share a value so the facet has something to narrow to. */
function rowsFor(v: View) {
  const base = v.base ?? {}
  return [
    { id: 'r1', ...base, [v.key]: 'alpha' },
    { id: 'r2', ...base, [v.key]: 'alpha' },
    { id: 'r3', ...base, [v.key]: 'beta' },
  ]
}

async function stub(page: Page, v: View) {
  const rows = rowsFor(v)
  const body = v.sheet ? { sheets: { [v.sheet]: rows }, meta: {} } : { rows, meta: {} }
  await page.route(`**/api/analytics/redzone/${v.endpoint}*`, route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }),
  )
}

async function openView(page: Page, view: string) {
  await page.goto(`/graph?project=${PROJECT}&table=${view}`)
  await page.waitForLoadState('networkidle')
}

const filtersButton = (page: Page) => page.getByRole('button', { name: /^Filters/ }).first()
const chips = (page: Page) => page.locator('[aria-label^="Remove filter:"]')

function waitForSave(page: Page) {
  return page.waitForResponse(
    r => r.url().includes('/api/user/preferences') && r.request().method() === 'PATCH',
    { timeout: 10_000 },
  )
}

for (const v of VIEWS) {
  test(`${v.view}: filter, reload, still filtered`, async ({ page }) => {
    await stub(page, v)
    await openView(page, v.view)

    await expect(page.locator('tbody tr')).toHaveCount(3)

    await filtersButton(page).click()
    const card = page.getByRole('button', { name: new RegExp(`^Filter by ${v.header}( \\(active\\))?$`) })
    await expect(card).toBeVisible()
    if ((await card.getAttribute('aria-expanded')) === 'false') await card.click()

    const saved = waitForSave(page)
    await page.locator('label').filter({ hasText: /^alpha/ }).locator('input[type="checkbox"]').check()
    await expect(page.locator('tbody tr')).toHaveCount(2)
    await saved

    // Reload: the chip and the narrowing must both come back.
    await openView(page, v.view)
    await expect(chips(page)).toHaveCount(1)
    await expect(page.locator('tbody tr')).toHaveCount(2)

    const cleared = waitForSave(page)
    await chips(page).first().click()
    await expect(page.locator('tbody tr')).toHaveCount(3)
    await cleared

    await openView(page, v.view)
    await expect(chips(page)).toHaveCount(0)
    await expect(page.locator('tbody tr')).toHaveCount(3)
  })
}

test('a filter on one page does not follow the user to another', async ({ page }) => {
  const [a, b] = [VIEWS[0], VIEWS[1]]
  await stub(page, a)
  await stub(page, b)

  await openView(page, a.view)
  await filtersButton(page).click()
  const card = page.getByRole('button', { name: new RegExp(`^Filter by ${a.header}`) })
  if ((await card.getAttribute('aria-expanded')) === 'false') await card.click()
  const saved = waitForSave(page)
  await page.locator('label').filter({ hasText: /^alpha/ }).locator('input[type="checkbox"]').check()
  await expect(page.locator('tbody tr')).toHaveCount(2)
  await saved

  await openView(page, b.view)
  await expect(chips(page)).toHaveCount(0)
  await expect(page.locator('tbody tr')).toHaveCount(3)

  await openView(page, a.view)
  await expect(chips(page)).toHaveCount(1)
})
