import { test, expect, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { signIn } from './auth'

/**
 * Regenerates the screenshots on the wiki's MCP Server page. Not an assertion
 * suite: run it when the Global Settings -> MCP Server tab changes.
 *
 *   npx playwright test tests/captureMcpServerDocsShots.spec.ts
 *
 * The token API is STUBBED, never written. Minting a real token needs the
 * account password and leaves a live credential behind, and the list on a dev
 * box shows real prefixes and account names, which must not be published.
 */

const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const OUT = join(__dirname, '..', '..', '..', 'whitehat.wiki', 'images')

const day = 86_400_000
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * day).toISOString()

const TOKENS = [
  {
    id: 'doc-token-1', name: 'Claude Code (laptop)', tokenPrefix: 'rdmn_mcp_4f1a9c2e',
    scopes: ['recon:read', 'triage:read', 'graph:cypher'],
    lastUsedAt: iso(0), expiresAt: iso(88), revokedAt: null, createdAt: iso(-2),
  },
  {
    id: 'doc-token-2', name: 'CI nightly rescan', tokenPrefix: 'rdmn_mcp_b83d07e5',
    scopes: ['recon:read', 'recon:scan', 'recon:settings', 'recon:queue'],
    lastUsedAt: iso(-1), expiresAt: iso(340), revokedAt: null, createdAt: iso(-25),
  },
  {
    id: 'doc-token-3', name: 'triage assistant (old)', tokenPrefix: 'rdmn_mcp_09e6d4b1',
    scopes: ['recon:read', 'triage:read', 'triage:write'],
    lastUsedAt: iso(-12), expiresAt: iso(30), revokedAt: iso(-10), createdAt: iso(-60),
  },
]

// Obviously synthetic: the reveal panel only ever renders what POST returned.
const FAKE_PLAINTEXT = 'rdmn_mcp_' + '0123456789abcdef'.repeat(3)

async function stubTokenApi(page: Page) {
  await page.route(`**/api/users/${USER}/mcp-tokens`, async route => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 201,
        json: { token: { ...TOKENS[0], id: 'doc-token-new' }, plaintext: FAKE_PLAINTEXT },
      })
      return
    }
    await route.fulfill({ json: { tokens: TOKENS } })
  })
}

async function openTab(page: Page) {
  await page.goto('/settings?tab=mcp-tokens')
  // Prefix match, not exact: the section heading carries two wiki links, so its
  // accessible name is 'MCP Server Open MCP Server wiki page ...'. An exact
  // match silently stopped finding it when those links were added.
  await expect(page.getByRole('heading', { name: /^MCP Server/ })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('CI nightly rescan')).toBeVisible()
  // Sticky chrome is painted over the element box and crops element shots.
  await page.addStyleTag({ content: `
    header, footer, [class*="stickyHeader"], [class*="statusBar"] { position: static !important; }
    * { animation: none !important; transition: none !important; }
  ` })
}

/** The tab body: the heading's nearest `section` container. */
function tabSection(page: Page) {
  return page.getByRole('heading', { name: /^MCP Server/ }).locator(
    'xpath=ancestor::div[contains(@class,"__section") and not(contains(@class,"sectionHeader"))][1]')
}

test.beforeEach(async ({ context, baseURL, page }) => {
  mkdirSync(OUT, { recursive: true })
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('whitehat-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('whitehat-github-star-dismissed', '1')
  })
  await page.setViewportSize({ width: 1400, height: 1400 })
  await stubTokenApi(page)
})

test('MCP Server tab with its token list', async ({ page }) => {
  await openTab(page)
  await page.waitForTimeout(300)
  await tabSection(page).screenshot({ path: join(OUT, 'mcp-server-tab.png') })
})

test('every row keeps its Edit and Revoke buttons inside the panel', async ({ page }) => {
  // The regression: nowrap permission tags made the table wider than the tab
  // and pushed the row actions past its right edge, behind a scrollbar.
  await page.setViewportSize({ width: 1280, height: 900 })
  await page.route(`**/api/users/${USER}/mcp-tokens`, route => route.fulfill({
    json: { tokens: [{ ...TOKENS[0], name: 'e2e full', scopes: ['recon:read', 'recon:scan', 'recon:overwrite', 'recon:settings', 'triage:read', 'recon:queue', 'triage:write', 'graph:cypher', 'kali:exec'] }, ...TOKENS] },
  }))
  await openTab(page)
  const wrap = await page.locator('[class*="__tableWrap"]').boundingBox()
  for (const btn of await page.getByTitle(/^(Edit|Revoke)$/).all()) {
    const box = await btn.boundingBox()
    expect(box!.x + box!.width).toBeLessThanOrEqual(wrap!.x + wrap!.width)
  }
})

test('Edit token panel', async ({ page }) => {
  await openTab(page)
  await page.getByTitle('Edit').nth(1).click()
  await page.getByLabel('Expires').selectOption('date')
  await page.getByLabel('Expiry date').fill('2027-03-31')
  await page.locator('label', { hasText: 'graph:cypher' }).locator('input[type="checkbox"]').check()
  const form = page.getByRole('heading', { name: 'Edit token' })
    .locator('xpath=ancestor::div[contains(@class,"__formBlock")][1]')
  await form.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await form.screenshot({ path: join(OUT, 'mcp-server-edit-token.png') })
})

test('New token form with its permissions', async ({ page }) => {
  await openTab(page)
  await page.getByRole('button', { name: 'New token' }).click()
  await page.getByLabel('Name').fill('CI nightly rescan')
  await page.getByLabel('Expires').selectOption('365')
  for (const scope of ['recon:scan', 'recon:settings', 'triage:read']) {
    await page.locator('label', { hasText: scope }).locator('input[type="checkbox"]').check()
  }
  const form = page.getByRole('heading', { name: 'New access token' })
    .locator('xpath=ancestor::div[contains(@class,"__formBlock")][1]')
  await form.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await form.screenshot({ path: join(OUT, 'mcp-server-new-token.png') })
})

test('Token shown once with the client snippet', async ({ page }) => {
  await openTab(page)
  await page.getByRole('button', { name: 'New token' }).click()
  await page.getByLabel('Name').fill('Claude Code (laptop)')
  await page.getByLabel('Confirm your password').fill('not-a-real-password')
  await page.getByRole('button', { name: 'Create token' }).click()
  const panel = page.getByText('Copy this token now', { exact: false })
    .locator('xpath=ancestor::div[contains(@class,"__revealPanel")][1]')
  await expect(panel).toBeVisible()
  await page.waitForTimeout(300)
  await panel.screenshot({ path: join(OUT, 'mcp-server-token-reveal.png') })
})
