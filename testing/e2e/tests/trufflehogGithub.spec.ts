import { test, expect, type Page } from '@playwright/test'
import { readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { signIn, mintToken } from './auth'

/**
 * The Secret Multiscanner GitHub source, driven through the real UI against the
 * real stack.
 *
 * The backend matrix (testing/e2e/backend/trufflehog_github_matrix.py) proves
 * what each PARAMETER does to a scan. This proves the parts only a browser can
 * reach: that the form renders every field, that the org-only fields stay
 * locked until an organization is named, that a missing token blocks Start
 * before anything runs, that a profile survives a reload, and that a finished
 * scan's findings reach the Red Zone table an operator reads.
 *
 * Requires the stack up, the webapp image rebuilt, and the fixtures built:
 *   ./testing/e2e/backend/build_github_fixtures.sh
 *
 * Run: cd testing/e2e && npx playwright test trufflehogGithub
 */

const PROJECT = process.env.WHITEHAT_PROJECT || 'e651f859c3114faf94196ab02'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const TOKEN_KEY = 'trufflehogGithubToken'

function repoRoot(): string {
  return join(__dirname, '..', '..', '..')
}

/** The fixtures the builder created, so the spec never hardcodes an account. */
function fixtures(): {
  owner: string; prefix: string; alpha: string; beta: string; gamma: string
  delta: string; gist: string
} {
  const raw = JSON.parse(
    readFileSync(join(repoRoot(), '_local', 'github_fixtures.json'), 'utf8'))
  return {
    owner: raw.owner, prefix: raw.prefix, alpha: raw.alpha, beta: raw.beta,
    gamma: raw.gamma, delta: raw.delta, gist: raw.gist,
  }
}

/** The real token, read from the same place the builder put it. Used only to
 *  put back what the credential-gate test deliberately clears. */
function fixtureToken(): string {
  return (process.env.GITHUB_FIXTURE_TOKEN
    || readFileSync(join(repoRoot(), '_local', 'gh_fixture_token'), 'utf8')).trim()
}

const FIELD_LABELS = [
  'Endpoint', 'Repositories', 'Organizations', 'Include repos', 'Exclude repos',
  'Include forks', 'Include member repos', 'Include wikis', 'Exclude archived',
  'Ignore gists', 'Scan issue comments', 'Scan PR comments', 'Scan gist comments',
  'Comments timeframe (days)', 'Include paths', 'Exclude paths',
]

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('whitehat-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('whitehat-github-star-dismissed', '1')
  })
  // ProjectProvider resolves the current project from localStorage first; without
  // it the graph header reads "No Project" and the Red Zone queries run with no
  // project id, so a populated table looks empty.
  await context.addInitScript(([u, p]) => {
    localStorage.setItem('whitehat-current-user', u)
    localStorage.setItem('whitehat-current-project', p)
  }, [USER, PROJECT])
})

/** Puts the token back no matter how the credential-gate test ended. Cheap, and
 *  it means a crashed run cannot leave the account's global key cleared. */
test.afterAll(async ({ playwright, baseURL }) => {
  // NOT the bare `request` fixture: it has no session cookie, so its PUT is
  // denied by requireUserAccess and the .catch() swallowed the failure - which
  // is how a failed run left the account's real GitHub token cleared.
  const ctx = await playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { cookie: `whitehat-auth=${mintToken(USER)}` },
  })
  const res = await ctx.put(`/api/users/${USER}/settings`, {
    data: { [TOKEN_KEY]: fixtureToken() },
  })
  // Loud on purpose. A silent failure here damages state outside the test.
  if (!res.ok()) {
    throw new Error(
      `could not restore ${TOKEN_KEY}: HTTP ${res.status()}. `
      + 'The global key is still cleared; set it in Global Settings > API Keys.')
  }
  await ctx.dispose()
})

/**
 * The GitHub row inside the Other Scans modal.
 *
 * Addressed by the CSS-module row class rather than by text: THREE cards in
 * that modal render a button whose accessible name is exactly "Start" (GitHub
 * Hunt, Secret Multiscanner, Supply Chain), and `locator('div')` filtered by
 * text resolves to an ancestor that contains no button at all - which is why
 * the earlier locator timed out with "element(s) not found".
 */
function multiscannerRow(page: Page) {
  return page.locator('[class*="sourceRow"]').filter({ hasText: 'GitHub' }).first()
}

async function openOtherScans(page: Page) {
  await page.goto(`/graph?project=${PROJECT}`)
  await page.getByRole('button', { name: /Other Scans/i }).click()
  await expect(multiscannerRow(page)).toBeVisible()
}

async function clearGithubProfiles(page: Page) {
  const res = await page.request.get(`/api/trufflehog/${PROJECT}/profiles`)
  if (!res.ok()) return
  const body = await res.json()
  for (const p of body.profiles ?? []) {
    if (p.source === 'github') {
      await page.request.delete(`/api/trufflehog/${PROJECT}/profiles/${p.id}`)
    }
  }
}

async function openTrufflehogSection(page: Page) {
  await page.goto(`/projects/${PROJECT}/settings`)
  // The form opens in workflow view, which replaces the tab content with a
  // diagram; the scanner sections only exist in tab view.
  const tabView = page.getByRole('button', { name: 'Tab view' })
  if (await tabView.isVisible().catch(() => false)) await tabView.click()
  await page.getByRole('button', { name: 'Other Scans', exact: true }).last().click()

  const section = page.locator('#trufflehog-scanner')
  await expect(section).toBeVisible()
  if (!(await section.getByText('Sources', { exact: true }).isVisible().catch(() => false))) {
    await section.locator('h2').click()
  }
  return section
}

async function addGithubSource(page: Page) {
  const section = await openTrufflehogSection(page)
  await section.getByLabel('Add a source').selectOption('github')
  await section.getByRole('button', { name: /Add source/i }).click()
  await expect(section.getByText('GitHub', { exact: true }).first()).toBeVisible()
  return section
}

test.describe('Secret Multiscanner GitHub source', () => {
  test('every github field is rendered', async ({ page }) => {
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    for (const label of FIELD_LABELS) {
      await expect(section.getByText(label, { exact: true }).first(),
        `field "${label}" is missing from the GitHub card`).toBeVisible()
    }
  })

  test('a target is required before the source can start', async ({ page }) => {
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    await expect(section.getByText(/set at least one repository or organization/i))
      .toBeVisible()
  })

  test('the org-only fields stay locked until an organization is named', async ({ page }) => {
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    const { owner } = fixtures()

    // The registry marks these `requires: 'orgs'`. Locked, not hidden: an
    // operator has to be able to see that the option exists and why it is off.
    await expect(section.getByLabel('Include repos')).toBeDisabled()
    await expect(section.getByLabel('Exclude repos')).toBeDisabled()

    await section.getByLabel('Organizations').fill(owner)
    await expect(section.getByLabel('Include repos')).toBeEnabled()
    await expect(section.getByLabel('Exclude repos')).toBeEnabled()
  })

  test('a configured profile survives a reload', async ({ page }) => {
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    const { alpha } = fixtures()
    await section.getByLabel('Repositories').fill(alpha)
    await expect(section.getByText(/set at least one repository or organization/i)).toBeHidden()

    // A reload returns the form to workflow view, so the section has to be
    // navigated to again rather than simply re-queried.
    const after = await openTrufflehogSection(page)
    await after.getByText('GitHub', { exact: true }).first().click()
    await expect(after.getByLabel('Repositories')).toHaveValue(alpha)
  })

  test('a missing token blocks Start, and pasting it in place unblocks it', async ({ page }) => {
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    const { alpha } = fixtures()
    await section.getByLabel('Repositories').fill(alpha)

    // Clear the GLOBAL key to reach the blocked state. afterAll puts it back
    // even if this test fails part way through.
    await page.request.put(`/api/users/${USER}/settings`, { data: { [TOKEN_KEY]: '' } })

    const blocked = await openTrufflehogSection(page)
    await blocked.getByText('GitHub', { exact: true }).first().click()
    await expect(blocked.getByText(/requires Secret Multiscanner GitHub Token/i)).toBeVisible()
    await expect(blocked.getByText('Required', { exact: true }).first()).toBeVisible()

    // The Other Scans modal is where an operator actually presses Start.
    await openOtherScans(page)
    await expect(multiscannerRow(page)
      .getByRole('button', { name: 'Start', exact: true })).toBeDisabled()

    // Paste it into the card's own box, the way the empty-state copy tells you to.
    const back = await openTrufflehogSection(page)
    await back.getByText('GitHub', { exact: true }).first().click()
    await back.getByPlaceholder(/Paste your Secret Multiscanner GitHub Token/i)
      .fill(fixtureToken())
    await back.getByRole('button', { name: /^Save$/ }).first().click()
    await expect(back.getByText('Set', { exact: true }).first()).toBeVisible()

    await openOtherScans(page)
    await expect(multiscannerRow(page)
      .getByRole('button', { name: 'Start', exact: true })).toBeEnabled()
  })

  test('a real scan runs from the UI and its findings reach the Red Zone', async ({ page }) => {
    test.setTimeout(300_000)
    await clearGithubProfiles(page)
    const section = await addGithubSource(page)
    const { alpha } = fixtures()
    await section.getByLabel('Repositories').fill(alpha)
    await expect(section.getByText(/set at least one repository or organization/i)).toBeHidden()

    await openOtherScans(page)
    const start = multiscannerRow(page).getByRole('button', { name: 'Start', exact: true })
    await expect(start).toBeEnabled()
    await start.click()

    // Poll the API rather than the spinner: the run is the source of truth.
    // Guarded, because expect.poll rethrows from its callback rather than
    // retrying, so one dropped keep-alive would fail the whole test.
    await expect.poll(async () => {
      try {
        const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
        if (!r.ok()) return 'http-error'
        const body = await r.json()
        return (body.runs ?? []).find((x: { source: string }) => x.source === 'github')
          ?.status ?? 'missing'
      } catch {
        return 'unreachable'
      }
    }, { timeout: 240_000, intervals: [3000] }).toBe('completed')

    await expect.poll(async () => {
      try {
        const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
        const body = await r.json()
        return (body.runs ?? []).find((x: { source: string }) => x.source === 'github')?.ingested
      } catch {
        return undefined
      }
    }, { timeout: 60_000, intervals: [2000] }).toBe(true)

    // Asserted through the API rather than the table, deliberately: the graph
    // page can be pinned to a saved scan version, and then the table correctly
    // shows that snapshot instead of the live graph.
    const secrets = await page.request.get(
      `/api/analytics/redzone/secrets?projectId=${PROJECT}`)
    expect(secrets.ok()).toBeTruthy()
    const rows = await secrets.json()
    const list = Array.isArray(rows) ? rows : (rows.rows ?? rows.secrets ?? [])
    const fromMultiscanner = list.filter(
      (r: { origin?: string }) => r.origin === 'MultiscannerFinding')
    expect(fromMultiscanner.map((r: { secretType: string }) => r.secretType))
      .toEqual(expect.arrayContaining(['PrivateKey', 'Github', 'SlackWebhook']))
  })
})

/**
 * Parameter combinations, every one of them configured through the settings UI
 * and started from the Other Scans modal.
 *
 * The backend matrix posts config straight to the orchestrator, which proves
 * what the FLAG does. It cannot prove that the form stores what the operator
 * typed, that the profile round-trips through Prisma, or that the start route
 * rebuilds the same config from it - the three places a parameter can be
 * silently dropped between a checkbox and a command line. So each case here
 * types the parameters, presses Start, and then reads the artifact the scan
 * actually produced.
 *
 * Assertions are on the artifact rather than the Red Zone table because the
 * table shows secret TYPES; "which repositories were enumerated" and "was the
 * gist skipped" are not visible there at all.
 */

const ARTIFACT = join(
  __dirname, '..', '..', '..', 'scanners', 'trufflehog_scan', 'output',
  `trufflehog_${PROJECT}_github.json`)

interface Artifact {
  status?: string
  findings?: { detector_name?: string; asset?: string; link?: string }[]
}

function readArtifact(): Artifact {
  if (!existsSync(ARTIFACT)) return {}
  try {
    return JSON.parse(readFileSync(ARTIFACT, 'utf8'))
  } catch {
    return {}
  }
}

const detectorsOf = (a: Artifact) =>
  [...new Set((a.findings ?? []).map(f => f.detector_name ?? ''))].sort()

/** `owner/repo` for every repository that produced a finding; gists collapse to
 *  `gist:<id>` so the two identity shapes never collide in an assertion. */
const reposOf = (a: Artifact) =>
  [...new Set((a.findings ?? []).map(f => {
    const asset = String(f.asset ?? '')
    if (asset.includes('gist.github.com')) {
      return 'gist:' + asset.replace(/\/$/, '').split('/').pop()!.replace(/\.git$/, '')
    }
    return asset.split('github.com/').pop()!.replace(/\.git$/, '').replace(/^\/+|\/+$/g, '')
  }).filter(Boolean))].sort()

interface UiConfig {
  repos?: string
  orgs?: string
  includeRepos?: string
  excludeRepos?: string
  includePaths?: string
  excludePaths?: string
  endpoint?: string
  commentsTimeframe?: string
  /** Toggles to switch ON, addressed by their visible label. */
  toggles?: string[]
}

/**
 * Fill the GitHub card from scratch.
 *
 * Order matters: `Include repos`, `Exclude repos` and `Include member repos`
 * are registry fields marked `requires: 'orgs'` and render DISABLED until an
 * organization is named, so Organizations has to be typed first or the fill
 * silently lands on a disabled input.
 */
async function configureGithub(page: Page, cfg: UiConfig) {
  await clearGithubProfiles(page)
  const section = await addGithubSource(page)

  if (cfg.orgs) await section.getByLabel('Organizations').fill(cfg.orgs)
  if (cfg.repos) await section.getByLabel('Repositories').fill(cfg.repos)
  if (cfg.endpoint) await section.getByLabel('Endpoint').fill(cfg.endpoint)
  if (cfg.includeRepos) {
    await expect(section.getByLabel('Include repos')).toBeEnabled()
    await section.getByLabel('Include repos').fill(cfg.includeRepos)
  }
  if (cfg.excludeRepos) {
    await expect(section.getByLabel('Exclude repos')).toBeEnabled()
    await section.getByLabel('Exclude repos').fill(cfg.excludeRepos)
  }
  if (cfg.includePaths) await section.getByLabel('Include paths').fill(cfg.includePaths)
  if (cfg.excludePaths) await section.getByLabel('Exclude paths').fill(cfg.excludePaths)
  if (cfg.commentsTimeframe) {
    await section.getByLabel('Comments timeframe (days)').fill(cfg.commentsTimeframe)
  }

  for (const label of cfg.toggles ?? []) {
    const sw = section.getByRole('switch', { name: label, exact: true })
    await expect(sw, `toggle "${label}" is not reachable by name`).toBeEnabled()
    await sw.click()
    await expect(sw).toHaveAttribute('aria-checked', 'true')
  }

  // The card saves on change; give the PUT time to land before Start reads the
  // profile back out of the database.
  await expect(section.getByText(/set at least one repository or organization/i))
    .toBeHidden()
  await page.waitForTimeout(1500)
  return section
}

/** Press Start in the Other Scans modal and wait for the run to finish. */
async function startFromModalAndWait(page: Page) {
  // A stale artifact would let a refused or crashed start "pass" on the
  // previous case's findings.
  rmSync(ARTIFACT, { force: true })

  await openOtherScans(page)
  const start = multiscannerRow(page).getByRole('button', { name: 'Start', exact: true })
  await expect(start).toBeEnabled()
  await start.click()

  await expect.poll(async () => {
    // expect.poll RETHROWS from its callback instead of retrying, so an
    // unguarded request turns a dropped keep-alive connection - which a
    // minutes-long poll will eventually hit - into a failed test that reads
    // like a scanner bug. A transient error is "not finished yet".
    try {
      const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
      if (!r.ok()) return 'http-error'
      const body = await r.json()
      return (body.runs ?? []).find((x: { source: string }) => x.source === 'github')
        ?.status ?? 'missing'
    } catch {
      return 'unreachable'
    }
  }, { timeout: 240_000, intervals: [3000] }).toBe('completed')

  // The artifact is published after the container exits, so a read that races
  // the publish sees the file we just deleted.
  await expect.poll(() => readArtifact().status ?? '', { timeout: 60_000, intervals: [2000] })
    .toBe('completed')
  return readArtifact()
}

test.describe('GitHub parameter combinations, driven from the settings UI', () => {
  test.describe.configure({ mode: 'serial', timeout: 300_000 })

  test('Repositories alone finds everything in the repo', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGithub(page, { repos: alpha })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['Github', 'PrivateKey', 'SlackWebhook'])
  })

  test('Exclude paths drops the env file', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGithub(page, { repos: alpha, excludePaths: '\\.env\\.example' })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['PrivateKey'])
  })

  test('Include paths keeps only the pem', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGithub(page, { repos: alpha, includePaths: '\\.pem$' })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['PrivateKey'])
  })

  test('Organizations plus an Include repos glob scopes the account scan', async ({ page }) => {
    const { owner, prefix } = fixtures()
    await configureGithub(page, { orgs: owner, includeRepos: `${owner}/${prefix}-*` })
    const art = await startFromModalAndWait(page)
    expect(reposOf(art)).toEqual([
      `${owner}/${prefix}-alpha`, `${owner}/${prefix}-beta`, `${owner}/${prefix}-gamma`,
    ])
  })

  test('Exclude archived removes the archived repo', async ({ page }) => {
    const { owner, prefix } = fixtures()
    await configureGithub(page, {
      orgs: owner, includeRepos: `${owner}/${prefix}-*`, toggles: ['Exclude archived'],
    })
    const art = await startFromModalAndWait(page)
    expect(reposOf(art)).toEqual([`${owner}/${prefix}-alpha`, `${owner}/${prefix}-beta`])
  })

  test('Include forks pulls the fork into an account scan', async ({ page }) => {
    const { owner } = fixtures()
    await configureGithub(page, {
      orgs: owner, includeRepos: `${owner}/test_keys`, toggles: ['Include forks'],
    })
    const art = await startFromModalAndWait(page)
    expect(reposOf(art)).toEqual([`${owner}/test_keys`])
  })

  test('Scan issue comments reaches a secret no file contains', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGithub(page, { repos: alpha, toggles: ['Scan issue comments'] })
    const art = await startFromModalAndWait(page)
    // SendGrid exists ONLY in the issue comment, so its presence is the proof.
    expect(detectorsOf(art)).toContain('SendGrid')
    expect((art.findings ?? []).some(f => (f.link ?? '').includes('/issues/'))).toBe(true)
  })

  test('Scan PR comments reaches the pull request description', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGithub(page, { repos: alpha, toggles: ['Scan PR comments'] })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toContain('Mailgun')
  })

  test('Ignore gists silences the gist while the repos stay in scope', async ({ page }) => {
    const { owner, prefix, gist } = fixtures()
    await configureGithub(page, {
      orgs: owner,
      includeRepos: `${owner}/${prefix}-*, *${gist}*`,
      toggles: ['Ignore gists'],
    })
    const art = await startFromModalAndWait(page)
    // LinearAPI lives only in the gist; the fixture repos are still scanned, so
    // this asserts the gist was skipped rather than that nothing ran.
    expect(detectorsOf(art)).not.toContain('LinearAPI')
    expect(detectorsOf(art).length).toBeGreaterThan(0)
  })
})
