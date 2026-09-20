import { test, expect, type Page, type Locator } from '@playwright/test'
import { readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { signIn, mintToken } from './auth'

/**
 * The Secret Multiscanner GitLab source, driven through the real UI against the
 * real stack.
 *
 * The backend matrix (testing/e2e/backend/trufflehog_gitlab_matrix.py) proves
 * what each PARAMETER does to a scan. This proves the parts only a browser can
 * reach: that the form renders every field, that NONE of them is gated (unlike
 * github, this source declares no `requires:`), that the shorthand-repo
 * validation message appears in the form before any start, that a missing token
 * blocks Start, that a profile survives a reload, and that a finished scan's
 * findings reach the Red Zone table an operator reads.
 *
 * Requires the stack up, the webapp image rebuilt, and the fixtures built:
 *   ./testing/e2e/backend/build_gitlab_fixtures.sh
 *
 * Run: cd testing/e2e && npx playwright test trufflehogGitlab
 */

const PROJECT = process.env.WHITEHAT_PROJECT || 'e651f859c3114faf94196ab02'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const TOKEN_KEY = 'trufflehogGitlabToken'
const SOURCE = 'gitlab'
const LABEL = 'GitLab'

function repoRoot(): string {
  return join(__dirname, '..', '..', '..')
}

/** The fixtures the builder created, so the spec never hardcodes an account. */
function fixtures(): {
  host: string; group: string; groupId: number
  alpha: string; beta: string; gamma: string
  alphaPath: string; betaPath: string; gammaPath: string
} {
  return JSON.parse(
    readFileSync(join(repoRoot(), '_local', 'gitlab_fixtures.json'), 'utf8'))
}

/** The real token, read from the same place the builder put it. Used only to
 *  put back what the credential-gate test deliberately clears. */
function fixtureToken(): string {
  return (process.env.GITLAB_FIXTURE_TOKEN
    || readFileSync(join(repoRoot(), '_local', 'gitlab_fixture_token'), 'utf8')).trim()
}

/** Every field the registry declares for `gitlab`. NONE carries `requires:`. */
const FIELD_LABELS = [
  'Endpoint', 'Repositories', 'Group IDs', 'Include repos', 'Exclude repos',
  'Include paths', 'Exclude paths',
]

test.beforeEach(async ({ context, baseURL, playwright }) => {
  await signIn(context, USER, baseURL!)
  // The credential-gate test CLEARS the global key to reach the blocked state.
  // If it fails between the clear and the paste, every later test runs with no
  // token: the scans fail, and the failures read like scanner bugs rather than
  // fallout. afterAll alone cannot prevent that, because it runs too late. This
  // costs one request per test and makes each one independent of the last.
  const ctx = await playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { cookie: `whitehat-auth=${mintToken(USER)}` },
  })
  await ctx.put(`/api/users/${USER}/settings`, { data: { [TOKEN_KEY]: fixtureToken() } })
  await ctx.dispose()
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
  // denied by requireUserAccess and a .catch() would swallow the failure,
  // which is how a failed run leaves the account's real token cleared.
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
 * The GitLab row inside the Other Scans modal.
 *
 * Addressed by the CSS-module row class rather than by text: THREE cards in
 * that modal render a button whose accessible name is exactly "Start" (GitHub
 * Hunt, Secret Multiscanner, Supply Chain), and `locator('div')` filtered by
 * text resolves to an ancestor that contains no button at all.
 */
function multiscannerRow(page: Page) {
  return page.locator('[class*="sourceRow"]').filter({ hasText: LABEL }).first()
}

/**
 * Open the Other Scans modal and wait for the GitLab row.
 *
 * Retried rather than awaited once. The modal builds its rows from a profiles
 * fetch issued when it opens, and the graph page behind it is still hydrating,
 * so both the click and the row can be a beat late: the row simply never
 * appears and the failure reads "element(s) not found", which looks like a
 * missing profile rather than a timing miss. Reopening is a couple of seconds
 * and is honest about what it is waiting for.
 */
async function openOtherScans(page: Page) {
  // Budget matters: the file's test timeout is 60s, so a retry loop that can
  // burn all of it turns a recoverable miss into "Target page has been closed",
  // which is what a too-generous version of this helper did. Three attempts at
  // 8s plus navigation stays well inside one test.
  for (let attempt = 0; attempt < 3; attempt++) {
    await page.goto(`/graph?project=${PROJECT}`)
    await page.getByRole('button', { name: /Other Scans/i }).click().catch(() => {})
    try {
      await multiscannerRow(page).waitFor({ state: 'visible', timeout: 8_000 })
      return
    } catch {
      // The modal builds its rows from a fetch issued when it opens, and the
      // graph page behind it is still hydrating, so both the click and the row
      // can be a beat late. Reopening is cheaper than guessing a sleep.
    }
  }
  // Unguarded, so the failure carries the real locator message.
  await page.goto(`/graph?project=${PROJECT}`)
  await page.getByRole('button', { name: /Other Scans/i }).click()
  await expect(multiscannerRow(page)).toBeVisible()
}

async function clearGitlabProfiles(page: Page) {
  const res = await page.request.get(`/api/trufflehog/${PROJECT}/profiles`)
  if (!res.ok()) return
  const body = await res.json()
  for (const p of body.profiles ?? []) {
    if (p.source === SOURCE) {
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

/**
 * The GitLab card, not the whole section.
 *
 * A project holds one profile per source and typically holds several, and
 * `Endpoint` / `Include paths` / `Exclude paths` are labels this source SHARES
 * with github, huggingface and filesystem. Scoped to the section, those
 * selectors resolve to two inputs and Playwright fails on strict mode, so the
 * card carries its own id (`trufflehog-source-<id>`, added for this).
 */
function card(page: Page): Locator {
  return page.locator(`#trufflehog-source-${SOURCE}`)
}

/** Open the card's body; it is collapsed until its header is clicked. */
async function expandCard(page: Page) {
  const c = card(page)
  await expect(c).toBeVisible()
  if (!(await c.getByLabel('Repositories').isVisible().catch(() => false))) {
    await c.getByText(LABEL, { exact: true }).first().click()
  }
  await expect(c.getByLabel('Repositories')).toBeVisible()
  return c
}

/**
 * Ensure the GitLab card exists and is open.
 *
 * Written to converge on the wanted state rather than to assume a clean one.
 * "Add a source" only offers sources the project has NOT configured, so a
 * lingering profile removes `gitlab` from the dropdown and the POST is refused
 * as a duplicate; the card then never appears and the failure points at the
 * card locator, which says nothing about why. Reusing an existing card covers
 * that, and one retry covers a delete that had not landed when the page loaded.
 */
async function addGitlabSource(page: Page) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const section = await openTrufflehogSection(page)
    if (await card(page).isVisible().catch(() => false)) return expandCard(page)

    const picker = section.getByLabel('Add a source')
    const offered = await picker.locator(`option[value="${SOURCE}"]`).count()
    if (offered > 0) {
      await picker.selectOption(SOURCE)
      await section.getByRole('button', { name: /Add source/i }).click()
    }
    try {
      await card(page).waitFor({ state: 'visible', timeout: 8_000 })
      return expandCard(page)
    } catch {
      await clearGitlabProfiles(page)
    }
  }
  // Unguarded, so the failure carries the real locator message.
  const section = await openTrufflehogSection(page)
  await section.getByLabel('Add a source').selectOption(SOURCE)
  await section.getByRole('button', { name: /Add source/i }).click()
  return expandCard(page)
}

test.describe('Secret Multiscanner GitLab source', () => {
  // The default is 60s, which a single helper retry plus a credential round trip
  // can exhaust. Serial because these share one profile row per source.
  test.describe.configure({ mode: 'serial', timeout: 120_000 })

  test('every gitlab field is rendered', async ({ page }) => {
    await clearGitlabProfiles(page)
    const c = await addGitlabSource(page)
    for (const label of FIELD_LABELS) {
      await expect(c.getByText(label, { exact: true }).first(),
        `field "${label}" is missing from the GitLab card`).toBeVisible()
    }
  })

  test('no gitlab field is gated: none of them is disabled', async ({ page }) => {
    // The github card locks includeRepos/excludeRepos behind `requires: 'orgs'`.
    // The gitlab registry entry declares NO `requires:` on any field, so every
    // one of them must be usable the moment the card is added. Asserted rather
    // than assumed: a stray `requires:` copied over from github would silently
    // make two filter fields unreachable in the UI while the backend kept
    // honouring them.
    await clearGitlabProfiles(page)
    const c = await addGitlabSource(page)
    for (const label of FIELD_LABELS) {
      await expect(c.getByLabel(label, { exact: true }),
        `field "${label}" must not be disabled on the GitLab card`).toBeEnabled()
    }
  })

  test('a shorthand group/project is refused in the form, before any start',
    async ({ page }) => {
      // The pinned binary answers `group/project` with "Gitlab requires
      // http/https repo urls" at INFO level and then scans NOTHING for it. The
      // operator would read a clean "0 findings" for a repository that was never
      // opened, so the form has to say so before Start is ever pressed.
      await clearGitlabProfiles(page)
      const { group } = fixtures()
      const c = await addGitlabSource(page)
      await c.getByLabel('Repositories').fill(`${group}/alpha`)
      await expect(c.getByText(/must be a full URL/i)).toBeVisible()

      // ...and the message goes away once the URL form is used.
      await c.getByLabel('Repositories').fill(fixtures().alpha)
      await expect(c.getByText(/must be a full URL/i)).toBeHidden()
    })

  test('an Include repos glob missing its wrapping stars is refused in the form',
    async ({ page }) => {
      // Measured against the pinned binary: TruffleHog applies this glob TWICE,
      // to `group/project` while enumerating and to
      // `https://host/group/project.git` before scanning, and scans a project
      // only if BOTH match. `group/project*` is exactly the shape that works on
      // github, matches the path, fails the URL, and silently selects NOTHING.
      // Refusing it in the form is the only place an operator ever learns this.
      await clearGitlabProfiles(page)
      const { group } = fixtures()
      const c = await addGitlabSource(page)
      await c.getByLabel('Include repos').fill(`${group}/a*`)
      await expect(c.getByText(/would match nothing/i)).toBeVisible()

      // Wrapping it in stars clears the error.
      await c.getByLabel('Include repos').fill(`*${group}/a*`)
      await expect(c.getByText(/would match nothing/i)).toBeHidden()

      // Exclusion is deliberately NOT restricted: it drops a project when
      // EITHER string matches, so the full-path shape works there.
      await c.getByLabel('Exclude repos').fill(`${group}/b*`)
      await expect(c.getByText(/would match nothing/i)).toBeHidden()
    })

  test('a configured profile survives a reload', async ({ page }) => {
    await clearGitlabProfiles(page)
    const { alpha } = fixtures()
    const c = await addGitlabSource(page)
    await c.getByLabel('Repositories').fill(alpha)
    await expect(c.getByText(/must be a full URL/i)).toBeHidden()

    // A reload returns the form to workflow view, so the section has to be
    // navigated to again rather than simply re-queried.
    await openTrufflehogSection(page)
    const after = await expandCard(page)
    await expect(after.getByLabel('Repositories')).toHaveValue(alpha)
  })

  test('a missing token blocks Start, and pasting it in place unblocks it', async ({ page }) => {
    await clearGitlabProfiles(page)
    const { alpha } = fixtures()
    const c = await addGitlabSource(page)
    await c.getByLabel('Repositories').fill(alpha)

    // Clear the GLOBAL key to reach the blocked state. afterAll puts it back
    // even if this test fails part way through.
    await page.request.put(`/api/users/${USER}/settings`, { data: { [TOKEN_KEY]: '' } })

    await openTrufflehogSection(page)
    const blocked = await expandCard(page)
    await expect(blocked.getByText(/requires Secret Multiscanner GitLab Token/i)).toBeVisible()
    await expect(blocked.getByText('Required', { exact: true }).first()).toBeVisible()

    // The Other Scans modal is where an operator actually presses Start.
    await openOtherScans(page)
    await expect(multiscannerRow(page)
      .getByRole('button', { name: 'Start', exact: true })).toBeDisabled()

    // Paste it into the card's own box, the way the empty-state copy tells you to.
    await openTrufflehogSection(page)
    const back = await expandCard(page)
    const box = back.getByPlaceholder(/Paste your Secret Multiscanner GitLab Token/i)
    await box.fill(fixtureToken())
    // Asserted before clicking: the card's commit() bails out when its `draft`
    // state is still empty, so a click that beats React's onChange does nothing
    // at all, silently, and only the missing badge 15 seconds later says so.
    await expect(box).toHaveValue(fixtureToken())
    await back.getByRole('button', { name: /^Save$/ }).first().click()
    // Two round trips behind the click (PUT, then a re-read of the keys), so
    // this is the slowest badge in the form.
    await expect(back.getByText('Set', { exact: true }).first())
      .toBeVisible({ timeout: 30_000 })

    await openOtherScans(page)
    await expect(multiscannerRow(page)
      .getByRole('button', { name: 'Start', exact: true })).toBeEnabled()
  })

  test('a real scan runs from the UI and its findings reach the Red Zone', async ({ page }) => {
    test.setTimeout(300_000)
    await clearGitlabProfiles(page)
    const { alpha } = fixtures()
    const c = await addGitlabSource(page)
    await c.getByLabel('Repositories').fill(alpha)
    await expect(c.getByText(/must be a full URL/i)).toBeHidden()
    await page.waitForTimeout(1500)

    await openOtherScans(page)
    const start = multiscannerRow(page).getByRole('button', { name: 'Start', exact: true })
    await expect(start).toBeEnabled()
    await start.click()

    // Poll the API rather than the spinner: the run is the source of truth.
    // Guarded, because expect.poll rethrows from its callback rather than
    // retrying, so one dropped keep-alive would fail the whole test.
    await expect.poll(async () => runStatus(page),
      { timeout: 240_000, intervals: [3000] }).toBe('completed')

    await expect.poll(async () => {
      try {
        const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
        const body = await r.json()
        return (body.runs ?? []).find((x: { source: string }) => x.source === SOURCE)?.ingested
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
 * rebuilds the same config from it: the three places a parameter can be
 * silently dropped between a text box and a command line. So each case here
 * types the parameters, presses Start, and then reads the artifact the scan
 * actually produced.
 *
 * Assertions are on the artifact rather than the Red Zone table because the
 * table shows secret TYPES; "which projects were enumerated" is not visible
 * there at all.
 */

const ARTIFACT = join(
  __dirname, '..', '..', '..', 'scanners', 'trufflehog_scan', 'output',
  `trufflehog_${PROJECT}_${SOURCE}.json`)

interface Artifact {
  status?: string
  target?: string
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

async function runStatus(page: Page): Promise<string> {
  // expect.poll RETHROWS from its callback instead of retrying, so an unguarded
  // request turns a dropped keep-alive connection, which a minutes-long poll
  // will eventually hit, into a failed test that reads like a scanner bug. A
  // transient error is "not finished yet".
  try {
    const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
    if (!r.ok()) return 'http-error'
    const body = await r.json()
    return (body.runs ?? []).find((x: { source: string }) => x.source === SOURCE)
      ?.status ?? 'missing'
  } catch {
    return 'unreachable'
  }
}

const detectorsOf = (a: Artifact) =>
  [...new Set((a.findings ?? []).map(f => f.detector_name ?? ''))].sort()

/** `group/project` for every project that produced a finding. */
const projectsOf = (a: Artifact) =>
  [...new Set((a.findings ?? []).map(f => {
    let s = String(f.asset ?? '')
    if (s.includes('://')) {
      s = s.split('://')[1]
      s = s.includes('/') ? s.slice(s.indexOf('/') + 1) : ''
    }
    return s.replace(/\.git$/, '').replace(/^\/+|\/+$/g, '')
  }).filter(Boolean))].sort()

interface UiConfig {
  repos?: string
  groupIds?: string
  includeRepos?: string
  excludeRepos?: string
  includePaths?: string
  excludePaths?: string
  endpoint?: string
}

/**
 * Fill the GitLab card from scratch.
 *
 * No ordering constraint here, unlike github: this source declares no
 * `requires:` fields, so nothing renders disabled and no dependency has to be
 * typed first. `Repositories`, `Group IDs`, `Include repos` and `Exclude repos`
 * are `multi` (typed comma-separated, stored as a list); `Include paths` and
 * `Exclude paths` are `pathfile` and render as a textarea, one regex per line.
 */
async function configureGitlab(page: Page, cfg: UiConfig) {
  await clearGitlabProfiles(page)
  const c = await addGitlabSource(page)

  if (cfg.endpoint) await c.getByLabel('Endpoint').fill(cfg.endpoint)
  if (cfg.repos) await c.getByLabel('Repositories').fill(cfg.repos)
  if (cfg.groupIds) await c.getByLabel('Group IDs').fill(cfg.groupIds)
  if (cfg.includeRepos) await c.getByLabel('Include repos').fill(cfg.includeRepos)
  if (cfg.excludeRepos) await c.getByLabel('Exclude repos').fill(cfg.excludeRepos)
  if (cfg.includePaths) await c.getByLabel('Include paths').fill(cfg.includePaths)
  if (cfg.excludePaths) await c.getByLabel('Exclude paths').fill(cfg.excludePaths)

  // No validation error may be standing, or Start is refused server-side.
  await expect(c.getByText(/must be a full URL/i)).toBeHidden()
  await expect(c.getByText(/would match nothing/i)).toBeHidden()
  await expectStoredConfig(page, cfg)
  return c
}

/**
 * Block until the profile row actually holds everything that was typed.
 *
 * Not a tidiness check, and not a substitute for a sleep. The card PATCHes on
 * every change, so a field that fails to persist leaves a profile that is still
 * VALID but means something else entirely: on gitlab, a config that lost its
 * `repos` is "no repos and no group ids", which is the legal empty scope that
 * scans every project the token can reach. A run like that completes cleanly and
 * reports findings, so the only symptom is an assertion about one project coming
 * back with three projects' worth. Waiting on the stored value turns that into a
 * failure here, naming the field, instead of a puzzling result two minutes later.
 */
async function expectStoredConfig(page: Page, cfg: UiConfig) {
  const asList = (v: string) => v.split(',').map(x => x.trim()).filter(Boolean)
  const want: Record<string, unknown> = {}
  if (cfg.endpoint) want.endpoint = cfg.endpoint
  if (cfg.repos) want.repos = asList(cfg.repos)
  if (cfg.groupIds) want.groupIds = asList(cfg.groupIds)
  if (cfg.includeRepos) want.includeRepos = asList(cfg.includeRepos)
  if (cfg.excludeRepos) want.excludeRepos = asList(cfg.excludeRepos)
  if (cfg.includePaths) want.includePaths = cfg.includePaths
  if (cfg.excludePaths) want.excludePaths = cfg.excludePaths

  await expect.poll(async () => {
    try {
      const r = await page.request.get(`/api/trufflehog/${PROJECT}/profiles`)
      if (!r.ok()) return 'http-error'
      const body = await r.json()
      const stored = (body.profiles ?? [])
        .find((p: { source: string }) => p.source === SOURCE)?.config ?? {}
      // Only the keys this case set: the profile may legitimately carry others.
      const seen: Record<string, unknown> = {}
      for (const k of Object.keys(want)) seen[k] = stored[k]
      return JSON.stringify(seen)
    } catch {
      return 'unreachable'
    }
  }, {
    message: 'the settings form never persisted every field that was typed',
    timeout: 20_000,
    intervals: [500],
  }).toBe(JSON.stringify(want))
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

  await expect.poll(async () => runStatus(page),
    { timeout: 240_000, intervals: [3000] }).toBe('completed')

  // The artifact is published after the container exits, so a read that races
  // the publish sees the file we just deleted.
  await expect.poll(() => readArtifact().status ?? '', { timeout: 60_000, intervals: [2000] })
    .toBe('completed')
  return readArtifact()
}

test.describe('GitLab parameter combinations, driven from the settings UI', () => {
  test.describe.configure({ mode: 'serial', timeout: 300_000 })

  test('Repositories with one full URL finds everything in the project', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGitlab(page, { repos: alpha })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['Github', 'PrivateKey', 'SlackWebhook'])
  })

  test('Group IDs alone enumerates the whole group', async ({ page }) => {
    const { groupId, alphaPath, betaPath, gammaPath } = fixtures()
    await configureGitlab(page, { groupIds: String(groupId) })
    const art = await startFromModalAndWait(page)
    expect(projectsOf(art)).toEqual([alphaPath, betaPath, gammaPath].sort())
  })

  test('Group IDs plus an Include repos glob narrows to one project', async ({ page }) => {
    // The wrapping stars are load-bearing: TruffleHog matches this glob against
    // BOTH `group/project` and `https://host/group/project.git`, and scans a
    // project only if both match. `${group}/a*` matches the path, fails the URL,
    // and selects nothing. The form refuses that shape outright, which the
    // Block A test above proves.
    const { groupId, group, alphaPath } = fixtures()
    await configureGitlab(page, { groupIds: String(groupId), includeRepos: `*${group}/a*` })
    const art = await startFromModalAndWait(page)
    expect(projectsOf(art)).toEqual([alphaPath])
  })

  test('Group IDs plus an Exclude repos glob drops one project', async ({ page }) => {
    const { groupId, group, alphaPath, gammaPath } = fixtures()
    await configureGitlab(page, { groupIds: String(groupId), excludeRepos: `${group}/b*` })
    const art = await startFromModalAndWait(page)
    expect(projectsOf(art)).toEqual([alphaPath, gammaPath].sort())
  })

  test('Exclude paths drops the env file', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGitlab(page, { repos: alpha, excludePaths: '\\.env\\.example' })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['PrivateKey'])
  })

  test('Include paths keeps only the pem', async ({ page }) => {
    const { alpha } = fixtures()
    await configureGitlab(page, { repos: alpha, includePaths: '\\.pem$' })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toEqual(['PrivateKey'])
  })
})
