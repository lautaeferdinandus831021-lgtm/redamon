import { test, expect, type Page } from '@playwright/test'
import { readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { signIn, mintToken } from './auth'

/**
 * The Secret Multiscanner `github_experimental` source, driven through the real
 * UI against the real stack.
 *
 * The backend matrix (trufflehog_github_experimental_matrix.py) proves what each
 * PARAMETER does to a scan. This proves the parts only a browser can reach: that
 * the card renders all three fields, that Repository is marked required and an
 * empty card says so, that a missing token blocks Start before anything runs,
 * that the profile survives a reload, and that a finished scan's findings reach
 * the Red Zone table an operator actually reads.
 *
 * This source is SLOW. Object discovery walks a short-SHA space rather than
 * cloning a tree, so every real scan here is minutes, not seconds - hence the
 * deliberately small parameter block and the generous test.setTimeout.
 *
 * Requires the stack up, the webapp image rebuilt, and the fixtures built:
 *   ./testing/e2e/backend/build_github_experimental_fixtures.sh
 *
 * Run: cd testing/e2e && npx playwright test trufflehogGithubExperimental
 */

const PROJECT = process.env.WHITEHAT_PROJECT || 'e651f859c3114faf94196ab02'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const SOURCE = 'github_experimental'
const SOURCE_LABEL = 'GitHub deleted commits'
const TOKEN_KEY = 'trufflehogGithubToken'

/**
 * One real scan's budget.
 *
 * MEASURED, not guessed: a run against the two-commit fixture took 5,666s
 * (94 min) on 2026-08-19. The cost is the 65,536-candidate short-SHA sweep,
 * which is the floor for ANY repository - a one-commit repo costs the same as a
 * large one - so this does not shrink with a smaller fixture. Two hours leaves
 * headroom for GitHub's secondary rate limiter, which TruffleHog answers by
 * sleeping 60s and retrying.
 *
 * A tight timeout here reads exactly like a scanner that found nothing.
 */
const SCAN_TIMEOUT_MS = Number(process.env.GHX_SCAN_TIMEOUT_MS || 7_200_000)

function repoRoot(): string {
  return join(__dirname, '..', '..', '..')
}

/** The fixtures the builder created, so the spec never hardcodes an account. */
function fixtures(): {
  owner: string; dangling: string; live: string; danglingSha: string
  danglingDetector: string
} {
  const raw = JSON.parse(readFileSync(
    join(repoRoot(), '_local', 'github_experimental_fixtures.json'), 'utf8'))
  return {
    owner: raw.owner, dangling: raw.dangling, live: raw.live,
    danglingSha: raw.danglingSha,
    // Read, never hardcoded: the fixture repo must be public for object
    // discovery, GitHub push-protects public pushes, and which detectors
    // survive that is GitHub's call. See the builder's header.
    danglingDetector: raw.danglingDetector,
  }
}

/** The real token, read from the same place the builder put it. Used only to
 *  put back what the credential-gate test deliberately clears. */
function fixtureToken(): string {
  return (process.env.GITHUB_FIXTURE_TOKEN
    || readFileSync(join(repoRoot(), '_local', 'gh_fixture_token'), 'utf8')).trim()
}

/** Addressed with getByLabel, which resolves the CONTROL rather than the label
 *  text: a required field renders its label as "Repository *", so an exact text
 *  match on the bare label misses it, and a rendered label with no reachable
 *  input is not a field an operator can use anyway. */
const FIELD_LABELS = ['Repository', 'Collision threshold', 'Delete cached data']

test.beforeEach(async ({ context, baseURL }) => {
  // The session must outlive the SCAN, not the default hour: a run here is
  // 95-105 minutes, and an expired cookie turns every status poll into a 401
  // that reads like a scan which never finished.
  await signIn(context, USER, baseURL!, SCAN_TIMEOUT_MS / 1000 + 1800)
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

/**
 * Puts the token back no matter how the credential-gate test ended.
 *
 * The credential is SHARED with the plain `github` source, so a run that left it
 * cleared would block both of them - and the account's real key with them.
 */
test.afterAll(async ({ playwright, baseURL }) => {
  // NOT the bare `request` fixture: it has no session cookie, so its PUT is
  // denied by requireUserAccess and a .catch() would swallow the failure.
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
      + 'The global key is still cleared, which blocks BOTH github sources; '
      + 'set it in Global Settings > API Keys.')
  }
  await ctx.dispose()
})

/**
 * The github_experimental row inside the Other Scans modal.
 *
 * Matched on the FULL label: `hasText: 'GitHub'` also matches the plain `GitHub`
 * row and the GitHub Hunt card, and three cards in that modal render a button
 * whose accessible name is exactly "Start".
 */
function multiscannerRow(page: Page) {
  return page.locator('[class*="sourceRow"]')
    .filter({ hasText: SOURCE_LABEL }).first()
}

/**
 * The row's start control.
 *
 * Located by its CSS-module class, not by the accessible name "Start", because
 * that name is TRANSIENT: the same button renders "Running..." while a scan of
 * this source is in flight and "Stopping..." while it is being cancelled. A
 * name-based locator therefore reports "element(s) not found" whenever a run is
 * active, which reads like a missing button rather than a busy scanner.
 */
function startButton(page: Page) {
  return multiscannerRow(page).locator('[class*="startButton"]')
}

/** Whether a run of this source is currently occupying the card. The credential
 *  gate is only observable on an IDLE source: a busy one disables Start for a
 *  reason that has nothing to do with the credential. */
async function sourceIsBusy(page: Page): Promise<boolean> {
  try {
    const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
    if (!r.ok()) return false
    const body = await r.json()
    const run = (body.runs ?? []).find((x: { source: string }) => x.source === SOURCE)
    return ['running', 'starting', 'stopping'].includes(run?.status ?? '')
  } catch {
    return false
  }
}

async function openOtherScans(page: Page) {
  await page.goto(`/graph?project=${PROJECT}`)
  await page.getByRole('button', { name: /Other Scans/i }).click()
  await expect(multiscannerRow(page)).toBeVisible()
}

/** Remove every Secret Multiscanner profile, not just this source's: the modal
 *  row is addressed by label, and a leftover `github` row from another spec
 *  would sit next to ours with its own "Start". */
async function clearProfiles(page: Page) {
  const res = await page.request.get(`/api/trufflehog/${PROJECT}/profiles`)
  if (!res.ok()) return
  const body = await res.json()
  for (const p of body.profiles ?? []) {
    await page.request.delete(`/api/trufflehog/${PROJECT}/profiles/${p.id}`)
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

async function addSource(page: Page) {
  const section = await openTrufflehogSection(page)
  await section.getByLabel('Add a source').selectOption(SOURCE)
  await section.getByRole('button', { name: /Add source/i }).click()
  await expect(section.getByText(SOURCE_LABEL, { exact: true }).first()).toBeVisible()
  return section
}

test.describe('Secret Multiscanner GitHub deleted-commits source', () => {
  test('every github_experimental field is rendered', async ({ page }) => {
    await clearProfiles(page)
    const section = await addSource(page)
    for (const label of FIELD_LABELS) {
      await expect(section.getByLabel(label).first(),
        `field "${label}" is missing from the ${SOURCE_LABEL} card`).toBeVisible()
    }
  })

  test('Repository is marked required and an empty card says so', async ({ page }) => {
    await clearProfiles(page)
    const section = await addSource(page)
    // The registry's only `required: true` field in this source. FieldInput
    // renders the marker by appending ' *' to the label text.
    await expect(section.getByText('Repository *', { exact: true })).toBeVisible()
    await expect(section.getByText(/'Repository' is required/i)).toBeVisible()
    // ...and it clears once a repo is named.
    const { dangling } = fixtures()
    await section.getByLabel('Repository').fill(dangling)
    await expect(section.getByText(/'Repository' is required/i)).toBeHidden()
  })

  test('the card explains that findings have no live file path', async ({ page }) => {
    await clearProfiles(page)
    const section = await addSource(page)
    // Not decoration: an operator who does not know this reads an empty
    // `location` column as a broken scan.
    await expect(section.getByText(/no live file path/i)).toBeVisible()
  })

  test('a missing token blocks Start, and pasting it in place unblocks it', async ({ page }) => {
    // A hard failure on a busy source would be a bug in the test, not a finding:
    // Start is disabled while a scan runs, so the credential gate cannot be
    // distinguished from ordinary busy-ness.
    test.skip(await sourceIsBusy(page),
      `a ${SOURCE} run is in flight, which disables Start on its own`)
    await clearProfiles(page)
    const section = await addSource(page)
    const { dangling } = fixtures()
    await section.getByLabel('Repository').fill(dangling)

    // Clear the GLOBAL key to reach the blocked state. afterAll puts it back
    // even if this test fails part way through.
    await page.request.put(`/api/users/${USER}/settings`, { data: { [TOKEN_KEY]: '' } })

    const blocked = await openTrufflehogSection(page)
    await blocked.getByText(SOURCE_LABEL, { exact: true }).first().click()
    await expect(blocked.getByText(/requires Secret Multiscanner GitHub Token/i)).toBeVisible()
    await expect(blocked.getByText('Required', { exact: true }).first()).toBeVisible()

    // The Other Scans modal is where an operator actually presses Start.
    await openOtherScans(page)
    await expect(startButton(page)).toBeDisabled()
    await expect(startButton(page)).toHaveText(/Start/)

    // Paste it into the card's own box, the way the empty-state copy tells you to.
    const back = await openTrufflehogSection(page)
    await back.getByText(SOURCE_LABEL, { exact: true }).first().click()
    await back.getByPlaceholder(/Paste your Secret Multiscanner GitHub Token/i)
      .fill(fixtureToken())
    await back.getByRole('button', { name: /^Save$/ }).first().click()
    await expect(back.getByText('Set', { exact: true }).first()).toBeVisible()

    await openOtherScans(page)
    await expect(startButton(page)).toBeEnabled()
  })

  test('a configured profile survives a reload', async ({ page }) => {
    await clearProfiles(page)
    const section = await addSource(page)
    const { dangling } = fixtures()
    await section.getByLabel('Repository').fill(dangling)
    await section.getByLabel('Collision threshold').fill('4')
    await expect(section.getByText(/'Repository' is required/i)).toBeHidden()

    // A reload returns the form to workflow view, so the section has to be
    // navigated to again rather than simply re-queried.
    const after = await openTrufflehogSection(page)
    await after.getByText(SOURCE_LABEL, { exact: true }).first().click()
    await expect(after.getByLabel('Repository')).toHaveValue(dangling)
    await expect(after.getByLabel('Collision threshold')).toHaveValue('4')
  })
})

/**
 * Parameter combinations, every one configured through the settings UI and
 * started from the Other Scans modal.
 *
 * The backend matrix posts config straight to the orchestrator, which proves
 * what the FLAG does. It cannot prove that the form stores what the operator
 * typed, that the profile round-trips through Prisma, or that the start route
 * rebuilds the same config from it - the three places a parameter can be
 * silently dropped between a text box and a command line.
 *
 * Kept SMALL on purpose: each case is a real object-discovery run.
 */

const ARTIFACT = join(
  __dirname, '..', '..', '..', 'scanners', 'trufflehog_scan', 'output',
  `trufflehog_${PROJECT}_${SOURCE}.json`)

interface Artifact {
  status?: string
  findings?: {
    detector_name?: string; asset?: string; link?: string
    commit?: string; location?: string
  }[]
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

/** The commit a finding came from. This source's findings have no live file
 *  path, so the commit is the only thing that says WHERE the secret was. */
const commitsOf = (a: Artifact) =>
  [...new Set((a.findings ?? []).map(f => String(f.commit ?? '')).filter(Boolean))]

/** Object discovery works in short-SHA space, so a short commit is a legitimate
 *  answer for the full SHA the builder recorded. */
function carriesDanglingCommit(a: Artifact, sha: string): boolean {
  return commitsOf(a).some(c => sha.startsWith(c) || c.startsWith(sha))
}

interface UiConfig {
  repo?: string
  collisionThreshold?: string
  /** Toggles to switch ON, addressed by their visible label. */
  toggles?: string[]
}

async function configure(page: Page, cfg: UiConfig) {
  await clearProfiles(page)
  const section = await addSource(page)

  if (cfg.repo) await section.getByLabel('Repository').fill(cfg.repo)
  if (cfg.collisionThreshold) {
    await section.getByLabel('Collision threshold').fill(cfg.collisionThreshold)
  }
  for (const label of cfg.toggles ?? []) {
    // FieldInput passes aria-label={field.label} to Toggle for every source, so
    // the switch has a real accessible name without a per-source fix.
    const sw = section.getByRole('switch', { name: label, exact: true })
    await expect(sw, `toggle "${label}" is not reachable by name`).toBeEnabled()
    await sw.click()
    await expect(sw).toHaveAttribute('aria-checked', 'true')
  }

  // The card saves on change; give the PUT time to land before Start reads the
  // profile back out of the database.
  await expect(section.getByText(/'Repository' is required/i)).toBeHidden()
  await page.waitForTimeout(1500)
  return section
}

/** Press Start in the Other Scans modal and wait for the run to finish. */
async function startFromModalAndWait(page: Page) {
  // A stale artifact would let a refused or crashed start "pass" on the
  // previous case's findings.
  rmSync(ARTIFACT, { force: true })

  await openOtherScans(page)
  const start = startButton(page)
  await expect(start).toBeEnabled()
  await start.click()

  await expect.poll(async () => {
    // expect.poll RETHROWS from its callback instead of retrying, so an
    // unguarded request turns a dropped keep-alive - which a run this long will
    // eventually hit - into a failed test that reads like a scanner bug.
    try {
      const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
      if (!r.ok()) return 'http-error'
      const body = await r.json()
      return (body.runs ?? []).find((x: { source: string }) => x.source === SOURCE)
        ?.status ?? 'missing'
    } catch {
      return 'unreachable'
    }
  }, { timeout: SCAN_TIMEOUT_MS, intervals: [5000] }).toBe('completed')

  // The artifact is published after the container exits, so a read that races
  // the publish sees the file we just deleted.
  await expect.poll(() => readArtifact().status ?? '', { timeout: 60_000, intervals: [2000] })
    .toBe('completed')
  return readArtifact()
}

test.describe('GitHub deleted-commits parameters, driven from the settings UI', () => {
  // A project holds ONE profile per source, so two tests configuring the same
  // card concurrently would overwrite each other.
  test.describe.configure({ mode: 'serial' })

  test('Repository alone finds the secret in the unreachable commit', async ({ page }) => {
    test.setTimeout(SCAN_TIMEOUT_MS + 300_000)
    const { dangling, danglingSha, danglingDetector } = fixtures()
    await configure(page, { repo: dangling })
    const art = await startFromModalAndWait(page)
    expect(detectorsOf(art)).toContain(danglingDetector)
    // The detector alone is not enough: it must come from the commit the builder
    // force-pushed out of main, not from anything still on a branch.
    expect(carriesDanglingCommit(art, danglingSha),
      `no finding carries the dangling commit ${danglingSha}; commits=${commitsOf(art)}`)
      .toBe(true)
  })

  test('Collision threshold typed into the form still completes', async ({ page }) => {
    test.setTimeout(SCAN_TIMEOUT_MS + 300_000)
    const { dangling, danglingDetector } = fixtures()
    await configure(page, { repo: dangling, collisionThreshold: '4' })
    const art = await startFromModalAndWait(page)
    expect(art.status).toBe('completed')
    expect(detectorsOf(art)).toContain(danglingDetector)
  })

  test('Delete cached data toggled on still completes', async ({ page }) => {
    test.setTimeout(SCAN_TIMEOUT_MS + 300_000)
    const { dangling, danglingDetector } = fixtures()
    await configure(page, { repo: dangling, toggles: ['Delete cached data'] })
    const art = await startFromModalAndWait(page)
    expect(art.status).toBe('completed')
    // A disk-hygiene flag must not change what the scan reports.
    expect(detectorsOf(art)).toContain(danglingDetector)
  })

  test('the findings reach the Red Zone', async ({ page }) => {
    test.setTimeout(300_000)
    // Reads the graph written by the run above rather than starting another: a
    // further object-discovery scan would add an hour and a half to prove
    // nothing new.
    //
    // Waits for ingest only while the run is still THERE to wait on. The
    // orchestrator drops terminal run state after TRUFFLEHOG_TERMINAL_RETENTION
    // (600s), so a poll for `ingested === true` never succeeds once the run has
    // been reaped - it just burns its timeout and fails an assertion about the
    // Red Zone on the basis of a transient bookkeeping record. The graph is the
    // durable truth here, so a reaped run means "go look at the graph", not
    // "this failed".
    await expect.poll(async () => {
      try {
        const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
        if (!r.ok()) return 'unreachable'
        const body = await r.json()
        const run = (body.runs ?? []).find((x: { source: string }) => x.source === SOURCE)
        if (!run) return 'reaped'
        return run.ingested === true ? 'ingested' : 'pending'
      } catch {
        return 'unreachable'
      }
    }, { timeout: 120_000, intervals: [2000] }).toMatch(/^(ingested|reaped)$/)

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

    // Attributed to THIS source, not merely present. The table carries rows from
    // every Secret Multiscanner source at once, and the plain `github` source is
    // pointed at a sibling fixture in the same project - so asserting only on
    // the detector name would pass on another source's row.
    const mine = fromMultiscanner.filter(
      (r: { trufflehogSource?: string }) => r.trufflehogSource === SOURCE)
    expect(mine.map((r: { secretType: string }) => r.secretType))
      .toEqual(expect.arrayContaining([fixtures().danglingDetector]))
  })
})
