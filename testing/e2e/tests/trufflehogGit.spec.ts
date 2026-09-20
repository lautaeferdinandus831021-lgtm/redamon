import { test, expect, type Page } from '@playwright/test'
import { signIn } from './auth'

/**
 * The Secret Multiscanner git source, driven through the real UI against the real stack.
 *
 * The backend matrix (testing/e2e/backend/trufflehog_git_matrix.py) proves what
 * each PARAMETER does to a scan. This proves the parts only a browser can reach:
 * that the form actually renders every field, that validation blocks a start
 * before anything runs, that a profile survives a reload, and that a finished
 * scan's findings reach the Red Zone table an operator reads.
 *
 * Requires the stack up, the webapp image rebuilt, and the fixtures built:
 *   ./testing/e2e/backend/build_fixtures.sh
 *
 * Run: cd testing/e2e && npx playwright test trufflehogGit
 */

const PROJECT = process.env.WHITEHAT_PROJECT || 'e651f859c3114faf94196ab02'
const USER = process.env.WHITEHAT_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const BARE = 'testrepo.git'
const WORK = 'workrepo'

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

/** Removes every git profile, so a test starts from a known shape. */
async function clearGitProfiles(page: Page) {
  const res = await page.request.get(`/api/trufflehog/${PROJECT}/profiles`)
  if (!res.ok()) return
  const body = await res.json()
  for (const p of body.profiles ?? []) {
    if (p.source === 'git') {
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
  // TruffleHog lives under the 'integrations' tab, labelled Other Scans.
  await page.getByRole('button', { name: 'Other Scans', exact: true }).last().click()

  const section = page.locator('#trufflehog-scanner')
  await expect(section).toBeVisible()
  // Sections render open; only click if this one is collapsed.
  if (!(await section.getByText('Sources', { exact: true }).isVisible().catch(() => false))) {
    await section.locator('h2').click()
  }
  return section
}

async function addGitSource(page: Page) {
  const section = await openTrufflehogSection(page)
  await section.getByLabel('Add a source').selectOption('git')
  await section.getByRole('button', { name: /Add source/i }).click()
  const card = section.locator('text=Git repository').first()
  await expect(card).toBeVisible()
  return section
}

test.describe('Secret Multiscanner git source', () => {
  test('the section explains where local repositories go', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    // The one fact the fields themselves cannot convey.
    await expect(section.getByText(/scanners\/scan_targets\/git\//).first()).toBeVisible()
    await expect(section.getByText(/mounted read-only/i).first()).toBeVisible()
  })

  test('every git field is rendered', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    for (const label of [
      'Repository URI', 'Local repository', 'Branch', 'Since commit',
      'Max commit depth', 'Bare repository', 'Include paths', 'Exclude paths',
      'Exclude globs',
    ]) {
      await expect(section.getByText(label, { exact: true }).first(),
        `field "${label}" is missing from the git card`).toBeVisible()
    }
  })

  test('a target is required before the source can start', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    await expect(section.getByText(/set a Repository URI, or a Local repository/i)).toBeVisible()
  })

  test('a traversing local name is refused in the form', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    await section.getByLabel('Local repository').fill('../../work/job.json')
    await expect(section.getByText(/not a valid local repository name/i)).toBeVisible()
  })

  test('URI and local repository are mutually exclusive', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    await section.getByLabel('Local repository').fill(WORK)
    await section.getByLabel('Repository URI').fill('https://example.com/a/b.git')
    await expect(section.getByText(/mutually exclusive/i)).toBeVisible()
  })

  test('a configured profile survives a reload', async ({ page }) => {
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    await section.getByLabel('Local repository').fill(WORK)
    await expect(section.getByText(/set a Repository URI/i)).toBeHidden()

    // A reload returns the form to workflow view, so the section has to be
    // navigated to again rather than simply re-queried.
    const after = await openTrufflehogSection(page)
    await expect(after.getByText('Git repository').first()).toBeVisible()
    await after.getByText('Git repository').first().click()
    await expect(after.getByLabel('Local repository')).toHaveValue(WORK)
  })

  test('shared options render and concurrency can be retyped', async ({ page }) => {
    await openTrufflehogSection(page)
    const section = page.locator('#trufflehog-scanner')
    await expect(section.getByText('Shared options')).toBeVisible()
    await expect(section.getByText('Result types')).toBeVisible()

    // The bug that made this field append-only: it must accept an empty state.
    const conc = section.getByLabel('Concurrency')
    await conc.fill('')
    await expect(conc).toHaveValue('')
    await conc.fill('4')
    await expect(conc).toHaveValue('4')
  })

  test('the detector picker lists the real catalogue and can filter', async ({ page }) => {
    await openTrufflehogSection(page)
    const section = page.locator('#trufflehog-scanner')
    await section.getByRole('button', { name: /Browse all \d+/ }).first().click()
    const filter = section.getByLabel('Filter detectors')
    await expect(filter).toBeVisible()
    await filter.fill('privatekey')
    await expect(section.getByRole('button', { name: 'PrivateKey', exact: true })).toBeVisible()
  })

  test('a real scan runs from the UI and its findings reach the Red Zone', async ({ page }) => {
    test.setTimeout(240_000)
    await clearGitProfiles(page)
    const section = await addGitSource(page)
    await section.getByLabel('Local repository').fill(WORK)
    await expect(section.getByText(/set a Repository URI/i)).toBeHidden()

    // Start through the Other Scans modal, the way an operator does.
    await page.goto(`/graph?project=${PROJECT}`)
    await page.getByRole('button', { name: /Other Scans/i }).click()
    const modal = page.locator('text=Other Scans').first()
    await expect(modal).toBeVisible()

    const row = page.locator('div').filter({ hasText: /^Git repository/ }).first()
    const start = row.getByRole('button', { name: /^Start$/ }).first()
    await expect(start).toBeEnabled()
    await start.click()

    // Poll the API rather than the spinner: the run is the source of truth.
    await expect.poll(async () => {
      const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
      if (!r.ok()) return 'http-error'
      const body = await r.json()
      const git = (body.runs ?? []).find((x: { source: string }) => x.source === 'git')
      return git?.status ?? 'missing'
    }, { timeout: 200_000, intervals: [3000] }).toBe('completed')

    // The run must also read as finished in the UI the operator started it from.
    await expect.poll(async () => {
      const r = await page.request.get(`/api/trufflehog/${PROJECT}/all`)
      const body = await r.json()
      return (body.runs ?? []).find((x: { source: string }) => x.source === 'git')?.ingested
    }, { timeout: 60_000, intervals: [2000] }).toBe(true)

    // ...and the findings must reach the Red Zone secrets query.
    //
    // Asserted through the API rather than the table, deliberately: the graph
    // page can be pinned to a saved scan version, and then the table correctly
    // shows that snapshot instead of the live graph. Driving the version picker
    // here would mutate the operator's own view state to make a test pass.
    const secrets = await page.request.get(
      `/api/analytics/redzone/secrets?projectId=${PROJECT}`)
    expect(secrets.ok()).toBeTruthy()
    const rows = await secrets.json()
    const list = Array.isArray(rows) ? rows : (rows.rows ?? rows.secrets ?? [])
    const fromTrufflehog = list.filter(
      (r: { origin?: string }) => r.origin === 'MultiscannerFinding')
    expect(fromTrufflehog.map((r: { secretType: string }) => r.secretType))
      .toEqual(expect.arrayContaining(['PrivateKey', 'Github', 'SlackWebhook']))
  })
})
