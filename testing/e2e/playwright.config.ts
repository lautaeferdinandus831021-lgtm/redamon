import { defineConfig, devices } from '@playwright/test'

/**
 * Drives the WhiteHat web app in a real browser against the running stack.
 *
 * This suite does NOT start the app - it points at whatever is serving
 * http://localhost:3000, so it exercises the built image rather than a dev
 * server. Bring the stack up first (`docker compose up -d webapp`).
 */
export default defineConfig({
  testDir: './tests',
  // Filters are per-user state in one shared DB row, so two workers filtering
  // at once would overwrite each other's preferences.
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: {
    baseURL: process.env.WHITEHAT_BASE_URL || 'http://localhost:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1600, height: 1000 },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
