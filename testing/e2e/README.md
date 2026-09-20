# Browser end-to-end tests

Drives the real WhiteHat web app in Chromium against the running stack.

```bash
cd testing/e2e
npm install
npx playwright install chromium
npx playwright test                 # everything
npx playwright test filtersSynthetic
```

## Why this lives outside `webapp/`

`webapp/node_modules` is created by the Docker build and is owned by root, so
`npm install` there fails for the desktop user. This directory has its own
`package.json` and depends on nothing from the app - it only speaks HTTP.

## Prerequisites

The stack must already be serving `http://localhost:3000`
(`docker compose up -d webapp`). The suite deliberately does NOT start the app:
it is meant to exercise the built image, so **rebuild after changing
`webapp/src`** (`docker compose build webapp && docker compose up -d webapp`)
or the tests will run against the previous bundle.

Override the target with `WHITEHAT_BASE_URL`, and the fixtures with
`WHITEHAT_PROJECT` / `WHITEHAT_USER`.

## Auth

`tests/auth.ts` signs the app's own session JWT with `AUTH_SECRET` from the
repo `.env` and sets it as the `whitehat-auth` cookie. No password is stored
here, and the tests do not depend on the login page's markup.

The onboarding gate and the GitHub star banner are full-screen overlays keyed
off localStorage; every spec pre-accepts them in `beforeEach` or nothing else
is reachable.

## The suites

- `filters.spec.ts` - the honest pass over every filterable page using whatever
  the project actually contains. Sheets with no rows assert that the Filters
  button is correctly disabled and then skip, and the run prints a coverage
  table so an empty project cannot look like an all-pass.
- `filtersSynthetic.spec.ts` - the same journey with the analytics API stubbed,
  so all 19 pages are really rendered, filtered, reloaded and re-checked
  regardless of project data.
