# Dashboard End-to-End Tests

Playwright tests for the dashboard, in `tests/e2e/`. They come in two groups,
configured in `playwright.config.ts`:

- **Frontend smoke** (projects `chromium`, `firefox`, `webkit`): specs that
  need no backend. Each of these projects ignores the backend files listed in
  `BACKEND_FILES` and every test tagged `@backend`.
- **Backend** (projects `backend-setup` and `backend-chromium`): specs tagged
  `@backend`, run against the full compose stack with the dashboard served by
  the gateway.

## Files

```text
tests/e2e/
├── *.spec.ts                    # 18 spec files
├── backend.setup.ts             # Setup project for the backend specs
├── support/backend.ts           # Shared helpers (accounts, API calls, sessions)
├── fixtures/threat-intel-seed.sql
└── page-objects/                # admin-page.ts, dashboard-page.ts, login-page.ts
```

Frontend smoke specs (3):

- `admin-ui-only.spec.ts`: login form, route guard redirects, form
  validation and layout, without a backend
- `quick-login-test.spec.ts`: the login page renders and its form accepts input
- `tool-schema.spec.ts`: unit tests of the toolbox's schema-to-form mapping
  (`src/lib/tool-schema.ts`), no page involved

Backend specs (15): `admin-comprehensive`, `api-docs`,
`cloud-security-compliance`, `cloud-security-overview`, `cloud-security-scans`,
`dashboard-home`, `login-flow`, `response`, `settings-management`,
`signup-flow`, `team-members`, `threat-intel-lookup`, `toolbox`,
`toolbox-run`, `vulnerabilities`.

## Configuration

From `playwright.config.ts`:

| Setting                          | Value                                                                                                                                                       |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `testDir`                        | `./tests/e2e`                                                                                                                                               |
| `baseURL`                        | `PLAYWRIGHT_BASE_URL`, default `http://localhost:3000`                                                                                                      |
| `fullyParallel`                  | `true`; one worker when `CI` is set                                                                                                                         |
| `retries`                        | 2 when `CI` is set, otherwise 0                                                                                                                             |
| `timeout`                        | 60 s with `CI`, 30 s otherwise (navigation: 30 s / 15 s)                                                                                                    |
| `reporter`                       | `html`; `list` and `html` when `CI` is set                                                                                                                  |
| `trace` / `screenshot` / `video` | `on-first-retry` / `only-on-failure` / `retain-on-failure`                                                                                                  |
| `webServer`                      | `npm run dev` (`npm run start` with `CI`) on `http://localhost:3000`, reusing a running server outside CI; disabled when `PLAYWRIGHT_SKIP_WEBSERVER` is set |

The backend projects set `ignoreHTTPSErrors` for the gateway's self-signed
development certificate. `backend-chromium` depends on `backend-setup`.

## Environment variables

| Variable                      | Used by                      | Meaning                                                                                                                                                                                                            |
| ----------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `TEST_EMAIL`, `TEST_PASSWORD` | `support/backend.ts`         | The stack admin, that is `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` from the repository's `.env`. Required by the backend specs; they never guess it, since a wrong guess counts towards the admin lockout |
| `PLAYWRIGHT_BASE_URL`         | config, `support/backend.ts` | Where the browser opens the dashboard. Set it to `https://localhost` for the backend specs, so the dashboard is reached through the gateway                                                                        |
| `PLAYWRIGHT_SKIP_WEBSERVER`   | config                       | Drive the dashboard already running in the compose stack instead of starting a Next.js server                                                                                                                      |
| `CI`                          | config                       | CI settings (retries, workers, timeouts, reporters, `npm run start`)                                                                                                                                               |

## Running the frontend smoke tests

No backend needed; Playwright starts `npm run dev` (or reuses a server on
port 3000):

```bash
cd open-security-dashboard
npm ci
npx playwright install chromium
npx playwright test --project=chromium \
  tests/e2e/admin-ui-only.spec.ts \
  tests/e2e/quick-login-test.spec.ts \
  tests/e2e/tool-schema.spec.ts
```

This is what `.github/workflows/test.yml` runs, after `npm run build`.

## Running the backend tests

1. Start the full stack from the repository root (`docker compose up -d`).
2. Load the threat-intel seed, because the data service has no API that
   creates indicators:

   ```bash
   docker compose exec -T postgres \
     psql -U postgres -d data -v ON_ERROR_STOP=1 \
     < open-security-dashboard/tests/e2e/fixtures/threat-intel-seed.sql
   ```

3. Run the backend project against the gateway, with the stack admin in
   `TEST_EMAIL` and `TEST_PASSWORD`:

   ```bash
   cd open-security-dashboard
   export TEST_EMAIL=...      # INITIAL_ADMIN_EMAIL from ../.env
   export TEST_PASSWORD=...   # INITIAL_ADMIN_PASSWORD from ../.env
   PLAYWRIGHT_SKIP_WEBSERVER=1 PLAYWRIGHT_BASE_URL=https://localhost \
     npx playwright test --project=backend-chromium
   ```

`backend-setup` signs in through the API, registers the member account the
specs use and checks that the seeded indicators are visible; it writes the
sessions to `tests/e2e/.auth/`. A test that changes an account or tries a
wrong password registers a fresh one with a random password. `.github/workflows/e2e-fullstack.yml` runs
these specs the same way, with `--retries=1`.

## npm scripts

| Script                                               | Command                                                                     |
| ---------------------------------------------------- | --------------------------------------------------------------------------- |
| `test:e2e`                                           | `playwright test` (all projects; the backend ones need the variables above) |
| `test:e2e:ui` / `test:e2e:headed` / `test:e2e:debug` | The same with `--ui`, `--headed`, `--debug`                                 |
| `test:admin` / `test:admin:headed`                   | `playwright test admin-comprehensive.spec.ts` (a backend spec)              |
| `test:frontend` / `test:frontend:headed`             | `playwright test admin-ui-only.spec.ts`                                     |

`run-admin-tests.sh` and `run-frontend-tests.sh` in the dashboard directory
check that a dashboard answers on port 3000 (the admin script also probes the
identity health route) and then run `admin-comprehensive.spec.ts` and
`admin-ui-only.spec.ts` respectively with the HTML reporter.

## Reports

The HTML report is written to `playwright-report/` (open it with
`npx playwright show-report`). Traces, screenshots and videos of failed tests
are attached to it.

## Writing tests

- Tag a test that needs the stack with `@backend` and add its file to
  `BACKEND_FILES` in `playwright.config.ts`.
- Use the helpers in `support/backend.ts`: `throwawayAccount()` for a test
  that changes an account or tries a wrong password, `startSession()` to put
  a token in the browser, `toast()` to target a toast unambiguously.
- Prefer `data-testid` and role-based locators.
