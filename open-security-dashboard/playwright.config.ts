import { defineConfig, devices } from '@playwright/test'

/* Specs that need the live stack (identity, data, gateway) behind the
   dashboard, and the setup that prepares the stack for them. The frontend
   smoke projects ignore these files; backend-chromium runs nothing else. */
const BACKEND_FILES = [
  /backend\.setup\.ts/,
  /login-flow\.spec\.ts/,
  /admin-comprehensive\.spec\.ts/,
  /settings-management\.spec\.ts/,
  /threat-intel-lookup\.spec\.ts/,
]

/**
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './tests/e2e',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters
     The list reporter puts every test and its outcome in the CI log; the
     HTML report is uploaded as an artifact. */
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'html',
  /* Increased timeout for CI environments where services need time to start */
  timeout: process.env.CI ? 60 * 1000 : 30 * 1000, // 60s in CI, 30s locally
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`.
       Overridable so the full-stack job (#103) can drive the app through the
       gateway (https://localhost) exactly as production does, instead of
       hitting Next directly. */
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000',

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',

    /* Take screenshot on failure */
    screenshot: 'only-on-failure',

    /* Record video for failed tests */
    video: 'retain-on-failure',

    /* Increased navigation timeout for slow CI environments */
    navigationTimeout: process.env.CI ? 30 * 1000 : 15 * 1000, // 30s in CI, 15s locally
  },

  /* Configure projects for major browsers */
  projects: [
    /* Frontend smoke: backend-free by design. Everything tagged @backend, and
       the setup that seeds the stack for it, stays out of these projects. */
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      grepInvert: /@backend/,
      testIgnore: BACKEND_FILES,
    },

    /* Backend-dependent specs (#103). They run against the full compose stack
       of .github/workflows/e2e-fullstack.yml, with the dashboard served by the
       gateway the way a user reaches it (https://localhost), so its API calls
       are same-origin. ignoreHTTPSErrors covers the gateway's self-signed
       development certificate.

       backend-setup signs in through the API, registers the accounts the
       specs use and checks that the seeded threat-intel rows are visible, so a
       broken stack fails once, in setup, instead of once per test. */
    {
      name: 'backend-setup',
      testMatch: /backend\.setup\.ts/,
      use: { ignoreHTTPSErrors: true },
    },
    {
      name: 'backend-chromium',
      use: { ...devices['Desktop Chrome'], ignoreHTTPSErrors: true },
      dependencies: ['backend-setup'],
      grep: /@backend/,
      testMatch: BACKEND_FILES.slice(1),
    },

    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
      grepInvert: /@backend/,
      testIgnore: BACKEND_FILES,
    },

    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
      grepInvert: /@backend/,
      testIgnore: BACKEND_FILES,
    },

    /* Test against mobile viewports. */
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] },
    // },

    /* Test against branded browsers. */
    // {
    //   name: 'Microsoft Edge',
    //   use: { ...devices['Desktop Edge'], channel: 'msedge' },
    // },
    // {
    //   name: 'Google Chrome',
    //   use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    // },
  ],

  /* Playwright manages the dashboard server itself.
     In CI we build first (see workflow) and serve the production build;
     locally we use the dev server and reuse one if it's already running. */
  /* PLAYWRIGHT_SKIP_WEBSERVER: drive a dashboard that is already running --
     the one in the compose stack -- instead of starting a second Next on the
     same port. */
  webServer: process.env.PLAYWRIGHT_SKIP_WEBSERVER
    ? undefined
    : {
        command: process.env.CI ? 'npm run start' : 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !process.env.CI,
        timeout: 120 * 1000, // 2 minutes
      },
})
