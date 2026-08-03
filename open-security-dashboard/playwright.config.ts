import { defineConfig, devices } from '@playwright/test';

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
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: 'html',
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
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },

    /* Backend-dependent specs (#103): need the full identity+gateway stack
       from .github/workflows/e2e-fullstack.yml behind them. The browser talks
       only to the gateway (PLAYWRIGHT_BASE_URL=https://localhost), which
       proxies both the dashboard and the APIs — same-origin, like production,
       and the only topology that works: the gateway emits no CORS headers
       (includes/cors_params.conf is a comment-only stub), so a dashboard
       served from a different origin has every API call blocked by the
       browser. ignoreHTTPSErrors covers the self-signed CI certificate. */
    {
      name: 'backend-chromium',
      use: { ...devices['Desktop Chrome'], ignoreHTTPSErrors: true },
      testMatch: /login-flow\.spec\.ts/,
    },

    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },

    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
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
  webServer: {
    command: process.env.CI ? 'npm run start' : 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000, // 2 minutes
  },
});
