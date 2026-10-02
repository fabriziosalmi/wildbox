/**
 * Prepares the live stack for the @backend specs (#103).
 *
 * - signs the stack admin in through the gateway (correct password only: a
 *   failed attempt here would count towards the admin's lockout);
 * - registers a fresh, non-admin member through the public registration route
 *   (it gets a team of its own, which the API-key flow needs);
 * - checks that the threat-intel rows from fixtures/threat-intel-seed.sql are
 *   visible through the gateway, so a missing seed fails here, once, with a
 *   message that says so.
 *
 * The two sessions are stored as storage states; specs that are not about
 * signing in start from them instead of driving the login form every time.
 */
import { expect, test as setup } from '@playwright/test'
import {
  SEEDED_INDICATORS,
  adminAccount,
  apiLogin,
  bearer,
  gatewayApi,
  registerUser,
  strongPassword,
  uniqueEmail,
  writeAuthFiles,
} from './support/backend'

setup('the dashboard is served and hydrates through the gateway', async ({ page }) => {
  // Every spec depends on this, and when it fails each of them only reports
  // a timeout. Collect what the browser saw so the failure says why.
  const problems: string[] = []
  page.on('console', message => {
    if (message.type() === 'error') problems.push(`console: ${message.text()}`)
  })
  page.on('pageerror', error => problems.push(`pageerror: ${error.message}`))
  page.on('response', response => {
    if (response.status() >= 400) problems.push(`${response.status()} ${response.url()}`)
  })
  page.on('requestfailed', request =>
    problems.push(`failed ${request.url()}: ${request.failure()?.errorText}`)
  )

  await page.goto('/auth/login')
  // The submit button is rendered by the client component, after hydration
  // and the auth check, so its presence proves the bundle ran.
  try {
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible({ timeout: 30_000 })
  } catch (error) {
    throw new Error(`login page did not hydrate:\n${problems.join('\n')}\n\n${error}`)
  }
})

setup('sign in, register the member and check the seed', async () => {
  const api = await gatewayApi()

  const adminToken = await apiLogin(api, adminAccount())
  const me = await api.get('/auth/users/me', { headers: bearer(adminToken) })
  expect(me.status(), await me.text()).toBe(200)
  expect((await me.json()).is_superuser, 'the stack admin must be a superuser').toBe(true)

  const member = { email: uniqueEmail('member'), password: strongPassword() }
  const registered = await registerUser(api, member)
  const memberToken = await apiLogin(api, member)

  for (const [kind, value] of [
    ['ips', SEEDED_INDICATORS.ip],
    ['domains', SEEDED_INDICATORS.domain],
    ['hashes', SEEDED_INDICATORS.hash],
  ]) {
    const response = await api.get(`/api/v1/data/${kind}/${value}`, {
      headers: bearer(adminToken),
    })
    expect(
      response.status(),
      `seeded indicator ${value} is not visible through the gateway -- was ` +
        `tests/e2e/fixtures/threat-intel-seed.sql applied? ${await response.text()}`
    ).toBe(200)
  }

  writeAuthFiles(adminToken, memberToken, { member: { ...member, id: registered.id } })
  await api.dispose()
})
