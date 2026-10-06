import { Route, expect, test } from '@playwright/test'
import {
  adminAccount,
  apiLogin,
  apiLogout,
  bearer,
  gatewayApi,
  registerUser,
  sessionToken,
  strongPassword,
  uiLogin,
  uniqueEmail,
} from './support/backend'

/**
 * Sign-in, session and sign-out against the live identity service (#103).
 *
 * Only the stack admin's correct password is ever typed for the admin. Every
 * failed attempt in this file uses an account created for it, so the
 * per-account lockout (5 failures) can never lock out the admin that the other
 * specs depend on.
 */
test.describe('Login flow', { tag: '@backend' }, () => {
  test('renders the sign-in form and keeps submit disabled until it is filled', async ({
    page,
  }) => {
    await page.goto('/auth/login')

    await expect(page.getByRole('heading', { name: 'Wildbox Security' })).toBeVisible()
    const email = page.getByLabel('Email address')
    const password = page.getByLabel('Password', { exact: true })
    const submit = page.getByRole('button', { name: 'Sign in' })

    await expect(submit).toBeDisabled()
    await email.fill('someone@wildbox.io')
    await expect(submit).toBeDisabled()
    await password.fill('not-submitted')
    await expect(submit).toBeEnabled()
  })

  test('rejects wrong credentials with an error and creates no session', async ({
    page,
    context,
  }) => {
    await page.goto('/auth/login')
    await page.getByLabel('Email address').fill(uniqueEmail('nobody'))
    await page.getByLabel('Password', { exact: true }).fill('Wrong-Password-1!')

    const login = page.waitForResponse(
      r => r.url().endsWith('/auth/jwt/login') && r.request().method() === 'POST'
    )
    await page.getByRole('button', { name: 'Sign in' }).click()
    expect((await login).status()).toBe(400)

    await expect(page.getByTestId('login-error')).toHaveText(/LOGIN_BAD_CREDENTIALS/)
    await expect(page).toHaveURL(/\/auth\/login$/)
    expect(await sessionToken(context)).toBeUndefined()
  })

  test('signs in and shows the signed-in user on the dashboard', async ({ page, context }) => {
    const admin = adminAccount()
    await uiLogin(page, admin)

    // The sidebar's account link carries the address /users/me returned.
    await expect(page.getByRole('link', { name: admin.email })).toBeVisible()
    await expect(page.getByRole('link', { name: /Administration/ })).toBeVisible()
    expect(await sessionToken(context)).toBeTruthy()
  })

  test('keeps the session across a reload', async ({ page }) => {
    const admin = adminAccount()
    await uiLogin(page, admin)

    await page.reload()

    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('link', { name: admin.email })).toBeVisible()
  })

  /* Revocation is a security property, not a timing one: these two must pass
     on the first attempt. A retry used to hide a revoked token that the
     gateway kept accepting -- a request authorized while the logout ran had
     its "allowed" cached after the purge (#571). */
  test.describe('revocation', () => {
    test.describe.configure({ retries: 0 })

    test('logout revokes the token at the gateway and closes protected routes', async ({
      page,
      context,
    }) => {
      await uiLogin(page, adminAccount())
      const token = await sessionToken(context)
      expect(token).toBeTruthy()

      const api = await gatewayApi()
      const protectedRoute = '/api/v1/data/health'
      expect((await api.get(protectedRoute, { headers: bearer(token!) })).status()).toBe(200)

      const revoke = page.waitForResponse(
        r => r.url().endsWith('/auth/jwt/logout') && r.request().method() === 'POST'
      )
      // Every page the tab lands on from here. The logout alone navigates
      // (#590): a redirect of the API client to '/' used to race it. Next's
      // router replaces the history entry once hydrated, which reports the
      // same page a second time, hence a set.
      const landed: string[] = []
      page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) landed.push(new URL(frame.url()).pathname)
      })
      await page.getByRole('button', { name: 'Logout' }).click()
      expect((await revoke).ok()).toBe(true)

      await expect(page).toHaveURL(/\/auth\/login$/)
      expect(await sessionToken(context)).toBeUndefined()

      // The token the browser held is dead server-side, not merely forgotten.
      expect((await api.get(protectedRoute, { headers: bearer(token!) })).status()).toBe(401)
      expect(new Set(landed)).toEqual(new Set(['/auth/login']))

      // And the dashboard sends an anonymous visitor back to sign in.
      await page.goto('/dashboard')
      await expect(page).toHaveURL(/\/\?redirect=%2Fdashboard$/)
      await api.dispose()
    })

    test('a request refused during the logout does not take the tab elsewhere', async ({
      page,
      context,
    }) => {
      // The race of #590, made deterministic: the dashboard's own API
      // requests are held, then answered by the gateway (401: the token is
      // revoked) while the logout request is still pending in the page.
      // The API client used to redirect to '/' on such a 401.
      const held: Route[] = []
      await page.route('**/api/v1/**', route => {
        if (route.request().method() === 'GET') held.push(route)
        else return route.continue()
      })
      let revokeStatus = 0
      const refused: (number | undefined)[] = []
      await page.route('**/auth/jwt/logout', async route => {
        const response = await route.fetch() // the token is revoked from here
        revokeStatus = response.status()
        for (const request of held.splice(0)) {
          await request.continue()
          refused.push((await request.request().response())?.status())
        }
        // The page may be gone already: that is what the test looks for.
        await route.fulfill({ response }).catch(() => undefined)
      })

      const api = await gatewayApi()
      const account = { email: uniqueEmail('logout-401'), password: strongPassword() }
      await registerUser(api, account)
      await api.dispose()
      await uiLogin(page, account)
      await expect.poll(() => held.length).toBeGreaterThan(0)

      const landed: string[] = []
      page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) landed.push(new URL(frame.url()).pathname)
      })
      await page.getByRole('button', { name: 'Logout' }).click()
      await expect.poll(() => revokeStatus).toBe(204)

      await expect(page).toHaveURL(/\/auth\/login$/)
      await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
      expect(await sessionToken(context)).toBeUndefined()
      expect(new Set(landed)).toEqual(new Set(['/auth/login']))
      expect(refused.length).toBeGreaterThan(0)
      expect(refused.every(status => status === 401)).toBe(true)
    })

    test('a logout racing in-flight requests leaves no window', async () => {
      // What the dashboard does on every sign-in: a burst of requests with a
      // token the gateway has not cached yet, each one asking identity. A
      // logout lands among them; once it has answered, the token must be
      // refused, every time.
      test.setTimeout(120_000)
      const api = await gatewayApi()
      const account = { email: uniqueEmail('revoke-race'), password: strongPassword() }
      await registerUser(api, account)
      const protectedRoute = '/api/v1/data/health'
      const iterations = 40
      const leaks: string[] = []

      for (let i = 0; i < iterations; i++) {
        const token = await apiLogin(api, account)
        const inFlight = Array.from({ length: 8 }, () =>
          api.get(protectedRoute, { headers: bearer(token) })
        )
        // Their answers do not matter (some may be 429: the per-team budget);
        // what matters is that each one makes the gateway ask identity.
        // Vary where the logout lands relative to the burst.
        await new Promise(resolve => setTimeout(resolve, i % 8))
        expect(await apiLogout(api, token)).toBe(204)
        await Promise.all(inFlight)

        for (let probe = 0; probe < 3; probe++) {
          const status = (await api.get(protectedRoute, { headers: bearer(token) })).status()
          if (status !== 401) leaks.push(`iteration ${i}, probe ${probe}: HTTP ${status}`)
        }
        // No pause between iterations: the stack these specs run against
        // does not hold the login and logout routes to the 5 requests a
        // second per address a deployment has (#756, support/backend.ts).
      }

      expect(leaks, `revoked token accepted after logout`).toEqual([])
      await api.dispose()
    })
  })

  test('hostile input in the password field is rejected and never executed', async ({
    page,
    context,
  }) => {
    // A throwaway account: the four bad attempts below stay under its lockout
    // threshold, and the final correct sign-in proves none of them got through
    // or broke the account.
    const api = await gatewayApi()
    const account = { email: uniqueEmail('hostile'), password: strongPassword() }
    await registerUser(api, account)
    await api.dispose()

    const dialogs: string[] = []
    page.on('dialog', async dialog => {
      dialogs.push(dialog.message())
      await dialog.dismiss()
    })

    await page.goto('/auth/login')
    const error = page.getByTestId('login-error')
    for (const payload of [
      "' OR '1'='1",
      "admin'--",
      "' OR 1=1--",
      '<img src=x onerror=alert(1)>',
    ]) {
      await page.getByLabel('Email address').fill(account.email)
      await page.getByLabel('Password', { exact: true }).fill(payload)
      const login = page.waitForResponse(r => r.url().endsWith('/auth/jwt/login'))
      await page.getByRole('button', { name: 'Sign in' }).click()
      expect((await login).status(), `payload ${payload}`).toBe(400)
      await expect(error).toHaveText(/LOGIN_BAD_CREDENTIALS/)
      await expect(page).toHaveURL(/\/auth\/login$/)
    }
    expect(await sessionToken(context)).toBeUndefined()
    expect(dialogs).toEqual([])

    await page.getByLabel('Password', { exact: true }).fill(account.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 })
  })
})
