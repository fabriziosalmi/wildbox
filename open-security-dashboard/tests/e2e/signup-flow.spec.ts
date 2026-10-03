import { Page, expect, test } from '@playwright/test'
import {
  gatewayApi,
  registerUser,
  sessionToken,
  strongPassword,
  uniqueEmail,
} from './support/backend'

/**
 * Self-service sign-up against the live identity service (#589).
 *
 * identity's register route answers 201 with the created user, not a token;
 * the dashboard then signs the new account in with the same credentials.
 * Every test creates its own throwaway address.
 */

async function fillSignup(page: Page, email: string, password: string) {
  await page.goto('/auth/signup')
  await page.getByLabel('Full name').fill('E2E Signup')
  await page.getByLabel('Email address').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByLabel('Confirm password').fill(password)
  await page.getByLabel(/I agree to the/).check()
}

function registerResponse(page: Page) {
  return page.waitForResponse(
    r => r.url().endsWith('/auth/register') && r.request().method() === 'POST'
  )
}

test.describe('Sign-up flow', { tag: '@backend' }, () => {
  test('a new account lands signed in on the dashboard, with no error', async ({
    page,
    context,
  }) => {
    const email = uniqueEmail('signup')
    await fillSignup(page, email, strongPassword())

    const register = registerResponse(page)
    const login = page.waitForResponse(
      r => r.url().endsWith('/auth/jwt/login') && r.request().method() === 'POST'
    )
    await page.getByRole('button', { name: 'Create account' }).click()
    expect((await register).status()).toBe(201)
    expect((await login).status()).toBe(200)

    await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 })
    // The sidebar's account link carries the address /users/me returned.
    await expect(page.getByRole('link', { name: email })).toBeVisible()
    await expect(page.getByTestId('signup-error')).toHaveCount(0)
    expect(await sessionToken(context)).toBeTruthy()
  })

  test('an address already registered shows the server refusal', async ({ page, context }) => {
    const api = await gatewayApi()
    const email = uniqueEmail('signup-dup')
    await registerUser(api, { email, password: strongPassword() })
    await api.dispose()

    await fillSignup(page, email, strongPassword())
    const register = registerResponse(page)
    await page.getByRole('button', { name: 'Create account' }).click()
    expect((await register).status()).toBe(400)

    await expect(page.getByTestId('signup-error')).toHaveText('REGISTER_USER_ALREADY_EXISTS')
    await expect(page).toHaveURL(/\/auth\/signup$/)
    expect(await sessionToken(context)).toBeUndefined()
  })

  test("a common password shows identity's reason", async ({ page, context }) => {
    // In identity's list (app/data/common_passwords.txt) and long enough to
    // pass the form's own length check, so the refusal comes from the server.
    await fillSignup(page, uniqueEmail('signup-common'), '1qaz2wsx3edc')
    const register = registerResponse(page)
    await page.getByRole('button', { name: 'Create account' }).click()
    expect((await register).status()).toBe(400)

    await expect(page.getByTestId('signup-error')).toHaveText(
      'This password is one of the most commonly used passwords. Choose a less common one.'
    )
    await expect(page).toHaveURL(/\/auth\/signup$/)
    expect(await sessionToken(context)).toBeUndefined()
  })

  test('a short password shows the policy reason before any request', async ({ page }) => {
    let registerCalls = 0
    page.on('request', r => {
      if (r.url().endsWith('/auth/register')) registerCalls++
    })
    await fillSignup(page, uniqueEmail('signup-short'), 'Short-1!')
    await page.getByRole('button', { name: 'Create account' }).click()

    await expect(page.getByTestId('signup-error')).toHaveText(
      'The password must be at least 12 characters long.'
    )
    expect(registerCalls).toBe(0)
  })

  test('an account that cannot sign in yet is sent to the login page with a notice', async ({
    page,
    context,
  }) => {
    // What identity would answer if it required a verified address before
    // sign-in: the account is created for real, only the login is refused.
    await page.route('**/auth/jwt/login', route =>
      route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'LOGIN_USER_NOT_VERIFIED' }),
      })
    )
    await fillSignup(page, uniqueEmail('signup-unverified'), strongPassword())
    const register = registerResponse(page)
    await page.getByRole('button', { name: 'Create account' }).click()
    expect((await register).status()).toBe(201)

    await expect(page).toHaveURL(/\/auth\/login\?registered=1$/)
    await expect(page.getByTestId('login-notice')).toHaveText(
      'Your account has been created. Sign in to continue.'
    )
    await expect(page.getByTestId('login-error')).toHaveCount(0)
    expect(await sessionToken(context)).toBeUndefined()
  })
})
