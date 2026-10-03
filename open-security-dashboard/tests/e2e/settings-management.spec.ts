import { APIRequestContext, BrowserContext, Page, expect, test } from '@playwright/test'
import {
  ADMIN_STATE,
  MEMBER_STATE,
  adminAccount,
  apiLogin,
  bearer,
  deleteUser,
  gatewayApi,
  loginStatus,
  readSeed,
  sessionToken,
  startSession,
  strongPassword,
  throwawayAccount,
  toast,
  uniqueEmail,
} from './support/backend'

/**
 * Settings against the live identity service (#103).
 *
 * The billing tests of the original spec are gone: /settings/billing does not
 * exist in the app (src/app/settings has profile, api-keys and team only), and
 * there is no billing anywhere in the backend to test against.
 */
test.describe('Settings', { tag: '@backend' }, () => {
  test.describe('as the stack admin', () => {
    test.use({ storageState: ADMIN_STATE })

    test('the overview shows the signed-in account', async ({ page }) => {
      const admin = adminAccount()
      await page.goto('/settings')

      const account = page.getByTestId('account-information')
      await expect(account).toContainText(admin.email, { timeout: 20_000 })
      await expect(account).toContainText('Administrator')
      await expect(page.getByText('Account Status').locator('..')).toHaveText(
        /^Account Status\s*Active$/
      )
    })

    test('the sidebar menu leads to each settings section', async ({ page }) => {
      await page.goto('/dashboard')
      await page.getByRole('button', { name: /^Settings/ }).click()
      await page.getByRole('link', { name: 'Profile', exact: true }).click()
      await expect(page).toHaveURL(/\/settings\/profile$/)
      await expect(page.getByRole('heading', { name: 'Profile Settings' })).toBeVisible()

      // From here on, the settings section's own navigation.
      await page.getByRole('link', { name: /^API Keys Manage API access keys/ }).click()
      await expect(page).toHaveURL(/\/settings\/api-keys$/)
      await expect(page.getByRole('heading', { name: 'API Keys', level: 1 })).toBeVisible()

      await page.getByRole('link', { name: /^Team Team members and roles/ }).click()
      await expect(page).toHaveURL(/\/settings\/team$/)
    })
  })

  test.describe('as a regular member', () => {
    test.use({ storageState: MEMBER_STATE })

    test('the profile page shows the account the server knows', async ({ page }) => {
      const { member } = readSeed()
      await page.goto('/settings/profile')

      await expect(page.getByRole('heading', { name: member.email, level: 2 })).toBeVisible({
        timeout: 20_000,
      })
      await expect(page.getByLabel('Email Address')).toHaveValue(member.email)
      await expect(page.getByText(member.id)).toBeVisible()
    })

    test('creates an API key, keeps it across a reload and revokes it', async ({ page }) => {
      const { member } = readSeed()
      const api = await gatewayApi()
      const token = await apiLogin(api, member)
      const listKeys = async () => {
        const response = await api.get('/api/v1/identity/api-keys', { headers: bearer(token) })
        expect(response.status(), await response.text()).toBe(200)
        return (await response.json()) as Array<{ name: string; scopes: string[] }>
      }

      const name = `e2e key ${Date.now()}`
      await page.goto('/settings/api-keys')
      await page.getByRole('button', { name: 'Create API Key' }).first().click()
      const form = page.locator('form')
      await form.getByLabel('Name').fill(name)
      await form.getByRole('button', { name: 'Read Only' }).click()

      const created = page.waitForResponse(
        r => r.url().endsWith('/api/v1/identity/api-keys') && r.request().method() === 'POST'
      )
      await form.getByRole('button', { name: 'Create API Key' }).click()
      expect((await created).status()).toBe(200)

      const card = page.getByTestId('api-key-card').filter({ hasText: name })
      await expect(card).toBeVisible()
      const stored = (await listKeys()).find(key => key.name === name)
      expect(stored?.scopes).toEqual(['read', 'tools:read', 'data:read', 'reports:read'])

      await page.reload()
      await expect(card).toBeVisible({ timeout: 20_000 })

      page.once('dialog', dialog => dialog.accept())
      await card.getByTestId('delete-api-key').click()
      await expect(card).toHaveCount(0)
      expect((await listKeys()).map(key => key.name)).not.toContain(name)
      await api.dispose()
    })
  })

  test.describe('team', () => {
    test.use({ storageState: MEMBER_STATE })

    test('lists the members identity returns for the team', async ({ page }) => {
      const { member } = readSeed()
      const api = await gatewayApi()
      const token = await apiLogin(api, member)

      const activity = await api.get('/api/v1/identity/admin/me/activity', {
        headers: bearer(token),
      })
      expect(activity.status(), await activity.text()).toBe(200)
      const [team] = (await activity.json()).team_memberships as Array<{
        team_id: string
        team_name: string
      }>
      const membersResponse = await api.get(
        `/api/v1/identity/admin/teams/${team.team_id}/members`,
        { headers: bearer(token) }
      )
      expect(membersResponse.status(), await membersResponse.text()).toBe(200)
      const members = (await membersResponse.json()) as Array<{
        role: string
        user: { email: string }
      }>
      expect(members.map(m => [m.user.email, m.role])).toEqual([[member.email, 'owner']])

      await page.goto('/settings/team')

      await expect(page.getByTestId('team-name')).toHaveText(team.team_name, { timeout: 20_000 })
      await expect(page.getByTestId('team-member-count')).toHaveText(String(members.length))
      const rows = page.getByTestId('team-member')
      await expect(rows).toHaveCount(members.length)
      await expect(rows.first()).toContainText(`${member.email} (You)`)
      await expect(rows.first()).toContainText('Owner')
      await api.dispose()
    })
  })

  test.describe('profile changes', () => {
    // Each test changes its own throwaway account, so a failure leaves the
    // shared accounts and the admin's lockout counter untouched.
    let api: APIRequestContext
    let adminToken: string
    const created: string[] = []

    test.beforeAll(async () => {
      api = await gatewayApi()
      adminToken = await apiLogin(api, adminAccount())
    })

    test.afterEach(async () => {
      while (created.length) await deleteUser(api, adminToken, created.pop()!)
    })

    test.afterAll(async () => {
      await api.dispose()
    })

    async function openProfile(page: Page, context: BrowserContext, label: string) {
      const account = await throwawayAccount(api, label)
      created.push(account.email)
      await startSession(context, account.token)
      await page.goto('/settings/profile')
      await expect(page.getByLabel('Email Address')).toHaveValue(account.email, {
        timeout: 20_000,
      })
      return account
    }

    async function fillPasswordForm(page: Page, current: string, next: string) {
      await page.getByRole('button', { name: 'Change Password' }).click()
      await page.getByLabel('Current Password').fill(current)
      await page.getByLabel('New Password', { exact: true }).fill(next)
      await page.getByLabel('Confirm New Password').fill(next)
      await page.locator('form').getByRole('button', { name: 'Change Password' }).click()
    }

    test('saves a new email address with the current password', async ({ page, context }) => {
      const account = await openProfile(page, context, 'profile-email')
      const newEmail = uniqueEmail('profile-renamed')
      created.push(newEmail)

      // The password field appears once the address differs (#569).
      await expect(page.getByLabel('Confirm with your password')).toHaveCount(0)
      await page.getByLabel('Email Address').fill(newEmail)
      await page.getByLabel('Confirm with your password').fill(account.password)
      await page.getByRole('button', { name: 'Save Changes' }).click()

      await expect(toast(page, 'Profile updated successfully')).toBeVisible()
      await expect(page.getByRole('heading', { name: newEmail, level: 2 })).toBeVisible()
      const me = await api.get('/auth/users/me', { headers: bearer(account.token) })
      expect(me.status(), await me.text()).toBe(200)
      expect((await me.json()).email).toBe(newEmail)

      await page.reload()
      await expect(page.getByLabel('Email Address')).toHaveValue(newEmail, { timeout: 20_000 })
    })

    test('refuses an email change with a wrong password', async ({ page, context }) => {
      const account = await openProfile(page, context, 'profile-email-wrong')
      const newEmail = uniqueEmail('profile-not-renamed')

      await page.getByLabel('Email Address').fill(newEmail)
      await page.getByLabel('Confirm with your password').fill(`not-${account.password}`)
      await page.getByRole('button', { name: 'Save Changes' }).click()

      await expect(toast(page, 'Incorrect current password')).toBeVisible()
      const me = await api.get('/auth/users/me', { headers: bearer(account.token) })
      expect(me.status(), await me.text()).toBe(200)
      expect((await me.json()).email).toBe(account.email)
    })

    test('changes the password with the current one', async ({ page, context }) => {
      const account = await openProfile(page, context, 'profile-password')
      const newPassword = strongPassword()
      // A second session of the same account, open at the gateway.
      const protectedRoute = '/api/v1/data/health'
      const otherSession = await apiLogin(api, account)
      expect((await api.get(protectedRoute, { headers: bearer(otherSession) })).status()).toBe(200)

      await fillPasswordForm(page, account.password, newPassword)

      await expect(toast(page, 'Password changed successfully')).toBeVisible()
      expect(await loginStatus(api, { email: account.email, password: newPassword })).toBe(200)
      expect(await loginStatus(api, account)).toBe(400)

      // The change ends every earlier session (#569): the other one, and the
      // token this page was opened with. No retry: a session that survives
      // is the defect, not a flake.
      for (const token of [otherSession, account.token]) {
        expect((await api.get(protectedRoute, { headers: bearer(token) })).status()).toBe(401)
      }
      // The page carries on with the new token identity handed over.
      const current = await sessionToken(context)
      expect(current).toBeTruthy()
      expect(current).not.toBe(account.token)
      expect((await api.get(protectedRoute, { headers: bearer(current!) })).status()).toBe(200)
      await page.reload()
      await expect(page.getByLabel('Email Address')).toHaveValue(account.email, {
        timeout: 20_000,
      })
    })

    test('refuses a password change with a wrong current password', async ({ page, context }) => {
      const account = await openProfile(page, context, 'profile-wrong')
      const newPassword = strongPassword()

      await fillPasswordForm(page, `not-${account.password}`, newPassword)

      await expect(toast(page, 'Incorrect current password')).toBeVisible()
      expect(await loginStatus(api, { email: account.email, password: newPassword })).toBe(400)
      expect(await loginStatus(api, account)).toBe(200)
    })
  })

  test.describe('without a session', () => {
    for (const path of ['/settings', '/settings/profile', '/settings/api-keys']) {
      test(`${path} sends the visitor to sign in`, async ({ page }) => {
        await page.goto(path)
        await expect(page).toHaveURL(`/?redirect=${encodeURIComponent(path)}`)
      })
    }
  })
})
