import { expect, test } from '@playwright/test'
import {
  ADMIN_STATE,
  MEMBER_STATE,
  adminAccount,
  apiLogin,
  bearer,
  gatewayApi,
  readSeed,
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

  test.describe('without a session', () => {
    for (const path of ['/settings', '/settings/profile', '/settings/api-keys']) {
      test(`${path} sends the visitor to sign in`, async ({ page }) => {
        await page.goto(path)
        await expect(page).toHaveURL(`/?redirect=${encodeURIComponent(path)}`)
      })
    }
  })
})
