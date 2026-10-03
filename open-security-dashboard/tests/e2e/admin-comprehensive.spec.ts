import { APIRequestContext, Page, expect, test } from '@playwright/test'
import {
  ADMIN_STATE,
  MEMBER_STATE,
  adminAccount,
  apiLogin,
  bearer,
  countUsers,
  deleteUser,
  findUser,
  gatewayApi,
  readSeed,
  registerUser,
  strongPassword,
  toast,
  uniqueEmail,
} from './support/backend'

/**
 * The System Administration page against the live identity service (#103).
 *
 * Every user these tests act on is created for the test and removed after it;
 * the stack admin is only ever the one doing the acting. Each UI action is
 * checked twice: on the page, and through the admin API, so a page that
 * updates its own state without the server agreeing does not pass.
 */
test.describe('Administration', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

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

  async function seedUser(label = 'managed'): Promise<string> {
    const email = uniqueEmail(label)
    await registerUser(api, { email, password: strongPassword() })
    created.push(email)
    return email
  }

  /** Emails in the user table, in the order the page shows them. */
  async function tableEmails(page: Page): Promise<string[]> {
    return page
      .locator('tbody tr')
      .evaluateAll(rows => rows.map(row => row.querySelector('td p')?.textContent?.trim() ?? ''))
  }

  /** The admin list request carrying `param=value`, as the page sends it. */
  function usersRequest(page: Page, param: string, value: string) {
    return page.waitForResponse(response => {
      const url = new URL(response.url())
      return (
        url.pathname === '/api/v1/identity/admin/users' && url.searchParams.get(param) === value
      )
    })
  }

  async function openAdmin(page: Page) {
    await page.goto('/admin')
    await expect(page.getByRole('heading', { name: 'System Administration' })).toBeVisible({
      timeout: 20_000,
    })
  }

  const rowFor = (page: Page, email: string) =>
    page.getByRole('row').filter({ has: page.getByText(email, { exact: true }) })

  test('opens from the sidebar and shows the live user count', async ({ page }) => {
    await page.goto('/dashboard')
    await page.getByRole('link', { name: /Administration/ }).click()

    await expect(page).toHaveURL(/\/admin$/)
    await expect(page.getByRole('heading', { name: 'System Administration' })).toBeVisible()
    const expected = await countUsers(api, adminToken)
    await expect(page.getByTestId('total-users-value')).toHaveText(String(expected))
  })

  test('stays on the admin page when it is loaded directly', async ({ page }) => {
    await openAdmin(page)
    await page.reload()
    await expect(page).toHaveURL(/\/admin$/)
    await expect(page.getByRole('heading', { name: 'System Administration' })).toBeVisible()
  })

  test('creates a user from the form', async ({ page }) => {
    const email = uniqueEmail('created')
    created.push(email)
    await openAdmin(page)

    await page.getByRole('button', { name: 'Create User', exact: true }).click()
    await page.getByLabel('Email Address *').fill(email)
    await page.getByLabel('Password *').fill(strongPassword())
    await page.getByRole('button', { name: 'Create User', exact: true }).click()

    await expect(toast(page, `User ${email} created successfully`)).toBeVisible()
    const row = rowFor(page, email)
    await expect(row).toBeVisible()
    await expect(row.getByText('Active', { exact: true })).toBeVisible()

    const stored = await findUser(api, adminToken, email)
    expect(stored).toMatchObject({ email, is_active: true, is_superuser: false })
  })

  test('deactivates and reactivates a user', async ({ page }) => {
    const email = await seedUser()
    await openAdmin(page)
    const row = rowFor(page, email)

    await row.getByRole('button', { name: 'Deactivate' }).click()
    await expect(row.getByText('Inactive', { exact: true })).toBeVisible()
    expect((await findUser(api, adminToken, email))?.is_active).toBe(false)

    await row.getByRole('button', { name: 'Activate' }).click()
    await expect(row.getByText('Active', { exact: true })).toBeVisible()
    expect((await findUser(api, adminToken, email))?.is_active).toBe(true)
  })

  test('promotes a user to super admin and demotes them again', async ({ page }) => {
    const email = await seedUser()
    const confirmations: string[] = []
    page.on('dialog', async dialog => {
      confirmations.push(dialog.message())
      await dialog.accept()
    })
    await openAdmin(page)
    const row = rowFor(page, email)

    await row.getByRole('button', { name: 'Promote' }).click()
    await expect(row.getByText('Super Admin')).toBeVisible()
    expect((await findUser(api, adminToken, email))?.is_superuser).toBe(true)

    await row.getByRole('button', { name: 'Demote' }).click()
    await expect(row.getByText('Super Admin')).toHaveCount(0)
    expect((await findUser(api, adminToken, email))?.is_superuser).toBe(false)

    expect(confirmations).toHaveLength(2)
    expect(confirmations[0]).toContain(`promote ${email} to superuser`)
  })

  test('search narrows the list to the users identity matches', async ({ page }) => {
    const wanted = await seedUser('search-hit')
    const other = await seedUser('search-miss')
    await openAdmin(page)
    await expect(rowFor(page, other)).toBeVisible()

    const searched = usersRequest(page, 'email_filter', wanted)
    await page.getByLabel('Search users by email').fill(wanted)
    const response = await searched
    expect(response.status()).toBe(200)

    await expect(rowFor(page, wanted)).toBeVisible()
    await expect(rowFor(page, other)).toHaveCount(0)
    const served = ((await response.json()) as Array<{ email: string }>).map(u => u.email)
    expect(served).toEqual([wanted])
    expect(await tableEmails(page)).toEqual(served)

    // Clearing the search brings the full list back.
    await page.getByLabel('Search users by email').fill('')
    await expect(rowFor(page, other)).toBeVisible()
  })

  test('the status filter shows only the users identity reports in that state', async ({
    page,
  }) => {
    const inactive = await seedUser('filter-inactive')
    const active = await seedUser('filter-active')
    const stored = await findUser(api, adminToken, inactive)
    const deactivated = await api.patch(`/api/v1/identity/admin/users/${stored!.id}/status`, {
      headers: bearer(adminToken),
      params: { is_active: 'false' },
    })
    expect(deactivated.status(), await deactivated.text()).toBe(200)
    await openAdmin(page)
    await expect(rowFor(page, active)).toBeVisible()

    const filtered = usersRequest(page, 'is_active', 'false')
    await page.getByLabel('Filter users by status').selectOption('inactive')
    const response = await filtered
    expect(response.status()).toBe(200)

    await expect(rowFor(page, inactive)).toBeVisible()
    await expect(rowFor(page, active)).toHaveCount(0)
    const served = (await response.json()) as Array<{ email: string; is_active: boolean }>
    expect(served.every(u => !u.is_active)).toBe(true)
    expect(served.map(u => u.email)).toContain(inactive)
    expect(await tableEmails(page)).toEqual(served.map(u => u.email))
  })

  test('system health shows identity, the gateway and their dependencies', async ({ page }) => {
    const response = await api.get('/api/v1/identity/health', { headers: bearer(adminToken) })
    expect(response.status(), await response.text()).toBe(200)
    const health = await response.json()
    expect(health.checks.database.status).toBe('healthy')
    expect(health.checks.redis.status).toBe('healthy')

    await openAdmin(page)

    await expect(page.getByTestId('health-identity')).toHaveText('● Online')
    await expect(page.getByTestId('health-gateway')).toHaveText('● Online')
    await expect(page.getByTestId('health-database')).toHaveText('● Healthy')
    await expect(page.getByTestId('health-redis')).toHaveText('● Healthy')
  })

  test('deletes a user once the deletion is confirmed', async ({ page }) => {
    const email = await seedUser()
    const confirmations: string[] = []
    page.on('dialog', async dialog => {
      confirmations.push(dialog.message())
      await dialog.accept()
    })
    await openAdmin(page)
    const row = rowFor(page, email)

    await row.getByTestId('delete-user').click()

    await expect(row).toHaveCount(0)
    expect(await findUser(api, adminToken, email)).toBeUndefined()
    // A registered user owns their own team, so the page asks twice: once to
    // escalate to a force delete, once to confirm it.
    expect(confirmations.length).toBeGreaterThanOrEqual(1)
    expect(confirmations[confirmations.length - 1]).toContain(email)
  })
})

test.describe('Administration access control', { tag: '@backend' }, () => {
  test.use({ storageState: MEMBER_STATE })

  test('a regular member gets neither the menu entry nor the page', async ({ page }) => {
    await page.goto('/dashboard')
    await expect(page.getByRole('link', { name: /Dashboard/ }).first()).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByRole('link', { name: /Administration/ })).toHaveCount(0)

    await page.goto('/admin')
    await expect(page).toHaveURL(/\/dashboard$/)
    await expect(page.getByRole('heading', { name: 'System Administration' })).toHaveCount(0)
  })

  test('the admin API refuses a member token', async () => {
    const api = await gatewayApi()
    const member = readSeed().member
    const token = await apiLogin(api, member)
    const response = await api.get('/api/v1/identity/admin/users', { headers: bearer(token) })
    expect(response.status()).toBe(403)
    await api.dispose()
  })
})
