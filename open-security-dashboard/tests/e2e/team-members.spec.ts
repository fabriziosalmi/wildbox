import { APIRequestContext, expect, test } from '@playwright/test'
import {
  adminAccount,
  apiLogin,
  bearer,
  deleteUser,
  gatewayApi,
  sessionToken,
  startSession,
  strongPassword,
  throwawayAccount,
  uniqueEmail,
} from './support/backend'

/**
 * A team owner creates an account in the team from the Team page, and that
 * account changes its initial password before anything else (#573).
 *
 * Every test works on throwaway accounts: an owner registered for it, and
 * the members it creates. They are deleted afterwards, members first, so
 * the owner's team goes with its owner.
 */
test.describe('Team members', { tag: '@backend' }, () => {
  let api: APIRequestContext
  let adminToken: string
  // Deleted in reverse order of creation: members before their owner.
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

  async function ownerWithTeam(label: string) {
    const owner = await throwawayAccount(api, label)
    created.push(owner.email)
    const activity = await api.get('/api/v1/identity/admin/me/activity', {
      headers: bearer(owner.token),
    })
    expect(activity.status(), await activity.text()).toBe(200)
    const [team] = (await activity.json()).team_memberships as Array<{ team_id: string }>
    return { ...owner, teamId: team.team_id }
  }

  async function teamMembers(token: string, teamId: string) {
    const response = await api.get(`/api/v1/identity/admin/teams/${teamId}/members`, {
      headers: bearer(token),
    })
    expect(response.status(), await response.text()).toBe(200)
    const rows = (await response.json()) as Array<{ role: string; user: { email: string } }>
    return Object.fromEntries(rows.map(row => [row.user.email, row.role]))
  }

  test('the owner adds a member from the Team page', async ({ page, context }) => {
    const owner = await ownerWithTeam('team-owner')
    const member = { email: uniqueEmail('team-new'), password: strongPassword() }
    created.push(member.email)

    await startSession(context, owner.token)
    await page.goto('/settings/team')
    await expect(page.getByTestId('team-member-count')).toHaveText('1', { timeout: 20_000 })

    await page.getByRole('button', { name: 'Add member' }).click()
    const form = page.getByRole('form', { name: 'Add member' })
    await form.getByLabel('Email').fill(member.email)
    await form.getByLabel('Initial password').fill(member.password)
    // An owner may create admins and members, never another owner.
    const role = form.getByLabel('Role')
    await expect(role.locator('option')).toHaveText(['Member', 'Admin'])
    await role.selectOption('member')

    const response = page.waitForResponse(
      r => r.url().endsWith(`/teams/${owner.teamId}/members`) && r.request().method() === 'POST'
    )
    await form.getByRole('button', { name: 'Add member' }).click()
    expect((await response).status()).toBe(201)

    // The list is the one identity returns after the change.
    await expect(page.getByTestId('team-member-count')).toHaveText('2')
    const row = page.getByTestId('team-member').filter({ hasText: member.email })
    await expect(row).toContainText('Member')
    expect(await teamMembers(owner.token, owner.teamId)).toEqual({
      [owner.email]: 'owner',
      [member.email]: 'member',
    })

    // The same email again: identity refuses it, and the page says so.
    await page.getByRole('button', { name: 'Add member' }).click()
    await form.getByLabel('Email').fill(member.email)
    await form.getByLabel('Initial password').fill(strongPassword())
    await form.getByRole('button', { name: 'Add member' }).click()
    await expect(page.getByTestId('add-member-error')).toHaveText(
      'This email address cannot be used for a new account'
    )
    await expect(page.getByTestId('team-member-count')).toHaveText('2')
  })

  test('a new member must change the initial password first', async ({ page, context }) => {
    const owner = await ownerWithTeam('team-owner-pw')
    const member = { email: uniqueEmail('team-first'), password: strongPassword() }
    created.push(member.email)
    const create = await api.post(`/api/v1/identity/admin/teams/${owner.teamId}/members`, {
      headers: bearer(owner.token),
      data: { email: member.email, password: member.password, role: 'member' },
    })
    expect(create.status(), await create.text()).toBe(201)

    await page.goto('/auth/login')
    await page.getByLabel('Email address').fill(member.email)
    await page.getByLabel('Password', { exact: true }).fill(member.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/auth\/change-password$/, { timeout: 30_000 })
    await expect(page.getByTestId('change-password-account')).toHaveText(member.email)

    // Every other page leads back here, and the services refuse the session.
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/auth\/change-password$/, { timeout: 20_000 })
    const first = await sessionToken(context)
    expect(first).toBeTruthy()
    const refused = await api.get('/api/v1/data/health', { headers: bearer(first!) })
    expect(refused.status()).toBe(403)
    expect((await refused.json()).error).toBe('PASSWORD_CHANGE_REQUIRED')

    const newPassword = strongPassword()
    await page.getByLabel('Initial password').fill(member.password)
    await page.getByLabel('New password', { exact: true }).fill(newPassword)
    await page.getByLabel('Confirm new password').fill(newPassword)
    await page.getByRole('button', { name: 'Set password' }).click()
    await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 })

    // The page carries on with the token identity handed over, which works
    // in the owner's team: the account's only one.
    const current = await sessionToken(context)
    expect(current).toBeTruthy()
    expect(current).not.toBe(first)
    const allowed = await api.get('/api/v1/data/health', { headers: bearer(current!) })
    expect(allowed.status(), await allowed.text()).toBe(200)
    const activity = await api.get('/api/v1/identity/admin/me/activity', {
      headers: bearer(current!),
    })
    expect(activity.status(), await activity.text()).toBe(200)
    const memberships = (await activity.json()).team_memberships as Array<{
      team_id: string
      role: string
    }>
    expect(memberships.map(m => [m.team_id, m.role])).toEqual([[owner.teamId, 'member']])

    // And the Team page shows the owner's team, where the member cannot add anyone.
    await page.goto('/settings/team')
    await expect(page.getByTestId('team-member-count')).toHaveText('2', { timeout: 20_000 })
    await expect(page.getByRole('button', { name: 'Add member' })).toHaveCount(0)
  })
})
