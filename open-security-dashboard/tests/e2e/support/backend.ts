/**
 * Shared plumbing for the backend-dependent specs (#103).
 *
 * Everything here talks to the real stack through the gateway, the same way
 * the browser does: no direct database access, no service ports. The one
 * exception is the threat-intel seed (fixtures/threat-intel-seed.sql), because
 * the data service has no API that creates indicators -- see that file.
 */
import { APIRequestContext, BrowserContext, Page, expect, request } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export const GATEWAY_URL = process.env.PLAYWRIGHT_BASE_URL || 'https://localhost'

const AUTH_DIR = path.join(__dirname, '..', '.auth')
export const ADMIN_STATE = path.join(AUTH_DIR, 'admin.json')
export const MEMBER_STATE = path.join(AUTH_DIR, 'member.json')
const SEED_FILE = path.join(AUTH_DIR, 'seed.json')

/* Indicators inserted by fixtures/threat-intel-seed.sql. Documentation and
   TEST-NET addresses only, so nothing here can collide with a real feed. */
export const SEEDED_INDICATORS = {
  ip: '203.0.113.66',
  domain: 'c2-panel.e2e-wildbox.io',
  // sha256("wildbox-e2e-seed")
  hash: 'ab0055ed8ed61a8dae075a1e5e5cdb58e3bf19f79ef3706d45f74de459ec85cd',
} as const
export const UNSEEDED_IP = '198.51.100.23'

export interface Account {
  email: string
  password: string
}

export interface SeedData {
  member: Account & { id: string }
}

export function adminAccount(): Account {
  const email = process.env.TEST_EMAIL
  const password = process.env.TEST_PASSWORD
  if (!email || !password) {
    throw new Error(
      'TEST_EMAIL and TEST_PASSWORD must hold the stack admin (INITIAL_ADMIN_EMAIL / ' +
        'INITIAL_ADMIN_PASSWORD from .env). The backend specs never guess them: a wrong ' +
        'guess counts towards the admin lockout.'
    )
  }
  return { email, password }
}

/** A fresh, unique address on every call, so no test ever reuses an account. */
export function uniqueEmail(label: string): string {
  const nonce = `${Date.now().toString(36)}${randomBytes(4).toString('hex')}`
  return `e2e-${label}-${nonce}@wildbox.io`
}

export function strongPassword(): string {
  // From the CSPRNG: these accounts live on a real stack, however briefly.
  return `E2e-${randomBytes(8).toString('hex')}-Pw9!`
}

export async function gatewayApi(): Promise<APIRequestContext> {
  return request.newContext({ baseURL: GATEWAY_URL, ignoreHTTPSErrors: true })
}

export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` }
}

/* The gateway limits the auth routes to 5 requests/s per address (burst 3).
   Setup and the API helpers below are the only callers that might trip it;
   retrying a 429 here keeps them deterministic. UI logins are never retried. */
async function withAuthRateLimit<T extends { status(): number }>(
  call: () => Promise<T>
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const response = await call()
    if (response.status() !== 429 || attempt === 5) return response
    await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)))
  }
}

export async function apiLogin(api: APIRequestContext, account: Account): Promise<string> {
  const response = await withAuthRateLimit(() =>
    api.post('/auth/jwt/login', {
      form: { username: account.email, password: account.password },
    })
  )
  expect(response.status(), `login of ${account.email}: ${await response.text()}`).toBe(200)
  const body = await response.json()
  return body.access_token as string
}

/** Registers a user through the public registration route (it gets a team of its own). */
export async function registerUser(
  api: APIRequestContext,
  account: Account
): Promise<{ id: string; email: string }> {
  const response = await withAuthRateLimit(() =>
    api.post('/auth/register', { data: { email: account.email, password: account.password } })
  )
  expect(response.status(), `register ${account.email}: ${await response.text()}`).toBe(201)
  return response.json()
}

export interface AdminUserRow {
  id: string
  email: string
  is_active: boolean
  is_superuser: boolean
}

export async function findUser(
  api: APIRequestContext,
  adminToken: string,
  email: string
): Promise<AdminUserRow | undefined> {
  const response = await api.get('/api/v1/identity/admin/users', {
    headers: bearer(adminToken),
    params: { email_filter: email, limit: 10 },
  })
  expect(response.status(), await response.text()).toBe(200)
  const rows = (await response.json()) as AdminUserRow[]
  return rows.find(row => row.email === email)
}

export async function countUsers(api: APIRequestContext, adminToken: string): Promise<number> {
  const response = await api.get('/api/v1/identity/admin/users', {
    headers: bearer(adminToken),
    params: { limit: 1000 },
  })
  expect(response.status(), await response.text()).toBe(200)
  return ((await response.json()) as unknown[]).length
}

/** Best-effort cleanup; a user that is already gone is not an error. */
export async function deleteUser(api: APIRequestContext, adminToken: string, email: string) {
  const user = await findUser(api, adminToken, email)
  if (!user) return
  const response = await api.delete(`/api/v1/identity/admin/users/${user.id}`, {
    headers: bearer(adminToken),
    params: { force: 'true' },
  })
  expect([200, 204, 404], await response.text()).toContain(response.status())
}

/** Storage state holding the dashboard's auth cookie, as js-cookie writes it. */
export function storageStateFor(token: string) {
  return {
    cookies: [
      {
        name: 'auth_token',
        value: token,
        domain: new URL(GATEWAY_URL).hostname,
        path: '/',
        expires: Math.floor(Date.now() / 1000) + 60 * 60,
        httpOnly: false,
        secure: GATEWAY_URL.startsWith('https:'),
        sameSite: 'Strict' as const,
      },
    ],
    origins: [],
  }
}

export function writeAuthFiles(admin: string, member: string, seed: SeedData) {
  fs.mkdirSync(AUTH_DIR, { recursive: true })
  fs.writeFileSync(ADMIN_STATE, JSON.stringify(storageStateFor(admin)))
  fs.writeFileSync(MEMBER_STATE, JSON.stringify(storageStateFor(member)))
  fs.writeFileSync(SEED_FILE, JSON.stringify(seed))
}

export function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(SEED_FILE, 'utf8')) as SeedData
}

/** The token the dashboard currently holds in its cookie, if any. */
export async function sessionToken(context: BrowserContext): Promise<string | undefined> {
  const cookies = await context.cookies()
  return cookies.find(cookie => cookie.name === 'auth_token')?.value
}

/** Signs in through the login form and waits for the dashboard. */
export async function uiLogin(page: Page, account: Account) {
  await page.goto('/auth/login')
  await page.getByLabel('Email address').fill(account.email)
  await page.getByLabel('Password', { exact: true }).fill(account.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 })
}
