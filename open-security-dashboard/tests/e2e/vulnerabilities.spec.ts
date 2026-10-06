import { APIRequestContext, Page, expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * /vulnerabilities against the live guardian service (#572).
 *
 * The page asked guardian for /api/v1/vulnerabilities/vulnerabilities/,
 * which is not the list, and turned the failure -- like any other -- into
 * an empty result. Every visit read "No vulnerabilities found", whatever
 * guardian held and whether or not it was up.
 */

const LIST_PATH = '/api/v1/guardian/vulnerabilities/'
const STATS_PATH = '/api/v1/guardian/vulnerabilities/stats/'

interface Fixture {
  api: APIRequestContext
  token: string
  assetId: string
  title: string
}

/** An asset with one vulnerability on it, created through the gateway. */
async function recordVulnerability(): Promise<Fixture> {
  const api = await gatewayApi()
  const token = await apiLogin(api, adminAccount())
  const nonce = randomBytes(4).toString('hex')
  const asset = await api.post('/api/v1/guardian/assets/assets/', {
    headers: bearer(token),
    data: { name: `e2e-vuln-${nonce}`, asset_type: 'server', hostname: 'e2e-vuln.invalid' },
  })
  expect(asset.status(), await asset.text()).toBe(201)
  const assetId = (await asset.json()).id as string

  const title = `E2E finding ${nonce}`
  const created = await api.post(LIST_PATH, {
    headers: bearer(token),
    data: {
      title,
      description: 'Recorded by the dashboard E2E suite.',
      asset: assetId,
      severity: 'high',
      cvss_v3_score: 7.5,
      cve_id: 'CVE-2024-3094',
    },
  })
  expect(created.status(), await created.text()).toBe(201)
  return { api, token, assetId, title }
}

async function removeFixture({ api, token, assetId }: Pick<Fixture, 'api' | 'token' | 'assetId'>) {
  // The vulnerability goes with its asset (on_delete=CASCADE).
  await api.delete(`/api/v1/guardian/assets/assets/${assetId}/`, { headers: bearer(token) })
  await api.dispose()
}

interface Pair {
  api: APIRequestContext
  token: string
  assetId: string
  nonce: string
  /** Severity high, status open. */
  open: string
  /** Severity low, status resolved. */
  resolved: string
}

/**
 * Two findings on one asset that differ in severity and in status, with a
 * nonce in both titles so a search shows these two and nothing else.
 */
async function recordPair(): Promise<Pair> {
  const api = await gatewayApi()
  const token = await apiLogin(api, adminAccount())
  const nonce = randomBytes(4).toString('hex')
  const asset = await api.post('/api/v1/guardian/assets/assets/', {
    headers: bearer(token),
    data: { name: `e2e-filter-${nonce}`, asset_type: 'server', hostname: 'e2e-filter.invalid' },
  })
  expect(asset.status(), await asset.text()).toBe(201)
  const assetId = (await asset.json()).id as string

  // A CVE each: guardian keeps one finding per asset, CVE and port.
  const record = async (label: string, severity: string, cve: string) => {
    const title = `E2E menu ${nonce} ${label}`
    const created = await api.post(LIST_PATH, {
      headers: bearer(token),
      data: {
        title,
        description: 'Recorded by the dashboard E2E suite.',
        asset: assetId,
        severity,
        cve_id: cve,
      },
    })
    expect(created.status(), await created.text()).toBe(201)
    // The answer to the creation has no id; the list does.
    const listed = await api.get(LIST_PATH, { headers: bearer(token), params: { search: title } })
    expect(listed.status(), await listed.text()).toBe(200)
    const rows = (await listed.json()).results as { id: string; title: string }[]
    expect(rows.map(row => row.title)).toEqual([title])
    return { id: rows[0].id, title }
  }
  const open = await record('still open', 'high', 'CVE-2024-3094')
  const resolved = await record('already fixed', 'low', 'CVE-2021-44228')
  const closed = await api.post(`${LIST_PATH}${resolved.id}/close/`, {
    headers: bearer(token),
    data: { reason: 'Closed by the dashboard E2E suite.' },
  })
  expect(closed.status(), await closed.text()).toBe(200)
  return { api, token, assetId, nonce, open: open.title, resolved: resolved.title }
}

/** Picks an entry of one of the two filter menus. */
async function choose(page: Page, menu: 'severity-filter' | 'status-filter', entry: string) {
  await page.getByTestId(menu).click()
  await page.getByRole('option', { name: entry, exact: true }).click()
}

test.describe('Vulnerabilities', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('lists the vulnerabilities guardian holds', async ({ page }) => {
    const fixture = await recordVulnerability()
    try {
      await page.goto('/vulnerabilities')
      await page.getByPlaceholder('Search vulnerabilities...').fill(fixture.title)
      await page.getByRole('button', { name: 'Search' }).click()

      const row = page.getByTestId('vulnerability-row').filter({ hasText: fixture.title })
      await expect(row).toBeVisible({ timeout: 30_000 })
      await expect(row).toContainText('HIGH')
      await expect(row).toContainText('CVE-2024-3094')
      await expect(page.getByTestId('vulnerabilities-error')).toHaveCount(0)
      await expect(page.getByTestId('vulnerabilities-empty')).toHaveCount(0)
    } finally {
      await removeFixture(fixture)
    }
  })

  // guardian matched no row for any ?severity= or ?status=: with either menu
  // off "All", the page read "No vulnerabilities found" whatever the team
  // held (#724).
  test('the severity and status menus narrow the list', async ({ page }) => {
    const pair = await recordPair()
    try {
      await page.goto('/vulnerabilities')
      await page.getByPlaceholder('Search vulnerabilities...').fill(pair.nonce)
      await page.getByRole('button', { name: 'Search' }).click()

      const rows = page.getByTestId('vulnerability-row')
      const open = rows.filter({ hasText: pair.open })
      const resolved = rows.filter({ hasText: pair.resolved })
      await expect(open).toBeVisible({ timeout: 30_000 })
      await expect(resolved).toBeVisible()

      // What guardian answered the request the menu made, and what the page
      // shows of it.
      const answer = page.waitForResponse(response => {
        const url = new URL(response.url())
        return url.pathname === LIST_PATH && url.searchParams.get('severity') === 'low'
      })
      await choose(page, 'severity-filter', 'Low')
      expect((await (await answer).json()).count).toBe(1)
      await expect(resolved).toBeVisible()
      await expect(open).toHaveCount(0)
      await expect(page.getByTestId('vulnerabilities-empty')).toHaveCount(0)

      await choose(page, 'severity-filter', 'High')
      await expect(open).toBeVisible()
      await expect(resolved).toHaveCount(0)

      await choose(page, 'severity-filter', 'All Severities')
      await expect(rows).toHaveCount(2)

      await choose(page, 'status-filter', 'Resolved')
      await expect(resolved).toBeVisible()
      await expect(open).toHaveCount(0)

      await choose(page, 'status-filter', 'Open')
      await expect(open).toBeVisible()
      await expect(resolved).toHaveCount(0)

      // Both menus at once: nothing is both low and open here.
      await choose(page, 'severity-filter', 'Low')
      await expect(page.getByTestId('vulnerabilities-empty')).toBeVisible()
      await expect(page.getByTestId('vulnerabilities-error')).toHaveCount(0)
    } finally {
      await removeFixture(pair)
    }
  })

  test('a failing guardian is an error with a retry, not an empty list', async ({ page }) => {
    const message = `injected outage ${randomBytes(4).toString('hex')}`
    const outage = {
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: { message, type: 'service_unavailable' } }),
    }
    const isList = (url: URL) => url.pathname === LIST_PATH
    await page.route(isList, route => route.fulfill(outage))
    await page.route(
      (url: URL) => url.pathname === STATS_PATH,
      route => route.fulfill(outage)
    )

    await page.goto('/vulnerabilities')

    const error = page.getByTestId('vulnerabilities-error')
    await expect(error).toContainText('Failed to load vulnerabilities', { timeout: 30_000 })
    await expect(error).toContainText(message)
    await expect(page.getByTestId('vulnerability-stats-error')).toContainText(message)
    await expect(page.getByTestId('vulnerabilities-empty')).toHaveCount(0)
    const main = page.locator('main')
    await expect(main).not.toContainText('No vulnerabilities found')
    await expect(main).not.toContainText('No Vulnerabilities Found')
    await expect(main).toContainText('Unavailable')

    // With the outage over, the retry asks guardian again and gets an answer.
    await page.unroute(isList)
    await error.getByRole('button', { name: 'Try Again' }).click()
    await expect(page.getByTestId('vulnerabilities-error')).toHaveCount(0, { timeout: 30_000 })
    await expect(main).not.toContainText('Unavailable')
  })
})
