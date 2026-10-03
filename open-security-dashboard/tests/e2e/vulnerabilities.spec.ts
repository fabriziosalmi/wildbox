import { APIRequestContext, expect, test } from '@playwright/test'
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

async function removeFixture({ api, token, assetId }: Fixture) {
  // The vulnerability goes with its asset (on_delete=CASCADE).
  await api.delete(`/api/v1/guardian/assets/assets/${assetId}/`, { headers: bearer(token) })
  await api.dispose()
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
