import { Page, expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/** The answer to the request the page makes of a guardian list with `page_size`. */
function guardianPage(page: Page, pathname: string, pageSize: string, status?: string) {
  return page.waitForResponse(response => {
    const url = new URL(response.url())
    return (
      url.pathname === pathname &&
      url.searchParams.get('page_size') === pageSize &&
      url.searchParams.get('status') === (status ?? null)
    )
  })
}

/**
 * The dashboard home against the live services (#559).
 *
 * It used to show sample values whenever a service had nothing to say -- 87%
 * compliance, 5 critical findings, 4/4 feeds, an IOC 192.168.1.100 -- so an
 * empty stack looked populated. Its cards now read the services' answers.
 */
test.describe('Dashboard home', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('shows the threat-intel feed counts the data service reports', async ({ page }) => {
    const api = await gatewayApi()
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/data/dashboard/threat-intel', {
      headers: bearer(token),
    })
    expect(response.status(), await response.text()).toBe(200)
    const summary = (await response.json()) as { active_feeds: number; total_feeds: number }
    await api.dispose()

    await page.goto('/dashboard')

    await expect(page.getByTestId('metric-threat-feeds-value')).toHaveText(
      `${summary.active_feeds}/${summary.total_feeds}`,
      { timeout: 20_000 }
    )
  })

  test('shows the compliance state the CSPM service reports', async ({ page }) => {
    const api = await gatewayApi()
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/cspm/dashboard/summary', { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    const summary = (await response.json()) as {
      total_scans: number
      total_findings: number
      compliance_score: number | null
    }
    await api.dispose()

    await page.goto('/dashboard')

    // An account with no completed scan has no score; the card used to read 87%.
    const expected =
      summary.compliance_score !== null
        ? `${Math.round(summary.compliance_score)}%`
        : summary.total_scans > 0
          ? 'Not assessed'
          : 'No scans'
    await expect(page.getByTestId('metric-cloud-compliance-value')).toHaveText(expected, {
      timeout: 20_000,
    })
    await expect(page.getByTestId('metric-failed-checks-value')).toHaveText(
      String(summary.total_findings)
    )
  })

  // The page asks guardian for one asset to read a count, and for the three
  // newest vulnerabilities. guardian ignored page_size and sent fifty rows
  // each time (#724).
  test('gets from guardian the page sizes it asks for', async ({ page }) => {
    const api = await gatewayApi()
    const token = await apiLogin(api, adminAccount())
    const nonce = randomBytes(4).toString('hex')
    const assetIds: string[] = []
    try {
      for (const label of ['a', 'b']) {
        const asset = await api.post('/api/v1/guardian/assets/assets/', {
          headers: bearer(token),
          data: { name: `e2e-home-${nonce}-${label}`, asset_type: 'server', status: 'active' },
        })
        expect(asset.status(), await asset.text()).toBe(201)
        assetIds.push((await asset.json()).id as string)
      }
      // A CVE each: guardian keeps one finding per asset, CVE and port.
      for (const cve of ['CVE-2014-0160', 'CVE-2017-0144', 'CVE-2021-44228', 'CVE-2024-3094']) {
        const created = await api.post('/api/v1/guardian/vulnerabilities/', {
          headers: bearer(token),
          data: {
            title: `E2E home ${nonce} ${cve}`,
            description: 'Recorded by the E2E suite.',
            asset: assetIds[0],
            cve_id: cve,
          },
        })
        expect(created.status(), await created.text()).toBe(201)
      }

      const assets = guardianPage(page, '/api/v1/guardian/assets/assets/', '1')
      const active = guardianPage(page, '/api/v1/guardian/assets/assets/', '1', 'active')
      const newest = guardianPage(page, '/api/v1/guardian/vulnerabilities/', '3')
      await page.goto('/dashboard')

      const allAssets = await (await assets).json()
      expect(allAssets.results).toHaveLength(1)
      expect(allAssets.count).toBeGreaterThanOrEqual(2)
      const activeAssets = await (await active).json()
      expect(activeAssets.results).toHaveLength(1)
      expect(activeAssets.count).toBeGreaterThanOrEqual(2)
      await expect(page.getByTestId('metric-assets-value')).toHaveText(
        `${activeAssets.count}/${allAssets.count}`,
        { timeout: 20_000 }
      )

      // Three of at least four, newest first. Not compared by title: with
      // local workers another spec may record a finding in between.
      const recent = await (await newest).json()
      expect(recent.count).toBeGreaterThanOrEqual(4)
      expect(recent.results).toHaveLength(3)
      const created = recent.results.map((row: { created_at: string }) =>
        Date.parse(row.created_at)
      )
      expect(created).toEqual([...created].sort((a, b) => b - a))
    } finally {
      // The vulnerabilities go with their asset (on_delete=CASCADE).
      for (const id of assetIds) {
        await api.delete(`/api/v1/guardian/assets/assets/${id}/`, { headers: bearer(token) })
      }
      await api.dispose()
    }
  })
})
