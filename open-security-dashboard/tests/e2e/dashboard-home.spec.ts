import { expect, test } from '@playwright/test'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

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
      compliance_score: number
    }
    await api.dispose()

    await page.goto('/dashboard')

    // An account with no scans has no score; the card used to read 87%.
    const expected =
      summary.total_scans === 0 ? 'No scans' : `${Math.round(summary.compliance_score)}%`
    await expect(page.getByTestId('metric-cloud-compliance-value')).toHaveText(expected, {
      timeout: 20_000,
    })
    await expect(page.getByTestId('metric-failed-checks-value')).toHaveText(
      String(summary.total_findings)
    )
  })
})
