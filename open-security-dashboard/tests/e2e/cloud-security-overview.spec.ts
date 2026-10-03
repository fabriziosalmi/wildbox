import { expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * /cloud-security (the CSPM overview) against the live CSPM service (#578).
 *
 * A failed request rendered as "0 scans, 0% compliance, 0 critical findings,
 * 0 cloud accounts"; the page read fields the service never returned
 * (total_accounts, last_scan_time, a risk level and a trend), so it showed
 * "Unknown", "Never" and a 'stable' trend it supplied itself; and the
 * service read a Redis key nothing writes, so its figures were 0 anyway.
 */

/** Text that only the old page produced: no source in the service has it. */
const INVENTED_TEXT = [
  'Security Posture',
  'Risk Level',
  'Trend',
  'stable',
  'Under management',
  'Never',
  ' active',
]

interface DashboardSummary {
  total_scans: number
  last_scan_at: string | null
  summary_period_days: number
  accounts_assessed: number
  compliance_score: number | null
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings: number
  unknown_severity_findings: number
}

const SEVERITY_FIELDS = [
  'critical_findings',
  'high_findings',
  'medium_findings',
  'low_findings',
  'info_findings',
] as const

async function dashboardSummary(): Promise<DashboardSummary> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/cspm/dashboard/summary', { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    const summary = (await response.json()) as DashboardSummary & Record<string, unknown>
    // The scan status counts are gone: the stored status never left "started".
    for (const gone of ['active_scans', 'completed_scans', 'failed_scans']) {
      expect(summary, `${gone} has no source and must not be reported`).not.toHaveProperty(gone)
    }
    if (summary.accounts_assessed === 0) {
      expect(summary.compliance_score, 'nothing assessed is not 0%').toBeNull()
    }
    return summary
  } finally {
    await api.dispose()
  }
}

test.describe('Cloud security overview', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('shows the figures the CSPM service reports and nothing invented', async ({ page }) => {
    const summary = await dashboardSummary()

    await page.goto('/cloud-security')

    await expect(page.getByTestId('cloud-overview-summary')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('cloud-overview-error')).toHaveCount(0)

    await expect(page.getByTestId('cloud-total-scans')).toHaveText(String(summary.total_scans))
    await expect(page.getByTestId('cloud-compliance-score')).toHaveText(
      summary.compliance_score === null ? 'Not assessed' : `${summary.compliance_score}%`
    )
    await expect(page.getByTestId('cloud-critical-findings')).toHaveText(
      String(summary.critical_findings)
    )
    await expect(page.getByTestId('cloud-accounts-assessed')).toHaveText(
      String(summary.accounts_assessed)
    )
    for (const field of SEVERITY_FIELDS) {
      await expect(page.getByTestId(`cloud-severity-${field}`)).toHaveText(String(summary[field]))
    }
    await expect(page.getByTestId('cloud-severity-unknown_severity_findings')).toHaveCount(
      summary.unknown_severity_findings > 0 ? 1 : 0
    )
    await expect(page.getByTestId('cloud-no-scans')).toHaveCount(summary.total_scans === 0 ? 1 : 0)

    const lastScan = page.getByTestId('cloud-last-scan')
    if (summary.last_scan_at === null) {
      await expect(lastScan).toHaveText('No scan yet')
    } else {
      // cspm sends naive UTC; the page must not read it as local time.
      const iso = new Date(`${summary.last_scan_at.replace(/Z$/, '')}Z`).toISOString()
      await expect(lastScan.locator('time')).toHaveAttribute('datetime', iso)
    }

    const main = page.locator('main')
    for (const invented of INVENTED_TEXT) {
      await expect(main).not.toContainText(invented)
    }
    // The old risk level badge read "Unknown"; the word may appear only on
    // the row of failed checks whose check left the catalog.
    if (summary.unknown_severity_findings === 0) {
      await expect(main).not.toContainText('Unknown')
    }
  })

  test('a failing CSPM service is an error with a retry, not zeros', async ({ page }) => {
    const message = `injected outage ${randomBytes(4).toString('hex')}`
    await page.route('**/api/v1/cspm/dashboard/summary**', route =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { message, type: 'service_unavailable' } }),
      })
    )

    await page.goto('/cloud-security')

    const error = page.getByTestId('cloud-overview-error')
    await expect(error).toContainText('Cloud security data could not be loaded', {
      timeout: 30_000,
    })
    await expect(error).toContainText(message)
    // No figure stands in for the missing answer: not 0, not "No scans yet".
    await expect(page.getByTestId('cloud-overview-summary')).toHaveCount(0)
    await expect(page.getByTestId('cloud-no-scans')).toHaveCount(0)
    await expect(page.getByTestId('cloud-findings-by-severity')).toHaveCount(0)
    await expect(page.getByTestId('cloud-last-scan')).toHaveCount(0)
    const main = page.locator('main')
    await expect(main).not.toContainText('0%')
    for (const invented of INVENTED_TEXT) {
      await expect(main).not.toContainText(invented)
    }

    // The retry asks the service again and, with the outage over, loads.
    await page.unroute('**/api/v1/cspm/dashboard/summary**')
    await error.getByRole('button', { name: 'Try again' }).click()
    await expect(page.getByTestId('cloud-overview-summary')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('cloud-overview-error')).toHaveCount(0)
  })
})
