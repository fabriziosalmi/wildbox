import { expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * /cloud-security/compliance against the live CSPM service (#572).
 *
 * The page and the service each carried the same invented account: when the
 * request failed the page filled itself with it "for demo", and when it
 * succeeded the service returned it anyway. Both paths showed 1547
 * resources, 86.7% compliant and CIS / NIST / PCI figures nobody measured.
 */

const INVENTED_VALUES = [
  '1547',
  '1342',
  '86.7',
  'CIS AWS Foundations',
  'NIST Cybersecurity Framework',
  'PCI DSS',
  '123456789012',
  'demo-bucket',
  'demo-trail',
  'from last month',
]

interface ComplianceSummary {
  total_resources: number
  compliant_resources: number
  overall_score: number | null
  frameworks: { name: string }[]
  scans_considered: number
}

async function complianceSummary(): Promise<ComplianceSummary> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/cspm/compliance/summary', { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    const body = await response.text()
    for (const invented of ['1547', '86.7', 'CIS AWS Foundations']) {
      expect(body, 'the service must not answer with the old constants').not.toContain(invented)
    }
    return JSON.parse(body) as ComplianceSummary
  } finally {
    await api.dispose()
  }
}

test.describe('Cloud security compliance', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('shows what the CSPM service reports and nothing invented', async ({ page }) => {
    const summary = await complianceSummary()

    await page.goto('/cloud-security/compliance')

    await expect(page.getByTestId('compliance-summary')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('compliance-error')).toHaveCount(0)
    await expect(page.getByTestId('compliance-overall-score')).toHaveText(
      summary.overall_score === null ? 'Not assessed' : `${summary.overall_score}%`
    )
    await expect(page.getByTestId('compliance-no-scans')).toHaveCount(
      summary.scans_considered === 0 ? 1 : 0
    )
    // Real checks are tagged "CIS AWS Foundations Benchmark v1.4.0 - ...", so
    // a name the service itself reports is not evidence of invention.
    const main = page.locator('main')
    for (const invented of INVENTED_VALUES) {
      if (summary.frameworks.some(framework => framework.name.includes(invented))) continue
      await expect(main).not.toContainText(invented)
    }
  })

  test('a failing CSPM service is an error with a retry, not demo data', async ({ page }) => {
    const message = `injected outage ${randomBytes(4).toString('hex')}`
    await page.route('**/api/v1/cspm/compliance/summary**', route =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { message, type: 'service_unavailable' } }),
      })
    )

    await page.goto('/cloud-security/compliance')

    const error = page.getByTestId('compliance-error')
    await expect(error).toContainText('Compliance data could not be loaded', { timeout: 30_000 })
    await expect(error).toContainText(message)
    await expect(page.getByTestId('compliance-summary')).toHaveCount(0)
    await expect(page.getByTestId('compliance-no-scans')).toHaveCount(0)
    const main = page.locator('main')
    for (const invented of INVENTED_VALUES) {
      await expect(main).not.toContainText(invented)
    }

    // The retry reaches the service again and, with the outage over, loads.
    await page.unroute('**/api/v1/cspm/compliance/summary**')
    await error.getByRole('button', { name: 'Try again' }).click()
    await expect(page.getByTestId('compliance-summary')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('compliance-error')).toHaveCount(0)
  })
})
