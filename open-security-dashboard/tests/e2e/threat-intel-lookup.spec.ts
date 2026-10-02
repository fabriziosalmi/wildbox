import { Page, expect, test } from '@playwright/test'
import { ADMIN_STATE, SEEDED_INDICATORS, UNSEEDED_IP } from './support/backend'

/**
 * IOC lookup against the live data service, through the gateway (#103).
 *
 * The indicators come from tests/e2e/fixtures/threat-intel-seed.sql (the data
 * service has no create API). Each lookup asserts what the seed says: the
 * verdict derived from its severity, its threat types, its tags. The original
 * spec searched 8.8.8.8 and google.com and passed whether or not anything was
 * found; a lookup that silently returned nothing would have passed it too.
 */
test.describe('Threat intel lookup', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  const lookupInput = (page: Page) => page.getByPlaceholder(/e\.g\., 8\.8\.8\.8/)

  async function lookUp(page: Page, value: string) {
    await lookupInput(page).fill(value)
    const response = page.waitForResponse(r => r.url().includes('/api/v1/data/'))
    await page.getByRole('button', { name: 'Lookup' }).click()
    return response
  }

  test('is reachable from the sidebar', async ({ page }) => {
    await page.goto('/dashboard')
    await page.getByRole('button', { name: /^Threat Intel/ }).click()
    await page.getByRole('link', { name: 'Lookup', exact: true }).click()

    await expect(page).toHaveURL(/\/threat-intel\/lookup$/)
    await expect(page.getByRole('heading', { name: 'IOC Lookup' })).toBeVisible()
    await expect(lookupInput(page)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Lookup' })).toBeDisabled()
  })

  const cases = [
    {
      kind: 'IP address',
      value: SEEDED_INDICATORS.ip,
      typeLabel: 'IP Address',
      verdict: 'Malicious',
      severity: '9/10',
      threatTypes: ['malware', 'c2'],
    },
    {
      kind: 'domain',
      value: SEEDED_INDICATORS.domain,
      typeLabel: 'Domain',
      verdict: 'Suspicious',
      severity: '6/10',
      threatTypes: ['phishing'],
    },
    {
      kind: 'file hash',
      value: SEEDED_INDICATORS.hash,
      typeLabel: 'File Hash',
      verdict: 'Malicious',
      severity: '10/10',
      threatTypes: ['ransomware'],
    },
  ]

  for (const lookupCase of cases) {
    test(`a seeded ${lookupCase.kind} returns its threat intelligence`, async ({ page }) => {
      await page.goto('/threat-intel/lookup')
      await lookupInput(page).fill(lookupCase.value)
      await expect(page.getByText('Detected type:').locator('..')).toContainText(
        lookupCase.typeLabel
      )

      const response = await lookUp(page, lookupCase.value)
      expect(response.status()).toBe(200)

      await expect(page.getByText('Analysis Results')).toBeVisible()
      await expect(page.locator('code', { hasText: lookupCase.value })).toBeVisible()
      // Verdict and score are derived from the seeded severity.
      await expect(
        page.getByText(`${lookupCase.verdict}(${lookupCase.severity})`).first()
      ).toBeVisible()
      for (const threatType of lookupCase.threatTypes) {
        await expect(page.getByText(threatType, { exact: true }).first()).toBeVisible()
      }
      // The tag is only rendered on the per-indicator card.
      await expect(page.getByText('e2e', { exact: true })).toBeVisible()
    })
  }

  test('an indicator that is not in the database is reported as not found', async ({ page }) => {
    await page.goto('/threat-intel/lookup')
    const response = await lookUp(page, UNSEEDED_IP)
    expect(response.status()).toBe(404)

    await expect(page.getByText('IOC Not Found')).toBeVisible()
    await expect(page.getByText('Lookup Failed')).toHaveCount(0)
  })

  test('input that is not an indicator is never sent to the service', async ({ page }) => {
    const dataRequests: string[] = []
    page.on('request', r => {
      if (r.url().includes('/api/v1/data/')) dataRequests.push(r.url())
    })
    await page.goto('/threat-intel/lookup')

    await lookupInput(page).fill('not an indicator!')
    await expect(page.getByText('Detected type:').locator('..')).toContainText('Unknown')
    await page.getByRole('button', { name: 'Lookup' }).click()

    // A real lookup afterwards: once its response is in, any request the
    // invalid input had triggered would have been recorded before it.
    await lookUp(page, SEEDED_INDICATORS.ip)
    await expect(page.getByText('Analysis Results')).toBeVisible()
    expect(dataRequests).toHaveLength(1)
    expect(dataRequests[0]).toContain(`/ips/${SEEDED_INDICATORS.ip}`)
  })
})
