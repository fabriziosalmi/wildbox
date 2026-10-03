import { expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * /cloud-security/scans on the live stack (#570, #612).
 *
 * The CSPM service has no endpoint that lists scans, and the page made up
 * for it with three invented scans (an AWS account 123456789012 at 45/45
 * checks, a GCP scan at 65%, an Azure one that failed authentication). It
 * now says that scan history is not available.
 *
 * The scan form listed AWS, GCP and Azure; the service accepted all three
 * and its worker failed every GCP and Azure scan. The form now offers the
 * providers GET /api/v1/cspm/providers lists, and nothing when that fails.
 */

interface ScanProvider {
  provider: string
  name: string
  checks: number
}

async function listedProviders(): Promise<ScanProvider[]> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/cspm/providers', { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    return ((await response.json()) as { providers: ScanProvider[] }).providers
  } finally {
    await api.dispose()
  }
}

test.describe('Cloud security scans', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('says scan history is not available and lists no invented scans', async ({ page }) => {
    await page.goto('/cloud-security/scans')

    await expect(page.getByTestId('scan-history-unavailable')).toContainText(
      'Scan history is not available',
      { timeout: 30_000 }
    )
    const main = page.locator('main')
    for (const invented of [
      'scan-001',
      'Production AWS',
      '123456789012',
      'GCP Production',
      'Azure Development',
      'Authentication failed',
    ]) {
      await expect(main).not.toContainText(invented)
    }
    // Starting a scan is real (POST /api/v1/scans), so the form stays.
    await expect(page.getByRole('button', { name: 'New Scan' })).toBeVisible()
  })

  test('the form offers exactly the providers the service lists', async ({ page }) => {
    const providers = await listedProviders()
    // GCP and Azure have no session or checks: the service does not list them.
    expect(providers.map(listed => listed.provider)).toEqual(['aws'])

    await page.goto('/cloud-security/scans')
    await page.getByRole('button', { name: 'New Scan' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByTestId('scan-provider-select')).toBeVisible({ timeout: 30_000 })
    await expect(dialog.getByTestId('scan-providers-error')).toHaveCount(0)

    await dialog.getByTestId('scan-provider-select').click()
    const options = page.getByRole('option')
    await expect(options).toHaveCount(providers.length)
    for (const listed of providers) {
      const checks = `${listed.checks} ${listed.checks === 1 ? 'check' : 'checks'}`
      await expect(page.getByTestId(`scan-provider-option-${listed.provider}`)).toHaveText(
        `${listed.name} (${checks})`
      )
    }
    for (const gone of ['Google Cloud Platform', 'Microsoft Azure']) {
      await expect(options.filter({ hasText: gone })).toHaveCount(0)
    }
  })

  test('a failing providers call is an error with a retry, not a guessed list', async ({
    page,
  }) => {
    const message = `injected outage ${randomBytes(4).toString('hex')}`
    await page.route('**/api/v1/cspm/providers', route =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { message, type: 'service_unavailable' } }),
      })
    )

    await page.goto('/cloud-security/scans')
    await page.getByRole('button', { name: 'New Scan' }).click()
    const dialog = page.getByRole('dialog')

    const error = dialog.getByTestId('scan-providers-error')
    await expect(error).toContainText('could not be loaded', { timeout: 30_000 })
    await expect(error).toContainText(message)
    // No provider stands in for the missing answer, and no scan can start.
    await expect(dialog.getByTestId('scan-provider-select')).toHaveCount(0)
    await expect(dialog.getByTestId('scan-provider-unavailable')).toHaveText('Not available')
    await expect(dialog.getByRole('button', { name: 'Create Scan' })).toBeDisabled()
    for (const name of ['Amazon Web Services', 'Google Cloud Platform', 'Microsoft Azure']) {
      await expect(dialog).not.toContainText(name)
    }

    // The retry asks the service again and, with the outage over, loads.
    await page.unroute('**/api/v1/cspm/providers')
    await error.getByRole('button', { name: 'Try again' }).click()
    await expect(dialog.getByTestId('scan-provider-select')).toBeVisible({ timeout: 30_000 })
    await expect(dialog.getByTestId('scan-providers-error')).toHaveCount(0)
    await expect(dialog.getByRole('button', { name: 'Create Scan' })).toBeEnabled()
  })
})
