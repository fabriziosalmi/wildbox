import { expect, test } from '@playwright/test'
import { ADMIN_STATE } from './support/backend'

/**
 * /cloud-security/scans on the live stack (#570).
 *
 * The CSPM service has no endpoint that lists scans, and the page made up
 * for it with three invented scans (an AWS account 123456789012 at 45/45
 * checks, a GCP scan at 65%, an Azure one that failed authentication). It
 * now says that scan history is not available.
 */
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
})
