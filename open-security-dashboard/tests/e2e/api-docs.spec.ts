import { expect, test } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { ADMIN_STATE } from './support/backend'

/**
 * /api-docs points at real references and claims nothing it cannot know (#572).
 *
 * It listed endpoints no service serves, a "healthy" badge on every service
 * that no probe set, Free / Business plan tiers nothing enforces, and an
 * example response with invented indicator counts.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..')
const REPO_BLOB = 'https://github.com/fabriziosalmi/wildbox/blob/main/'

const INVENTED_CONTENT = [
  // endpoints that do not exist
  '/api/v1/responder/metrics',
  '/api/v1/identity/user/profile',
  '/api/v1/user/profile',
  'dashboards/1/data',
  // static health, plans and figures
  'healthy',
  'Free+',
  'Business+',
  'Enterprise',
  '150420',
  'Port 8002',
  'api.wildbox.local',
]

test.describe('API documentation page', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('lists the gateway routes, links real references, invents nothing', async ({ page }) => {
    await page.goto('/api-docs')

    const routes = page.getByTestId('api-docs-routes')
    await expect(routes).toBeVisible({ timeout: 30_000 })
    for (const prefix of ['/api/v1/guardian/', '/api/v1/data/', '/api/v1/cspm/', '/auth/jwt/']) {
      await expect(routes).toContainText(prefix)
    }

    const main = page.locator('main')
    for (const invented of INVENTED_CONTENT) {
      await expect(main).not.toContainText(invented)
    }
    await expect(main.getByRole('button', { name: 'Test' })).toHaveCount(0)

    // Every link into the repository names a file that exists.
    const hrefs = await main
      .locator(`a[href^="${REPO_BLOB}"]`)
      .evaluateAll(anchors => anchors.map(a => a.getAttribute('href') ?? ''))
    expect(hrefs.length).toBeGreaterThan(0)
    for (const href of hrefs) {
      const file = path.join(REPO_ROOT, href.slice(REPO_BLOB.length).split('#')[0])
      expect(fs.existsSync(file), `${href} points at a missing file`).toBe(true)
    }
  })
})
