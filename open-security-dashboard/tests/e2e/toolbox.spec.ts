import { expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * /toolbox against the live tools service (#572).
 *
 * The tool list request caught its own failure and returned an empty
 * list, so an outage showed a toolbox with "Total Tools 0" and the page's
 * error state could never appear.
 */

const TOOLS_PATH = '/api/v1/tools'

async function toolCount(): Promise<number> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get(TOOLS_PATH, { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    return ((await response.json()) as unknown[]).length
  } finally {
    await api.dispose()
  }
}

test.describe('Toolbox', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('counts the tools the service lists', async ({ page }) => {
    const count = await toolCount()
    expect(count, 'the stack ships tools; an empty list proves nothing').toBeGreaterThan(0)

    await page.goto('/toolbox')

    await expect(page.getByTestId('toolbox-total')).toHaveText(String(count), { timeout: 30_000 })
    await expect(page.getByTestId('toolbox-error')).toHaveCount(0)
  })

  test('a failing tools service is an error with a retry, not 0 tools', async ({ page }) => {
    const message = `injected outage ${randomBytes(4).toString('hex')}`
    const isList = (url: URL) => url.pathname === TOOLS_PATH
    await page.route(isList, route =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { message, type: 'service_unavailable' } }),
      })
    )

    await page.goto('/toolbox')

    // React Query retries three times with back-off before giving up.
    const error = page.getByTestId('toolbox-error')
    await expect(error).toContainText(message, { timeout: 30_000 })
    await expect(page.getByTestId('toolbox-total')).toHaveCount(0)

    await page.unroute(isList)
    await error.getByRole('button', { name: 'Try Again' }).click()
    await expect(page.getByTestId('toolbox-total')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('toolbox-error')).toHaveCount(0)
  })
})
