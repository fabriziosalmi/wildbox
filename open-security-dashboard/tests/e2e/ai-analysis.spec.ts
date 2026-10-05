import { expect, test } from '@playwright/test'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * The AI analysis page against the live agents service (#727).
 *
 * The CI stack has no model API key (.env.example leaves ANTHROPIC_API_KEY
 * empty), which is a path of its own, end to end: the gateway, the agents
 * API, its worker and Redis accept the analysis, the worker fails it at once
 * for want of a key, and the page shows it failed with the service's reason.
 * No model is called. On a stack that has a key these tests are skipped: a
 * submission there would call the model. ai-analysis-ui.spec.ts covers what
 * this stack cannot produce, a running task and a report.
 */

const NOT_CONFIGURED = 'AI analysis is not configured on this server: no model API key is set.'

interface TaskRead {
  status: string
  error: string | null
}

/** One request to the agents service through the gateway, as the admin. */
async function agents<T>(path: string): Promise<T> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get(`/api/v1/agents/${path}`, { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    return (await response.json()) as T
  } finally {
    await api.dispose()
  }
}

test.describe('AI analysis', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test.beforeEach(async () => {
    const stats = await agents<{ model_configured: boolean }>('stats')
    test.skip(
      stats.model_configured,
      'this stack has a model API key: an analysis submitted here would call the model'
    )
  })

  test('an analysis submitted without a model key ends failed, with the reason', async ({
    page,
  }) => {
    await page.goto('/dashboard')
    await page.getByRole('link', { name: /AI Analysis/ }).click()
    await expect(page).toHaveURL(/\/ai-analysis$/)

    // The service says that analyses cannot run, before one is submitted.
    await expect(page.getByTestId('model-not-configured')).toContainText(NOT_CONFIGURED, {
      timeout: 30_000,
    })

    await page.getByLabel('Indicator type').selectOption('domain')
    await page.getByLabel('Indicator', { exact: true }).fill('example.com')
    await page.keyboard.press('Enter')

    const card = page.getByTestId('analysis-card')
    await expect(card).toHaveCount(1, { timeout: 30_000 })
    await expect(card).toContainText('example.com')
    await expect(card.getByTestId('analysis-status')).toHaveText('failed', { timeout: 60_000 })
    await expect(card.getByTestId('analysis-error')).toContainText(NOT_CONFIGURED)
    await expect(card.getByTestId('analysis-report')).toHaveCount(0)

    // What the page shows is what the service answers for that task.
    const taskId = await card.getAttribute('data-task-id')
    const read = await agents<TaskRead>(`analyze/${taskId}`)
    expect(read).toMatchObject({ status: 'failed', error: NOT_CONFIGURED })

    // The list is this browser's: it is still there after a reload.
    await page.reload()
    await expect(card.getByTestId('analysis-status')).toHaveText('failed', { timeout: 30_000 })
  })

  test('an indicator the service refuses is not submitted, and the page says why', async ({
    page,
  }) => {
    await page.goto('/ai-analysis')

    await page.getByLabel('Indicator type').selectOption('ipv4')
    const value = page.getByLabel('Indicator', { exact: true })
    await value.fill('not-an-address')
    await page.getByTestId('submit-analysis').click()

    await expect(page.getByTestId('ioc-value-error')).toHaveText(
      "Invalid format for ipv4 IOC: 'not-an-address'",
      { timeout: 30_000 }
    )
    await expect(value).toBeFocused()
    await expect(page.getByTestId('analysis-card')).toHaveCount(0)
  })
})
