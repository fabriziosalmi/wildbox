import { expect, test } from '@playwright/test'
import { randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * The /response pages against the live responder (#570).
 *
 * They called the responder at /v1/... through a client already mounted on
 * /api/v1/responder, i.e. at /v1/v1/..., so every request was a 404; the
 * overview hid that behind invented figures (45 runs, 87% success, three
 * made-up runs) and the run list behind "showing demo data".
 */

interface PlaybookList {
  playbooks: { playbook_id: string; name: string }[]
  total: number
}

async function responderPlaybooks(): Promise<PlaybookList> {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.get('/api/v1/responder/playbooks', { headers: bearer(token) })
    expect(response.status(), await response.text()).toBe(200)
    return (await response.json()) as PlaybookList
  } finally {
    await api.dispose()
  }
}

test.describe('Response pages', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('the overview shows the responder playbooks and no invented run figures', async ({
    page,
  }) => {
    const list = await responderPlaybooks()
    expect(list.total, 'the stack ships playbooks; an empty list proves nothing').toBeGreaterThan(0)

    await page.goto('/response')

    await expect(page.getByTestId('response-playbook-count')).toHaveText(String(list.total), {
      timeout: 30_000,
    })
    const listed = page.getByTestId('response-playbook-list')
    for (const playbook of list.playbooks) {
      await expect(listed.locator(`[data-playbook-id="${playbook.playbook_id}"]`)).toContainText(
        playbook.name
      )
    }

    // The responder neither lists nor counts runs, so the page must say so
    // rather than show totals. These were the old constants.
    await expect(page.getByTestId('response-run-stats-unavailable')).toContainText(
      'Run statistics are not available'
    )
    const main = page.locator('main')
    for (const invented of ['Success Rate', 'Running Now', 'Total Runs', '87%', 'run-001']) {
      await expect(main).not.toContainText(invented)
    }
  })

  test('the playbooks page lists the playbooks the responder reports', async ({ page }) => {
    const list = await responderPlaybooks()
    expect(list.total, 'the stack ships playbooks; an empty list proves nothing').toBeGreaterThan(0)

    await page.goto('/response/playbooks')

    const cards = page.getByTestId('playbook-card')
    await expect(cards).toHaveCount(list.total, { timeout: 30_000 })
    for (const playbook of list.playbooks) {
      await expect(
        page.locator(`[data-testid="playbook-card"][data-playbook-id="${playbook.playbook_id}"]`)
      ).toContainText(playbook.name)
    }
  })

  test('the runs page asks the responder for a run and invents none', async ({ page }) => {
    // A run ID nobody started: the page must show the responder's answer
    // (not found), never a fabricated status.
    const runId = randomBytes(16).toString('hex')

    const responderCalls: number[] = []
    page.on('response', response => {
      if (response.url().includes(`/api/v1/responder/runs/${runId}`)) {
        responderCalls.push(response.status())
      }
    })

    await page.goto(`/response/runs?run_id=${runId}`)

    await expect(page.getByTestId('run-history-unavailable')).toContainText(
      'Run history is not available',
      { timeout: 30_000 }
    )
    const card = page.locator(`[data-testid="run-card"][data-run-id="${runId}"]`)
    await expect(card).toContainText('The responder did not return this run', {
      timeout: 30_000,
    })
    await expect(card.getByTestId('run-status')).toHaveCount(0)
    expect(responderCalls).toContain(404)
  })
})
