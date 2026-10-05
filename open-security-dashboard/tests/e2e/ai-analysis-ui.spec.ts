import { expect, test, type Page, type Route } from '@playwright/test'

/**
 * The AI analysis page, with the agents service's answers supplied by the
 * test (#727). No backend: the session and every /api/v1/agents answer are
 * routed here, so the states a stack without a model key cannot produce (a
 * running task, a report) are covered too. ai-analysis.spec.ts runs the page
 * against the real service.
 *
 * Each answer below has the shape the service gives it
 * (open-security-agents/app/schemas.py, docs/api/agents/endpoints.md).
 */

const USER_ID = '7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77'
const OTHER_USER_ID = '9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d'
const TASK_ID = '550e8400-e29b-41d4-a716-446655440000'
const CREATED_AT = '2026-10-03T10:00:00Z'
const STORAGE_KEY = (userId: string) => `wildbox_ai_analyses:${userId}`

const NOT_CONFIGURED = 'AI analysis is not configured on this server: no model API key is set.'

const task = (status: string, extra: Record<string, unknown> = {}) => ({
  task_id: TASK_ID,
  status,
  created_at: CREATED_AT,
  started_at: null,
  completed_at: null,
  progress: null,
  error: null,
  result_url: `/api/v1/agents/analyze/${TASK_ID}`,
  ...extra,
})

const REPORT = {
  task_id: TASK_ID,
  ioc: { type: 'domain', value: 'example.com' },
  verdict: 'Suspicious',
  confidence: 0.75,
  executive_summary: 'One reputation source lists the domain.',
  evidence: [
    { source: 'reputation_check_tool', finding: 'Listed by one source.', severity: 'medium' },
  ],
  recommended_actions: ['Monitor DNS queries for the domain'],
  full_report: '# Threat Analysis Report\n\n<script>window.__injected = true</script>\n',
  analysis_duration: 45.2,
  tools_used: ['reputation_check_tool', 'whois_lookup_tool'],
}

const json = (status: number, body: unknown) => ({
  status,
  contentType: 'application/json',
  body: JSON.stringify(body),
})

/** A signed-in session, and what the agents service's statistics answer. */
async function signedIn(
  page: Page,
  { userId = USER_ID, stats = json(200, { model_configured: true }) } = {}
) {
  const { baseURL } = test.info().project.use
  await page.context().addCookies([{ name: 'auth_token', value: 'mocked', url: baseURL }])
  await page.route('**/auth/users/me', route =>
    route.fulfill(
      json(200, {
        id: userId,
        email: 'analyst@example.com',
        is_active: true,
        is_superuser: false,
        created_at: CREATED_AT,
        updated_at: CREATED_AT,
        team_memberships: [],
      })
    )
  )
  await page.route('**/api/v1/agents/stats', route => route.fulfill(stats))
}

/** The answers to the task's reads, in order; the last one repeats. */
async function taskAnswers(page: Page, answers: ReturnType<typeof json>[]) {
  let reads = 0
  await page.route(`**/api/v1/agents/analyze/${TASK_ID}`, route =>
    route.fulfill(answers[Math.min(reads++, answers.length - 1)])
  )
}

/** Accepts submissions and records what was posted. */
async function acceptSubmissions(page: Page) {
  const posted: unknown[] = []
  await page.route('**/api/v1/agents/analyze', async (route: Route) => {
    posted.push(route.request().postDataJSON())
    await route.fulfill(json(202, task('pending')))
  })
  return posted
}

/** A task this account submitted earlier from this browser. */
async function submittedEarlier(page: Page, userId = USER_ID) {
  await page.addInitScript(
    ([key, item]) => localStorage.setItem(key, item),
    [
      STORAGE_KEY(userId),
      JSON.stringify([
        {
          task_id: TASK_ID,
          ioc: { type: 'domain', value: 'example.com' },
          submitted_at: CREATED_AT,
        },
      ]),
    ]
  )
}

const card = (page: Page) => page.getByTestId('analysis-card')

test.describe('AI analysis page', () => {
  test('sends a visitor without a session to sign in', async ({ page }) => {
    await page.goto('/ai-analysis')
    await expect(page).toHaveURL(`/?redirect=${encodeURIComponent('/ai-analysis')}`)
  })

  test('is reached from the navigation', async ({ page }) => {
    await signedIn(page)
    await page.goto('/ai-analysis')

    const link = page.getByRole('link', { name: /AI Analysis/ })
    await expect(link).toHaveAttribute('href', '/ai-analysis')
    await expect(page.getByRole('heading', { level: 1, name: 'AI Analysis' })).toBeVisible()
    await expect(page.getByTestId('no-analyses')).toBeVisible()
    await expect(page.getByTestId('analysis-list-scope')).toContainText('does not list analyses')
  })

  test('says that no model key is set when the service says so', async ({ page }) => {
    await signedIn(page, { stats: json(200, { model_configured: false }) })
    await page.goto('/ai-analysis')

    await expect(page.getByTestId('model-not-configured')).toContainText(NOT_CONFIGURED)
    // The form stays usable: the submission's own failure says the same.
    await expect(page.getByTestId('submit-analysis')).toBeEnabled()
  })

  for (const [name, stats] of [
    ['a model key is set', json(200, { model_configured: true })],
    ['the statistics cannot be read', json(503, { error: { message: 'unavailable' } })],
  ] as const) {
    test(`says nothing about the model key when ${name}`, async ({ page }) => {
      await signedIn(page, { stats })
      const answered = page.waitForResponse('**/api/v1/agents/stats')
      await page.goto('/ai-analysis')
      await answered

      await expect(page.getByTestId('analysis-form')).toBeVisible()
      await expect(page.getByTestId('model-not-configured')).toHaveCount(0)
    })
  }

  test('submits with the keyboard and follows the task to its report', async ({ page }) => {
    await signedIn(page)
    const posted = await acceptSubmissions(page)
    await taskAnswers(page, [
      json(200, task('pending')),
      json(200, task('running', { started_at: CREATED_AT, progress: 'Running AI analysis...' })),
      json(200, REPORT),
    ])
    await page.goto('/ai-analysis')

    await page.getByLabel('Indicator type').selectOption('domain')
    const value = page.getByLabel('Indicator', { exact: true })
    await value.focus()
    await page.keyboard.type('  example.com ')
    await page.keyboard.press('Enter')

    // What was sent is the indicator, trimmed, and nothing else.
    await expect.poll(() => posted).toEqual([{ ioc: { type: 'domain', value: 'example.com' } }])
    await expect(page.getByTestId('submit-status')).toHaveText(
      'Submitted example.com. Its status is first in the list below.'
    )
    await expect(value).toHaveValue('')
    await expect(value).toBeFocused()

    await expect(card(page)).toHaveAttribute('data-task-id', TASK_ID)
    await expect(card(page).getByTestId('analysis-progress')).toContainText(
      'Running AI analysis...'
    )
    await expect(card(page).getByTestId('analysis-status')).toHaveText('completed', {
      timeout: 15_000,
    })
    await expect(card(page).getByTestId('analysis-verdict')).toHaveText('Suspicious')
    await expect(card(page).getByTestId('analysis-confidence')).toHaveText('75%')
    const report = card(page).getByTestId('analysis-report')
    await expect(report).toContainText('One reputation source lists the domain.')
    await expect(report).toContainText('Listed by one source.')
    await expect(report).toContainText('Monitor DNS queries for the domain')
    await expect(report).toContainText('reputation_check_tool, whois_lookup_tool')

    // The full report opens with the keyboard, and is shown as text.
    const full = card(page).getByTestId('analysis-full-report')
    await expect(full).toBeHidden()
    await card(page).getByText('Full report').focus()
    await page.keyboard.press('Enter')
    await expect(full).toBeVisible()
    await expect(full).toContainText('<script>window.__injected = true</script>')
    expect(await page.evaluate(() => '__injected' in window)).toBe(false)
  })

  test('keeps the focus on the button that submitted', async ({ page }) => {
    await signedIn(page)
    await acceptSubmissions(page)
    await taskAnswers(page, [json(200, task('pending'))])
    await page.goto('/ai-analysis')

    await page.getByLabel('Indicator', { exact: true }).fill('203.0.113.10')
    const submit = page.getByTestId('submit-analysis')
    await submit.focus()
    await page.keyboard.press('Space')

    await expect(card(page)).toBeVisible()
    await expect(submit).toBeFocused()
  })

  test('shows a failed task as failed, with the reason and no report', async ({ page }) => {
    await signedIn(page)
    await submittedEarlier(page)
    await taskAnswers(page, [
      json(200, task('failed', { completed_at: CREATED_AT, error: NOT_CONFIGURED })),
    ])
    await page.goto('/ai-analysis')

    await expect(card(page).getByTestId('analysis-status')).toHaveText('failed')
    await expect(card(page).getByTestId('analysis-error')).toContainText(NOT_CONFIGURED)
    await expect(card(page).getByTestId('analysis-error')).toContainText('There is no report')
    await expect(card(page).getByTestId('analysis-report')).toHaveCount(0)
    await expect(card(page).getByTestId('analysis-verdict')).toHaveCount(0)
  })

  test('shows a canceled task as revoked', async ({ page }) => {
    await signedIn(page)
    await submittedEarlier(page)
    await taskAnswers(page, [json(200, task('revoked', { completed_at: CREATED_AT }))])
    await page.goto('/ai-analysis')

    await expect(card(page).getByTestId('analysis-status')).toHaveText('revoked')
    await expect(card(page)).toContainText('The analysis was canceled')
    await expect(card(page).getByTestId('analysis-report')).toHaveCount(0)
  })

  test('puts the reason of a refused indicator at the field', async ({ page }) => {
    await signedIn(page)
    await page.route('**/api/v1/agents/analyze', route =>
      route.fulfill(
        json(422, {
          error: {
            code: 422,
            message: 'Request validation failed',
            type: 'ValidationError',
            request_id: 'req-1',
            details: [
              {
                type: 'value_error',
                loc: ['body', 'ioc', 'value'],
                msg: "Value error, Invalid format for ipv4 IOC: 'nope'",
              },
            ],
          },
        })
      )
    )
    await page.goto('/ai-analysis')

    const value = page.getByLabel('Indicator', { exact: true })
    await value.fill('nope')
    await page.keyboard.press('Enter')

    await expect(page.getByTestId('ioc-value-error')).toHaveText(
      "Invalid format for ipv4 IOC: 'nope'"
    )
    await expect(value).toHaveAttribute('aria-invalid', 'true')
    await expect(value).toBeFocused()
    await expect(card(page)).toHaveCount(0)
    await expect(page.getByTestId('submit-error')).toHaveCount(0)

    // The answer was about what was submitted: a change of the type or of
    // the value takes it away, and nothing stale takes its place.
    await page.getByLabel('Indicator type').selectOption('domain')
    await expect(page.getByTestId('ioc-value-error')).toHaveCount(0)
    await expect(page.getByTestId('submit-error')).toHaveCount(0)
    await expect(value).not.toHaveAttribute('aria-invalid', 'true')
  })

  test('shows any other refusal as the service gave it', async ({ page }) => {
    await signedIn(page)
    await page.route('**/api/v1/agents/analyze', route =>
      route.fulfill(
        json(429, {
          error: { code: 429, message: 'Rate limit exceeded: 5 per 1 minute', request_id: 'r-2' },
        })
      )
    )
    await page.goto('/ai-analysis')

    await page.getByLabel('Indicator', { exact: true }).fill('203.0.113.10')
    await page.getByTestId('submit-analysis').click()

    const error = page.getByTestId('submit-error')
    await expect(error).toContainText('The analysis was not submitted')
    await expect(error).toContainText('HTTP 429')
    await expect(error).toContainText('Rate limit exceeded: 5 per 1 minute')
    await expect(card(page)).toHaveCount(0)
  })

  test('asks for an indicator instead of submitting an empty one', async ({ page }) => {
    await signedIn(page)
    const posted = await acceptSubmissions(page)
    await page.goto('/ai-analysis')

    await page.getByTestId('submit-analysis').click()

    const value = page.getByLabel('Indicator', { exact: true })
    await expect(page.getByTestId('ioc-value-error')).toHaveText('Enter the indicator to analyze.')
    await expect(value).toBeFocused()
    expect(posted).toEqual([])
  })

  test('says that an expired task is gone, and removes it with the keyboard', async ({ page }) => {
    await signedIn(page)
    await submittedEarlier(page)
    await taskAnswers(page, [json(404, { error: { code: 404, message: 'Task not found' } })])
    await page.goto('/ai-analysis')

    await expect(card(page).getByTestId('analysis-gone')).toContainText(
      'The service no longer has this analysis'
    )
    // No status the service did not give.
    await expect(card(page).getByTestId('analysis-status')).toHaveCount(0)

    await card(page).getByRole('button', { name: 'Remove example.com from this list' }).focus()
    await page.keyboard.press('Enter')

    await expect(card(page)).toHaveCount(0)
    await expect(page.getByTestId('no-analyses')).toBeVisible()
    // The focus the removed button held goes to the list's heading.
    await expect(page.getByRole('heading', { name: 'Submitted analyses' })).toBeFocused()
    expect(await page.evaluate(key => localStorage.getItem(key), STORAGE_KEY(USER_ID))).toBe('[]')
  })

  test('shows a read that failed as a failure, not as a status', async ({ page }) => {
    await signedIn(page)
    await submittedEarlier(page)
    await taskAnswers(page, [
      json(500, { error: { code: 500, message: 'Failed to retrieve analysis result' } }),
    ])
    await page.goto('/ai-analysis')

    await expect(card(page).getByTestId('analysis-read-error')).toContainText(
      'Failed to retrieve analysis result',
      { timeout: 15_000 }
    )
    await expect(card(page).getByTestId('analysis-status')).toHaveCount(0)
    await expect(card(page).getByRole('button', { name: 'Read it again' })).toBeVisible()
  })

  test("does not show another account's analyses", async ({ page }) => {
    await signedIn(page, { userId: OTHER_USER_ID })
    await submittedEarlier(page, USER_ID)
    await page.goto('/ai-analysis')

    await expect(page.getByTestId('no-analyses')).toBeVisible()
    await expect(card(page)).toHaveCount(0)
  })
})
