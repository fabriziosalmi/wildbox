import { expect, test, type Page, type Request } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'
import { ADMIN_STATE, adminAccount, apiLogin, bearer, gatewayApi } from './support/backend'

/**
 * Running a tool from /toolbox/<name> against the live stack (#585).
 *
 * The form is generated from the input schema the tools service serves, the
 * run goes through the gateway with the session's Bearer token, and what the
 * page shows is compared with what the API answers for the same input.
 *
 * hash_generator is the tool for every successful run: it makes no network
 * call, so its output depends on the input alone. The refusals use IP
 * literals, refused before any request leaves the stack.
 */

const TOOL_PATH = '/api/v1/tools/hash_generator'
const isRun = (request: Request) => request.method() === 'POST' && request.url().endsWith(TOOL_PATH)
const isAsyncRun = (request: Request) =>
  request.method() === 'POST' && request.url().endsWith(`${TOOL_PATH}/async`)

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex')
const sha512 = (text: string) => createHash('sha512').update(text).digest('hex')
// Python's hashlib.blake2b is BLAKE2b-512.
const blake2b = (text: string) => createHash('blake2b512').update(text).digest('hex')

/** The algorithms hash_generator implements: its schema's enum, in order (#611). */
const HASH_ALGORITHMS = ['sha224', 'sha256', 'sha384', 'sha512', 'blake2b', 'blake2s']

/** One algorithm's checkbox in the hash_types group the schema's enum yields. */
const hashType = (page: Page, algorithm: string) =>
  page.getByTestId('field-hash_types').getByLabel(algorithm, { exact: true })

/** Leaves exactly `wanted` checked; the form sends them in the order checked. */
async function chooseHashTypes(page: Page, wanted: string[]) {
  for (const algorithm of HASH_ALGORITHMS) await hashType(page, algorithm).uncheck()
  for (const algorithm of wanted) await hashType(page, algorithm).check()
}

interface HashResult {
  algorithm: string
  hash_value: string
}

/** The JSON the result view shows, parsed from its raw JSON block. */
async function shownJson(page: Page): Promise<Record<string, unknown>> {
  const raw = await page.getByTestId('result-raw').textContent()
  return JSON.parse(raw ?? 'null')
}

const hashesOf = (body: Record<string, unknown>) =>
  (body.hash_results as HashResult[]).map(h => ({
    algorithm: h.algorithm,
    hash_value: h.hash_value,
  }))

/** POSTs a body to a tool through the gateway as the admin, as curl would. */
async function apiRun(tool: string, body: unknown) {
  const api = await gatewayApi()
  try {
    const token = await apiLogin(api, adminAccount())
    const response = await api.post(`/api/v1/tools/${tool}`, {
      headers: bearer(token),
      data: body,
      timeout: 60_000,
    })
    return { status: response.status(), body: await response.json() }
  } finally {
    await api.dispose()
  }
}

async function openTool(page: Page, tool: string) {
  await page.goto(`/toolbox/${tool}`)
  await expect(page.getByTestId('tool-form')).toBeVisible({ timeout: 30_000 })
}

test.describe('Toolbox: run a tool', { tag: '@backend' }, () => {
  test.use({ storageState: ADMIN_STATE })

  test('a synchronous run shows what the API answers for the same input', async ({ page }) => {
    const text = `wildbox-e2e-${randomBytes(8).toString('hex')}`

    // Opened from the catalog, as a user would.
    await page.goto('/toolbox')
    await page.getByTestId('open-tool-hash_generator').click()
    await expect(page).toHaveURL(/\/toolbox\/hash_generator$/)
    await expect(page.getByTestId('tool-title')).toHaveText('Hash Generator', { timeout: 30_000 })

    // The form came from the schema: its defaults are already in place.
    await expect(page.getByTestId('field-iterations')).toHaveValue('1')
    // hash_types is an enum: one checkbox per implemented algorithm, the
    // default ones checked, and nothing the tool would refuse (#611).
    const group = page.getByTestId('field-hash_types')
    await expect(group.getByRole('checkbox')).toHaveCount(HASH_ALGORITHMS.length)
    for (const algorithm of HASH_ALGORITHMS) {
      const box = hashType(page, algorithm)
      if (['sha256', 'sha512'].includes(algorithm)) await expect(box).toBeChecked()
      else await expect(box).not.toBeChecked()
    }
    await expect(group.getByLabel('md5', { exact: true })).toHaveCount(0)
    await expect(group.getByLabel('sha1', { exact: true })).toHaveCount(0)

    await page.getByTestId('field-input_text').fill(text)
    await hashType(page, 'blake2b').check()

    const sent = page.waitForRequest(isRun)
    await page.getByTestId('run-tool').click()
    const request = await sent

    // JSON, typed by the schema, with the session's Bearer token.
    expect(request.headers()['authorization']).toMatch(/^Bearer .+/)
    const body = request.postDataJSON()
    expect(body).toMatchObject({
      input_text: text,
      hash_types: ['sha256', 'sha512', 'blake2b'],
      iterations: 1,
      include_salted: false,
      timeout: 30,
    })
    // Empty optional fields are left to the service's defaults.
    expect(body).not.toHaveProperty('salt')
    expect(body).not.toHaveProperty('target')

    await expect(page.getByTestId('run-result')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('result-status')).toHaveText('completed')

    const shown = await shownJson(page)
    const api = await apiRun('hash_generator', body)
    expect(api.status, JSON.stringify(api.body)).toBe(200)
    expect(shown.success, JSON.stringify(shown)).toBe(true)
    expect(hashesOf(shown)).toEqual(hashesOf(api.body))
    expect(hashesOf(shown)).toEqual([
      { algorithm: 'sha256', hash_value: sha256(text) },
      { algorithm: 'sha512', hash_value: sha512(text) },
      { algorithm: 'blake2b', hash_value: blake2b(text) },
    ])
    // Rendered as a table too, not only as JSON.
    await expect(page.getByTestId('run-output').locator('td').getByText(sha256(text))).toBeVisible()
  })

  test('an asynchronous run is followed until its task completes', async ({ page }) => {
    const text = `wildbox-e2e-${randomBytes(8).toString('hex')}`
    await openTool(page, 'hash_generator')

    await page.getByTestId('field-input_text').fill(text)
    await chooseHashTypes(page, ['sha256'])
    await page.getByTestId('mode-async').check()

    const submitted = page.waitForResponse(response => isAsyncRun(response.request()))
    await page.getByTestId('run-tool').click()
    const accepted = await submitted
    expect(accepted.status()).toBe(202)
    const taskId = (await accepted.json()).task_id as string

    const panel = page.getByTestId('task-panel')
    await expect(panel).toContainText(taskId)
    await expect(page.getByTestId('result-status')).toHaveText('completed', { timeout: 120_000 })

    const shown = await shownJson(page)
    expect(hashesOf(shown)).toEqual([{ algorithm: 'sha256', hash_value: sha256(text) }])
    expect(shown.task_id).toBe(taskId)
  })

  test('a running task can be cancelled', async ({ page }) => {
    await openTool(page, 'hash_generator')

    // PBKDF2 hashes of a million iterations: seconds of CPU in the worker,
    // so the task has not finished when it is cancelled. The form offers each
    // algorithm once, and the six take about a second, too close to the
    // cancellation; the body the form builds is sent with its algorithms
    // repeated four times, which the service accepts.
    await page.getByTestId('field-input_text').fill('wildbox')
    await chooseHashTypes(page, HASH_ALGORITHMS)
    await page.getByTestId('field-include_salted').check()
    await page.getByTestId('field-iterations').fill('1000000')
    await page.getByTestId('mode-async').check()

    let built: Record<string, unknown> | undefined
    await page.route(`**${TOOL_PATH}/async`, async route => {
      built = route.request().postDataJSON()
      const hashTypes = built?.hash_types as string[]
      await route.continue({
        postData: JSON.stringify({ ...built, hash_types: [...Array(4)].flatMap(() => hashTypes) }),
      })
    })
    await page.getByTestId('run-tool').click()

    const cancel = page.getByTestId('cancel-task')
    await expect(cancel).toBeEnabled({ timeout: 30_000 })
    const deleted = page.waitForResponse(
      response =>
        response.request().method() === 'DELETE' && /\/api\/v1\/tasks\//.test(response.url())
    )
    await cancel.click()
    expect((await deleted).status()).toBe(200)

    await expect(page.getByTestId('result-status')).toHaveText('cancelled', { timeout: 60_000 })
    await expect(cancel).toHaveCount(0)
    expect(built).toMatchObject({
      hash_types: HASH_ALGORITHMS,
      include_salted: true,
      iterations: 1000000,
    })
  })

  test('the schema constraints are checked before anything is sent', async ({ page }) => {
    await openTool(page, 'hash_generator')
    let posted = 0
    page.on('request', request => {
      if (isRun(request) || isAsyncRun(request)) posted++
    })

    // input_text is required and empty.
    await page.getByTestId('run-tool').click()
    await expect(page.getByTestId('field-error-input_text')).toHaveText('Required')
    await expect(page.getByTestId('field-input_text')).toBeFocused()
    await expect(page.getByTestId('field-input_text')).toHaveAttribute('aria-invalid', 'true')

    // iterations: minimum 1 in the schema.
    await page.getByTestId('field-input_text').fill('wildbox')
    await page.getByTestId('field-iterations').fill('0')
    await page.getByTestId('run-tool').click()
    await expect(page.getByTestId('field-error-iterations')).toHaveText('Must be at least 1')
    await expect(page.getByTestId('field-error-input_text')).toHaveCount(0)

    expect(posted).toBe(0)
    await expect(page.getByTestId('run-result')).toHaveCount(0)
  })

  test('an input the service rejects shows its field errors', async ({ page }) => {
    // custom_headers is Dict[str, str]: the form only checks that it is
    // JSON, the service refuses a number as a header value.
    await openTool(page, 'header_analyzer')
    await page.getByTestId('field-url').fill('https://example.com')
    await page.getByTestId('field-custom_headers').fill('{"X-Wildbox": 1}')
    await page.getByTestId('run-tool').click()

    const error = page.getByTestId('run-error')
    await expect(error).toContainText('HTTP 422', { timeout: 30_000 })
    await expect(page.getByTestId('run-error-message')).toHaveText('Input validation failed')
    await expect(page.getByTestId('field-error-custom_headers')).toContainText('X-Wildbox')
    await expect(page.getByTestId('field-error-custom_headers')).toContainText('valid string')
  })

  test('an SSRF refusal is shown with the reason the service gives', async ({ page }) => {
    const body = { target_url: 'http://169.254.169.254/latest/meta-data/' }
    const api = await apiRun('cookie_scanner', body)
    expect(api.status, JSON.stringify(api.body)).toBe(400)

    await openTool(page, 'cookie_scanner')
    await page.getByTestId('field-target_url').fill(body.target_url)
    await page.getByTestId('run-tool').click()

    await expect(page.getByTestId('run-error')).toContainText('HTTP 400', { timeout: 30_000 })
    await expect(page.getByTestId('run-error-message')).toHaveText(api.body.error.message)
    await expect(page.getByTestId('run-result')).toHaveCount(0)
  })

  test('an authorization refusal is shown with the reason the service gives', async ({ page }) => {
    // The stack grants nobody destructive tests (no USER_PERMISSIONS_FILE),
    // so the scanner is refused before it sends anything.
    await openTool(page, 'sql_injection_scanner')
    await page.getByTestId('field-target_url').fill('http://93.184.215.14/page?id=1')
    await page.getByTestId('run-tool').click()

    await expect(page.getByTestId('run-error')).toContainText('HTTP 403', { timeout: 30_000 })
    await expect(page.getByTestId('run-error-message')).toContainText(
      'not authorized for destructive_test'
    )
  })

  test('an unknown tool is a not-found page, not an empty form', async ({ page }) => {
    const name = `no_such_tool_${randomBytes(4).toString('hex')}`
    await page.goto(`/toolbox/${name}`)
    await expect(page.getByTestId('tool-info-error')).toContainText(`No tool named "${name}"`, {
      timeout: 30_000,
    })
    await expect(page.getByTestId('tool-form')).toHaveCount(0)
  })
})
