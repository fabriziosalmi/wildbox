# Wildbox Security Dashboard

The web interface of the Wildbox suite: a Next.js application that signs a
user in and drives the backend services (identity, data, tools, guardian,
responder, cspm, agents) through the Wildbox gateway.

## Pages

The routes under `src/app/`:

| Route                                                                    | What it does                                                                    |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `/`                                                                      | Sign-in page (the `/auth/login` form)                                           |
| `/auth/login`, `/auth/signup`, `/auth/logout`                            | Sign in, register an account, sign out                                          |
| `/auth/change-password`                                                  | Where an account with an initial password is sent to replace it                 |
| `/dashboard`                                                             | Summary figures from the data, cspm, guardian and responder services            |
| `/threat-intel/lookup`                                                   | Look up an IP address, domain or file hash in the data service                  |
| `/threat-intel/feeds`                                                    | Threat-intel sources and feed statistics                                        |
| `/threat-intel/data`                                                     | Data service statistics, sources and an indicator search                        |
| `/toolbox`, `/toolbox/<name>`                                            | The tools service catalog, and a form to run one tool                           |
| `/ai-analysis`                                                           | Submit an indicator to the agents service and follow its AI analysis            |
| `/vulnerabilities`                                                       | Vulnerabilities held by guardian                                                |
| `/response`, `/response/playbooks`, `/response/runs`                     | Responder playbooks: list and start them, then follow a run's status            |
| `/cloud-security`, `/cloud-security/scans`, `/cloud-security/compliance` | CSPM summary, scan form and compliance findings (not in the sidebar, see below) |
| `/settings/profile`, `/settings/api-keys`, `/settings/team`              | Profile and password, API keys, team members                                    |
| `/api-docs`                                                              | Gateway routes, with links to the API references in `docs/api/`                 |
| `/admin`                                                                 | Superusers only: user management, system health and usage analytics             |

Notes:

- **Cloud security** is reachable by URL but is not in the sidebar
  (`src/components/main-layout.tsx`), and its pages show an "AWS only"
  notice. The scan form offers only the providers the cspm service
  lists at `GET /api/v1/cspm/providers`; on this version that is AWS only.
- **Response runs**: the responder has no endpoint that lists runs, so
  `/response/runs` shows the runs started from this browser and a run named
  in the URL, each with the status the responder reports.
- **AI analysis**: the agents service has no endpoint that lists analyses
  and keeps each one for a limited time (an hour by default), so
  `/ai-analysis` shows the analyses submitted from this browser by the
  signed-in account, each with the status, the failure reason or the report
  the service answers for it. It says so when the service reports that no
  model API key is set, in which case every analysis fails.
- There is no endpoint (sensor) page.

### Security Toolbox

`/toolbox` lists the tools from `GET /api/v1/tools`. Each tool's **Run**
button opens `/toolbox/<name>`, which runs it (#585):

- **The form** is generated from the `input_schema` of
  `GET /api/v1/tools/<name>/info` (Pydantic JSON Schema), in
  `src/lib/tool-schema.ts`. Strings are text inputs, `integer`/`number`
  number inputs, `enum` (also behind a `$ref`) a select, `boolean` a
  checkbox, an array of primitives one value per line (a group of
  checkboxes when its items are an enum), and anything else, such as an
  object, a JSON text area. `anyOf` with `null` is an optional field. The
  schema's `title`, `description`, `default` and `example` are the label,
  the help text, the initial value and the placeholder.
- **Validation** applies the schema's own constraints before anything is
  sent: required fields, `minimum`/`maximum` and their exclusive forms,
  whole numbers, `minLength`/`maxLength`/`pattern`, `minItems`/`maxItems`.
  An empty optional field is not sent, so the service applies its default.
  When the service still refuses the input, its field errors (422) are
  shown under the fields, and any other refusal (an SSRF-blocked target,
  400; a tool the caller is not authorized for, 403) is shown with the
  reason the service gives.
- **Running**: "Wait for the result" is `POST /api/v1/tools/<name>`; the
  gateway waits up to 60 s for it. "Run as a background task" is
  `POST /api/v1/tools/<name>/async`, then `GET /api/v1/tasks/<id>` every
  second until the task finishes, with `DELETE /api/v1/tasks/<id>` to
  cancel it. Every call goes through `apiClient` with the session's Bearer
  token. "Copy as cURL" copies the request with the form's body; the
  command reads the token from `$WILDBOX_TOKEN` rather than containing it.
- **The result** is the service's answer as it came: objects as key/value
  tables, arrays as lists, the raw JSON, and "Copy JSON" / "Download
  JSON". Values are rendered as text, never as HTML, and URLs in the
  output are not links.

## Technology

From `package.json`:

- Next.js 16 (App Router), React 19, TypeScript (`strict` mode)
- Tailwind CSS, with Radix UI primitives wrapped in `src/components/ui/`
  (shadcn/ui style), `class-variance-authority`, `tailwind-merge`
- TanStack Query for data fetching, Axios for HTTP
- `react-hook-form` and `zod` for forms, `date-fns`, `next-themes`
  (light/dark), `lucide-react` icons, `react-syntax-highlighter`
- `js-cookie` for the session cookie
- Playwright for end-to-end tests (see [tests/README.md](tests/README.md))

The Docker images use Node.js 24 (`node:24-alpine`, pinned by digest).

## How it talks to the backend

The dashboard calls only the gateway. `src/lib/api-client.ts` builds one
Axios client per gateway prefix; it never calls a service port directly:

| Client            | Gateway path                             | Service   |
| ----------------- | ---------------------------------------- | --------- |
| `identityClient`  | `/auth/...`, `/api/v1/identity/...`      | identity  |
| `apiClient`       | `/api/v1/tools/...`, `/api/v1/tasks/...` | tools     |
| `dataClient`      | `/api/v1/data/...`                       | data      |
| `guardianClient`  | `/api/v1/guardian/...`                   | guardian  |
| `responderClient` | `/api/v1/responder/...`                  | responder |
| `cspmClient`      | `/api/v1/cspm/...`                       | cspm      |
| `agentsClient`    | `/api/v1/agents/...`                     | agents    |

In the root `docker-compose.yml` stack, the gateway serves both the dashboard
and the API on one origin (`https://localhost`, self-signed certificate in
development), so every request is relative to the page's origin.

## Authentication

- Sign-in posts the credentials to `/auth/jwt/login` through the gateway and
  stores the returned JWT in a cookie named `auth_token`. The cookie is set
  from JavaScript with `js-cookie` (`src/components/auth-provider.tsx`), so it
  is **not** `HttpOnly`; it is `SameSite=Strict`, expires after 7 days, and is
  `Secure` when the page is served over HTTPS. The API client sends it as an
  `Authorization: Bearer` header.
- `src/proxy.ts` redirects a request without the cookie away from the
  protected routes. This only checks that the cookie is present; the gateway
  and identity validate the token on every API call.
- Sign-out revokes the token at `/auth/jwt/logout` before deleting the cookie.
- There are no default credentials. The first superuser is created by the
  identity service from `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` in
  the repository's `.env`. Passwords must be 12 to 128 characters and must
  not contain the account's email address; identity also refuses the most common
  passwords (`src/lib/password-policy.ts` mirrors the rule for form hints).
- An account created by a team admin has `must_change_password` set and is
  sent to `/auth/change-password` after sign-in.

## Configuration

Next.js compiles `NEXT_PUBLIC_*` values into the browser bundle at build time,
so they are build arguments of the production image, not runtime settings.

| Variable                  | Read by                                   | Meaning                                                                                                                                                                                                                                                                             |
| ------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NEXT_PUBLIC_GATEWAY_URL` | `src/lib/api-client.ts`, `next.config.js` | Origin of the gateway. Empty (the default): call the API on the page's own origin, which is right when the gateway serves the dashboard. Set it only when the dashboard runs on another origin, such as `next dev` on port 3000; that origin is then added to the CSP `connect-src` |
| `NEXT_PUBLIC_USE_GATEWAY` | `src/lib/api-client.ts`                   | Defaults to on. `false` only for development against a bare service                                                                                                                                                                                                                 |
| `NEXT_PUBLIC_APP_URL`     | `src/app/layout.tsx`                      | Public URL of the dashboard, for absolute links in page metadata. Defaults to `http://localhost:3000`                                                                                                                                                                               |
| `INTERNAL_GATEWAY_URL`    | `src/lib/api-client.ts`                   | Server side only: the gateway URL for requests made during server rendering. The root compose file sets it to `http://open-security-gateway:8080`                                                                                                                                   |

See [.env.example](.env.example) and, for production, the deployment guide,
section [The dashboard's browser settings](../docs/guides/deployment.md#the-dashboards-browser-settings).

## Running it

### With the full stack

The root `docker-compose.yml` builds the `dashboard` service from
`Dockerfile.dev` (the Next.js dev server) and puts it behind the gateway.
Start the stack as described in the root README, then open
`https://localhost`.

The container runs as the unprivileged `nextjs` user (uid 1001) and
bind-mounts only `src/` and `public/` from this directory, so edits there
reload live whatever user owns the checkout. Everything else comes from the
image: after changing `package.json`, `next.config.js`, `tsconfig.json` or
`postcss.config.js`, rebuild with `docker compose up -d --build dashboard`.
The server writes `next-env.d.ts` and `.next/` inside the container, never
into the checkout.

### Local development server

Requires Node.js 24 and npm (the repository ships `package-lock.json`).

```bash
cd open-security-dashboard
npm ci
cp .env.example .env.local
# In .env.local, set NEXT_PUBLIC_GATEWAY_URL=https://localhost to reach the
# gateway of a running stack.
npm run dev
```

Then open `http://localhost:3000`. The browser has to trust the gateway's
certificate (or you accept it once at `https://localhost`), otherwise every
API call fails. The gateway accepts cross-origin calls from the origins in
`CORS_ORIGINS` only; `docker-compose.yml` defaults it to
`http://localhost:3000`, this server's origin. For another port or host,
set `CORS_ORIGINS` in `.env` and recreate the gateway.

### Production image

`Dockerfile` is a multi-stage build:

1. `base`: `node:24-alpine`, with the build metadata `GIT_SHA` and
   `BUILD_DATE` as labels and environment variables.
2. `deps`: `npm ci` from `package.json` and `package-lock.json`.
3. `builder`: copies the source and runs `npm run build`, with
   `NEXT_PUBLIC_GATEWAY_URL`, `NEXT_PUBLIC_USE_GATEWAY` and
   `NEXT_PUBLIC_APP_URL` as build arguments.
4. `runner`: the standalone output (`output: 'standalone'` in
   `next.config.js`) and static assets, run as the non-root `nextjs` user
   with `node server.js` on port 3000.

```bash
docker build \
  --build-arg NEXT_PUBLIC_GATEWAY_URL= \
  --build-arg NEXT_PUBLIC_APP_URL=https://wildbox.example.com \
  -t wildbox-dashboard .
```

`docker-compose.prod.yml` at the repository root passes these build
arguments from the root `.env`.

## Scripts

| Script                            | Command                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| `npm run dev`                     | `next dev`                                                 |
| `npm run build`                   | `next build`                                               |
| `npm run start`                   | `next start`                                               |
| `npm run lint`                    | `eslint . --max-warnings=0`                                |
| `npm run type-check`              | `tsc --noEmit`                                             |
| `npm run format` / `format:check` | Prettier write / check                                     |
| `npm run test:e2e`                | `playwright test` (see [tests/README.md](tests/README.md)) |

## Project structure

```text
src/
├── app/                 # App Router pages (see "Pages")
│   ├── api/admin/analytics/route.ts
│   ├── layout.tsx, providers.tsx, page.tsx, globals.css
│   ├── error.tsx, global-error.tsx, not-found.tsx
│   └── admin/ ai-analysis/ api-docs/ auth/ cloud-security/ dashboard/
│       response/ settings/ threat-intel/ toolbox/ vulnerabilities/
├── components/
│   ├── ui/              # Radix-based UI primitives
│   ├── toolbox/         # Tool form, runner, task panel, result view
│   ├── auth-provider.tsx, main-layout.tsx, theme-provider.tsx, json-view.tsx
├── hooks/               # use-auth, use-threat-lookup, use-responder-playbooks, ...
├── lib/                 # api-client, agents-api, tools-api, tool-schema, password-policy, utils
├── types/
└── proxy.ts             # Route guard (Next.js 16 proxy, formerly middleware)
```

## Security headers

`next.config.js` sets `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` and a
Content Security Policy. The CSP allows `'unsafe-inline'` scripts, and
`'unsafe-eval'` only in development (`next dev` needs it).

## License

MIT, see [LICENSE](../LICENSE).
