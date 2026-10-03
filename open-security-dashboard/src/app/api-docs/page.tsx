import Link from 'next/link'
import { BookOpen, ExternalLink, KeyRound, Route } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { MainLayout } from '@/components/main-layout'

/*
 * Where the Wildbox APIs are and how to call them, and nothing else.
 *
 * This page used to carry a hand-written endpoint catalogue that described
 * routes no service serves (responder GET /v1/metrics, identity GET
 * /api/v1/user/profile), a "healthy" badge on every service that no probe
 * ever set, Free / Business plan labels that nothing enforces, and an
 * example response with invented indicator counts (#572). The services'
 * OpenAPI pages are not routed through the gateway (identity's are off in
 * production), so the page points at the references maintained in the
 * repository and on the documentation site instead of copying them.
 */

const REPO_DOCS = 'https://github.com/fabriziosalmi/wildbox/blob/main/docs/api'
const SITE = 'https://www.wildbox.io'

interface GatewayRoute {
  prefix: string
  service: string
  upstream: string
  reference?: string
  note?: string
}

/* Mirrors open-security-gateway/nginx/conf.d/wildbox_gateway.conf, as the
   gateway routes table on the documentation site does. */
const GATEWAY_ROUTES: GatewayRoute[] = [
  {
    prefix: '/auth/jwt/…, /auth/register',
    service: 'identity',
    upstream: '/api/v1/auth/…',
    reference: `${REPO_DOCS}/identity/endpoints.md`,
    note: 'No token needed to log in or register.',
  },
  {
    prefix: '/api/v1/identity/…',
    service: 'identity',
    upstream: '/api/v1/…',
    reference: `${REPO_DOCS}/identity/endpoints.md`,
  },
  {
    prefix: '/api/v1/data/…',
    service: 'data',
    upstream: '/api/v1/…',
    reference: `${REPO_DOCS}/data/endpoints.md`,
  },
  {
    prefix: '/api/v1/guardian/…',
    service: 'guardian',
    upstream: '/api/v1/…',
    reference: `${REPO_DOCS}/guardian/endpoints.md`,
  },
  {
    prefix: '/api/v1/responder/…',
    service: 'responder',
    upstream: '/v1/…',
    reference: `${REPO_DOCS}/responder/endpoints.md`,
  },
  {
    prefix: '/api/v1/agents/…',
    service: 'agents',
    upstream: '/v1/…',
    reference: `${REPO_DOCS}/agents/endpoints.md`,
  },
  {
    prefix: '/api/v1/tools, /api/v1/tools/…',
    service: 'tools',
    upstream: '/api/tools/…',
    reference: `${REPO_DOCS}/tools/endpoints.md`,
  },
  {
    prefix: '/api/v1/cspm/…',
    service: 'cspm',
    upstream: '/api/v1/…',
    note: 'No written reference yet.',
  },
  {
    prefix: '/api/v1/automations/…',
    service: 'automations',
    upstream: '/…',
    note: 'Only with the automations Compose profile; 502 otherwise.',
  },
]

const LOGIN_EXAMPLE = `curl -X POST "https://<gateway-host>/auth/jwt/login" \\
  -d "username=<email>" -d "password=<password>"`

const CALL_EXAMPLE = `curl "https://<gateway-host>/api/v1/guardian/vulnerabilities/" \\
  -H "Authorization: Bearer <access_token>"`

function ExternalAnchor({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
    >
      {children}
      <ExternalLink className="h-3 w-3" aria-hidden="true" />
    </a>
  )
}

export default function APIDocumentation() {
  return (
    <MainLayout>
      <div className="space-y-6" data-testid="api-docs">
        <div>
          <h1 className="text-3xl font-bold">API Documentation</h1>
          <p className="mt-2 text-muted-foreground">
            Every Wildbox API is reached through the gateway, the same host that serves this
            dashboard. The endpoint references live with the code and on the documentation site.
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="h-5 w-5" />
              References
            </CardTitle>
            <CardDescription>Maintained in the repository, next to the code</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm">
              <li>
                <ExternalAnchor href={`${REPO_DOCS}/README.md`}>
                  API documentation index
                </ExternalAnchor>
                <span className="text-muted-foreground">
                  : one endpoint reference per service, in <code>docs/api/</code>.
                </span>
              </li>
              <li>
                <ExternalAnchor href={`${SITE}/docs.html#gateway-routes`}>
                  Gateway routes
                </ExternalAnchor>
                <span className="text-muted-foreground">
                  : the prefixes the gateway serves and which need authentication.
                </span>
              </li>
              <li>
                <ExternalAnchor href={`${SITE}/guides/authentication/`}>
                  Authentication and sessions
                </ExternalAnchor>
                <span className="text-muted-foreground">
                  : login, token lifetime, logout and the failed-login lockout.
                </span>
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5" />
              Authentication
            </CardTitle>
            <CardDescription>Log in once, then send the token with every request</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>
              <code>POST /auth/jwt/login</code> takes a form-encoded <code>username</code> (the
              email address) and <code>password</code> and returns an <code>access_token</code>.
            </p>
            <pre className="overflow-x-auto rounded bg-gray-900 p-3 text-xs text-white">
              {LOGIN_EXAMPLE}
            </pre>
            <p>
              Send it as <code>Authorization: Bearer &lt;access_token&gt;</code>. The gateway also
              accepts a personal API key in the <code>X-API-Key</code> header; create one under{' '}
              <Link href="/settings/api-keys" className="text-primary hover:underline">
                Settings, API Keys
              </Link>
              .
            </p>
            <pre className="overflow-x-auto rounded bg-gray-900 p-3 text-xs text-white">
              {CALL_EXAMPLE}
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Route className="h-5 w-5" />
              Gateway routes
            </CardTitle>
            <CardDescription>
              Each prefix is forwarded to its service with the upstream path shown. Every{' '}
              <code>/api/v1/</code> prefix needs a token or an API key, and any other path under{' '}
              <code>/api/</code> answers 404.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-lg border">
              <table className="w-full text-sm" data-testid="api-docs-routes">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="p-3 text-left font-medium">Gateway path</th>
                    <th className="p-3 text-left font-medium">Service</th>
                    <th className="p-3 text-left font-medium">Upstream path</th>
                    <th className="p-3 text-left font-medium">Reference</th>
                  </tr>
                </thead>
                <tbody>
                  {GATEWAY_ROUTES.map(route => (
                    <tr key={route.prefix} className="border-b last:border-0">
                      <td className="p-3 font-mono text-xs">{route.prefix}</td>
                      <td className="p-3">{route.service}</td>
                      <td className="p-3 font-mono text-xs">{route.upstream}</td>
                      <td className="p-3">
                        {route.reference && (
                          <ExternalAnchor href={route.reference}>endpoints.md</ExternalAnchor>
                        )}
                        {route.note && (
                          <span className="block text-xs text-muted-foreground">{route.note}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs text-muted-foreground">
              The services&apos; interactive OpenAPI pages are not routed through the gateway, and
              identity&apos;s are disabled in production.
            </p>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  )
}
