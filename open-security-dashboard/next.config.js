// Next.js' dev server (next dev) compiles with eval-source-map, which needs
// 'unsafe-eval' in the CSP. Production (next start) does not — keep it strict.
const isDev = process.env.NODE_ENV !== 'production'
const scriptSrc = isDev
  ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
  : "script-src 'self' 'unsafe-inline'"

// The dashboard calls the gateway on its own origin ('self') unless
// NEXT_PUBLIC_GATEWAY_URL names another one; that origin must then be allowed
// to connect to, or the browser blocks every API call. Read at build time,
// like the variable itself (see src/lib/api-client.ts).
const gatewayOrigin = (() => {
  try {
    return process.env.NEXT_PUBLIC_GATEWAY_URL
      ? new URL(process.env.NEXT_PUBLIC_GATEWAY_URL).origin
      : ''
  } catch {
    throw new Error(
      `NEXT_PUBLIC_GATEWAY_URL is not a URL: ${JSON.stringify(process.env.NEXT_PUBLIC_GATEWAY_URL)}`
    )
  }
})()
const connectSrc = [
  "'self'",
  gatewayOrigin,
  'http://localhost:*',
  'https://localhost:*',
  'ws://localhost:*',
  'wss://localhost:*',
]
  .filter(Boolean)
  .join(' ')

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  images: {
    // images.domains is deprecated in Next 16; this is the same allowance.
    remotePatterns: [{ hostname: 'localhost' }],
  },
  async headers() {
    return [
      {
        // Security headers for all routes
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          {
            key: 'Content-Security-Policy',
            value: `default-src 'self'; ${scriptSrc}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src ${connectSrc};`,
          },
        ],
      },
    ]
  },
}

module.exports = nextConfig
