'use client'

import { useEffect } from 'react'

/**
 * Top-level error boundary. Catches errors thrown in the root layout itself
 * (which the route-level error.tsx cannot), and replaces the whole document.
 * It must render its own <html>/<body>, and can't rely on the app's styles or
 * components — keep it self-contained with inline styles.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#0a0b0d',
          color: '#e7e9ee',
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
          padding: '1rem',
        }}
      >
        <div style={{ maxWidth: '28rem', textAlign: 'center' }}>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Something went wrong
          </h1>
          <p style={{ color: '#9aa1ac', marginBottom: '1.5rem', lineHeight: 1.6 }}>
            The dashboard hit an unexpected error and couldn&rsquo;t render. Please try again.
          </p>
          <button
            onClick={() => reset()}
            style={{
              background: '#3b82f6',
              color: '#fff',
              border: 'none',
              borderRadius: '8px',
              padding: '0.5rem 1.25rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
          {error.digest && (
            <p style={{ color: '#6b7280', fontSize: '0.75rem', marginTop: '1rem' }}>
              Error reference: {error.digest}
            </p>
          )}
        </div>
      </body>
    </html>
  )
}
