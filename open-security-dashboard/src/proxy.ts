import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// Routes that require authentication
const protectedRoutes = [
  '/dashboard',
  '/threat-intel',
  '/toolbox',
  '/cloud-security',
  '/vulnerabilities',
  '/response',
  '/ai-analysis',
  '/settings',
  '/api-docs',
  // Where an account with an initial password is sent first (#573).
  '/auth/change-password',
]

// Routes that require superuser access
const adminRoutes = ['/admin']

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl
  const authToken = request.cookies.get('auth_token')?.value

  // Check if route requires authentication
  const isProtected = protectedRoutes.some(route => pathname.startsWith(route))
  const isAdmin = adminRoutes.some(route => pathname.startsWith(route))

  if ((isProtected || isAdmin) && !authToken) {
    // Redirect to login if no auth token
    const loginUrl = new URL('/', request.url)
    loginUrl.searchParams.set('redirect', pathname)
    return NextResponse.redirect(loginUrl)
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/threat-intel/:path*',
    '/toolbox/:path*',
    '/cloud-security/:path*',
    '/vulnerabilities/:path*',
    '/response/:path*',
    '/ai-analysis/:path*',
    '/settings/:path*',
    '/api-docs/:path*',
    '/admin/:path*',
    '/auth/change-password',
  ],
}
