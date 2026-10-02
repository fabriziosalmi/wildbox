import { NextRequest, NextResponse } from 'next/server'
import { identityClient, getIdentityPath } from '@/lib/api-client'

export async function GET(request: NextRequest) {
  try {
    // Verify authentication: forward the auth token to identity service for validation
    const authToken = request.cookies.get('auth_token')?.value
    if (!authToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Fetch real analytics data from identity service, forwarding the auth token
    // The identity service will verify the token and check superuser status
    const [systemStats, usageSummary] = await Promise.allSettled([
      identityClient.get(getIdentityPath('/api/v1/analytics/admin/system-stats?days=30')),
      identityClient.get(getIdentityPath('/api/v1/analytics/admin/usage-summary'))
    ])

    // Extract analytics data
    const analytics = systemStats.status === 'fulfilled' ? systemStats.value : null
    const usage = usageSummary.status === 'fulfilled' ? usageSummary.value : null

    // Combine and format response
    const response = {
      success: true,
      data: {
        systemStats: analytics || null,
        usageSummary: usage || null,
        lastUpdated: new Date().toISOString()
      }
    }

    return NextResponse.json(response)
  } catch {
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch analytics data',
        data: null
      },
      { status: 500 }
    )
  }
}
