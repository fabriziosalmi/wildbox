import { NextResponse } from 'next/server'
import { identityClient, getIdentityPath } from '@/lib/api-client'

export async function GET() {
  try {
    // Fetch real analytics data from identity service
    const [systemStats, usageSummary] = await Promise.allSettled([
      identityClient.get(getIdentityPath('/api/v1/analytics/admin/analytics/system-stats?days=30')),
      identityClient.get(getIdentityPath('/api/v1/analytics/admin/analytics/usage-summary'))
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
  } catch (error) {
    console.error('Failed to fetch admin analytics:', error)
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
