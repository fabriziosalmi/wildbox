'use client'

import { useEffect, useState } from 'react'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Activity, Database, Zap, Globe } from 'lucide-react'
import { identityClient, dataClient, getDataPath } from '@/lib/api-client'

export interface SystemHealthData {
  avgResponseTime: number | null
  errorRate: number | null
  servicesOnline: number
  totalServices: number
  gatewayStatus: string
  identityStatus: string
  databaseStatus: string
  redisStatus: string
}

interface SystemHealthProps {
  onHealthUpdate?: (health: SystemHealthData) => void
  autoRefresh?: boolean
  refreshInterval?: number
}

export function SystemHealth({ 
  onHealthUpdate, 
  autoRefresh = false, 
  refreshInterval = 30000 
}: SystemHealthProps) {
  const [health, setHealth] = useState<SystemHealthData>({
    avgResponseTime: null,
    errorRate: null,
    servicesOnline: 0,
    totalServices: 4,
    gatewayStatus: 'unknown',
    identityStatus: 'unknown',
    databaseStatus: 'unknown',
    redisStatus: 'unknown'
  })
  const [isLoading, setIsLoading] = useState(true)

  const fetchSystemHealth = async () => {
    try {
      setIsLoading(true)
      
      // Check health of various services
      const [identityHealth, gatewayHealth, dataHealth] = await Promise.allSettled([
        identityClient.get('/api/v1/identity/health').catch(() => null),
        fetch(`${process.env.NEXT_PUBLIC_GATEWAY_URL || ''}/health`)
          .then(r => r.json())
          .catch(() => null),
        dataClient.get(getDataPath('/health')).catch(() => null)
      ])

      let servicesOnline = 0
      const totalServices = 4

      // Update service statuses
      const identityStatus = identityHealth.status === 'fulfilled' && identityHealth.value 
        ? 'online' 
        : 'offline'
      const gatewayStatus = gatewayHealth.status === 'fulfilled' && gatewayHealth.value 
        ? 'online' 
        : 'offline'
      const databaseStatus = identityStatus === 'online' ? 'healthy' : 'unknown'
      const redisStatus = identityStatus === 'online' ? 'connected' : 'unknown'

      if (identityStatus === 'online') servicesOnline++
      if (gatewayStatus === 'online') servicesOnline++
      if (databaseStatus === 'healthy') servicesOnline++
      if (redisStatus === 'connected') servicesOnline++

      // Metrics require Prometheus integration
      // See docs/OBSERVABILITY_ROADMAP.md for implementation plan
      const avgResponseTime = null
      const errorRate = null

      const healthData: SystemHealthData = {
        avgResponseTime,
        errorRate,
        servicesOnline,
        totalServices,
        gatewayStatus,
        identityStatus,
        databaseStatus,
        redisStatus
      }

      setHealth(healthData)
      onHealthUpdate?.(healthData)
    } catch (error) {
      console.error('Failed to fetch system health:', error)
      
      // Set default error state
      const errorHealthData: SystemHealthData = {
        avgResponseTime: null,
        errorRate: null,
        servicesOnline: 0,
        totalServices: 4,
        gatewayStatus: 'unknown',
        identityStatus: 'unknown',
        databaseStatus: 'unknown',
        redisStatus: 'unknown'
      }
      
      setHealth(errorHealthData)
      onHealthUpdate?.(errorHealthData)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchSystemHealth()

    if (autoRefresh) {
      const interval = setInterval(fetchSystemHealth, refreshInterval)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, refreshInterval])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
      case 'healthy':
      case 'connected':
        return 'text-green-600'
      case 'offline':
        return 'text-red-600'
      default:
        return 'text-gray-500'
    }
  }

  const getStatusBadgeVariant = (status: string): "default" | "secondary" | "destructive" | "outline" => {
    switch (status) {
      case 'online':
      case 'healthy':
      case 'connected':
        return 'default'
      case 'offline':
        return 'destructive'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
              <Globe className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Gateway</p>
              <p className={`text-lg font-semibold ${getStatusColor(health.gatewayStatus)}`}>
                {health.gatewayStatus}
              </p>
            </div>
          </div>
          <Badge variant={getStatusBadgeVariant(health.gatewayStatus)}>
            {health.gatewayStatus}
          </Badge>
        </div>
      </Card>

      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Identity Service</p>
              <p className={`text-lg font-semibold ${getStatusColor(health.identityStatus)}`}>
                {health.identityStatus}
              </p>
            </div>
          </div>
          <Badge variant={getStatusBadgeVariant(health.identityStatus)}>
            {health.identityStatus}
          </Badge>
        </div>
      </Card>

      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
              <Database className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Database</p>
              <p className={`text-lg font-semibold ${getStatusColor(health.databaseStatus)}`}>
                {health.databaseStatus}
              </p>
            </div>
          </div>
          <Badge variant={getStatusBadgeVariant(health.databaseStatus)}>
            {health.databaseStatus}
          </Badge>
        </div>
      </Card>

      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900 rounded-lg flex items-center justify-center">
              <Zap className="w-5 h-5 text-orange-600" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Redis Cache</p>
              <p className={`text-lg font-semibold ${getStatusColor(health.redisStatus)}`}>
                {health.redisStatus}
              </p>
            </div>
          </div>
          <Badge variant={getStatusBadgeVariant(health.redisStatus)}>
            {health.redisStatus}
          </Badge>
        </div>
      </Card>
    </div>
  )
}
