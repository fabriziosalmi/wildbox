'use client'

import { Card } from '@/components/ui/card'
import { Users, UserCheck, Crown, Activity } from 'lucide-react'

export interface SystemStatsData {
  totalUsers: number
  activeUsers: number
  superAdmins: number
  totalTeams: number
  newUsersThisWeek: number
  apiRequestsToday: number
}

interface SystemStatsCardsProps {
  stats: SystemStatsData
  isLoading?: boolean
}

export function SystemStatsCards({ stats, isLoading = false }: SystemStatsCardsProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <Card key={i} className="p-6 animate-pulse">
            <div className="h-12 bg-gray-200 dark:bg-gray-700 rounded" />
          </Card>
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-6" data-testid="admin-stats-cards">
      <Card className="p-6" data-testid="total-users-card">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
            <Users className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Total Users</p>
            <p className="text-2xl font-bold" data-testid="total-users-value">
              {stats.totalUsers}
            </p>
            <p className="text-xs text-muted-foreground">
              +{stats.newUsersThisWeek} this week
            </p>
          </div>
        </div>
      </Card>
      
      <Card className="p-6" data-testid="active-users-card">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
            <UserCheck className="w-6 h-6 text-green-600" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Active Users</p>
            <p className="text-2xl font-bold" data-testid="active-users-value">
              {stats.activeUsers}
            </p>
            <p className="text-xs text-muted-foreground">
              {Math.round((stats.activeUsers / stats.totalUsers) * 100) || 0}% of total
            </p>
          </div>
        </div>
      </Card>

      <Card className="p-6" data-testid="super-admins-card">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-red-100 dark:bg-red-900 rounded-lg flex items-center justify-center">
            <Crown className="w-6 h-6 text-red-600" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Super Admins</p>
            <p className="text-2xl font-bold" data-testid="super-admins-value">
              {stats.superAdmins}
            </p>
            <p className="text-xs text-muted-foreground">
              Elevated privileges
            </p>
          </div>
        </div>
      </Card>

      <Card className="p-6" data-testid="api-requests-card">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
            <Activity className="w-6 h-6 text-purple-600" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">API Requests</p>
            <p className="text-2xl font-bold" data-testid="api-requests-value">
              {stats.apiRequestsToday.toLocaleString()}
            </p>
            <p className="text-xs text-muted-foreground">
              Today
            </p>
          </div>
        </div>
      </Card>
    </div>
  )
}
