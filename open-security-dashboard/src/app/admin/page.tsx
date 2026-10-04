'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuth } from '@/components/auth-provider'
import { MainLayout } from '@/components/main-layout'
import { identityClient, getIdentityPath, gatewayBaseUrl } from '@/lib/api-client'
import Cookies from 'js-cookie'
import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  PASSWORD_RULE_HINT,
  passwordPolicyProblem,
} from '@/lib/password-policy'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Shield,
  Users,
  Search,
  Trash2,
  UserCheck,
  UserX,
  Calendar,
  Mail,
  Crown,
  Filter,
  Settings,
  Database,
  Activity,
  UserPlus,
  Lock,
  AtSign,
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import type { AdminSystemAnalytics, AdminUsageSummary } from '@/types'
import { getErrorMessage } from '@/lib/utils'
import { useRouter } from 'next/navigation'

interface CanDeleteResponse {
  can_delete: boolean
  can_force_delete: boolean
  reasons: string[]
  force_delete_info: string[]
}

interface AdminUserData {
  id: string
  email: string
  is_active: boolean
  is_superuser: boolean
  created_at: string
  updated_at: string
  team_memberships?: Array<{
    user_id: string
    team_id: string
    team_name: string
    role: string
    joined_at: string
  }>
}

type ProbeStatus = 'online' | 'offline' | 'unknown'
type CheckStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown'

interface SystemHealthState {
  gatewayStatus: ProbeStatus
  identityStatus: ProbeStatus
  databaseStatus: CheckStatus
  redisStatus: CheckStatus
}

/** identity's GET /health, through the gateway at /api/v1/identity/health. */
interface IdentityHealth {
  status?: string
  checks?: Record<string, { status?: string } | undefined>
}

const UNKNOWN_HEALTH: SystemHealthState = {
  gatewayStatus: 'unknown',
  identityStatus: 'unknown',
  databaseStatus: 'unknown',
  redisStatus: 'unknown',
}

const SEARCH_DEBOUNCE_MS = 300

/** The stat cards' counts, taken from an unfiltered user list. */
function statsFromUsers(users: AdminUserData[]) {
  const oneWeekAgo = new Date()
  oneWeekAgo.setDate(oneWeekAgo.getDate() - 7)
  return {
    totalUsers: users.length,
    activeUsers: users.filter(u => u.is_active).length,
    superAdmins: users.filter(u => u.is_superuser).length,
    totalTeams: new Set(users.flatMap(u => u.team_memberships?.map(tm => tm.team_id) || [])).size,
    newUsersThisWeek: users.filter(u => new Date(u.created_at) >= oneWeekAgo).length,
  }
}

function checkStatus(value: string | undefined): CheckStatus {
  return value === 'healthy' || value === 'degraded' || value === 'unhealthy' ? value : 'unknown'
}

const PROBE_LABELS: Record<ProbeStatus, [string, string]> = {
  online: ['Online', 'text-green-600'],
  offline: ['Offline', 'text-red-600'],
  unknown: ['Checking...', 'text-muted-foreground'],
}

const CHECK_LABELS: Record<CheckStatus, [string, string]> = {
  healthy: ['Healthy', 'text-green-600'],
  degraded: ['Degraded', 'text-yellow-600'],
  unhealthy: ['Unhealthy', 'text-red-600'],
  unknown: ['Unknown', 'text-muted-foreground'],
}

function HealthRow({
  label,
  testId,
  status,
}: {
  label: string
  testId: string
  status: [string, string]
}) {
  const [text, color] = status
  return (
    <div className="flex justify-between text-sm">
      <span>{label}</span>
      <span className={color} data-testid={testId}>
        ● {text}
      </span>
    </div>
  )
}

export default function AdminPage() {
  const { user, isLoading: authLoading } = useAuth()
  const { toast } = useToast()
  const router = useRouter()
  const [users, setUsers] = useState<AdminUserData[]>([])
  // Latest fetched list, for the stats fallback: reading `users` there
  // would capture the list as it was when the callback was created.
  const usersRef = useRef<AdminUserData[]>([])
  // Whether the stat cards hold identity's analytics, which count every user,
  // rather than counts taken from the (at most 100-row) list.
  const analyticsLoadedRef = useRef(false)
  const [isLoading, setIsLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  // What the user list is actually filtered by: the search box, once typing
  // has paused (or on Enter / Search), and the status filter.
  const [appliedSearch, setAppliedSearch] = useState('')
  const [filterActive, setFilterActive] = useState<boolean | null>(null)
  // Responses to earlier searches that arrive late must not replace the list.
  const usersRequestRef = useRef(0)
  const [systemStats, setSystemStats] = useState({
    totalUsers: 0,
    activeUsers: 0,
    superAdmins: 0,
    totalTeams: 0,
    newUsersThisWeek: 0,
    // Keys used in the last 24 hours, from identity's usage summary; null
    // when it could not be read.
    apiKeysUsedToday: null as number | null,
  })
  const [systemHealth, setSystemHealth] = useState<SystemHealthState>(UNKNOWN_HEALTH)

  // Create user form state
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [isCreatingUser, setIsCreatingUser] = useState(false)
  const [createUserForm, setCreateUserForm] = useState({
    email: '',
    password: '',
    is_superuser: false,
    is_active: true,
  })

  // Check if user is superuser -- once the session has been read. On a
  // direct load or a reload the user is still null while /users/me is in
  // flight, and redirecting then sent every admin to /dashboard whenever that
  // call took longer than the first render.
  useEffect(() => {
    if (!authLoading && !user?.is_superuser) {
      router.push('/dashboard')
    }
  }, [authLoading, user, router])

  // Debounce the search box: the list follows what is typed once typing
  // pauses, instead of on every keystroke.
  useEffect(() => {
    const timer = setTimeout(() => setAppliedSearch(searchTerm.trim()), SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [searchTerm])

  const fetchSystemHealth = useCallback(async () => {
    // Every status below comes from a response. Database and Redis are what
    // identity's /health reports about its own dependencies; they used to be
    // set to healthy whenever identity answered, and identity's probe went to
    // a path that does not exist, so the card showed Offline and Unknown on a
    // healthy stack (#559).
    const [identityHealth, gatewayHealth] = await Promise.allSettled([
      identityClient.get<IdentityHealth>(getIdentityPath('/api/v1/health')),
      fetch(`${gatewayBaseUrl}/health`).then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      }),
    ])

    const identity = identityHealth.status === 'fulfilled' ? identityHealth.value : null
    setSystemHealth({
      gatewayStatus: gatewayHealth.status === 'fulfilled' ? 'online' : 'offline',
      identityStatus: identity ? 'online' : 'offline',
      databaseStatus: checkStatus(identity?.checks?.database?.status),
      redisStatus: checkStatus(identity?.checks?.redis?.status),
    })
  }, [])

  const fetchSystemStats = useCallback(async () => {
    const [systemAnalytics, usageSummary] = await Promise.allSettled([
      identityClient.get<AdminSystemAnalytics>(
        getIdentityPath('/api/v1/analytics/admin/system-stats?days=30')
      ),
      identityClient.get<AdminUsageSummary>(
        getIdentityPath('/api/v1/analytics/admin/usage-summary')
      ),
    ])

    const analytics = systemAnalytics.status === 'fulfilled' ? systemAnalytics.value : null
    const usage = usageSummary.status === 'fulfilled' ? usageSummary.value : null

    if (analytics) {
      analyticsLoadedRef.current = true
      setSystemStats({
        totalUsers: analytics.users.total,
        activeUsers: analytics.users.active,
        superAdmins: analytics.users.super_admins,
        totalTeams: analytics.teams.total,
        newUsersThisWeek: analytics.users.new_this_week,
        apiKeysUsedToday: usage ? usage.summary.api_keys_active : null,
      })
    } else {
      // Without the analytics, the counts come from the unfiltered user list
      // (see fetchUsers). Nothing is invented for what the list cannot tell.
      analyticsLoadedRef.current = false
      setSystemStats(prev => ({
        ...prev,
        ...statsFromUsers(usersRef.current),
        apiKeysUsedToday: usage ? usage.summary.api_keys_active : null,
      }))
    }
  }, [])

  const fetchUsers = useCallback(async () => {
    const requestId = ++usersRequestRef.current
    // identity filters the list itself: email_filter is a case-insensitive
    // substring match on the email, is_active an exact match. The page used
    // to ignore both controls and always load the first 100 users (#559).
    const params: Record<string, string | number | boolean> = { limit: 100 }
    if (appliedSearch) params.email_filter = appliedSearch
    if (filterActive !== null) params.is_active = filterActive
    const unfiltered = !appliedSearch && filterActive === null

    try {
      setIsLoading(true)
      const data = await identityClient.get<AdminUserData[]>(
        getIdentityPath('/api/v1/admin/users'),
        params
      )
      if (requestId !== usersRequestRef.current) return

      setUsers(data)
      if (unfiltered) {
        usersRef.current = data
        if (!analyticsLoadedRef.current) {
          setSystemStats(prev => ({ ...prev, ...statsFromUsers(data) }))
        }
      }
    } catch (error) {
      if (requestId !== usersRequestRef.current) return
      console.error('Failed to fetch users:', error)
      toast({
        title: 'Error',
        description: 'Failed to load users',
        variant: 'destructive',
      })
    } finally {
      if (requestId === usersRequestRef.current) setIsLoading(false)
    }
  }, [toast, appliedSearch, filterActive])

  useEffect(() => {
    if (user?.is_superuser) {
      fetchUsers()
    }
  }, [user, fetchUsers])

  useEffect(() => {
    if (user?.is_superuser) {
      fetchSystemStats()
      fetchSystemHealth()
    }
  }, [user, fetchSystemStats, fetchSystemHealth])

  const handleSearch = () => {
    // Apply what is typed now, without waiting for the debounce.
    const term = searchTerm.trim()
    if (term === appliedSearch) {
      fetchUsers()
    } else {
      setAppliedSearch(term)
    }
  }

  const handleToggleUserStatus = async (userId: string, currentStatus: boolean) => {
    try {
      await identityClient.patch(
        `/api/v1/identity/admin/users/${userId}/status?is_active=${!currentStatus}`
      )

      toast({
        title: 'Success',
        description: `User ${!currentStatus ? 'activated' : 'deactivated'} successfully`,
      })

      fetchUsers()
    } catch (error) {
      console.error('Failed to toggle user status:', error)
      toast({
        title: 'Error',
        description: 'Failed to update user status',
        variant: 'destructive',
      })
    }
  }

  const handleDeleteUser = async (
    userId: string,
    userEmail: string,
    forceDelete: boolean = false
  ) => {
    // Check if this is a superuser (except primary superadmin)
    const targetUser = users.find(u => u.id === userId)
    const isSuperuser = targetUser?.is_superuser

    // First check if the user can be deleted (unless forcing)
    if (!forceDelete) {
      try {
        const checkResponse = await identityClient.get<CanDeleteResponse>(
          `/api/v1/identity/admin/users/${userId}/can-delete`
        )

        if (!checkResponse.can_delete) {
          // Check if force delete is possible
          if (checkResponse.can_force_delete) {
            let forceMessage = `User cannot be deleted normally.\n\nReasons:\n• ${checkResponse.reasons.join('\n• ')}\n\n`

            forceMessage += `As a superadmin, you can FORCE DELETE this user which will:\n• ${checkResponse.force_delete_info.join('\n• ')}\n\n`
            forceMessage += `Do you want to FORCE DELETE this user?`

            const forceConfirm = confirm(forceMessage)

            if (forceConfirm) {
              return handleDeleteUser(userId, userEmail, true)
            }
            return
          } else {
            // Cannot delete at all
            toast({
              title: 'Cannot Delete User',
              description: `User cannot be deleted:\n\n• ${checkResponse.reasons.join('\n• ')}`,
              variant: 'destructive',
            })
            return
          }
        }
      } catch (error) {
        console.error('Failed to check if user can be deleted:', error)

        // If the can-delete endpoint fails (404), assume we need force delete for superusers/team owners
        const isSuperuser = targetUser?.is_superuser
        const hasTeamOwnership =
          targetUser?.team_memberships?.some(m => m.role === 'owner') || false

        if (isSuperuser || hasTeamOwnership) {
          let forceMessage = `Cannot verify deletion safety (server error).\n\n`

          if (isSuperuser) {
            forceMessage += `This user is a superuser. `
          }
          if (hasTeamOwnership) {
            forceMessage += `This user may own teams. `
          }

          forceMessage += `\nAs a superadmin, you can FORCE DELETE this user.\n\n`
          forceMessage += `Do you want to FORCE DELETE this user?`

          const forceConfirm = confirm(forceMessage)

          if (forceConfirm) {
            return handleDeleteUser(userId, userEmail, true)
          }
          return
        }

        // Show warning but allow to continue for regular users
        toast({
          title: 'Warning',
          description: 'Could not verify if user can be deleted safely. Proceeding with caution.',
          variant: 'destructive',
        })
      }
    }

    // Different confirmation messages for normal vs force delete
    let confirmMessage = ''

    if (forceDelete) {
      confirmMessage = `FORCE DELETE: Are you sure you want to force delete ${userEmail}?\n\n`

      if (isSuperuser) {
        confirmMessage += `This will:\n- Remove superuser privileges\n- Permanently delete the user account\n`
      } else {
        confirmMessage += `This will:\n- Permanently remove the user account\n`
      }

      confirmMessage +=
        `- Transfer team ownership to other admins/members\n` +
        `- Delete teams with no other members\n` +
        `- Delete all their API keys\n\n` +
        `This action cannot be undone!`
    } else {
      confirmMessage =
        `Are you sure you want to delete ${userEmail}?\n\n` +
        `This action cannot be undone and will:\n` +
        `- Permanently remove the user account\n` +
        `- Remove them from all teams\n` +
        `- Delete all their API keys`
    }

    if (!confirm(confirmMessage)) {
      return
    }

    try {
      const deleteUrl = forceDelete
        ? `/api/v1/identity/admin/users/${userId}?force=true`
        : `/api/v1/identity/admin/users/${userId}`

      await identityClient.delete(deleteUrl)

      toast({
        title: 'Success',
        description: `User ${userEmail} ${forceDelete ? 'force ' : ''}deleted successfully`,
      })

      fetchUsers()
    } catch (error) {
      console.error('Failed to delete user:', error)

      // Extract specific error message from the API response
      // The API client rejects with an ApiError whose message already
      // carries the server's `detail`; it has no `response` to read.
      let errorMessage = getErrorMessage(error, 'Failed to delete user')

      // Provide more helpful error message for common cases
      if (
        (errorMessage.includes('owns') && errorMessage.includes('team')) ||
        errorMessage.includes('superuser')
      ) {
        if (!forceDelete) {
          errorMessage +=
            "\n\nAs a superadmin, you can force delete users who own teams or have superuser privileges. Try again and choose 'Force Delete' when prompted."
        }
      }

      toast({
        title: 'Cannot Delete User',
        description: errorMessage,
        variant: 'destructive',
      })
    }
  }

  const handlePromoteToSuperuser = async (userId: string, userEmail: string) => {
    if (
      !confirm(
        `Are you sure you want to promote ${userEmail} to superuser? This will give them full administrative access.`
      )
    ) {
      return
    }

    try {
      await identityClient.patch(`/api/v1/identity/admin/users/${userId}/role`, {
        is_superuser: true,
      })

      toast({
        title: 'Success',
        description: `User ${userEmail} promoted to superuser successfully`,
      })

      fetchUsers()
    } catch (error) {
      console.error('Failed to promote user to superuser:', error)
      toast({
        title: 'Error',
        description: 'Failed to promote user to superuser',
        variant: 'destructive',
      })
    }
  }

  const handleDemoteFromSuperuser = async (userId: string, userEmail: string) => {
    if (!confirm(`Are you sure you want to remove superuser privileges from ${userEmail}?`)) {
      return
    }

    try {
      await identityClient.patch(`/api/v1/identity/admin/users/${userId}/role`, {
        is_superuser: false,
      })

      toast({
        title: 'Success',
        description: `Superuser privileges removed from ${userEmail} successfully`,
      })

      fetchUsers()
    } catch (error) {
      console.error('Failed to demote user from superuser:', error)
      toast({
        title: 'Error',
        description: 'Failed to update user privileges',
        variant: 'destructive',
      })
    }
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!createUserForm.email || !createUserForm.password) {
      toast({
        title: 'Error',
        description: 'Email and password are required',
        variant: 'destructive',
      })
      return
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(createUserForm.email)) {
      toast({
        title: 'Error',
        description: 'Please enter a valid email address',
        variant: 'destructive',
      })
      return
    }

    // identity's password rule (#583); its reason is shown if it refuses one.
    const passwordProblem = passwordPolicyProblem(createUserForm.password, createUserForm.email)
    if (passwordProblem) {
      toast({
        title: 'Error',
        description: passwordProblem,
        variant: 'destructive',
      })
      return
    }

    try {
      setIsCreatingUser(true)

      const token = Cookies.get('auth_token')

      const response = await fetch(`${gatewayBaseUrl}/api/v1/identity/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          email: createUserForm.email,
          password: createUserForm.password,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        // identity's canonical error body carries the reason in error.message.
        throw new Error(errorData?.error?.message || errorData?.detail || `HTTP ${response.status}`)
      }

      const newUser = await response.json()

      // If user should be a superuser or inactive, update via admin endpoint
      if (createUserForm.is_superuser || !createUserForm.is_active) {
        const userId = newUser.id

        // Update superuser status if needed
        if (createUserForm.is_superuser) {
          const superuserResponse = await fetch(
            `${gatewayBaseUrl}/api/v1/identity/admin/users/${userId}/role`,
            {
              method: 'PATCH',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({
                is_superuser: true,
              }),
            }
          )

          if (!superuserResponse.ok) {
            console.warn('Failed to set superuser status for new user')
          }
        }

        // Update active status if needed
        if (!createUserForm.is_active) {
          const statusResponse = await fetch(
            `${gatewayBaseUrl}/api/v1/identity/admin/users/${userId}/status?is_active=false`,
            {
              method: 'PATCH',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
              },
            }
          )

          if (!statusResponse.ok) {
            console.warn('Failed to set inactive status for new user')
          }
        }
      }

      toast({
        title: 'Success',
        description: `User ${createUserForm.email} created successfully`,
      })

      // Reset form and close modal
      setCreateUserForm({
        email: '',
        password: '',
        is_superuser: false,
        is_active: true,
      })
      setShowCreateUser(false)

      // Refresh users list
      fetchUsers()
    } catch (error) {
      console.error('Failed to create user:', error)
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to create user'),
        variant: 'destructive',
      })
    } finally {
      setIsCreatingUser(false)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  // Helper function to check if user owns any teams
  const isTeamOwner = (user: AdminUserData) => {
    return user.team_memberships?.some(membership => membership.role === 'owner') || false
  }

  // Helper function to get owned teams count
  const getOwnedTeamsCount = (user: AdminUserData) => {
    return user.team_memberships?.filter(membership => membership.role === 'owner').length || 0
  }

  // Don't render anything if not superuser
  if (!user?.is_superuser) {
    return null
  }

  return (
    <MainLayout>
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-linear-to-br/srgb from-red-500 to-red-600">
              <Crown className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">System Administration</h1>
              <p className="text-muted-foreground">Manage users, teams, and system settings</p>
            </div>
          </div>
          <Badge variant="outline" className="border-red-600 text-red-600">
            <Shield className="mr-1 h-3 w-3" />
            Super Admin Access
          </Badge>
        </div>

        {/* Admin Stats */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-4" data-testid="admin-stats-cards">
          <Card className="p-6" data-testid="total-users-card">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900">
                <Users className="h-6 w-6 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Users</p>
                <p className="text-2xl font-bold" data-testid="total-users-value">
                  {systemStats.totalUsers}
                </p>
                <p className="text-xs text-muted-foreground">
                  +{systemStats.newUsersThisWeek} this week
                </p>
              </div>
            </div>
          </Card>

          <Card className="p-6" data-testid="active-users-card">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-100 dark:bg-green-900">
                <UserCheck className="h-6 w-6 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active Users</p>
                <p className="text-2xl font-bold" data-testid="active-users-value">
                  {systemStats.activeUsers}
                </p>
                <p className="text-xs text-muted-foreground">
                  {Math.round(
                    (systemStats.activeUsers / Math.max(systemStats.totalUsers, 1)) * 100
                  )}
                  % of total
                </p>
              </div>
            </div>
          </Card>

          <Card className="p-6" data-testid="super-admins-card">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-orange-100 dark:bg-orange-900">
                <Shield className="h-6 w-6 text-orange-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Super Admins</p>
                <p className="text-2xl font-bold" data-testid="super-admins-value">
                  {systemStats.superAdmins}
                </p>
                <p className="text-xs text-muted-foreground">System administrators</p>
              </div>
            </div>
          </Card>

          <Card className="p-6" data-testid="total-teams-card">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-purple-100 dark:bg-purple-900">
                <Activity className="h-6 w-6 text-purple-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Teams</p>
                <p className="text-2xl font-bold" data-testid="total-teams-value">
                  {systemStats.totalTeams}
                </p>
                <p className="text-xs text-muted-foreground">Active organizations</p>
              </div>
            </div>
          </Card>
        </div>

        {/* User Management */}
        <Card className="p-6">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="text-xl font-semibold">User Management</h2>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search users..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleSearch()}
                  className="w-64"
                  aria-label="Search users by email"
                />
                <Button onClick={handleSearch} variant="outline" size="sm">
                  Search
                </Button>
              </div>
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <select
                  value={filterActive === null ? 'all' : filterActive ? 'active' : 'inactive'}
                  onChange={e => {
                    const value = e.target.value
                    setFilterActive(value === 'all' ? null : value === 'active')
                  }}
                  className="rounded border px-2 py-1 text-sm"
                  aria-label="Filter users by status"
                >
                  <option value="all">All Users</option>
                  <option value="active">Active Only</option>
                  <option value="inactive">Inactive Only</option>
                </select>
              </div>
            </div>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-8 w-8 animate-spin rounded-full border-b-2 border-primary"></div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b">
                    <th className="p-3 text-left font-medium">User</th>
                    <th className="p-3 text-left font-medium">Status</th>
                    <th className="p-3 text-left font-medium">Teams</th>
                    <th className="p-3 text-left font-medium">Created</th>
                    <th className="p-3 text-left font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.id} className="border-b hover:bg-muted/50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary">
                            <Mail className="h-4 w-4 text-primary-foreground" />
                          </div>
                          <div>
                            <p className="font-medium">{user.email}</p>
                            {user.is_superuser && (
                              <Badge
                                variant="outline"
                                className="mt-1 border-red-600 text-xs text-red-600"
                              >
                                <Crown className="mr-1 h-3 w-3" />
                                Super Admin
                              </Badge>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant={user.is_active ? 'default' : 'secondary'}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <div className="space-y-1">
                          {user.team_memberships?.map(membership => (
                            <Badge
                              key={membership.team_id}
                              variant={membership.role === 'owner' ? 'default' : 'outline'}
                              className={`text-xs ${membership.role === 'owner' ? 'border-blue-200 bg-blue-100 text-blue-800' : ''}`}
                            >
                              {membership.team_name} ({membership.role})
                              {membership.role === 'owner' && (
                                <Crown className="ml-1 inline h-3 w-3" />
                              )}
                            </Badge>
                          ))}
                          {!user.team_memberships?.length && (
                            <span className="text-sm text-muted-foreground">No teams</span>
                          )}
                          {isTeamOwner(user) && (
                            <div className="mt-1 text-xs text-blue-600">
                              Owns {getOwnedTeamsCount(user)} team(s)
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Calendar className="h-4 w-4" />
                          {formatDate(user.created_at)}
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleToggleUserStatus(user.id, user.is_active)}
                            disabled={false}
                          >
                            {user.is_active ? (
                              <>
                                <UserX className="mr-1 h-4 w-4" />
                                Deactivate
                              </>
                            ) : (
                              <>
                                <UserCheck className="mr-1 h-4 w-4" />
                                Activate
                              </>
                            )}
                          </Button>

                          {!user.is_superuser && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handlePromoteToSuperuser(user.id, user.email)}
                              className="text-blue-600 hover:text-blue-700"
                              title="Promote to Super Admin"
                            >
                              <Crown className="mr-1 h-4 w-4" />
                              Promote
                            </Button>
                          )}

                          {user.is_superuser && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleDemoteFromSuperuser(user.id, user.email)}
                              className="text-orange-600 hover:text-orange-700"
                              title="Remove Super Admin privileges"
                            >
                              <UserX className="mr-1 h-4 w-4" />
                              Demote
                            </Button>
                          )}

                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteUser(user.id, user.email)}
                            className="text-red-600 hover:text-red-700"
                            data-testid="delete-user"
                            title={
                              user.is_superuser
                                ? 'Superuser account - requires force deletion confirmation'
                                : isTeamOwner(user)
                                  ? `User owns ${getOwnedTeamsCount(user)} team(s). As superadmin, you can force delete to automatically handle team ownership.`
                                  : 'Delete user permanently'
                            }
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {users.length === 0 && (
                <div className="py-8 text-center text-muted-foreground">No users found</div>
              )}
            </div>
          )}
        </Card>

        {/* Create User Section */}
        <Card className="p-6">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="text-xl font-semibold">Create New User</h2>
            <Button
              onClick={() => setShowCreateUser(!showCreateUser)}
              variant={showCreateUser ? 'outline' : 'default'}
            >
              <UserPlus className="mr-2 h-4 w-4" />
              {showCreateUser ? 'Cancel' : 'Create User'}
            </Button>
          </div>

          {showCreateUser && (
            <form onSubmit={handleCreateUser} className="max-w-md space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="email">
                  Email Address *
                </label>
                <div className="relative">
                  <AtSign className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="user@example.com"
                    value={createUserForm.email}
                    onChange={e => setCreateUserForm(prev => ({ ...prev, email: e.target.value }))}
                    className="pl-10"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="password">
                  Password *
                </label>
                <div className="relative">
                  <Lock className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={createUserForm.password}
                    onChange={e =>
                      setCreateUserForm(prev => ({ ...prev, password: e.target.value }))
                    }
                    className="pl-10"
                    minLength={MIN_PASSWORD_LENGTH}
                    maxLength={MAX_PASSWORD_LENGTH}
                    required
                  />
                </div>
                <p className="text-xs text-muted-foreground">{PASSWORD_RULE_HINT}</p>
              </div>

              <div className="space-y-3">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={createUserForm.is_active}
                    onChange={e =>
                      setCreateUserForm(prev => ({ ...prev, is_active: e.target.checked }))
                    }
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm font-medium">User Active</span>
                  <span className="text-xs text-muted-foreground">(User can log in)</span>
                </label>

                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={createUserForm.is_superuser}
                    onChange={e =>
                      setCreateUserForm(prev => ({ ...prev, is_superuser: e.target.checked }))
                    }
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm font-medium">Super Admin</span>
                  <span className="text-xs text-muted-foreground">(Full system access)</span>
                </label>
              </div>

              <div className="flex gap-3 pt-4">
                <Button type="submit" disabled={isCreatingUser} className="flex items-center gap-2">
                  {isCreatingUser ? (
                    <>
                      <div className="h-4 w-4 animate-spin rounded-full border-b-2 border-white"></div>
                      Creating...
                    </>
                  ) : (
                    <>
                      <UserPlus className="h-4 w-4" />
                      Create User
                    </>
                  )}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowCreateUser(false)
                    setCreateUserForm({
                      email: '',
                      password: '',
                      is_superuser: false,
                      is_active: true,
                    })
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          )}

          {!showCreateUser && (
            <div className="rounded-lg border-2 border-dashed border-muted py-8 text-center">
              <UserPlus className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
              <p className="mb-4 text-muted-foreground">
                Create new users manually with custom permissions
              </p>
              <Button onClick={() => setShowCreateUser(true)} variant="outline">
                <UserPlus className="mr-2 h-4 w-4" />
                Create New User
              </Button>
            </div>
          )}
        </Card>

        {/* System Settings */}
        <Card className="p-6">
          <h2 className="mb-4 text-xl font-semibold">System Management</h2>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <Card className="border-2 border-dashed border-muted p-4">
              <div className="mb-2 flex items-center gap-3">
                <Database className="h-5 w-5 text-muted-foreground" />
                <h3 className="font-medium">System Health</h3>
              </div>
              <p className="mb-3 text-sm text-muted-foreground">
                Monitor system performance and status
              </p>
              <div className="space-y-2" data-testid="system-health">
                <HealthRow
                  label="Identity Service"
                  testId="health-identity"
                  status={PROBE_LABELS[systemHealth.identityStatus]}
                />
                <HealthRow
                  label="Gateway"
                  testId="health-gateway"
                  status={PROBE_LABELS[systemHealth.gatewayStatus]}
                />
                <HealthRow
                  label="Database"
                  testId="health-database"
                  status={CHECK_LABELS[systemHealth.databaseStatus]}
                />
                <HealthRow
                  label="Redis Cache"
                  testId="health-redis"
                  status={CHECK_LABELS[systemHealth.redisStatus]}
                />
              </div>
            </Card>

            <Card className="border-2 border-dashed border-muted p-4">
              <div className="mb-2 flex items-center gap-3">
                <Activity className="h-5 w-5 text-muted-foreground" />
                <h3 className="font-medium">Usage Analytics</h3>
              </div>
              <p className="mb-3 text-sm text-muted-foreground">
                API usage and performance metrics
              </p>
              {/* Request counts, response times and error rates are not
                  collected yet (they need the Prometheus integration), so
                  they read N/A instead of a number. */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>API Keys Used (24h)</span>
                  <span className="font-medium" data-testid="api-keys-used-today">
                    {systemStats.apiKeysUsedToday !== null
                      ? systemStats.apiKeysUsedToday.toLocaleString()
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Avg Response Time</span>
                  <span className="font-medium text-muted-foreground">N/A</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Error Rate</span>
                  <span className="font-medium text-muted-foreground">N/A</span>
                </div>
              </div>
            </Card>

            <Card className="border-2 border-dashed border-muted p-4">
              <div className="mb-2 flex items-center gap-3">
                <Settings className="h-5 w-5 text-muted-foreground" />
                <h3 className="font-medium">Admin Actions</h3>
              </div>
              <p className="mb-3 text-sm text-muted-foreground">System administration tools</p>
              <div className="space-y-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start"
                  onClick={() => fetchSystemHealth()}
                >
                  <Activity className="mr-2 h-4 w-4" />
                  Refresh Health
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start"
                  onClick={() => fetchSystemStats()}
                >
                  <Database className="mr-2 h-4 w-4" />
                  Refresh Stats
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <Settings className="mr-2 h-4 w-4" />
                  System Config
                </Button>
              </div>
            </Card>
          </div>
        </Card>
      </div>
    </MainLayout>
  )
}
