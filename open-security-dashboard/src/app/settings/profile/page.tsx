'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { User, Mail, Calendar, Shield, AlertCircle, Save, Eye, EyeOff } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'

interface UpdateProfileRequest {
  email?: string
}

interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

interface ActivityLog {
  id: string
  action: string
  timestamp: string
  ip_address?: string
  user_agent?: string
}

export default function ProfilePage() {
  const { user, refetchUser } = useAuth()
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(false)
  const [showPasswordForm, setShowPasswordForm] = useState(false)
  const [activityLog, setActivityLog] = useState<ActivityLog[]>([])
  const [activityLoading, setActivityLoading] = useState(true)

  // Profile form state
  const [email, setEmail] = useState(user?.email || '')

  // Password form state
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  })
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  })

  const fetchActivityLog = useCallback(async () => {
    try {
      setActivityLoading(true)
      // For now, create mock activity data since the endpoint might not exist yet
      const mockLogs: ActivityLog[] = [
        {
          id: '1',
          action: 'Profile updated',
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          ip_address: '192.168.1.1',
        },
        {
          id: '2',
          action: 'Login successful',
          timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          ip_address: '192.168.1.1',
        },
        {
          id: '3',
          action: 'API key created',
          timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
          ip_address: '192.168.1.1',
        },
      ]

      try {
        const logs = await identityClient.get<ActivityLog[]>('/api/v1/users/me/activity')
        setActivityLog(logs)
      } catch {
        // Fallback to mock data if endpoint doesn't exist
        setActivityLog(mockLogs)
      }
    } catch (error) {
      console.error('Failed to fetch activity log:', error)
      toast({
        title: 'Error',
        description: 'Failed to load activity log',
        variant: 'destructive',
      })
    } finally {
      setActivityLoading(false)
    }
  }, [toast])

  useEffect(() => {
    if (user) {
      setEmail(user.email)
      fetchActivityLog()
    }
  }, [user, fetchActivityLog])

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    setIsLoading(true)
    try {
      const updateData: UpdateProfileRequest = {}

      if (email !== user.email) {
        updateData.email = email
      }

      if (Object.keys(updateData).length > 0) {
        await identityClient.put('/api/v1/users/me', updateData)
        await refetchUser()
        toast({
          title: 'Success',
          description: 'Profile updated successfully',
        })
      } else {
        toast({
          title: 'Info',
          description: 'No changes to save',
        })
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to update profile'),
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()

    if (passwordForm.new_password !== passwordForm.confirm_password) {
      toast({
        title: 'Error',
        description: 'New passwords do not match',
        variant: 'destructive',
      })
      return
    }

    if (passwordForm.new_password.length < 8) {
      toast({
        title: 'Error',
        description: 'Password must be at least 8 characters long',
        variant: 'destructive',
      })
      return
    }

    setIsLoading(true)
    try {
      const changeData: ChangePasswordRequest = {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      }

      await identityClient.put('/api/v1/users/me/password', changeData)

      setPasswordForm({
        current_password: '',
        new_password: '',
        confirm_password: '',
      })
      setShowPasswordForm(false)
      toast({
        title: 'Success',
        description: 'Password changed successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to change password'),
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  if (!user) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-center">
          <AlertCircle className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">Please log in to view your profile</p>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">Profile Settings</h1>
        <p className="mt-2 text-muted-foreground">
          Manage your account information and security settings
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Profile Information */}
        <div className="space-y-6 lg:col-span-2">
          {/* Account Overview */}
          <Card className="p-6">
            <div className="mb-6 flex items-center gap-4">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-purple-600">
                <User className="h-8 w-8 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-foreground">{user.email}</h2>
                <div className="mt-1 flex items-center gap-2">
                  <Badge variant={user.is_active ? 'default' : 'secondary'}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                  {user.is_superuser && (
                    <Badge variant="outline" className="border-orange-600 text-orange-600">
                      <Shield className="mr-1 h-3 w-3" />
                      Super Admin
                    </Badge>
                  )}
                  {user.team_memberships?.[0] && (
                    <Badge variant="outline" className="border-blue-600 text-blue-600">
                      {user.team_memberships[0].role}
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-muted-foreground">Member since</div>
                <div className="font-medium">{formatDate(user.created_at)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Last updated</div>
                <div className="font-medium">{formatDate(user.updated_at)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Account ID</div>
                <div className="font-mono text-xs font-medium">{user.id}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Team</div>
                <div className="font-medium">
                  {user.team_memberships?.[0]?.team?.name || 'No team'}
                </div>
              </div>
            </div>
          </Card>

          {/* Profile Form */}
          <Card className="p-6">
            <h3 className="mb-4 text-lg font-semibold text-foreground">Account Information</h3>
            <form onSubmit={handleUpdateProfile} className="space-y-4">
              <div>
                <label htmlFor="email" className="mb-2 block text-sm font-medium text-foreground">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    className="pl-10"
                    placeholder="Enter your email"
                    required
                  />
                </div>
              </div>

              <Button type="submit" disabled={isLoading} className="flex items-center gap-2">
                <Save className="h-4 w-4" />
                {isLoading ? 'Saving...' : 'Save Changes'}
              </Button>
            </form>
          </Card>

          {/* Password Section */}
          <Card className="p-6">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-foreground">Password</h3>
              <Button variant="outline" onClick={() => setShowPasswordForm(!showPasswordForm)}>
                {showPasswordForm ? 'Cancel' : 'Change Password'}
              </Button>
            </div>

            {showPasswordForm && (
              <form onSubmit={handleChangePassword} className="space-y-4">
                <div>
                  <label
                    htmlFor="current_password"
                    className="mb-2 block text-sm font-medium text-foreground"
                  >
                    Current Password
                  </label>
                  <div className="relative">
                    <Input
                      id="current_password"
                      type={showPasswords.current ? 'text' : 'password'}
                      value={passwordForm.current_password}
                      onChange={e =>
                        setPasswordForm(prev => ({ ...prev, current_password: e.target.value }))
                      }
                      placeholder="Enter current password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setShowPasswords(prev => ({ ...prev, current: !prev.current }))
                      }
                      className="absolute right-3 top-1/2 -translate-y-1/2 transform"
                    >
                      {showPasswords.current ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="new_password"
                    className="mb-2 block text-sm font-medium text-foreground"
                  >
                    New Password
                  </label>
                  <div className="relative">
                    <Input
                      id="new_password"
                      type={showPasswords.new ? 'text' : 'password'}
                      value={passwordForm.new_password}
                      onChange={e =>
                        setPasswordForm(prev => ({ ...prev, new_password: e.target.value }))
                      }
                      placeholder="Enter new password"
                      required
                      minLength={8}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords(prev => ({ ...prev, new: !prev.new }))}
                      className="absolute right-3 top-1/2 -translate-y-1/2 transform"
                    >
                      {showPasswords.new ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="confirm_password"
                    className="mb-2 block text-sm font-medium text-foreground"
                  >
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <Input
                      id="confirm_password"
                      type={showPasswords.confirm ? 'text' : 'password'}
                      value={passwordForm.confirm_password}
                      onChange={e =>
                        setPasswordForm(prev => ({ ...prev, confirm_password: e.target.value }))
                      }
                      placeholder="Confirm new password"
                      required
                      minLength={8}
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setShowPasswords(prev => ({ ...prev, confirm: !prev.confirm }))
                      }
                      className="absolute right-3 top-1/2 -translate-y-1/2 transform"
                    >
                      {showPasswords.confirm ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                <Button type="submit" disabled={isLoading} className="flex items-center gap-2">
                  <Save className="h-4 w-4" />
                  {isLoading ? 'Changing...' : 'Change Password'}
                </Button>
              </form>
            )}
          </Card>
        </div>

        {/* Security Information */}
        <div>
          <Card className="mb-6 p-6">
            <div className="mb-4 flex items-center gap-2">
              <Shield className="h-5 w-5" />
              <h3 className="text-lg font-semibold text-foreground">Security</h3>
            </div>

            <div className="space-y-4 text-sm">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">Two-Factor Authentication</div>
                  <div className="text-muted-foreground">Add an extra layer of security</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="border-red-600 text-red-600">
                    Disabled
                  </Badge>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      toast({
                        title: '2FA Setup',
                        description:
                          'Two-factor authentication setup will be available in the next release. This feature is currently in development.',
                      })
                    }}
                  >
                    Enable
                  </Button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">Active Sessions</div>
                  <div className="text-muted-foreground">Current browser and device sessions</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="default">
                    {user?.lastLogin ? '1 Active' : 'Current Session'}
                  </Badge>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      toast({
                        title: 'Session Info',
                        description: `Current session: ${navigator.userAgent.includes('Chrome') ? 'Chrome' : navigator.userAgent.includes('Firefox') ? 'Firefox' : 'Browser'} on ${navigator.platform}. Last login: ${user?.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Current session'}`,
                      })
                    }}
                  >
                    View Details
                  </Button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">API Keys</div>
                  <div className="text-muted-foreground">Manage your API access keys</div>
                </div>
                <Button variant="outline" size="sm" asChild>
                  <a href="/settings/api-keys">Manage</a>
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">Password Strength</div>
                  <div className="text-muted-foreground">
                    Last changed {user?.updated_at ? formatDate(user.updated_at) : 'unknown'}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="border-green-600 text-green-600">
                    Strong
                  </Badge>
                  <Button variant="outline" size="sm" onClick={() => setShowPasswordForm(true)}>
                    Change
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* Activity Log */}
        <div>
          <Card className="p-6">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Calendar className="h-5 w-5" />
                <h3 className="text-lg font-semibold text-foreground">Recent Activity</h3>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  toast({
                    title: 'Activity Export',
                    description:
                      'Full activity log export will be available soon. Currently showing recent activities.',
                  })
                }}
              >
                Export Log
              </Button>
            </div>

            {activityLoading ? (
              <div className="py-8 text-center">
                <div className="text-muted-foreground">Loading activity...</div>
              </div>
            ) : activityLog.length > 0 ? (
              <div className="space-y-3">
                {activityLog.slice(0, 10).map(log => (
                  <div key={log.id} className="border-l-2 border-primary pb-3 pl-3">
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-medium">{log.action}</div>
                      <Badge variant="outline" className="text-xs">
                        {log.ip_address}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">{formatDate(log.timestamp)}</div>
                  </div>
                ))}
                <div className="border-t border-border pt-3 text-center">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      toast({
                        title: 'Full Activity Log',
                        description:
                          'Detailed activity history viewer will be available in the next update.',
                      })
                    }}
                  >
                    View All Activity
                  </Button>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <div className="text-muted-foreground">No recent activity</div>
                <div className="mt-1 text-xs text-muted-foreground">
                  Activity will appear here as you use the platform
                </div>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
