'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient } from '@/lib/api-client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { 
  Shield, 
  Users, 
  Search,
  Eye,
  Ban,
  Trash2,
  AlertCircle,
  UserCheck,
  UserX,
  Calendar,
  Mail,
  Crown,
  Filter,
  MoreHorizontal
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { User as UserType } from '@/types'

interface AdminUserData {
  id: string
  email: string
  is_active: boolean
  is_superuser: boolean
  created_at: string
  updated_at: string
  stripe_customer_id?: string
  team_memberships?: Array<{
    user_id: string
    team_id: string
    team_name: string
    role: string
    joined_at: string
  }>
}

export default function AdminPage() {
  const { user } = useAuth()
  const { toast } = useToast()
  const [users, setUsers] = useState<AdminUserData[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'inactive'>('all')
  const [selectedUser, setSelectedUser] = useState<AdminUserData | null>(null)
  const [showUserModal, setShowUserModal] = useState(false)

  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const [totalUsers, setTotalUsers] = useState(0)
  const usersPerPage = 20

  useEffect(() => {
    if (user?.is_superuser) {
      fetchUsers()
    }
  }, [user, currentPage, searchTerm, statusFilter])

  const fetchUsers = async () => {
    try {
      setIsLoading(true)
      const params = new URLSearchParams({
        skip: ((currentPage - 1) * usersPerPage).toString(),
        limit: usersPerPage.toString(),
      })

      if (searchTerm) {
        params.append('email_filter', searchTerm)
      }

      if (statusFilter !== 'all') {
        params.append('is_active', (statusFilter === 'active').toString())
      }

      const response = await identityClient.get(`/api/v1/users/admin/users?${params}`)
      setUsers(response)
      
      // In a real implementation, this would come from the API response
      setTotalUsers(response.length)
    } catch (error: any) {
      console.error('Failed to fetch users:', error)
      toast({
        title: "Error",
        description: "Failed to load users",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleViewUser = async (userId: string) => {
    try {
      const userData = await identityClient.get(`/api/v1/users/admin/users/${userId}`)
      setSelectedUser(userData)
      setShowUserModal(true)
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to load user details",
        variant: "destructive",
      })
    }
  }

  const handleToggleUserStatus = async (userId: string, currentStatus: boolean) => {
    const action = currentStatus ? 'deactivate' : 'activate'
    
    if (!confirm(`Are you sure you want to ${action} this user?`)) {
      return
    }

    try {
      await identityClient.patch(`/api/v1/users/admin/users/${userId}/status`, {
        is_active: !currentStatus
      })
      
      await fetchUsers()
      
      toast({
        title: "Success",
        description: `User ${action}d successfully`,
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || `Failed to ${action} user`,
        variant: "destructive",
      })
    }
  }

  const handleDeleteUser = async (userId: string, userEmail: string) => {
    if (!confirm(`Are you sure you want to delete the user "${userEmail}"? This action cannot be undone.`)) {
      return
    }

    try {
      await identityClient.delete(`/api/v1/users/admin/users/${userId}`)
      
      await fetchUsers()
      
      toast({
        title: "Success",
        description: "User deleted successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to delete user",
        variant: "destructive",
      })
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  const getStatusBadge = (isActive: boolean) => {
    return (
      <Badge variant={isActive ? "default" : "secondary"}>
        {isActive ? "Active" : "Inactive"}
      </Badge>
    )
  }

  const getRoleBadge = (role: string) => {
    const colors = {
      owner: "text-yellow-600 border-yellow-600",
      admin: "text-blue-600 border-blue-600",
      member: "text-gray-600 border-gray-600",
    }
    
    return (
      <Badge variant="outline" className={colors[role as keyof typeof colors] || colors.member}>
        {role}
      </Badge>
    )
  }

  // Check if user is admin
  if (!user?.is_superuser) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">Access Denied</h3>
          <p className="text-muted-foreground">You need administrator privileges to access this page.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">User Administration</h1>
            <p className="text-muted-foreground mt-2">
              Manage all users in the system
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-orange-600 border-orange-600">
              <Crown className="w-3 h-3 mr-1" />
              Admin Access
            </Badge>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <Card className="p-6 mb-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search by email..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'inactive')}
              className="px-3 py-2 border border-border rounded-md bg-background"
            >
              <option value="all">All Users</option>
              <option value="active">Active Only</option>
              <option value="inactive">Inactive Only</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Users Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-border">
              <tr>
                <th className="px-6 py-3 text-left text-sm font-medium text-foreground">User</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-foreground">Status</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-foreground">Role</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-foreground">Created</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-foreground">Last Active</th>
                <th className="px-6 py-3 text-center text-sm font-medium text-foreground">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">
                    Loading users...
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-muted-foreground">
                    No users found
                  </td>
                </tr>
              ) : (
                users.map((userData) => (
                  <tr key={userData.id} className="hover:bg-muted/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                          <span className="text-white text-sm font-medium">
                            {userData.email.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="font-medium text-foreground">{userData.email}</div>
                          <div className="text-sm text-muted-foreground">ID: {userData.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        {getStatusBadge(userData.is_active)}
                        {userData.is_superuser && (
                          <Badge variant="outline" className="text-orange-600 border-orange-600">
                            <Shield className="w-3 h-3 mr-1" />
                            Super Admin
                          </Badge>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="space-y-1">
                        {userData.team_memberships?.map((membership, index) => (
                          <div key={index} className="flex items-center gap-2">
                            {getRoleBadge(membership.role)}
                            <span className="text-sm text-muted-foreground">
                              {membership.team_name}
                            </span>
                          </div>
                        )) || (
                          <span className="text-sm text-muted-foreground">No team membership</span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-muted-foreground">
                        {formatDate(userData.created_at)}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-muted-foreground">
                        {userData.updated_at ? formatDate(userData.updated_at) : 'Never'}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleViewUser(userData.id)}
                        >
                          <Eye className="w-4 h-4" />
                        </Button>
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleToggleUserStatus(userData.id, userData.is_active)}
                          className={userData.is_active ? "text-red-600 hover:text-red-700" : "text-green-600 hover:text-green-700"}
                        >
                          {userData.is_active ? <UserX className="w-4 h-4" /> : <UserCheck className="w-4 h-4" />}
                        </Button>
                        
                        {userData.id !== user.id && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteUser(userData.id, userData.email)}
                            className="text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {users.length > 0 && (
          <div className="px-6 py-4 border-t border-border">
            <div className="flex items-center justify-between">
              <div className="text-sm text-muted-foreground">
                Showing {((currentPage - 1) * usersPerPage) + 1} to {Math.min(currentPage * usersPerPage, totalUsers)} of {totalUsers} users
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {currentPage}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => prev + 1)}
                  disabled={users.length < usersPerPage}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* User Detail Modal */}
      {showUserModal && selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-background rounded-lg shadow-lg max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-semibold text-foreground">User Details</h3>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowUserModal(false)}
                >
                  Close
                </Button>
              </div>

              <div className="space-y-6">
                {/* User Info */}
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                    <span className="text-white text-xl font-medium">
                      {selectedUser.email.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-foreground">{selectedUser.email}</h4>
                    <div className="flex items-center gap-2 mt-1">
                      {getStatusBadge(selectedUser.is_active)}
                      {selectedUser.is_superuser && (
                        <Badge variant="outline" className="text-orange-600 border-orange-600">
                          <Shield className="w-3 h-3 mr-1" />
                          Super Admin
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>

                {/* Account Details */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-1">User ID</label>
                    <div className="text-sm text-muted-foreground font-mono">{selectedUser.id}</div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Email</label>
                    <div className="text-sm text-muted-foreground">{selectedUser.email}</div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Created</label>
                    <div className="text-sm text-muted-foreground">{formatDate(selectedUser.created_at)}</div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Last Updated</label>
                    <div className="text-sm text-muted-foreground">{formatDate(selectedUser.updated_at)}</div>
                  </div>
                </div>

                {/* Team Memberships */}
                {selectedUser.team_memberships && selectedUser.team_memberships.length > 0 && (
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-3">Team Memberships</label>
                    <div className="space-y-2">
                      {selectedUser.team_memberships.map((membership, index) => (
                        <div key={index} className="flex items-center justify-between p-3 border border-border rounded-lg">
                          <div>
                            <div className="font-medium text-foreground">{membership.team_name}</div>
                            <div className="text-sm text-muted-foreground">
                              Joined {formatDate(membership.joined_at)}
                            </div>
                          </div>
                          {getRoleBadge(membership.role)}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="border-t border-border pt-6">
                  <label className="block text-sm font-medium text-foreground mb-3">Actions</label>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      onClick={() => handleToggleUserStatus(selectedUser.id, selectedUser.is_active)}
                      className={selectedUser.is_active ? "text-red-600 hover:text-red-700" : "text-green-600 hover:text-green-700"}
                    >
                      {selectedUser.is_active ? (
                        <>
                          <Ban className="w-4 h-4 mr-2" />
                          Deactivate User
                        </>
                      ) : (
                        <>
                          <UserCheck className="w-4 h-4 mr-2" />
                          Activate User
                        </>
                      )}
                    </Button>
                    
                    {selectedUser.id !== user.id && (
                      <Button
                        variant="outline"
                        onClick={() => handleDeleteUser(selectedUser.id, selectedUser.email)}
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete User
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
