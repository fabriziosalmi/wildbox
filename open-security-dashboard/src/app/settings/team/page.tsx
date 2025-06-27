'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient, getAuthPath } from '@/lib/api-client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { 
  Users, 
  Plus, 
  Trash2, 
  Mail,
  Calendar,
  AlertCircle,
  Crown,
  Shield,
  User,
  Settings,
  UserPlus,
  Edit
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { Team, TeamMembership, User as UserType } from '@/types'

interface TeamData {
  team: Team
  members: (TeamMembership & { user: UserType })[]
  canManage: boolean
}

interface InviteUserRequest {
  email: string
  role: 'admin' | 'member'
}

const roleIcons = {
  owner: Crown,
  admin: Shield,
  member: User,
}

const roleColors = {
  owner: 'text-yellow-600',
  admin: 'text-blue-600', 
  member: 'text-gray-600',
}

export default function TeamPage() {
  const { user } = useAuth()
  const { toast } = useToast()
  const [teamData, setTeamData] = useState<TeamData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isInviting, setIsInviting] = useState(false)
  const [showInviteForm, setShowInviteForm] = useState(false)
  const [showEditTeam, setShowEditTeam] = useState(false)
  
  const [inviteForm, setInviteForm] = useState({
    email: '',
    role: 'member' as 'admin' | 'member',
  })
  
  const [teamEditForm, setTeamEditForm] = useState({
    name: '',
  })

  useEffect(() => {
    if (user) {
      fetchTeamData()
    }
  }, [user])

  const fetchTeamData = async () => {
    try {
      setIsLoading(true)
      const userData = await identityClient.get(getAuthPath('/api/v1/auth/me'))
      
      if (userData.team_memberships && userData.team_memberships.length > 0) {
        const primaryMembership = userData.team_memberships[0]
        const canManage = ['owner', 'admin'].includes(primaryMembership.role)
        
        // Get detailed team information with all members
        const teamMembers = await identityClient.get(`/api/v1/teams/${primaryMembership.team_id}/members`)
        
        setTeamData({
          team: primaryMembership.team,
          members: teamMembers,
          canManage
        })
        
        setTeamEditForm({
          name: primaryMembership.team.name
        })
      }
    } catch (error: any) {
      console.error('Failed to fetch team data:', error)
      toast({
        title: "Error",
        description: "Failed to load team information",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!inviteForm.email.trim()) {
      toast({
        title: "Error",
        description: "Email address is required",
        variant: "destructive",
      })
      return
    }

    setIsInviting(true)
    try {
      const inviteData: InviteUserRequest = {
        email: inviteForm.email.trim(),
        role: inviteForm.role,
      }

      await identityClient.post(`/api/v1/teams/${teamData?.team.id}/invite`, inviteData)
      
      setInviteForm({ email: '', role: 'member' })
      setShowInviteForm(false)
      await fetchTeamData() // Refresh team data
      
      toast({
        title: "Success",
        description: "User invited successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to invite user",
        variant: "destructive",
      })
    } finally {
      setIsInviting(false)
    }
  }

  const handleUpdateTeam = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!teamEditForm.name.trim()) {
      toast({
        title: "Error",
        description: "Team name is required",
        variant: "destructive",
      })
      return
    }

    try {
      await identityClient.put(`/api/v1/teams/${teamData?.team.id}`, {
        name: teamEditForm.name.trim()
      })
      
      setShowEditTeam(false)
      await fetchTeamData()
      
      toast({
        title: "Success",
        description: "Team updated successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update team",
        variant: "destructive",
      })
    }
  }

  const handleUpdateMemberRole = async (userId: string, newRole: 'admin' | 'member') => {
    try {
      await identityClient.patch(`/api/v1/teams/${teamData?.team.id}/members/${userId}/role`, {
        role: newRole
      })
      
      await fetchTeamData()
      
      toast({
        title: "Success",
        description: "Member role updated successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update member role",
        variant: "destructive",
      })
    }
  }

  const handleRemoveMember = async (userId: string, userName: string) => {
    if (!confirm(`Are you sure you want to remove ${userName} from the team?`)) {
      return
    }

    try {
      await identityClient.delete(`/api/v1/teams/${teamData?.team.id}/members/${userId}`)
      
      await fetchTeamData()
      
      toast({
        title: "Success",
        description: "Member removed successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to remove member",
        variant: "destructive",
      })
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const getRoleDisplayName = (role: string) => {
    return role.charAt(0).toUpperCase() + role.slice(1)
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">Please log in to view team settings</p>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="text-muted-foreground">Loading team information...</div>
        </div>
      </div>
    )
  }

  if (!teamData) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">No team found</p>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Team Settings</h1>
            <p className="text-muted-foreground mt-2">
              Manage your team members and settings
            </p>
          </div>
          {teamData.canManage && (
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => setShowEditTeam(true)}
                className="flex items-center gap-2"
              >
                <Edit className="w-4 h-4" />
                Edit Team
              </Button>
              <Button onClick={() => setShowInviteForm(true)} className="flex items-center gap-2">
                <Plus className="w-4 h-4" />
                Invite Member
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Team Overview */}
      <Card className="p-6 mb-6">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Users className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-foreground">{teamData.team.name}</h2>
            <div className="text-muted-foreground">
              {teamData.members.length} member{teamData.members.length !== 1 ? 's' : ''}
            </div>
          </div>
        </div>

        {/* Team Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center p-3 border border-border rounded-lg">
            <div className="font-semibold text-lg">{teamData.members.length}</div>
            <div className="text-sm text-muted-foreground">Total Members</div>
          </div>
          <div className="text-center p-3 border border-border rounded-lg">
            <div className="font-semibold text-lg">{teamData.members.filter(m => m.role === 'admin').length}</div>
            <div className="text-sm text-muted-foreground">Admins</div>
          </div>
          <div className="text-center p-3 border border-border rounded-lg">
            <div className="font-semibold text-lg">{teamData.members.filter(m => m.role === 'owner').length}</div>
            <div className="text-sm text-muted-foreground">Owners</div>
          </div>
          <div className="text-center p-3 border border-border rounded-lg">
            <div className="font-semibold text-lg text-green-600">Active</div>
            <div className="text-sm text-muted-foreground">Status</div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-muted-foreground">Created</div>
            <div className="font-medium">{formatDate(teamData.team.created_at)}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Plan</div>
            <div className="font-medium capitalize">
              {teamData.team.subscription?.plan_id || 'Free'}
            </div>
          </div>
        </div>
      </Card>

      {/* Edit Team Form */}
      {showEditTeam && teamData.canManage && (
        <Card className="p-6 mb-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Edit Team</h3>
          
          <form onSubmit={handleUpdateTeam} className="space-y-4">
            <div>
              <label htmlFor="team-name" className="block text-sm font-medium text-foreground mb-2">
                Team Name
              </label>
              <Input
                id="team-name"
                type="text"
                value={teamEditForm.name}
                onChange={(e) => setTeamEditForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Enter team name"
                required
              />
            </div>

            <div className="flex gap-2">
              <Button type="submit">
                Save Changes
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowEditTeam(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Invite Member Form */}
      {showInviteForm && teamData.canManage && (
        <Card className="p-6 mb-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Invite Team Member</h3>
          
          <form onSubmit={handleInviteUser} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-foreground mb-2">
                Email Address
              </label>
              <Input
                id="email"
                type="email"
                value={inviteForm.email}
                onChange={(e) => setInviteForm(prev => ({ ...prev, email: e.target.value }))}
                placeholder="user@example.com"
                required
              />
            </div>

            <div>
              <label htmlFor="role" className="block text-sm font-medium text-foreground mb-2">
                Role
              </label>
              <select
                id="role"
                value={inviteForm.role}
                onChange={(e) => setInviteForm(prev => ({ ...prev, role: e.target.value as 'admin' | 'member' }))}
                className="w-full px-3 py-2 border border-border rounded-md bg-background"
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div className="flex gap-2">
              <Button type="submit" disabled={isInviting}>
                {isInviting ? 'Inviting...' : 'Send Invitation'}
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowInviteForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Team Members */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-foreground mb-4">Team Members</h3>
        
        <div className="space-y-4">
          {teamData.members.map((member) => {
            const RoleIcon = roleIcons[member.role as keyof typeof roleIcons]
            const roleColor = roleColors[member.role as keyof typeof roleColors]
            const isCurrentUser = member.user_id === user.id
            const canModify = teamData.canManage && !isCurrentUser && member.role !== 'owner'
            
            return (
              <div key={member.user_id} className="flex items-center justify-between p-4 border border-border rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-gray-500 to-gray-700 rounded-full flex items-center justify-center">
                    <User className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="font-medium text-foreground">
                      {member.user.email}
                      {isCurrentUser && <span className="text-muted-foreground"> (You)</span>}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className={roleColor}>
                        <RoleIcon className="w-3 h-3 mr-1" />
                        {getRoleDisplayName(member.role)}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        Joined {formatDate(member.joined_at)}
                      </span>
                    </div>
                  </div>
                </div>

                {canModify && (
                  <div className="flex items-center gap-2">
                    {member.role === 'member' && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleUpdateMemberRole(member.user_id, 'admin')}
                      >
                        Promote to Admin
                      </Button>
                    )}
                    {member.role === 'admin' && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleUpdateMemberRole(member.user_id, 'member')}
                      >
                        Demote to Member
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRemoveMember(member.user_id, member.user.email)}
                      className="text-red-600 hover:text-red-700"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Card>

      {/* Role Information */}
      <Card className="p-6 mt-6">
        <div className="flex items-center gap-3 mb-4">
          <Settings className="w-8 h-8 text-blue-500" />
          <h3 className="text-lg font-semibold text-foreground">Role Permissions</h3>
        </div>
        
        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="border border-border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Crown className="w-5 h-5 text-yellow-600" />
                <h4 className="font-medium text-foreground">Owner</h4>
              </div>
              <ul className="text-muted-foreground space-y-1">
                <li>• Full team management</li>
                <li>• Billing and subscription</li>
                <li>• Add/remove members</li>
                <li>• Change member roles</li>
                <li>• Delete team</li>
              </ul>
            </div>
            
            <div className="border border-border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-5 h-5 text-blue-600" />
                <h4 className="font-medium text-foreground">Admin</h4>
              </div>
              <ul className="text-muted-foreground space-y-1">
                <li>• Add/remove members</li>
                <li>• Change member roles</li>
                <li>• Manage team settings</li>
                <li>• Access all tools</li>
                <li>• View all data</li>
              </ul>
            </div>
            
            <div className="border border-border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <User className="w-5 h-5 text-gray-600" />
                <h4 className="font-medium text-foreground">Member</h4>
              </div>
              <ul className="text-muted-foreground space-y-1">
                <li>• Access assigned tools</li>
                <li>• View shared data</li>
                <li>• Create reports</li>
                <li>• Basic team features</li>
              </ul>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
