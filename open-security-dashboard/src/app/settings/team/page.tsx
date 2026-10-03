'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient, getIdentityPath } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/utils'
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
  Users,
  Trash2,
  AlertCircle,
  Crown,
  Shield,
  User,
  Settings,
  Edit,
  UserPlus,
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'

type TeamRole = 'owner' | 'admin' | 'member'

/** One entry of GET /admin/me/activity's team_memberships (identity). */
interface MyMembership {
  team_id: string
  team_name: string
  role: TeamRole
  joined_at: string
}

/** One entry of GET /admin/teams/{id}/members (identity). */
interface TeamMember {
  user_id: string
  team_id: string
  role: TeamRole
  joined_at: string
  user: {
    id: string
    email: string
    is_active: boolean
    created_at: string
  }
}

/** The roles a caller may give a new member: strictly below its own (#573). */
const CREATABLE_ROLES: Record<TeamRole, TeamRole[]> = {
  owner: ['member', 'admin'],
  admin: ['member'],
  member: [],
}

interface TeamData {
  membership: MyMembership
  members: TeamMember[]
  canManage: boolean
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

// identity's team routes, through the gateway. The page used to call
// /auth/me and /api/v1/teams/..., which the gateway does not route: the first
// fell through to the dashboard, the second to the catch-all 404, so the page
// never loaded (#559). Both routes below are open to any member of the team;
// renaming it, adding and removing members are limited to its owners and
// admins by identity itself.
const myActivityPath = () => getIdentityPath('/api/v1/admin/me/activity')
const teamPath = (teamId: string) =>
  getIdentityPath(`/api/v1/admin/teams/${encodeURIComponent(teamId)}`)

export default function TeamPage() {
  const { user } = useAuth()
  const { toast } = useToast()
  const [teamData, setTeamData] = useState<TeamData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [showEditTeam, setShowEditTeam] = useState(false)

  const [teamEditForm, setTeamEditForm] = useState({
    name: '',
  })

  const [showAddMember, setShowAddMember] = useState(false)
  const [addMemberForm, setAddMemberForm] = useState<{
    email: string
    password: string
    role: TeamRole
  }>({ email: '', password: '', role: 'member' })
  const [addMemberError, setAddMemberError] = useState<string | null>(null)
  const [addingMember, setAddingMember] = useState(false)

  const fetchTeamData = useCallback(async () => {
    try {
      setIsLoading(true)
      setLoadError(null)
      const activity = await identityClient.get<{ team_memberships?: MyMembership[] }>(
        myActivityPath()
      )
      const membership = activity.team_memberships?.[0]

      if (!membership) {
        setTeamData(null)
        return
      }

      const members = await identityClient.get<TeamMember[]>(
        `${teamPath(membership.team_id)}/members`
      )

      setTeamData({
        membership,
        members,
        canManage: membership.role === 'owner' || membership.role === 'admin',
      })
      setTeamEditForm({ name: membership.team_name })
    } catch (error) {
      setTeamData(null)
      setLoadError(getErrorMessage(error, 'Failed to load team information'))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (user) {
      fetchTeamData()
    }
  }, [user, fetchTeamData])

  const handleUpdateTeam = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!teamData) return

    if (!teamEditForm.name.trim()) {
      toast({
        title: 'Error',
        description: 'Team name is required',
        variant: 'destructive',
      })
      return
    }

    try {
      await identityClient.put(teamPath(teamData.membership.team_id), {
        name: teamEditForm.name.trim(),
      })

      setShowEditTeam(false)
      await fetchTeamData()

      toast({
        title: 'Success',
        description: 'Team updated successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to update team'),
        variant: 'destructive',
      })
    }
  }

  // Creates the account directly in this team (#573); the list then shows
  // what identity returns, not what was typed.
  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!teamData) return
    setAddMemberError(null)
    // identity's password rule (#583); its reason is shown if it refuses one.
    const passwordProblem = passwordPolicyProblem(addMemberForm.password, addMemberForm.email)
    if (passwordProblem) {
      setAddMemberError(passwordProblem)
      return
    }

    setAddingMember(true)
    try {
      const created = await identityClient.post<TeamMember>(
        `${teamPath(teamData.membership.team_id)}/members`,
        {
          email: addMemberForm.email.trim(),
          password: addMemberForm.password,
          role: addMemberForm.role,
        }
      )
      setAddMemberForm({ email: '', password: '', role: 'member' })
      setShowAddMember(false)
      await fetchTeamData()
      toast({
        title: 'Member added',
        description: `${created.user.email} was added as ${created.role}. Share the initial password with them privately; they must change it when they first sign in.`,
      })
    } catch (error) {
      setAddMemberError(getErrorMessage(error, 'Failed to add the member'))
    } finally {
      setAddingMember(false)
    }
  }

  const handleRemoveMember = async (userId: string, userName: string) => {
    if (!teamData) return
    if (!confirm(`Are you sure you want to remove ${userName} from the team?`)) {
      return
    }

    try {
      await identityClient.delete(
        `${teamPath(teamData.membership.team_id)}/members/${encodeURIComponent(userId)}`
      )

      await fetchTeamData()

      toast({
        title: 'Success',
        description: 'Member removed successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to remove member'),
        variant: 'destructive',
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
      <div className="flex h-64 items-center justify-center">
        <div className="text-center">
          <AlertCircle className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">Please log in to view team settings</p>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-center">
          <div className="text-muted-foreground">Loading team information...</div>
        </div>
      </div>
    )
  }

  if (loadError) {
    return (
      <div className="flex h-64 items-center justify-center" role="alert">
        <div className="text-center">
          <AlertCircle className="mx-auto mb-4 h-12 w-12 text-red-500" />
          <p className="font-medium text-foreground">Could not load the team</p>
          <p className="mt-1 text-sm text-muted-foreground">{loadError}</p>
          <Button variant="outline" size="sm" className="mt-4" onClick={() => fetchTeamData()}>
            Try again
          </Button>
        </div>
      </div>
    )
  }

  if (!teamData) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-center">
          <AlertCircle className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">You are not a member of any team</p>
        </div>
      </div>
    )
  }

  const { membership, members } = teamData
  const creatableRoles = CREATABLE_ROLES[membership.role] ?? []

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Team Settings</h1>
            <p className="mt-2 text-muted-foreground">Manage your team members and settings</p>
          </div>
          {teamData.canManage && (
            <Button
              variant="outline"
              onClick={() => setShowEditTeam(true)}
              className="flex items-center gap-2"
            >
              <Edit className="h-4 w-4" />
              Edit Team
            </Button>
          )}
        </div>
      </div>

      {/* Team Overview */}
      <Card className="mb-6 p-6">
        <div className="mb-6 flex items-center gap-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-lg bg-gradient-to-br from-purple-500 to-blue-600">
            <Users className="h-8 w-8 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-foreground" data-testid="team-name">
              {membership.team_name}
            </h2>
            <div className="text-muted-foreground">
              {members.length} member{members.length !== 1 ? 's' : ''}
            </div>
          </div>
        </div>

        {/* Team Stats */}
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <div className="rounded-lg border border-border p-3 text-center">
            <div className="text-lg font-semibold" data-testid="team-member-count">
              {members.length}
            </div>
            <div className="text-sm text-muted-foreground">Total Members</div>
          </div>
          <div className="rounded-lg border border-border p-3 text-center">
            <div className="text-lg font-semibold">
              {members.filter(m => m.role === 'admin').length}
            </div>
            <div className="text-sm text-muted-foreground">Admins</div>
          </div>
          <div className="rounded-lg border border-border p-3 text-center">
            <div className="text-lg font-semibold">
              {members.filter(m => m.role === 'owner').length}
            </div>
            <div className="text-sm text-muted-foreground">Owners</div>
          </div>
          <div className="rounded-lg border border-border p-3 text-center">
            <div className="text-lg font-semibold">{getRoleDisplayName(membership.role)}</div>
            <div className="text-sm text-muted-foreground">Your Role</div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-muted-foreground">You joined</div>
            <div className="font-medium">{formatDate(membership.joined_at)}</div>
          </div>
        </div>
      </Card>

      {/* Edit Team Form */}
      {showEditTeam && teamData.canManage && (
        <Card className="mb-6 p-6">
          <h3 className="mb-4 text-lg font-semibold text-foreground">Edit Team</h3>

          <form onSubmit={handleUpdateTeam} className="space-y-4">
            <div>
              <label htmlFor="team-name" className="mb-2 block text-sm font-medium text-foreground">
                Team Name
              </label>
              <Input
                id="team-name"
                type="text"
                value={teamEditForm.name}
                onChange={e => setTeamEditForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Enter team name"
                required
              />
            </div>

            <div className="flex gap-2">
              <Button type="submit">Save Changes</Button>
              <Button type="button" variant="outline" onClick={() => setShowEditTeam(false)}>
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Team Members */}
      <Card className="p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-foreground">Team Members</h3>
          {teamData.canManage && creatableRoles.length > 0 && !showAddMember && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setAddMemberError(null)
                setShowAddMember(true)
              }}
              className="flex items-center gap-2"
            >
              <UserPlus className="h-4 w-4" />
              Add member
            </Button>
          )}
        </div>

        {showAddMember && teamData.canManage && (
          <form
            onSubmit={handleAddMember}
            className="mb-6 space-y-4 rounded-lg border border-border p-4"
            aria-label="Add member"
          >
            <p className="text-sm text-muted-foreground">
              Creates a new account in this team. Choose an initial password and share it with the
              new member privately: they must replace it when they first sign in.
            </p>
            {addMemberError && (
              <p
                role="alert"
                data-testid="add-member-error"
                className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
              >
                {addMemberError}
              </p>
            )}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div>
                <label
                  htmlFor="member-email"
                  className="mb-2 block text-sm font-medium text-foreground"
                >
                  Email
                </label>
                <Input
                  id="member-email"
                  type="email"
                  value={addMemberForm.email}
                  onChange={e => setAddMemberForm(prev => ({ ...prev, email: e.target.value }))}
                  required
                  disabled={addingMember}
                />
              </div>
              <div>
                <label
                  htmlFor="member-password"
                  className="mb-2 block text-sm font-medium text-foreground"
                >
                  Initial password
                </label>
                <Input
                  id="member-password"
                  type="password"
                  autoComplete="new-password"
                  value={addMemberForm.password}
                  onChange={e => setAddMemberForm(prev => ({ ...prev, password: e.target.value }))}
                  minLength={MIN_PASSWORD_LENGTH}
                  maxLength={MAX_PASSWORD_LENGTH}
                  required
                  disabled={addingMember}
                  aria-describedby="member-password-rule"
                />
                <p id="member-password-rule" className="mt-1 text-xs text-muted-foreground">
                  {PASSWORD_RULE_HINT}
                </p>
              </div>
              <div>
                <label
                  htmlFor="member-role"
                  className="mb-2 block text-sm font-medium text-foreground"
                >
                  Role
                </label>
                <select
                  id="member-role"
                  value={addMemberForm.role}
                  onChange={e =>
                    setAddMemberForm(prev => ({ ...prev, role: e.target.value as TeamRole }))
                  }
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                  disabled={addingMember}
                >
                  {creatableRoles.map(role => (
                    <option key={role} value={role}>
                      {getRoleDisplayName(role)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={addingMember}>
                {addingMember ? 'Adding...' : 'Add member'}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => setShowAddMember(false)}
                disabled={addingMember}
              >
                Cancel
              </Button>
            </div>
          </form>
        )}

        <div className="space-y-4">
          {members.map(member => {
            const RoleIcon = roleIcons[member.role] ?? User
            const roleColor = roleColors[member.role] ?? roleColors.member
            const isCurrentUser = member.user_id === user.id
            const canRemove = teamData.canManage && !isCurrentUser && member.role !== 'owner'

            return (
              <div
                key={member.user_id}
                data-testid="team-member"
                className="flex items-center justify-between rounded-lg border border-border p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-gray-500 to-gray-700">
                    <User className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <div className="font-medium text-foreground">
                      {member.user.email}
                      {isCurrentUser && <span className="text-muted-foreground"> (You)</span>}
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <Badge variant="outline" className={roleColor}>
                        <RoleIcon className="mr-1 h-3 w-3" />
                        {getRoleDisplayName(member.role)}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        Joined {formatDate(member.joined_at)}
                      </span>
                    </div>
                  </div>
                </div>

                {canRemove && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleRemoveMember(member.user_id, member.user.email)}
                    className="text-red-600 hover:text-red-700"
                    aria-label={`Remove ${member.user.email}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            )
          })}
        </div>
      </Card>

      {/* Role Information: what identity enforces today. */}
      <Card className="mt-6 p-6">
        <div className="mb-4 flex items-center gap-3">
          <Settings className="h-8 w-8 text-blue-500" />
          <h3 className="text-lg font-semibold text-foreground">Role Permissions</h3>
        </div>

        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded-lg border border-border p-4">
              <div className="mb-2 flex items-center gap-2">
                <Crown className="h-5 w-5 text-yellow-600" />
                <h4 className="font-medium text-foreground">Owner</h4>
              </div>
              <ul className="space-y-1 text-muted-foreground">
                <li>• Rename the team</li>
                <li>• Add admins and members</li>
                <li>• Remove admins and members</li>
                <li>• View all members</li>
              </ul>
            </div>

            <div className="rounded-lg border border-border p-4">
              <div className="mb-2 flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-600" />
                <h4 className="font-medium text-foreground">Admin</h4>
              </div>
              <ul className="space-y-1 text-muted-foreground">
                <li>• Rename the team</li>
                <li>• Add members</li>
                <li>• Remove admins and members</li>
                <li>• View all members</li>
              </ul>
            </div>

            <div className="rounded-lg border border-border p-4">
              <div className="mb-2 flex items-center gap-2">
                <User className="h-5 w-5 text-gray-600" />
                <h4 className="font-medium text-foreground">Member</h4>
              </div>
              <ul className="space-y-1 text-muted-foreground">
                <li>• View all members</li>
              </ul>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
