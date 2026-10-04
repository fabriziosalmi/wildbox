'use client'

import { useAuth } from '@/components/auth-provider'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import Link from 'next/link'
import { User, Key, Users, ArrowRight, Settings } from 'lucide-react'

const settingsCards = [
  {
    title: 'Profile',
    description: 'Manage your account information and security settings',
    icon: User,
    href: '/settings/profile',
    color: 'from-blue-500 to-blue-600',
  },
  {
    title: 'API Keys',
    description: 'Create and manage API keys for programmatic access',
    icon: Key,
    href: '/settings/api-keys',
    color: 'from-purple-500 to-purple-600',
  },
  {
    title: 'Team',
    description: 'Manage team members and permissions',
    icon: Users,
    href: '/settings/team',
    color: 'from-orange-500 to-orange-600',
  },
]

export default function SettingsPage() {
  const { user } = useAuth()

  // Use base settings cards only - admin is now a separate page
  const allCards = settingsCards

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <div className="mb-4 flex items-center gap-3">
          <Settings className="h-8 w-8 text-foreground" />
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
        </div>
        <p className="text-muted-foreground">Manage your account, team, and system preferences</p>
      </div>

      {/* Quick Stats */}
      <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-3">
        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-linear-to-br/srgb from-blue-500 to-purple-600">
              <User className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Account Status</div>
              <div className="font-semibold text-foreground">
                {user?.is_active ? 'Active' : 'Inactive'}
              </div>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-linear-to-br/srgb from-purple-500 to-pink-600">
              <Users className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Team Members</div>
              <div className="font-semibold text-foreground">
                {user?.team_memberships?.length || 1}
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Settings Categories */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {allCards.map(card => {
          const Icon = card.icon

          return (
            <Card key={card.title} className="p-6 transition-shadow hover:shadow-lg">
              <div className="mb-4 flex items-start justify-between">
                <div
                  className={`h-12 w-12 bg-linear-to-br/srgb ${card.color} flex items-center justify-center rounded-lg`}
                >
                  <Icon className="h-6 w-6 text-white" />
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>

              <h3 className="mb-2 text-lg font-semibold text-foreground">{card.title}</h3>

              <p className="mb-4 text-sm text-muted-foreground">{card.description}</p>

              <Link href={card.href}>
                <Button variant="outline" className="w-full">
                  Manage {card.title}
                </Button>
              </Link>
            </Card>
          )
        })}
      </div>

      {/* Account Information */}
      <Card className="mt-8 p-6" data-testid="account-information">
        <h3 className="mb-4 text-lg font-semibold text-foreground">Account Information</h3>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          <div>
            <div className="mb-1 text-sm text-muted-foreground">Email Address</div>
            <div className="font-medium text-foreground">{user?.email}</div>
          </div>

          <div>
            <div className="mb-1 text-sm text-muted-foreground">Account Type</div>
            <div className="font-medium text-foreground">
              {user?.is_superuser ? 'Administrator' : 'Standard User'}
            </div>
          </div>

          <div>
            <div className="mb-1 text-sm text-muted-foreground">Member Since</div>
            <div className="font-medium text-foreground">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
            </div>
          </div>

          <div>
            <div className="mb-1 text-sm text-muted-foreground">Last Updated</div>
            <div className="font-medium text-foreground">
              {user?.updated_at ? new Date(user.updated_at).toLocaleDateString() : 'Never'}
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
