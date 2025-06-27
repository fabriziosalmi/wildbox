'use client'

import { useAuth } from '@/components/auth-provider'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import Link from 'next/link'
import { 
  User, 
  CreditCard, 
  Key, 
  Users, 
  Shield,
  ArrowRight,
  Settings
} from 'lucide-react'

const settingsCards = [
  {
    title: 'Profile',
    description: 'Manage your account information and security settings',
    icon: User,
    href: '/settings/profile',
    color: 'from-blue-500 to-blue-600',
  },
  {
    title: 'Billing',
    description: 'View subscription details and manage billing',
    icon: CreditCard,
    href: '/settings/billing',
    color: 'from-green-500 to-green-600',
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
        <div className="flex items-center gap-3 mb-4">
          <Settings className="w-8 h-8 text-foreground" />
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
        </div>
        <p className="text-muted-foreground">
          Manage your account, team, and system preferences
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <User className="w-6 h-6 text-white" />
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
            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-blue-600 rounded-lg flex items-center justify-center">
              <CreditCard className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Plan</div>
              <div className="font-semibold text-foreground">Free</div>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-600 rounded-lg flex items-center justify-center">
              <Users className="w-6 h-6 text-white" />
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {allCards.map((card) => {
          const Icon = card.icon
          
          return (
            <Card key={card.title} className="p-6 hover:shadow-lg transition-shadow">
              <div className="flex items-start justify-between mb-4">
                <div className={`w-12 h-12 bg-gradient-to-br ${card.color} rounded-lg flex items-center justify-center`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <ArrowRight className="w-5 h-5 text-muted-foreground" />
              </div>
              
              <h3 className="text-lg font-semibold text-foreground mb-2">
                {card.title}
              </h3>
              
              <p className="text-muted-foreground text-sm mb-4">
                {card.description}
              </p>
              
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
      <Card className="p-6 mt-8">
        <h3 className="text-lg font-semibold text-foreground mb-4">Account Information</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <div className="text-sm text-muted-foreground mb-1">Email Address</div>
            <div className="font-medium text-foreground">{user?.email}</div>
          </div>
          
          <div>
            <div className="text-sm text-muted-foreground mb-1">Account Type</div>
            <div className="font-medium text-foreground">
              {user?.is_superuser ? 'Administrator' : 'Standard User'}
            </div>
          </div>
          
          <div>
            <div className="text-sm text-muted-foreground mb-1">Member Since</div>
            <div className="font-medium text-foreground">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
            </div>
          </div>
          
          <div>
            <div className="text-sm text-muted-foreground mb-1">Last Updated</div>
            <div className="font-medium text-foreground">
              {user?.updated_at ? new Date(user.updated_at).toLocaleDateString() : 'Never'}
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
