'use client'

import { useAuth } from '@/components/auth-provider'
import { MainLayout } from '@/components/main-layout'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { 
  User, 
  CreditCard, 
  Key, 
  Users, 
  Shield,
  Settings as SettingsIcon
} from 'lucide-react'

const settingsNavigation = [
  {
    name: 'Profile',
    href: '/settings/profile',
    icon: User,
    description: 'Manage your account details',
  },
  {
    name: 'Billing',
    href: '/settings/billing',
    icon: CreditCard,
    description: 'Subscription and billing',
  },
  {
    name: 'API Keys',
    href: '/settings/api-keys',
    icon: Key,
    description: 'Manage API access keys',
  },
  {
    name: 'Team',
    href: '/settings/team',
    icon: Users,
    description: 'Team members and roles',
  },
]

interface SettingsLayoutProps {
  children: React.ReactNode
}

export default function SettingsLayout({ children }: SettingsLayoutProps) {
  const { user } = useAuth()
  const pathname = usePathname()

  // Add admin navigation if user is superuser
  const navigation = user?.is_superuser 
    ? [
        ...settingsNavigation,
        {
          name: 'Admin',
          href: '/settings/admin',
          icon: Shield,
          description: 'System administration',
        },
      ]
    : settingsNavigation

  return (
    <MainLayout>
      <div className="flex flex-1 overflow-hidden">
        {/* Settings Sidebar */}
        <div className="w-64 bg-card border-r border-border">
          <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <SettingsIcon className="w-6 h-6 text-foreground" />
              <h1 className="text-xl font-semibold text-foreground">Settings</h1>
            </div>
            
            <nav className="space-y-2">
              {navigation.map((item) => {
                const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
                const Icon = item.icon
                
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted"
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    <div>
                      <div className="font-medium">{item.name}</div>
                      <div className="text-xs opacity-70">{item.description}</div>
                    </div>
                  </Link>
                )
              })}
            </nav>
          </div>
        </div>

        {/* Settings Content */}
        <div className="flex-1 overflow-auto">
          <div className="p-6">
            {children}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
