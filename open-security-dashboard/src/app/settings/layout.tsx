'use client'

import { MainLayout } from '@/components/main-layout'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { User, Key, Users, Settings as SettingsIcon } from 'lucide-react'

const settingsNavigation = [
  {
    name: 'Profile',
    href: '/settings/profile',
    icon: User,
    description: 'Manage your account details',
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
  const pathname = usePathname()

  // Use base settings navigation only - admin is now in main nav
  const navigation = settingsNavigation

  return (
    <MainLayout>
      <div className="flex flex-1 overflow-hidden">
        {/* Settings Sidebar */}
        <div className="w-64 border-r border-border bg-card">
          <div className="p-6">
            <div className="mb-6 flex items-center gap-3">
              <SettingsIcon className="h-6 w-6 text-foreground" />
              <h1 className="text-xl font-semibold text-foreground">Settings</h1>
            </div>

            <nav className="space-y-2">
              {navigation.map(item => {
                const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
                const Icon = item.icon

                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                      isActive
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                    )}
                  >
                    <Icon className="h-4 w-4" />
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
          <div className="p-6">{children}</div>
        </div>
      </div>
    </MainLayout>
  )
}
