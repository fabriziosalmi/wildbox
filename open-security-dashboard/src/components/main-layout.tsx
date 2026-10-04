'use client'

import { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { CHANGE_PASSWORD_PAGE, useAuth } from '@/components/auth-provider'
import Link from 'next/link'
import {
  LayoutDashboard,
  Shield,
  Wrench,
  Bug,
  Zap,
  Settings,
  Menu,
  X,
  User,
  LogOut,
  ChevronDown,
  Crown,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import type { User as UserType } from '@/types'

interface NavigationItem {
  name: string
  href: string
  icon: LucideIcon
  description: string
  children?: { name: string; href: string }[]
}

const baseNavigation: NavigationItem[] = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
    description: 'Overview and metrics',
  },
  {
    name: 'Threat Intel',
    href: '/threat-intel',
    icon: Shield,
    description: 'Feeds and lookups',
    children: [
      { name: 'Feeds', href: '/threat-intel/feeds' },
      { name: 'Lookup', href: '/threat-intel/lookup' },
      { name: 'Data', href: '/threat-intel/data' },
    ],
  },
  {
    name: 'Toolbox',
    href: '/toolbox',
    icon: Wrench,
    description: 'Security tools execution',
  },
  // REMOVED FOR v1.0 - Cloud Security (CSPM) - Roadmap Future
  // {
  //   name: 'Cloud Security',
  //   href: '/cloud-security',
  //   icon: Cloud,
  //   description: 'CSPM and compliance',
  //   children: [
  //     { name: 'Scans', href: '/cloud-security/scans' },
  //     { name: 'Compliance', href: '/cloud-security/compliance' },
  //   ],
  // },
  // REMOVED FOR v1.0 - Endpoints (Sensor) - Roadmap Future
  // {
  //   name: 'Endpoints',
  //   href: '/endpoints',
  //   icon: Monitor,
  //   description: 'Sensor management',
  // },
  {
    name: 'Vulnerabilities',
    href: '/vulnerabilities',
    icon: Bug,
    description: 'Guardian findings',
  },
  {
    name: 'Response',
    href: '/response',
    icon: Zap,
    description: 'Playbooks and automation',
    children: [
      { name: 'Playbooks', href: '/response/playbooks' },
      { name: 'Runs', href: '/response/runs' },
    ],
  },
  {
    name: 'API Docs',
    href: '/api-docs',
    icon: Shield,
    description: 'API reference and examples',
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: Settings,
    description: 'Account and configuration',
    children: [
      { name: 'Profile', href: '/settings/profile' },
      { name: 'API Keys', href: '/settings/api-keys' },
      { name: 'Team', href: '/settings/team' },
    ],
  },
]

// Function to get navigation items based on user role
const getNavigation = (user: UserType | null): NavigationItem[] => {
  const navigation = [...baseNavigation]

  const isSuperuser = user?.is_superuser

  // Add admin navigation for superusers as a separate top-level item
  if (isSuperuser) {
    navigation.push({
      name: 'Administration',
      href: '/admin',
      icon: Crown,
      description: 'System administration',
    })
  }

  return navigation
}

interface MainLayoutProps {
  children: React.ReactNode
}

export function MainLayout({ children }: MainLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [expandedItems, setExpandedItems] = useState<string[]>([])
  const pathname = usePathname()
  const { user, logout, isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  // Get navigation items based on user role
  const navigation = getNavigation(user)

  const toggleExpanded = (name: string) => {
    setExpandedItems(prev =>
      prev.includes(name) ? prev.filter(item => item !== name) : [...prev, name]
    )
  }

  const isActive = (href: string) => {
    return pathname === href || pathname.startsWith(href + '/')
  }

  const handleLogout = () => {
    // logout() navigates to the login page itself, once the session is gone.
    void logout()
  }

  const getUserRole = () => {
    if (user?.is_superuser) return 'Super Admin'
    if (user?.team_memberships?.[0]?.role === 'owner') return 'Team Owner'
    if (user?.team_memberships?.[0]?.role === 'admin') return 'Team Admin'
    return 'Member'
  }

  const getRoleBadgeColor = () => {
    if (user?.is_superuser) return 'text-red-600 border-red-600'
    if (user?.team_memberships?.[0]?.role === 'owner') return 'text-yellow-600 border-yellow-600'
    if (user?.team_memberships?.[0]?.role === 'admin') return 'text-blue-600 border-blue-600'
    return 'text-gray-600 border-gray-600'
  }

  // An account with an initial password changes it before anything else
  // (#573); every other request of its session is refused meanwhile.
  const mustChangePassword = !!user?.must_change_password
  useEffect(() => {
    if (mustChangePassword) router.replace(CHANGE_PASSWORD_PAGE)
  }, [mustChangePassword, router])

  // If authentication is still loading, show loading state
  if (isLoading || mustChangePassword) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <Shield className="mx-auto mb-4 h-16 w-16 animate-pulse text-primary" />
          <h1 className="mb-2 text-2xl font-bold">Wildbox Security</h1>
          <p className="mb-6 text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  // If not authenticated, redirect to login (but only after loading is complete)
  if (!isLoading && !isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <Shield className="mx-auto mb-4 h-16 w-16 text-primary" />
          <h1 className="mb-2 text-2xl font-bold">Wildbox Security</h1>
          <p className="mb-6 text-muted-foreground">Please log in to continue</p>
          <Link
            href="/"
            className="inline-flex items-center rounded-md bg-primary px-4 py-2 text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Go to Login
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <div
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-64 transform border-r bg-card transition-transform duration-200 ease-in-out lg:static lg:inset-0 lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex h-full flex-col">
          {/* Logo */}
          <div className="flex h-16 items-center border-b px-6">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-linear-to-br/srgb from-blue-500 to-purple-600">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-foreground">Wildbox</h1>
                <p className="text-xs text-muted-foreground">Security Suite</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 scrollbar-thin space-y-2 overflow-y-auto px-4 py-6">
            {navigation.map(item => (
              <div key={item.name}>
                {item.children ? (
                  <div>
                    <button
                      onClick={() => toggleExpanded(item.name)}
                      className={cn(
                        'nav-item w-full justify-between',
                        isActive(item.href) && 'active'
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <item.icon className="h-5 w-5" />
                        <div className="text-left">
                          <div className="text-sm font-medium">{item.name}</div>
                          <div className="text-xs text-muted-foreground">{item.description}</div>
                        </div>
                      </div>
                      <ChevronDown
                        className={cn(
                          'h-4 w-4 transition-transform',
                          expandedItems.includes(item.name) && 'rotate-180'
                        )}
                      />
                    </button>
                    {expandedItems.includes(item.name) && (
                      <div className="mt-2 ml-8 space-y-1">
                        {item.children.map(child => (
                          <Link
                            key={child.href}
                            href={child.href}
                            className={cn(
                              'block rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent',
                              isActive(child.href) && 'bg-primary text-primary-foreground'
                            )}
                          >
                            {child.name}
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <Link
                    href={item.href}
                    className={cn('nav-item w-full', isActive(item.href) && 'active')}
                  >
                    <item.icon className="h-5 w-5" />
                    <div>
                      <div className="text-sm font-medium">{item.name}</div>
                      <div className="text-xs text-muted-foreground">{item.description}</div>
                    </div>
                  </Link>
                )}
              </div>
            ))}
          </nav>

          {/* User Profile */}
          <div className="border-t p-4">
            <div className="flex items-center gap-3 rounded-lg p-2 transition-colors hover:bg-accent">
              <Link href="/settings/profile" className="flex flex-1 items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary">
                  <User className="h-4 w-4 text-primary-foreground" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-medium">{user?.email || 'User'}</div>
                  <div className="mt-1 flex items-center gap-1">
                    <Badge variant="outline" className={`text-xs ${getRoleBadgeColor()}`}>
                      {user?.is_superuser && <Crown className="mr-1 h-3 w-3" />}
                      {getUserRole()}
                    </Badge>
                  </div>
                </div>
              </Link>
              <button
                onClick={handleLogout}
                className="rounded p-1 transition-colors hover:bg-destructive/10"
                title="Logout"
              >
                <LogOut className="h-4 w-4 text-muted-foreground hover:text-destructive" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header */}
        <header className="flex h-16 items-center justify-between border-b bg-card px-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="rounded-md p-2 hover:bg-accent lg:hidden"
            >
              {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>

            {/* Global search, notifications and the system-status pill are
                hidden until they're backed by real data — showing a static
                badge / always-green "operational" pill / dead search box made
                the app look like a mockup. */}
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto p-6">{children}</main>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  )
}
