'use client'

import { useState } from 'react'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/components/auth-provider'
import Link from 'next/link'
import {
  LayoutDashboard,
  Shield,
  Wrench,
  Cloud,
  Monitor,
  Bug,
  Zap,
  Brain,
  Settings,
  Menu,
  X,
  Bell,
  Search,
  User,
  LogOut,
  ChevronDown,
  Crown,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'

interface NavigationItem {
  name: string
  href: string
  icon: any
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
  {
    name: 'Cloud Security',
    href: '/cloud-security',
    icon: Cloud,
    description: 'CSPM and compliance',
    children: [
      { name: 'Scans', href: '/cloud-security/scans' },
      { name: 'Compliance', href: '/cloud-security/compliance' },
    ],
  },
  {
    name: 'Endpoints',
    href: '/endpoints',
    icon: Monitor,
    description: 'Sensor management',
  },
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
    name: 'AI Analyst',
    href: '/ai-analyst',
    icon: Brain,
    description: 'Intelligent analysis',
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
      { name: 'Billing', href: '/settings/billing' },
      { name: 'API Keys', href: '/settings/api-keys' },
      { name: 'Team', href: '/settings/team' },
    ],
  },
]

// Function to get navigation items based on user role
const getNavigation = (user: any): NavigationItem[] => {
  const navigation = [...baseNavigation]
  
  // Debug logging
  console.log('getNavigation - user:', user)
  console.log('getNavigation - is_superuser:', user?.is_superuser)
  console.log('getNavigation - user email:', user?.email)
  
  // Check for superuser or development override
  const isSuperuser = user?.is_superuser || user?.email === 'superadmin@wildbox.com'
  
  // Add admin navigation for superusers as a separate top-level item
  if (isSuperuser) {
    console.log('Adding admin navigation for superuser')
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

  // Get navigation items based on user role
  const navigation = getNavigation(user)

  const toggleExpanded = (name: string) => {
    setExpandedItems(prev =>
      prev.includes(name)
        ? prev.filter(item => item !== name)
        : [...prev, name]
    )
  }

  const isActive = (href: string) => {
    return pathname === href || pathname.startsWith(href + '/')
  }

  const handleLogout = () => {
    logout()
  }

  const getUserRole = () => {
    if (user?.is_superuser || user?.email === 'superadmin@wildbox.com') return 'Super Admin'
    if (user?.team_memberships?.[0]?.role === 'owner') return 'Team Owner'
    if (user?.team_memberships?.[0]?.role === 'admin') return 'Team Admin'
    return 'Member'
  }

  const getRoleBadgeColor = () => {
    if (user?.is_superuser || user?.email === 'superadmin@wildbox.com') return 'text-red-600 border-red-600'
    if (user?.team_memberships?.[0]?.role === 'owner') return 'text-yellow-600 border-yellow-600'
    if (user?.team_memberships?.[0]?.role === 'admin') return 'text-blue-600 border-blue-600'
    return 'text-gray-600 border-gray-600'
  }

  // If authentication is still loading, show loading state
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <Shield className="w-16 h-16 text-primary mx-auto mb-4 animate-pulse" />
          <h1 className="text-2xl font-bold mb-2">Wildbox Security</h1>
          <p className="text-muted-foreground mb-6">Loading...</p>
        </div>
      </div>
    )
  }

  // If not authenticated, redirect to login (but only after loading is complete)
  if (!isLoading && !isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <Shield className="w-16 h-16 text-primary mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">Wildbox Security</h1>
          <p className="text-muted-foreground mb-6">Please log in to continue</p>
          <Link 
            href="/"
            className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
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
      <div className={cn(
        "fixed inset-y-0 left-0 z-50 w-64 bg-card border-r transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:static lg:inset-0",
        sidebarOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center h-16 px-6 border-b">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-foreground">Wildbox</h1>
                <p className="text-xs text-muted-foreground">Security Suite</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto scrollbar-thin">
            {navigation.map((item) => (
              <div key={item.name}>
                {item.children ? (
                  <div>
                    <button
                      onClick={() => toggleExpanded(item.name)}
                      className={cn(
                        "nav-item w-full justify-between",
                        isActive(item.href) && "active"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <item.icon className="w-5 h-5" />
                        <div className="text-left">
                          <div className="text-sm font-medium">{item.name}</div>
                          <div className="text-xs text-muted-foreground">{item.description}</div>
                        </div>
                      </div>
                      <ChevronDown
                        className={cn(
                          "w-4 h-4 transition-transform",
                          expandedItems.includes(item.name) && "rotate-180"
                        )}
                      />
                    </button>
                    {expandedItems.includes(item.name) && (
                      <div className="ml-8 mt-2 space-y-1">
                        {item.children.map((child) => (
                          <Link
                            key={child.href}
                            href={child.href}
                            className={cn(
                              "block px-3 py-2 text-sm rounded-md transition-colors hover:bg-accent",
                              isActive(child.href) && "bg-primary text-primary-foreground"
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
                    className={cn(
                      "nav-item w-full",
                      isActive(item.href) && "active"
                    )}
                  >
                    <item.icon className="w-5 h-5" />
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
          <div className="p-4 border-t">
            <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-accent transition-colors">
              <Link href="/settings/profile" className="flex items-center gap-3 flex-1">
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center">
                  <User className="w-4 h-4 text-primary-foreground" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-medium">{user?.email || 'User'}</div>
                  <div className="flex items-center gap-1 mt-1">
                    <Badge variant="outline" className={`text-xs ${getRoleBadgeColor()}`}>
                      {(user?.is_superuser || user?.email === 'superadmin@wildbox.com') && <Crown className="w-3 h-3 mr-1" />}
                      {getUserRole()}
                    </Badge>
                  </div>
                </div>
              </Link>
              <button
                onClick={handleLogout}
                className="p-1 rounded hover:bg-destructive/10 transition-colors"
                title="Logout"
              >
                <LogOut className="w-4 h-4 text-muted-foreground hover:text-destructive" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="h-16 bg-card border-b flex items-center justify-between px-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden p-2 rounded-md hover:bg-accent"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            
            {/* Search */}
            <div className="hidden md:flex items-center gap-2 bg-accent/50 rounded-md px-3 py-2 min-w-96">
              <Search className="w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search IOCs, playbooks, tools..."
                className="bg-transparent border-0 outline-none flex-1 text-sm placeholder:text-muted-foreground"
              />
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Notifications */}
            <button className="relative p-2 rounded-md hover:bg-accent">
              <Bell className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full text-xs flex items-center justify-center text-white">
                3
              </span>
            </button>

            {/* Status Indicator */}
            <div className="flex items-center gap-2 px-3 py-1 bg-green-100 dark:bg-green-900 rounded-full">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              <span className="text-xs font-medium text-green-800 dark:text-green-100">
                All Systems Operational
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  )
}
