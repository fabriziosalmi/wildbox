import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'System Administration - Wildbox Security',
  description: 'System administration and user management',
}

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return children
}
