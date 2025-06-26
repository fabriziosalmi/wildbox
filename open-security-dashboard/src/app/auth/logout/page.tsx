'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/components/auth-provider'

export default function LogoutPage() {
  const { logout } = useAuth()
  const router = useRouter()

  useEffect(() => {
    logout()
    router.replace('/auth/login')
  }, [logout, router])

  return null
}
