'use client'

import { useEffect, useRef } from 'react'
import { useAuth } from '@/components/auth-provider'

export default function LogoutPage() {
  const { logout } = useAuth()
  const started = useRef(false)

  useEffect(() => {
    // logout() owns the navigation to the login page (#590); it runs once,
    // although the provider hands over a new logout on every render.
    if (started.current) return
    started.current = true
    void logout()
  }, [logout])

  return null
}
