'use client'

import { createContext, useContext, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Cookies from 'js-cookie'
import { User } from '@/types'
import { apiClient } from '@/lib/api-client'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  refetchUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: React.ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  const isAuthenticated = !!user

  const login = async (email: string, password: string) => {
    try {
      const response = await apiClient.post('/auth/login', { email, password })
      const { token, user: userData } = response

      // Store token
      Cookies.set('auth_token', token, { expires: 7, secure: true, sameSite: 'strict' })
      localStorage.setItem('auth_token', token)
      localStorage.setItem('user', JSON.stringify(userData))

      setUser(userData)
      router.push('/dashboard')
    } catch (error) {
      throw error
    }
  }

  const logout = () => {
    // Clear tokens
    Cookies.remove('auth_token')
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')

    setUser(null)
    router.push('/auth/login')
  }

  const refetchUser = async () => {
    try {
      const userData = await apiClient.get('/auth/me')
      setUser(userData)
      localStorage.setItem('user', JSON.stringify(userData))
    } catch (error) {
      console.error('Failed to refetch user:', error)
      logout()
    }
  }

  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = Cookies.get('auth_token') || localStorage.getItem('auth_token')
        const savedUser = localStorage.getItem('user')

        if (token && savedUser) {
          try {
            const userData = JSON.parse(savedUser)
            setUser(userData)
            
            // Validate token by making a request
            await apiClient.get('/auth/me')
          } catch (error) {
            // Token is invalid, clear it
            logout()
          }
        }
      } catch (error) {
        console.error('Auth initialization error:', error)
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
  }, [])

  const value = {
    user,
    isLoading,
    isAuthenticated,
    login,
    logout,
    refetchUser,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
