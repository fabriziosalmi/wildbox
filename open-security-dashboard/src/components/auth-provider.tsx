'use client'

import { createContext, useContext, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Cookies from 'js-cookie'
import { User } from '@/types'
import { identityClient } from '@/lib/api-client'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, name: string) => Promise<void>
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
      // Login with form data (OAuth2PasswordRequestForm)
      const formData = new URLSearchParams()
      formData.append('username', email)
      formData.append('password', password)

      const response = await identityClient.postForm('/api/v1/auth/login', formData)
      const { access_token } = response

      // Store token
      Cookies.set('auth_token', access_token, { expires: 7, secure: true, sameSite: 'strict' })
      localStorage.setItem('auth_token', access_token)

      // Fetch user data separately
      const userData = await identityClient.get('/api/v1/auth/me')
      setUser(userData)
      localStorage.setItem('user', JSON.stringify(userData))

      router.push('/dashboard')
    } catch (error) {
      throw error
    }
  }

  const register = async (email: string, password: string, name: string) => {
    try {
      const response = await identityClient.post('/api/v1/auth/register', { email, password, name })
      const { access_token } = response

      // Store token
      Cookies.set('auth_token', access_token, { expires: 7, secure: true, sameSite: 'strict' })
      localStorage.setItem('auth_token', access_token)

      // Fetch user data separately
      const userData = await identityClient.get('/api/v1/auth/me')
      setUser(userData)
      localStorage.setItem('user', JSON.stringify(userData))

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
      const userData = await identityClient.get('/api/v1/auth/me')
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
            await identityClient.get('/api/v1/auth/me')
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
    register,
    logout,
    refetchUser,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
