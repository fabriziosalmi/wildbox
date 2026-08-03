'use client'

import { createContext, useContext, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Cookies from 'js-cookie'
import { User } from '@/types'
import { identityClient, getAuthPath } from '@/lib/api-client'

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

// Cookie options for the auth token. `secure` is derived from the actual
// page protocol instead of being hardcoded true: a Secure cookie is dropped
// by the browser on a plain-HTTP origin (local dev, and the CI E2E harness
// on http://localhost), which silently broke login there — the token was
// never stored, so the post-login /users/me call and redirect never ran. In
// production the dashboard is served over HTTPS, so this stays true.
function authCookieOptions(): Cookies.CookieAttributes {
  const secure =
    typeof window !== 'undefined' && window.location.protocol === 'https:'
  return { expires: 7, secure, sameSite: 'strict' }
}

export function useAuth() {
  const context = useContext(AuthContext)
  
  // Check if we're on the client side and context is available
  if (typeof window === 'undefined' || context === undefined) {
    // Return a default state for SSR or when outside provider
    return {
      user: null,
      isLoading: true,
      isAuthenticated: false,
      login: async () => {},
      register: async () => {},
      logout: () => {},
      refetchUser: async () => {},
    }
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

      const response = await identityClient.postForm(getAuthPath('/api/v1/auth/jwt/login'), formData)
      const { access_token } = response

      // Store token in cookie only (no localStorage to reduce XSS attack surface)
      if (typeof window !== 'undefined') {
        Cookies.set('auth_token', access_token, authCookieOptions())
      }

      // Fetch user data separately using the correct FastAPI Users endpoint
      const userData = await identityClient.get(getAuthPath('/api/v1/users/me'))
      setUser(userData)

      // Redirect immediately after successful login to prevent race conditions
      router.replace('/dashboard')
    } catch (error) {
      throw error
    }
  }

  const register = async (email: string, password: string, name: string) => {
    try {
      const response = await identityClient.post(getAuthPath('/api/v1/auth/register'), { email, password, name })
      const { access_token } = response

      // Store token in cookie only (no localStorage to reduce XSS attack surface)
      if (typeof window !== 'undefined') {
        Cookies.set('auth_token', access_token, authCookieOptions())
      }

      // Fetch user data separately using the correct FastAPI Users endpoint
      const userData = await identityClient.get(getAuthPath('/api/v1/users/me'))
      setUser(userData)

      // Redirect immediately after successful registration
      router.replace('/dashboard')
    } catch (error) {
      throw error
    }
  }

  const logout = () => {
    // Skip during SSR
    if (typeof window === 'undefined') return

    // Clear auth cookie
    Cookies.remove('auth_token')

    setUser(null)

    // Use replace to prevent going back to authenticated state
    router.replace('/auth/login')
  }

  const refetchUser = async () => {
    // Skip during SSR
    if (typeof window === 'undefined') return

    try {
      const userData = await identityClient.get(getAuthPath('/api/v1/users/me'))
      setUser(userData)
    } catch (error) {
      // Clear auth silently and let the page handle the redirect
      Cookies.remove('auth_token')
      setUser(null)
    }
  }

  useEffect(() => {
    // Skip during SSR
    if (typeof window === 'undefined') {
      setIsLoading(false)
      return
    }

    const initAuth = async () => {
      try {
        const token = Cookies.get('auth_token')

        if (token) {
          try {
            // Always fetch fresh user data to ensure we have the latest info
            const userData = await identityClient.get(getAuthPath('/api/v1/users/me'))
            setUser(userData)
          } catch (error) {
            // Token is invalid, clear it silently without redirect
            Cookies.remove('auth_token')
            setUser(null)
          }
        }
      } catch (error) {
        // Auth initialization error - non-fatal
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
