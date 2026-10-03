'use client'

import { createContext, useContext, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Cookies from 'js-cookie'
import { LoginResponse, RegisterRequest, User } from '@/types'
import { beginSignOut, identityClient, getAuthPath } from '@/lib/api-client'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, name: string) => Promise<void>
  logout: () => Promise<void>
  refetchUser: () => Promise<void>
}

/** Where an account with an initial password changes it (#573). */
export const CHANGE_PASSWORD_PAGE = '/auth/change-password'

export const LOGIN_PAGE = '/auth/login'

/** Query flag telling the login page that a sign-up just created the account (#589). */
export const ACCOUNT_CREATED_PARAM = 'registered'

const AuthContext = createContext<AuthContextType | undefined>(undefined)

// Cookie options for the auth token. `secure` is derived from the actual
// page protocol instead of being hardcoded true: a Secure cookie is dropped
// by the browser on a plain-HTTP origin (local dev, and the CI E2E harness
// on http://localhost), which silently broke login there — the token was
// never stored, so the post-login /users/me call and redirect never ran. In
// production the dashboard is served over HTTPS, so this stays true.
function authCookieOptions(): Cookies.CookieAttributes {
  const secure = typeof window !== 'undefined' && window.location.protocol === 'https:'
  return { expires: 7, secure, sameSite: 'strict' }
}

/**
 * Replace the session's token, e.g. with the one change-password returns:
 * a password change ends every session issued before it, the current one
 * included (#569), and hands over a new token for this one.
 */
export function storeSessionToken(token: string) {
  if (typeof window !== 'undefined') {
    Cookies.set('auth_token', token, authCookieOptions())
  }
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
      logout: async () => {},
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

      const response = await identityClient.postForm<LoginResponse>(
        getAuthPath('/api/v1/auth/jwt/login'),
        formData
      )
      const { access_token } = response

      // Store token in cookie only (no localStorage to reduce XSS attack surface)
      if (typeof window !== 'undefined') {
        Cookies.set('auth_token', access_token, authCookieOptions())
      }

      // Fetch user data separately using the correct FastAPI Users endpoint
      const userData = await identityClient.get<User>(getAuthPath('/api/v1/users/me'))
      setUser(userData)

      // Redirect immediately after successful login to prevent race conditions.
      // An account a team admin created must change its initial password
      // first: identity and the gateway refuse everything else until then.
      router.replace(userData.must_change_password ? CHANGE_PASSWORD_PAGE : '/dashboard')
    } catch (error) {
      throw error
    }
  }

  const register = async (email: string, password: string, name: string) => {
    // identity's register route (fastapi-users) answers 201 with the created
    // user, not a token (#589). A refusal (password policy, address already
    // registered) is thrown as it came, for the form to show.
    const request: RegisterRequest = { email, password, name }
    await identityClient.post<User>(getAuthPath('/api/v1/auth/register'), request)

    // Then sign in with the same credentials through the one login flow: it
    // stores the token, loads the user and redirects, to the change-password
    // screen first for an account that must change its password (#573).
    // identity's login does not require a verified address, so this normally
    // succeeds. If it does not, the account exists all the same: send the
    // user to sign in instead of reporting an error that a retry would turn
    // into "already exists".
    try {
      await login(email, password)
    } catch {
      Cookies.remove('auth_token')
      setUser(null)
      router.replace(`${LOGIN_PAGE}?${ACCOUNT_CREATED_PARAM}=1`)
    }
  }

  const logout = async () => {
    // Skip during SSR
    if (typeof window === 'undefined') return

    // This function is the only owner of the navigation after a logout
    // (#590). The page's own requests keep going while it runs and answer
    // 401 once the token is revoked or the cookie removed; the API client
    // used to answer each with a hard redirect to '/', which raced the
    // redirect to the login page and sometimes won.
    beginSignOut()

    // Revoke the token server-side before forgetting it. Deleting the cookie
    // alone left the session valid at the gateway for the rest of the token's
    // lifetime, for anyone who had copied it. The request carries the token
    // from the cookie, so it has to go out first; a failure must not keep the
    // user logged in locally, hence no early return.
    try {
      await identityClient.post(getAuthPath('/api/v1/auth/jwt/logout'))
    } catch {
      // Signed out locally all the same.
    }

    Cookies.remove('auth_token')

    // A full navigation, issued once the cookie is gone: it also drops every
    // piece of client state of the old session (this context, the query
    // cache), and replace() keeps it out of the history.
    window.location.replace(LOGIN_PAGE)
  }

  const refetchUser = async () => {
    // Skip during SSR
    if (typeof window === 'undefined') return

    try {
      const userData = await identityClient.get<User>(getAuthPath('/api/v1/users/me'))
      setUser(userData)
    } catch {
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
            const userData = await identityClient.get<User>(getAuthPath('/api/v1/users/me'))
            setUser(userData)
          } catch {
            // Token is invalid, clear it silently without redirect
            Cookies.remove('auth_token')
            setUser(null)
          }
        }
      } catch {
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
