'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { KeyRound, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { storeSessionToken, useAuth } from '@/components/auth-provider'
import { identityClient, getIdentityPath } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/utils'
import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  PASSWORD_RULE_HINT,
  passwordPolicyProblem,
} from '@/lib/password-policy'

// A password change ends every session issued before it, this one included,
// and answers with a new token for this session (#569).
interface ChangePasswordResponse {
  message: string
  access_token: string
  token_type: string
}

/**
 * The first screen of an account a team owner or admin created (#573).
 *
 * Its initial password was chosen by that administrator, so until the user
 * replaces it identity and the gateway refuse every other request of the
 * session (PASSWORD_CHANGE_REQUIRED). The main layout and the login send
 * such a user here before anything else.
 */
export default function ChangeInitialPasswordPage() {
  const { user, isLoading: authLoading, refetchUser, logout } = useAuth()
  const router = useRouter()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const mustChange = !!user?.must_change_password

  // Nothing to do here for an account that already chose its password.
  useEffect(() => {
    if (!authLoading && user && !mustChange) router.replace('/dashboard')
  }, [authLoading, user, mustChange, router])

  if (authLoading || (user && !mustChange)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <p className="mb-4 text-muted-foreground">Please log in to continue</p>
          <Link href="/auth/login" className="font-medium text-primary">
            Go to Login
          </Link>
        </div>
      </div>
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (next !== confirm) {
      setError('The new passwords do not match')
      return
    }
    // identity's password rule (#583); its reason is shown if it refuses one.
    const problem = passwordPolicyProblem(next, user?.email)
    if (problem) {
      setError(problem)
      return
    }
    setSaving(true)
    try {
      const { access_token } = await identityClient.post<ChangePasswordResponse>(
        getIdentityPath('/api/v1/admin/me/change-password'),
        { current_password: current, new_password: next }
      )
      // The token this page was using no longer works; carry on with the new one.
      storeSessionToken(access_token)
      await refetchUser()
      router.replace('/dashboard')
    } catch (err) {
      setError(getErrorMessage(err, 'The password could not be changed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-linear-to-br/srgb from-blue-50 to-indigo-100 p-4 dark:from-gray-900 dark:to-gray-800">
      <div className="w-full max-w-md">
        <Card className="border-0 shadow-xl">
          <CardHeader className="pb-4 text-center">
            <div className="mb-2 flex justify-center">
              <KeyRound className="h-8 w-8 text-primary" />
            </div>
            <CardTitle className="text-2xl">Choose your password</CardTitle>
            <CardDescription>
              Your account was created by a team administrator. Replace the initial password before
              you continue.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div
                  role="alert"
                  className="rounded-md border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-900/20"
                >
                  <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
                </div>
              )}
              <p className="text-sm text-muted-foreground" data-testid="change-password-account">
                {user.email}
              </p>
              <div className="space-y-2">
                <label htmlFor="initial-password" className="text-sm font-medium">
                  Initial password
                </label>
                <Input
                  id="initial-password"
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={e => setCurrent(e.target.value)}
                  required
                  disabled={saving}
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="new-password" className="text-sm font-medium">
                  New password
                </label>
                <Input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  onChange={e => setNext(e.target.value)}
                  minLength={MIN_PASSWORD_LENGTH}
                  maxLength={MAX_PASSWORD_LENGTH}
                  required
                  disabled={saving}
                  aria-describedby="new-password-rule"
                />
                <p id="new-password-rule" className="text-xs text-muted-foreground">
                  {PASSWORD_RULE_HINT}
                </p>
              </div>
              <div className="space-y-2">
                <label htmlFor="confirm-password" className="text-sm font-medium">
                  Confirm new password
                </label>
                <Input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={e => setConfirm(e.target.value)}
                  minLength={MIN_PASSWORD_LENGTH}
                  maxLength={MAX_PASSWORD_LENGTH}
                  required
                  disabled={saving}
                />
              </div>
              <Button type="submit" className="w-full" disabled={saving}>
                {saving ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Saving...
                  </>
                ) : (
                  'Set password'
                )}
              </Button>
              <Button type="button" variant="ghost" className="w-full" onClick={logout}>
                Log out
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
