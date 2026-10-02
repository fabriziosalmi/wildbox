import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { identityClient, getAuthPath } from '@/lib/api-client'
import { User } from '@/types'

// Custom hook for fetching user data
export function useUser() {
  return useQuery({
    queryKey: ['user'],
    queryFn: () => identityClient.get<User>(getAuthPath('/api/v1/users/me')),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

// Custom hook for updating user profile
export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (userData: Partial<User>) =>
      identityClient.put<User>(getAuthPath('/api/v1/users/me'), userData),
    onSuccess: updatedUser => {
      queryClient.setQueryData(['user'], updatedUser)
    },
  })
}

// Custom hook for logout
export function useLogout() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => identityClient.post(getAuthPath('/api/v1/auth/jwt/logout')),
    onSuccess: () => {
      queryClient.clear()
      // A full reload is intended: it also resets the AuthProvider context,
      // which a client-side router.push() would leave holding the old user.
      // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- hard reload by design
      window.location.href = '/'
    },
  })
}
