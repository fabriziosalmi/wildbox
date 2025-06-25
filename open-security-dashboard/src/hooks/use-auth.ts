import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { identityClient } from '@/lib/api-client'
import { User } from '@/types'

// Custom hook for fetching user data
export function useUser() {
  return useQuery({
    queryKey: ['user'],
    queryFn: () => identityClient.get<User>('/api/v1/auth/me'),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })
}

// Custom hook for updating user profile
export function useUpdateUser() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (userData: Partial<User>) => 
      identityClient.put<User>('/api/v1/auth/profile', userData),
    onSuccess: (updatedUser) => {
      queryClient.setQueryData(['user'], updatedUser)
    },
  })
}

// Custom hook for logout
export function useLogout() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: () => identityClient.post('/api/v1/auth/logout'),
    onSuccess: () => {
      queryClient.clear()
      window.location.href = '/auth/login'
    },
  })
}
