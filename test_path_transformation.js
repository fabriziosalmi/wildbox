#!/usr/bin/env node

// Simple test script to verify API client path transformations
const useGateway = process.env.NEXT_PUBLIC_USE_GATEWAY === 'true'
const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:80'

console.log('=== API Client Path Transformation Test ===')
console.log('useGateway:', useGateway)
console.log('gatewayUrl:', gatewayUrl)
console.log('')

// Helper function to get the correct auth endpoint path
const getAuthPath = (endpoint) => {
  if (useGateway) {
    // When using gateway with identityClient, just return the auth path
    // since identityClient base URL is already /api/v1/identity
    return endpoint.replace('/api/v1/auth', '/auth')
  }
  return endpoint
}

// Test the transformations
const testEndpoints = [
  '/api/v1/auth/login',
  '/api/v1/auth/me',
  '/api/v1/auth/register',
  '/api/v1/auth/logout'
]

testEndpoints.forEach(endpoint => {
  const transformed = getAuthPath(endpoint)
  const fullUrl = `${gatewayUrl}/api/v1/identity${transformed}`
  console.log(`${endpoint} -> ${transformed} -> ${fullUrl}`)
})

console.log('')
console.log('Expected working endpoints:')
console.log('- http://localhost:80/api/v1/identity/auth/login')
console.log('- http://localhost:80/api/v1/identity/auth/me')
console.log('- http://localhost:80/api/v1/identity/auth/register')
console.log('- http://localhost:80/api/v1/identity/auth/logout')
