import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios'
import Cookies from 'js-cookie'

export interface ApiError {
  message: string
  status: number
  code?: string
  details?: any
}

class ApiClient {
  private client: AxiosInstance
  private baseURL: string

  constructor(baseURL: string) {
    this.baseURL = baseURL
    this.client = axios.create({
      baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    this.setupInterceptors()
  }

  private setupInterceptors() {
    // Request interceptor - add auth token
    this.client.interceptors.request.use(
      (config) => {
        console.log('🔍 Outgoing API Request:')
        console.log('  - Base URL:', this.baseURL)
        console.log('  - Endpoint:', config.url)
        console.log('  - Method:', config.method?.toUpperCase())
        
        // Check if this is a request to the security tools API service
        const isSecurityAPI = this.baseURL.includes('/api/v1/tools') || this.baseURL.includes('localhost:8000') || this.baseURL.includes(':8000')
        
        // Check if this is a request to the Guardian service
        const isGuardianAPI = this.baseURL.includes('/api/v1/guardian') || this.baseURL.includes('localhost:8013') || this.baseURL.includes(':8013')
        
        if (isSecurityAPI) {
          // Use API key for security tools API
          const apiKey = process.env.NEXT_PUBLIC_API_KEY || 'wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90'
          config.headers['X-API-Key'] = apiKey
          console.log('  - Auth Type: API Key (Security Tools)')
        } else if (isGuardianAPI) {
          // Use API key for Guardian service
          const guardianApiKey = 'wbx-guardian-6fb6e69a0d7c62d6931e6bdfe7754263' // From Guardian database
          config.headers['X-API-Key'] = guardianApiKey
          console.log('  - Auth Type: API Key (Guardian)')
        } else {
          // Use JWT token for other services (identity, etc.)
          const token = Cookies.get('auth_token') || localStorage.getItem('auth_token')
          if (token) {
            config.headers.Authorization = `Bearer ${token}`
            console.log('  - Auth Type: JWT Token')
          } else {
            console.log('  - Auth Type: None (no token found)')
          }
        }
        
        console.log('  - Final Headers:', config.headers)
        return config
      },
      (error) => {
        return Promise.reject(error)
      }
    )

    // Response interceptor - handle errors
    this.client.interceptors.response.use(
      (response: AxiosResponse) => response,
      (error: AxiosError) => {
        const apiError: ApiError = {
          message: 'An error occurred',
          status: 500,
        }

        if (error.response) {
          apiError.status = error.response.status
          apiError.message = (error.response.data as any)?.message || error.message || 'API Error'
          apiError.details = error.response.data

          // Enhanced debugging for all errors
          console.log('🔍 API Error Details:')
          console.log('  - Base URL:', this.baseURL)
          console.log('  - Endpoint:', error.config?.url)
          console.log('  - Method:', error.config?.method?.toUpperCase())
          console.log('  - Status:', error.response.status)
          console.log('  - Response:', error.response.data)
          console.log('  - Headers sent:', error.config?.headers)

          // Handle auth errors
          if (error.response.status === 401) {
            console.error('🚨 401 UNAUTHORIZED ERROR DETECTED!')
            console.error('🚨 Service Base URL:', this.baseURL)
            console.error('🚨 Failed Endpoint:', error.config?.url)
            console.error('🚨 Request Headers:', error.config?.headers)
            console.error('🚨 Response Data:', error.response.data)
            console.error('🚨 Full Request Config:', error.config)
            
            // Only trigger auth error handling for non-admin pages and if not already on auth page
            if (typeof window !== 'undefined' && 
                !window.location.pathname.includes('/admin') &&
                !window.location.pathname.includes('/auth')) {
              this.handleAuthError()
            }
          }
        } else if (error.request) {
          apiError.message = 'Network error - please check your connection'
          apiError.status = 0
        } else {
          apiError.message = error.message
        }

        return Promise.reject(apiError)
      }
    )
  }

  private handleAuthError() {
    console.error('🚨 AUTH ERROR: 401 received, clearing tokens and redirecting')
    console.error('🚨 Current URL:', window.location.href)
    console.error('🚨 Request that failed - Service:', this.baseURL)
    console.error('🚨 Stack trace:', new Error().stack)
    
    // Check if this is a gateway request that might need different handling
    const isGatewayRequest = this.baseURL.includes('localhost:80') || this.baseURL.includes(':80')
    
    // Don't immediately redirect for gateway requests - they might need special auth handling
    if (isGatewayRequest) {
      console.warn('🚨 Gateway auth error - not auto-redirecting, may need token refresh')
      return
    }
    
    // Clear auth tokens only for non-gateway auth errors
    Cookies.remove('auth_token')
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')
    
    // Redirect to login if we're not already there and not on an admin page
    if (typeof window !== 'undefined' && 
        !window.location.pathname.includes('/auth') &&
        !window.location.pathname.includes('/admin')) {
      console.error('🚨 Redirecting to login due to auth error from service:', this.baseURL)
      window.location.href = '/'
    }
  }

  // Generic request methods
  async get<T = any>(endpoint: string, params?: any): Promise<T> {
    const response = await this.client.get(endpoint, { params })
    return response.data
  }

  async post<T = any>(endpoint: string, data?: any): Promise<T> {
    const response = await this.client.post(endpoint, data)
    return response.data
  }

  // Form data POST (for OAuth2 login)
  async postForm<T = any>(endpoint: string, formData: URLSearchParams): Promise<T> {
    const response = await this.client.post(endpoint, formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })
    return response.data
  }

  async put<T = any>(endpoint: string, data?: any): Promise<T> {
    const response = await this.client.put(endpoint, data)
    return response.data
  }

  async patch<T = any>(endpoint: string, data?: any): Promise<T> {
    const response = await this.client.patch(endpoint, data)
    return response.data
  }

  async delete<T = any>(endpoint: string): Promise<T> {
    const response = await this.client.delete(endpoint)
    return response.data
  }

  // File upload
  async upload<T = any>(endpoint: string, file: File, onProgress?: (progress: number) => void): Promise<T> {
    const formData = new FormData()
    formData.append('file', file)

    const response = await this.client.post(endpoint, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = (progressEvent.loaded / progressEvent.total) * 100
          onProgress(Math.round(progress))
        }
      },
    })

    return response.data
  }
}

// API Clients - All requests go through Wildbox Gateway for production
const useGateway = process.env.NEXT_PUBLIC_USE_GATEWAY === 'true'
const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:80'

// Helper function to get the correct gateway URL based on environment
const getGatewayUrl = (): string => {
  // If we're on server-side (SSR) and have an internal gateway URL, use it
  if (typeof window === 'undefined' && process.env.INTERNAL_GATEWAY_URL) {
    return process.env.INTERNAL_GATEWAY_URL
  }
  // Otherwise use the public gateway URL for client-side requests
  return gatewayUrl
}

// Helper function to get the correct auth endpoint path
export const getAuthPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway with identityClient, transform paths correctly
    // Gateway routes: /auth/ -> identity:/api/v1/auth/ and /auth/users/ -> identity:/api/v1/users/
    return endpoint
      .replace('/api/v1/auth/jwt/login', '/auth/login')  // Special case for login endpoint
      .replace('/api/v1/auth/jwt', '/auth/jwt')
      .replace('/api/v1/auth', '/auth')
      .replace('/api/v1/users', '/auth/users')
  }
  return endpoint
}

// Helper function to get the correct identity endpoint path
export const getIdentityPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, transform /api/v1/ to /api/v1/identity/
    // But avoid double transformation - if it already has /api/v1/identity/, don't transform again
    if (endpoint.includes('/api/v1/identity/')) {
      return endpoint
    }
    return endpoint.replace('/api/v1/', '/api/v1/identity/')
  }
  return endpoint
}

// Helper function to get the correct data endpoint path
export const getDataPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, transform /api/v1/ to just / since base URL already has /api/v1/data
    // This prevents double /api/v1/ in the path
    if (endpoint.startsWith('/api/v1/')) {
      return endpoint.substring(7) // Remove '/api/v1' prefix
    }
  }
  return endpoint
}

// Helper function to get the correct guardian endpoint path
export const getGuardianPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, remove /api/v1 prefix since gateway already routes to /api/v1/guardian
    return endpoint.replace('/api/v1/', '/')
  }
  return endpoint
}

// Helper function to get the correct sensor endpoint path
export const getSensorPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, remove /api/v1 prefix since gateway already routes to /api/v1/sensor
    return endpoint.replace('/api/v1/', '/')
  }
  return endpoint
}

// Helper function to get the correct responder endpoint path
export const getResponderPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, remove /api/v1 prefix since gateway already routes to /api/v1/responder
    return endpoint.replace('/api/v1/', '/')
  }
  return endpoint
}

// Helper function to get the correct CSPM endpoint path
export const getCSPMPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, remove /api/v1 prefix since gateway already routes to /api/v1/cspm
    return endpoint.replace('/api/v1/', '/')
  }
  return endpoint
}

// Helper function to get the correct agents endpoint path
export const getAgentsPath = (endpoint: string): string => {
  if (useGateway) {
    // When using gateway, remove /api/v1 prefix since gateway already routes to /api/v1/agents
    return endpoint.replace('/api/v1/', '/')
  }
  return endpoint
}

// Production-ready clients that always route through the gateway
export const apiClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/tools`
    : (process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000')
)

export const identityClient = new ApiClient(
  useGateway 
    ? getGatewayUrl()  // Use gateway root URL for auth endpoints
    : (process.env.NEXT_PUBLIC_IDENTITY_API_URL || 'http://localhost:8001')
)

export const dataClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/data`
    : (process.env.NEXT_PUBLIC_DATA_API_URL || 'http://localhost:8002')
)

export const guardianClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/guardian`
    : (process.env.NEXT_PUBLIC_GUARDIAN_API_URL || 'http://localhost:8013')
)

export const sensorClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/sensor`
    : (process.env.NEXT_PUBLIC_SENSOR_API_URL || 'http://localhost:8004')
)

export const responderClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/responder`
    : (process.env.NEXT_PUBLIC_RESPONDER_API_URL || 'http://localhost:8018')
)

export const agentsClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/agents`
    : (process.env.NEXT_PUBLIC_AGENTS_API_URL || 'http://localhost:8006')
)

export const cspmClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/cspm`
    : (process.env.NEXT_PUBLIC_CSPM_API_URL || 'http://localhost:8019')
)

// Gateway client for direct gateway API access
export const gatewayDataClient = new ApiClient(getGatewayUrl())

export default apiClient
