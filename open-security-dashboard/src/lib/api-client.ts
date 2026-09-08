import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios'
import Cookies from 'js-cookie'

export interface ApiError {
  message: string
  status: number
  code?: string
  /** Correlation id from the canonical error body, for matching against logs. */
  requestId?: string
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
        // All services (incl. Guardian) authenticate via the gateway with the
        // user's JWT; the gateway validates it and forwards X-Wildbox-* headers.
        // Guardian no longer uses a browser-exposed API key (#113).
        const token = Cookies.get('auth_token')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }

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
          const data = error.response.data as any
          apiError.status = error.response.status
          // Services answer with the canonical shape from open_security_shared.errors:
          //   { error: { code, message, type, request_id } }
          // The older shapes (a top-level `message`, or FastAPI's default
          // `detail`) are still accepted so a partially-upgraded deployment does
          // not lose the server's explanation (WILDBO-API-01).
          apiError.message =
            data?.error?.message ||
            data?.detail ||
            data?.message ||
            error.message ||
            'API Error'
          apiError.code = data?.error?.type
          apiError.requestId = data?.error?.request_id
          apiError.details = error.response.data

          // Handle auth errors
          if (error.response.status === 401) {
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
    // Check if this is a gateway request that might need different handling
    const isGatewayRequest = this.baseURL.includes('localhost:80') || this.baseURL.includes(':80')

    // Don't immediately redirect for gateway requests - they might need special auth handling
    if (isGatewayRequest) {
      return
    }

    // Clear auth cookie for non-gateway auth errors
    Cookies.remove('auth_token')
    
    // Redirect to login if we're not already there and not on an admin page
    if (typeof window !== 'undefined' &&
        !window.location.pathname.includes('/auth') &&
        !window.location.pathname.includes('/admin')) {
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

// API Clients - every request goes through the Wildbox Gateway.
//
// The gateway is the only supported topology: it is where authentication, rate
// limiting and the X-Wildbox-* identity injection live, and the backend services
// refuse requests that do not carry the gateway's proof-of-origin secret. The
// previous direct-to-service wiring (NEXT_PUBLIC_*_API_URL per service) was a
// second, untested topology that could not work against those services, so it
// has been removed (WILDBO-ARCH-04).
//
// NEXT_PUBLIC_USE_GATEWAY is still honoured for local development against a
// bare service, but it now defaults to ON rather than OFF: an unset variable
// gives the supported deployment instead of the unsupported one.
const useGateway = process.env.NEXT_PUBLIC_USE_GATEWAY !== 'false'
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
    // NOTE: do NOT special-case login to '/auth/login' — the gateway routes
    // '/auth/login' to the dashboard (the login *page*), so the JWT login POST
    // would hit the SPA and never reach identity. Let it become
    // '/auth/jwt/login', which the gateway routes to identity's
    // /api/v1/auth/jwt/login.
    return endpoint
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

// The gateway mounts each service under /api/v1/<service>/ and rewrites that
// prefix away before proxying, so a client that already has the service prefix
// in its baseURL must not repeat /api/v1/ in the path. One helper does this for
// every service; there is no per-service variation to encode (WILDBO-ARCH-05).
//
// This mirrors the gateway's route table in exactly one place. If a route's
// rewrite rule changes, change it here -- and see the gateway route-coverage
// test in tests/integration/test_gateway_routes.py, which asserts that every
// base path below resolves to something other than the catch-all 404.
const stripApiV1 = (endpoint: string): string => {
  if (!useGateway) return endpoint
  return endpoint.replace('/api/v1/', '/')
}

export const getGuardianPath = stripApiV1
export const getResponderPath = stripApiV1
export const getCSPMPath = stripApiV1
export const getAgentsPath = stripApiV1

// Production-ready clients. Every one addresses the gateway; the service
// prefixes below are the gateway's route table (WILDBO-ARCH-01/ARCH-04).
const gw = getGatewayUrl()

export const apiClient = new ApiClient(`${gw}/api/v1`)
export const identityClient = new ApiClient(gw) // auth endpoints live at the gateway root
export const dataClient = new ApiClient(`${gw}/api/v1/data`)
export const guardianClient = new ApiClient(`${gw}/api/v1/guardian`)
export const responderClient = new ApiClient(`${gw}/api/v1/responder`)
export const agentsClient = new ApiClient(`${gw}/api/v1/agents`)
export const cspmClient = new ApiClient(`${gw}/api/v1/cspm`)

// NOTE: there is deliberately no sensorClient. The sensor exposes no
// gateway-facing API in v1.0 (see the commented-out /api/v1/sensor/ block in
// wildbox_gateway.conf); it forwards telemetry to the data service directly.
// The client used to exist and every call it made returned the gateway's
// catch-all 404 (WILDBO-ARCH-01).

// Gateway client for direct gateway API access
export const gatewayDataClient = new ApiClient(gw)

export default apiClient
