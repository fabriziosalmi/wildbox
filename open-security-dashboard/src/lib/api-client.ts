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
        const token = Cookies.get('auth_token') || localStorage.getItem('auth_token')
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
          apiError.status = error.response.status
          apiError.message = (error.response.data as any)?.message || error.message || 'API Error'
          apiError.details = error.response.data

          // Handle auth errors
          if (error.response.status === 401) {
            this.handleAuthError()
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
    // Clear auth tokens
    Cookies.remove('auth_token')
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')
    
    // Redirect to login if we're not already there
    if (typeof window !== 'undefined' && !window.location.pathname.includes('/auth')) {
      window.location.href = '/auth/login'
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

// API Clients for different services
export const apiClient = new ApiClient(
  process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'
)

export const identityClient = new ApiClient(
  process.env.NEXT_PUBLIC_IDENTITY_API_URL || 'http://localhost:8001'
)

export const dataClient = new ApiClient(
  process.env.NEXT_PUBLIC_DATA_API_URL || 'http://localhost:8002'
)

export const guardianClient = new ApiClient(
  process.env.NEXT_PUBLIC_GUARDIAN_API_URL || 'http://localhost:8003'
)

export const sensorClient = new ApiClient(
  process.env.NEXT_PUBLIC_SENSOR_API_URL || 'http://localhost:8004'
)

export const responderClient = new ApiClient(
  process.env.NEXT_PUBLIC_RESPONDER_API_URL || 'http://localhost:8005'
)

export const agentsClient = new ApiClient(
  process.env.NEXT_PUBLIC_AGENTS_API_URL || 'http://localhost:8006'
)

export default apiClient
