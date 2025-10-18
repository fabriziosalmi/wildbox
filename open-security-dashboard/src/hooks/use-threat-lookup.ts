/**
 * Custom hook for IOC (Indicator of Compromise) threat intelligence lookups
 * 
 * Provides type-safe access to the Data service threat intel APIs:
 * - /api/v1/ips/{ip}
 * - /api/v1/domains/{domain}
 * - /api/v1/hashes/{hash}
 * 
 * Features:
 * - Automatic IOC type detection
 * - Intelligent caching (30s stale time)
 * - Error handling with user-friendly messages
 * - TypeScript interfaces matching backend schemas
 */

import { useQuery, UseQueryResult } from '@tanstack/react-query'
import { dataClient } from '@/lib/api-client'

// ============================================================================
// TypeScript Interfaces (matching backend Pydantic schemas)
// ============================================================================

export type IOCType = 'ip_address' | 'domain' | 'file_hash' | 'unknown'
export type ConfidenceLevel = 'low' | 'medium' | 'high' | 'verified'

/**
 * Individual threat indicator from the database
 */
export interface ThreatIndicator {
  id: string
  indicator_type: string
  value: string
  normalized_value: string
  threat_types: string[]
  confidence: ConfidenceLevel
  severity: number // 1-10 scale
  description: string
  tags: string[]
  first_seen: string // ISO8601
  last_seen: string // ISO8601
  expires_at: string | null
  active: boolean
  source_id: string
  indicator_metadata: Record<string, any>
  created_at: string | null
  updated_at: string | null
}

/**
 * IP address intelligence response
 */
export interface IPIntelligence {
  ip_address: string
  threat_count: number
  indicators: ThreatIndicator[]
  enrichment: {
    asn?: string
    asn_organization?: string
    country_code?: string
    city?: string
    coordinates?: {
      latitude: number
      longitude: number
    }
  } | null
  query_time: string
}

/**
 * Domain intelligence response
 */
export interface DomainIntelligence {
  domain: string
  threat_count: number
  indicators: ThreatIndicator[]
  enrichment: {
    registrar?: string
    creation_date?: string
    expiration_date?: string
    name_servers?: string[]
  } | null
  query_time: string
}

/**
 * File hash intelligence response
 */
export interface HashIntelligence {
  file_hash: string
  threat_count: number
  indicators: ThreatIndicator[]
  enrichment: {
    file_type?: string
    file_size?: number
    file_names?: string[]
  } | null
  query_time: string
}

/**
 * Union type for all intelligence response types
 */
export type ThreatIntelligence = IPIntelligence | DomainIntelligence | HashIntelligence

/**
 * API error response
 */
export interface ThreatLookupError {
  detail: string
}

// ============================================================================
// IOC Type Detection Utilities
// ============================================================================

/**
 * Validate if string is a valid IPv4 address
 */
export function isValidIPv4(value: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!ipv4Regex.test(value)) return false
  
  const parts = value.split('.')
  return parts.every(part => {
    const num = parseInt(part, 10)
    return num >= 0 && num <= 255
  })
}

/**
 * Validate if string is a valid IPv6 address (basic check)
 */
export function isValidIPv6(value: string): boolean {
  // Basic IPv6 check (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
  return ipv6Regex.test(value)
}

/**
 * Validate if string is a valid domain name
 */
export function isValidDomain(value: string): boolean {
  // Domain must have at least one dot and valid characters
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  return domainRegex.test(value)
}

/**
 * Validate if string is a valid file hash (MD5, SHA1, SHA256)
 */
export function isValidHash(value: string): boolean {
  const md5Regex = /^[a-fA-F0-9]{32}$/
  const sha1Regex = /^[a-fA-F0-9]{40}$/
  const sha256Regex = /^[a-fA-F0-9]{64}$/
  
  return md5Regex.test(value) || sha1Regex.test(value) || sha256Regex.test(value)
}

/**
 * Automatically detect IOC type from value
 */
export function detectIOCType(value: string): IOCType {
  const trimmed = value.trim().toLowerCase()
  
  if (isValidIPv4(trimmed) || isValidIPv6(trimmed)) {
    return 'ip_address'
  }
  
  if (isValidDomain(trimmed)) {
    return 'domain'
  }
  
  if (isValidHash(trimmed)) {
    return 'file_hash'
  }
  
  return 'unknown'
}

// ============================================================================
// API Functions
// ============================================================================

/**
 * Lookup IP address threat intelligence
 */
async function lookupIP(ip: string): Promise<IPIntelligence> {
  const response = await dataClient.get(`/api/v1/ips/${encodeURIComponent(ip)}`)
  return response.data
}

/**
 * Lookup domain threat intelligence
 */
async function lookupDomain(domain: string): Promise<DomainIntelligence> {
  const response = await dataClient.get(`/api/v1/domains/${encodeURIComponent(domain)}`)
  return response.data
}

/**
 * Lookup file hash threat intelligence
 */
async function lookupHash(hash: string): Promise<HashIntelligence> {
  const response = await dataClient.get(`/api/v1/hashes/${encodeURIComponent(hash)}`)
  return response.data
}

// ============================================================================
// Main Hook
// ============================================================================

export interface UseThreatLookupOptions {
  /**
   * IOC value to lookup (IP, domain, or hash)
   */
  iocValue?: string
  
  /**
   * Optional: Specify IOC type explicitly (auto-detected if not provided)
   */
  iocType?: IOCType
  
  /**
   * Whether to enable the query (default: true if iocValue provided)
   */
  enabled?: boolean
}

export interface UseThreatLookupResult {
  /**
   * Threat intelligence data (null if not found or error)
   */
  data: ThreatIntelligence | null
  
  /**
   * Detected or specified IOC type
   */
  iocType: IOCType
  
  /**
   * Whether the query is currently loading
   */
  isLoading: boolean
  
  /**
   * Error object if query failed
   */
  error: Error | null
  
  /**
   * Whether IOC was not found (404 response)
   */
  isNotFound: boolean
  
  /**
   * Whether query has succeeded at least once
   */
  isSuccess: boolean
  
  /**
   * Refetch function to manually trigger lookup
   */
  refetch: () => void
}

/**
 * Custom hook for IOC threat intelligence lookups
 * 
 * @example
 * ```tsx
 * // IP lookup
 * const { data, isLoading, error, isNotFound } = useThreatLookup({ 
 *   iocValue: '8.8.8.8' 
 * })
 * 
 * // Domain lookup with manual type specification
 * const result = useThreatLookup({ 
 *   iocValue: 'malicious-domain.evil',
 *   iocType: 'domain'
 * })
 * 
 * // Controlled query (enable manually)
 * const [searchValue, setSearchValue] = useState('')
 * const result = useThreatLookup({ 
 *   iocValue: searchValue,
 *   enabled: searchValue.length > 0
 * })
 * ```
 */
export function useThreatLookup(options: UseThreatLookupOptions = {}): UseThreatLookupResult {
  const { iocValue, iocType: explicitType, enabled = true } = options
  
  // Detect IOC type if not explicitly provided
  const detectedType = iocValue ? detectIOCType(iocValue) : 'unknown'
  const iocType = explicitType || detectedType
  
  // Determine query function based on IOC type
  const queryFn = async (): Promise<ThreatIntelligence> => {
    if (!iocValue) {
      throw new Error('No IOC value provided')
    }
    
    switch (iocType) {
      case 'ip_address':
        return lookupIP(iocValue)
      case 'domain':
        return lookupDomain(iocValue)
      case 'file_hash':
        return lookupHash(iocValue)
      default:
        throw new Error(`Unknown IOC type: ${iocType}. Please provide a valid IP, domain, or hash.`)
    }
  }
  
  // Execute query with TanStack Query
  const query = useQuery<ThreatIntelligence, Error>({
    queryKey: ['threat-lookup', iocType, iocValue],
    queryFn,
    enabled: enabled && !!iocValue && iocType !== 'unknown',
    staleTime: 30000, // 30 seconds - threat intel changes slowly
    gcTime: 5 * 60 * 1000, // 5 minutes - keep in cache
    retry: (failureCount, error: any) => {
      // Don't retry on 404 (IOC not found)
      if (error?.response?.status === 404) return false
      // Retry up to 2 times for other errors
      return failureCount < 2
    },
  })
  
  // Detect 404 errors (IOC not found in database)
  const isNotFound = query.error ? 
    (query.error as any)?.response?.status === 404 : 
    false
  
  return {
    data: query.data || null,
    iocType,
    isLoading: query.isLoading,
    error: query.error,
    isNotFound,
    isSuccess: query.isSuccess,
    refetch: query.refetch,
  }
}

// ============================================================================
// Helper Functions for UI
// ============================================================================

/**
 * Get highest severity from indicators array
 */
export function getMaxSeverity(indicators?: ThreatIndicator[]): number {
  if (!indicators || indicators.length === 0) return 0
  return Math.max(...indicators.map(ind => ind.severity))
}

/**
 * Get all unique threat types from indicators
 */
export function getAllThreatTypes(indicators?: ThreatIndicator[]): string[] {
  if (!indicators || indicators.length === 0) return []
  
  const allTypes = indicators.flatMap(ind => ind.threat_types || [])
  return Array.from(new Set(allTypes))
}

/**
 * Get reputation verdict based on severity
 */
export function getReputationVerdict(severity: number): 'clean' | 'suspicious' | 'malicious' {
  if (severity <= 3) return 'clean'
  if (severity <= 6) return 'suspicious'
  return 'malicious'
}

/**
 * Format confidence level for display
 */
export function formatConfidence(confidence: ConfidenceLevel): string {
  const labels: Record<ConfidenceLevel, string> = {
    low: 'Low Confidence',
    medium: 'Medium Confidence',
    high: 'High Confidence',
    verified: 'Verified Threat',
  }
  return labels[confidence] || confidence
}

/**
 * Get color classes for severity level
 */
export function getSeverityColor(severity: number): string {
  if (severity >= 8) return 'text-red-600 dark:text-red-400'
  if (severity >= 5) return 'text-orange-600 dark:text-orange-400'
  if (severity >= 3) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-green-600 dark:text-green-400'
}

/**
 * Get color classes for confidence level
 */
export function getConfidenceColor(confidence: ConfidenceLevel): string {
  const colors: Record<ConfidenceLevel, string> = {
    verified: 'text-green-600 dark:text-green-400',
    high: 'text-blue-600 dark:text-blue-400',
    medium: 'text-yellow-600 dark:text-yellow-400',
    low: 'text-gray-600 dark:text-gray-400',
  }
  return colors[confidence] || 'text-gray-600 dark:text-gray-400'
}
