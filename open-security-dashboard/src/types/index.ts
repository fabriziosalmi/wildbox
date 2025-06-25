// User and Authentication Types
export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'analyst' | 'viewer'
  avatar?: string
  lastLogin?: Date
  permissions: string[]
  organization?: string
  settings: UserSettings
}

export interface UserSettings {
  theme: 'light' | 'dark' | 'system'
  timezone: string
  notifications: NotificationSettings
  dashboard: DashboardSettings
}

export interface NotificationSettings {
  email: boolean
  push: boolean
  threatAlerts: boolean
  scanComplete: boolean
  playbookComplete: boolean
  systemStatus: boolean
}

export interface DashboardSettings {
  defaultView: string
  refreshInterval: number
  compactMode: boolean
  showMetrics: string[]
}

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean
  data: T
  message?: string
  meta?: PaginationMeta
}

export interface PaginationMeta {
  page: number
  limit: number
  total: number
  pages: number
}

// Threat Intelligence Types
export interface ThreatFeed {
  id: string
  name: string
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email'
  source: string
  description: string
  lastUpdated: Date
  recordCount: number
  status: 'active' | 'inactive' | 'error'
}

export interface IOC {
  id: string
  value: string
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email'
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown'
  confidence: number
  firstSeen: Date
  lastSeen: Date
  sources: string[]
  tags: string[]
  metadata: Record<string, any>
}

export interface IOCLookupResult {
  ioc: IOC
  reputation: ReputationData
  geolocation?: GeoLocation
  whois?: WhoisData
  certificate?: CertificateData
  threatIntel: ThreatIntelData[]
}

export interface ReputationData {
  score: number
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown'
  sources: ReputationSource[]
  lastChecked: Date
}

export interface ReputationSource {
  name: string
  verdict: string
  confidence: number
  details?: string
}

export interface GeoLocation {
  country: string
  countryCode: string
  region: string
  city: string
  latitude: number
  longitude: number
  asn: string
  isp: string
}

export interface WhoisData {
  domain: string
  registrar: string
  creationDate: Date
  expirationDate: Date
  nameServers: string[]
  contacts: Record<string, any>
}

export interface CertificateData {
  subject: string
  issuer: string
  validFrom: Date
  validTo: Date
  fingerprint: string
  algorithm: string
}

export interface ThreatIntelData {
  source: string
  category: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tags: string[]
  references: string[]
}

// Cloud Security Types
export interface CloudAccount {
  id: string
  name: string
  provider: 'aws' | 'azure' | 'gcp'
  accountId: string
  region: string
  status: 'active' | 'inactive' | 'error'
  lastScanned: Date
  complianceScore: number
}

export interface ComplianceScan {
  id: string
  accountId: string
  framework: string
  status: 'running' | 'completed' | 'failed'
  startTime: Date
  endTime?: Date
  totalChecks: number
  passedChecks: number
  failedChecks: number
  score: number
  findings: ComplianceFinding[]
}

export interface ComplianceFinding {
  id: string
  checkId: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'passed' | 'failed' | 'warning'
  resource: string
  region: string
  category: string
  remediation: RemediationGuide
}

export interface RemediationGuide {
  description: string
  steps: string[]
  cliCommands?: string[]
  consoleLink?: string
  automationAvailable: boolean
}

// Tools and Execution Types
export interface SecurityTool {
  id: string
  name: string
  category: string
  description: string
  version: string
  parameters: ToolParameter[]
  riskLevel: 'low' | 'medium' | 'high'
  permissions: string[]
}

export interface ToolParameter {
  name: string
  type: 'string' | 'number' | 'boolean' | 'array' | 'file'
  description: string
  required: boolean
  default?: any
  validation?: ValidationRule[]
}

export interface ValidationRule {
  type: 'regex' | 'range' | 'enum' | 'custom'
  value: any
  message: string
}

export interface ToolExecution {
  id: string
  toolId: string
  toolName: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  startTime: Date
  endTime?: Date
  duration?: number
  input: Record<string, any>
  output?: any
  error?: string
  userId: string
}

// Response and Playbooks Types
export interface Playbook {
  id: string
  name: string
  description: string
  category: string
  version: string
  author: string
  tags: string[]
  parameters: PlaybookParameter[]
  steps: PlaybookStep[]
  triggers: PlaybookTrigger[]
  lastModified: Date
  isActive: boolean
}

export interface PlaybookParameter {
  name: string
  type: string
  description: string
  required: boolean
  default?: any
}

export interface PlaybookStep {
  id: string
  name: string
  type: 'action' | 'condition' | 'loop' | 'parallel'
  action?: string
  condition?: string
  parameters: Record<string, any>
  onSuccess?: string
  onFailure?: string
  timeout?: number
}

export interface PlaybookTrigger {
  type: 'manual' | 'scheduled' | 'webhook' | 'alert'
  condition: string
  parameters: Record<string, any>
}

export interface PlaybookRun {
  id: string
  playbookId: string
  playbookName: string
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  startTime: Date
  endTime?: Date
  duration?: number
  trigger: string
  input: Record<string, any>
  steps: PlaybookStepExecution[]
  output?: any
  error?: string
  userId: string
}

export interface PlaybookStepExecution {
  stepId: string
  stepName: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  startTime?: Date
  endTime?: Date
  input?: any
  output?: any
  error?: string
  logs: string[]
}

// Endpoint and Sensor Types
export interface Endpoint {
  id: string
  name: string
  hostname: string
  ipAddress: string
  macAddress: string
  os: string
  osVersion: string
  agentVersion: string
  status: 'online' | 'offline' | 'error'
  lastSeen: Date
  registrationDate: Date
  tags: string[]
  location?: string
  department?: string
  owner?: string
  riskScore: number
}

export interface EndpointAlert {
  id: string
  endpointId: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  timestamp: Date
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
  assignee?: string
  tags: string[]
  metadata: Record<string, any>
}

// AI Agents Types
export interface Agent {
  id: string
  name: string
  type: 'analyst' | 'hunter' | 'responder'
  description: string
  capabilities: string[]
  status: 'active' | 'idle' | 'busy' | 'error'
  lastActivity: Date
  tasksCompleted: number
  averageResponseTime: number
}

export interface AnalysisTask {
  id: string
  type: 'ioc_analysis' | 'threat_hunting' | 'incident_analysis' | 'compliance_check'
  status: 'pending' | 'running' | 'completed' | 'failed'
  priority: 'low' | 'medium' | 'high' | 'critical'
  input: any
  output?: any
  progress: number
  steps: AnalysisStep[]
  startTime: Date
  endTime?: Date
  assignedAgent?: string
  error?: string
}

export interface AnalysisStep {
  id: string
  name: string
  description: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  output?: any
  error?: string
}

export interface AnalysisReport {
  id: string
  taskId: string
  title: string
  summary: string
  findings: AnalysisFinding[]
  recommendations: string[]
  confidence: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  generatedAt: Date
  format: 'markdown' | 'json' | 'pdf'
  content: string
}

export interface AnalysisFinding {
  category: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  evidence: string[]
  references: string[]
}

// Vulnerability Management Types
export interface Vulnerability {
  id: string
  cveId?: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvssScore: number
  discoveredDate: Date
  publishedDate?: Date
  lastModified: Date
  status: 'new' | 'triaged' | 'in_progress' | 'resolved' | 'accepted_risk'
  affectedAssets: string[]
  category: string
  tags: string[]
  assignee?: string
  dueDate?: Date
  remediation?: RemediationGuide
}

// System and Dashboard Types
export interface DashboardWidget {
  id: string
  type: 'metric' | 'chart' | 'table' | 'alert' | 'status'
  title: string
  position: { x: number; y: number; w: number; h: number }
  config: Record<string, any>
  dataSource: string
  refreshInterval: number
  lastUpdated: Date
}

export interface SystemMetric {
  name: string
  value: number
  unit?: string
  change?: number
  changeType?: 'increase' | 'decrease'
  status?: 'good' | 'warning' | 'critical'
  timestamp: Date
}

export interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message: string
  timestamp: Date
  read: boolean
  category: string
  actionUrl?: string
  userId: string
}

// Chart and Visualization Types
export interface ChartData {
  labels: string[]
  datasets: ChartDataset[]
}

export interface ChartDataset {
  label: string
  data: number[]
  backgroundColor?: string | string[]
  borderColor?: string | string[]
  borderWidth?: number
  fill?: boolean
}

export interface TimeSeriesData {
  timestamp: Date
  value: number
  label?: string
}

// Form Types
export interface FormField {
  name: string
  label: string
  type: 'text' | 'email' | 'password' | 'number' | 'select' | 'multiselect' | 'textarea' | 'checkbox' | 'radio' | 'file'
  placeholder?: string
  required?: boolean
  validation?: ValidationRule[]
  options?: { label: string; value: any }[]
  description?: string
  defaultValue?: any
}
