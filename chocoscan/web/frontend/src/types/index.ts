// Types miroir des schémas Pydantic du backend

export interface CVE {
  id: string
  description: string
  description_fr: string
  cvss: number | string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
  affected_versions: string | string[]
  source: string
  tags: string[]
  cisa_kev: boolean
  exploit_available: boolean
  contextual_score: number | null
  exploits: { url: string; title?: string }[]
  msf_modules: { path: string; type: string; rank: string; description: string; needs_lhost: boolean }[]
  cpe: string | null
}

export interface ServiceResult {
  host: string
  port: number
  protocol: string
  state: string
  service_name: string
  product: string
  version: string
  banner: string
  cves: CVE[]
}

export interface ScanStats {
  total_cves: number
  critical: number
  high: number
  medium: number
  low: number
  services: number
  hosts: number
  with_exploit: number
  cisa_kev: number
}

export interface ScanSummary {
  id: number
  created_at: string
  target: string
  input_type: 'file' | 'direct' | 'ssh'
  status: 'pending' | 'running' | 'done' | 'error'
  stats: ScanStats | null
  error_msg: string | null
}

export interface ScanDetail extends ScanSummary {
  results: ServiceResult[]
}

export interface ScanFilters {
  min_cvss?: number
  severity?: string[]
  after_year?: number | null
  no_api?: boolean
}
