// ── Auth ──────────────────────────────────────────────────────────────────────
export interface User {
  id: string
  email: string
  display_name: string
  email_verified: boolean
  created_at: string
  last_login: string | null
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

// ── Chat ──────────────────────────────────────────────────────────────────────
export type MessageRole = 'user' | 'bot'

export interface Message {
  id: string
  session_id: string
  role: MessageRole
  content: string
  structured?: ScanResult | null
  module_used?: string | null
  risk_level?: string | null
  media_url?: string | null
  media_type?: string | null
  created_at: string
  isStreaming?: boolean
  thinkingStep?: string
}

export interface ChatSession {
  id: string
  title: string
  created_at: string
  updated_at: string
  is_archived: boolean
  message_count: number
}

export interface ChatSessionDetail {
  id: string
  title: string
  created_at: string
  updated_at: string
  messages: Message[]
}

// ── WebSocket protocol ─────────────────────────────────────────────────────────
export interface WsInbound {
  type: 'message' | 'ping'
  session_id?: string | null
  content: string
  media_id?: string | null
}

export interface WsThinking {
  type: 'thinking'
  content: string
  step: number
}

export interface WsResult {
  type: 'result'
  session_id: string
  message_id: string
  module?: string | null
  risk_level?: string | null
  content: string
  structured?: Record<string, unknown>
  flags?: string[]
  action?: string
}

export interface WsError {
  type: 'error'
  content: string
  code?: string
}

export type WsEvent = WsThinking | WsResult | WsError | { type: 'pong' }

// ── Upload ────────────────────────────────────────────────────────────────────
export interface UploadResult {
  media_id: string
  media_type: 'image' | 'video'
  filename: string
  size_bytes: number
  detected_qr?: boolean
  qr_result?: Record<string, unknown> | null
  deepfake_ready?: boolean
}

// ── Scan Results ──────────────────────────────────────────────────────────────
export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface ScanResult {
  overall_risk_level?: string
  overall_risk_score?: number
  risk_level?: string
  confidence_score?: number
  all_flags?: string[]
  virustotal_report?: string
  screenshot_url?: string
  whois?: { domain_age_days?: number }
  detection_counts?: { malicious?: number; suspicious?: number }
  scanners_count?: number
  redirects?: { hop_count?: number; final_url?: string }
  hibp_count?: number
  pwned_count?: number
  is_disposable?: boolean
  verdict?: { final_score?: number; risk_level?: string; fraud_type?: string; top_flags?: string[] }
  is_smishing?: boolean
  confidence?: number
  category?: string
  ensemble_probability?: number
  face_info?: { faces_detected?: number }
  combined_score?: number
  signals?: string[]
  recommended_action?: string
  bulk_results?: ScanResult[]
  [key: string]: unknown
}

// ── History ───────────────────────────────────────────────────────────────────
export interface ScanHistoryEntry {
  id: string
  entry_type: string
  verdict: string
  risk_level: string
  scanned_at: string
}

export interface ScanStats {
  total_scans: number
  threats_found: number
  links_scanned: number
  credentials_checked: number
  profiles_analysed: number
  smishing_detected: number
}
