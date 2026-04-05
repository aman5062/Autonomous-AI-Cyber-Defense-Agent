const BASE = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000'

async function req<T>(path: string, opts?: RequestInit): Promise<T | null> {
  try {
    const r = await fetch(`${BASE}${path}`, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts?.headers ?? {}) },
      signal: AbortSignal.timeout(8000), // 8s timeout — backend may be busy processing attacks
    })
    if (!r.ok) return null
    return r.json()
  } catch {
    return null
  }
}

const get = <T>(path: string) => req<T>(path)
const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined })

// ── Types ──────────────────────────────────────────────────────────────────
export interface Attack {
  id: number
  timestamp: string
  ip: string
  method: string
  path: string
  status: number
  attack_type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  blocked: boolean
  user_agent: string
  explanation?: string
  impact?: string
  mitigation?: string | string[]
  code_fix?: { vulnerable?: string; secure?: string; recommendation?: string }
  references_list?: string[]
}

export interface BlockedIP {
  id: number
  ip: string
  attack_type: string
  severity: string
  block_time: string
  unblock_time?: string
  status: string
  reason?: string
  blocked_by: string
}

export interface Stats {
  total_attacks: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
  blocked_count: number
  timeline: { date: string; count: number }[]
}

export interface Health {
  status: string
  timestamp: string
  services: Record<string, string>
  defense_mode: { auto_block: boolean; dry_run: boolean }
}

export interface SystemMetrics {
  available: boolean
  cpu_percent?: number
  memory_percent?: number
  disk_percent?: number
  net_bytes_sent?: number
  net_bytes_recv?: number
}

export interface ExtScan {
  id: number
  domain: string
  url: string
  risk_level: string
  score: number
  is_https: number
  issues: { type: string; severity: string; description: string; recommendation: string }[]
  action: string
  scanned_at: string
}

export interface ExtStats {
  total_scans: number
  by_risk: Record<string, number>
  blocked_count: number
  unsafe_http_count: number
  recent_domains: { domain: string; risk_level: string; score: number; scanned_at: string }[]
}

// ── API calls ──────────────────────────────────────────────────────────────
export const api = {
  health: () => get<Health>('/health'),
  attacks: (limit = 30) => get<{ attacks: Attack[]; total: number }>(`/api/attacks/recent?limit=${limit}`),
  stats: (days = 7) => get<Stats>(`/api/stats/attacks?days=${days}`),
  blockedIps: () => get<{ blocked_ips: BlockedIP[]; total: number }>('/api/defense/blocked-ips'),
  whitelist: () => get<{ whitelist: string[] }>('/api/whitelist'),
  metrics: () => get<SystemMetrics>('/api/metrics/system'),
  ollamaHealth: () => get<{ available: boolean; models: string[]; target_model: string; model_ready: boolean }>('/api/analysis/ollama-health'),

  blockIp: (ip: string, reason: string, duration: number) =>
    post<{ success: boolean; message: string }>('/api/defense/block-ip', { ip, reason, duration }),
  unblockIp: (ip: string) =>
    post<{ success: boolean }>('/api/defense/unblock-ip', { ip }),
  emergencyUnblock: () =>
    post<{ success: boolean }>('/api/defense/emergency-unblock'),
  setDefenseMode: (auto_block?: boolean, dry_run?: boolean) =>
    post<{ auto_block: boolean; dry_run: boolean }>('/api/defense/mode', { auto_block, dry_run }),
  addWhitelist: (ip: string, reason: string) =>
    post<{ success: boolean }>('/api/whitelist/add', { ip, reason }),
  removeWhitelist: (ip: string) =>
    post<{ success: boolean }>('/api/whitelist/remove', { ip }),

  injectAll: () => post<{ injected: number; detected: number; attacks: Attack[] }>('/api/test/inject'),
  injectCustom: (lines: string[]) =>
    post<{ injected: number; detected: number; attacks: Attack[] }>('/api/test/inject-custom', { lines }),
  runScan: () => post('/api/scan/run'),

  // Extension
  extensionScans: (limit = 50) => get<{ scans: ExtScan[]; total: number }>(`/api/extension/scans?limit=${limit}`),
  extensionStats: () => get<ExtStats>('/api/extension/stats'),
}

export const WS_URL = (process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000')
  .replace('http', 'ws') + '/ws/attacks'
