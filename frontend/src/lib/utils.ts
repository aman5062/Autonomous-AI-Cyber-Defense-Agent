export const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-green-400',
}

export const SEV_BG: Record<string, string> = {
  CRITICAL: 'bg-red-900/40 border-red-700/50 text-red-300',
  HIGH: 'bg-orange-900/40 border-orange-700/50 text-orange-300',
  MEDIUM: 'bg-yellow-900/40 border-yellow-700/50 text-yellow-300',
  LOW: 'bg-green-900/40 border-green-700/50 text-green-300',
}

export const SEV_DOT: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-green-500',
}

export const ATTACK_ICON: Record<string, string> = {
  SQL_INJECTION: '💉',
  BRUTE_FORCE: '🔨',
  PATH_TRAVERSAL: '📁',
  XSS: '🕷️',
  COMMAND_INJECTION: '⚡',
  BOT_SCAN: '🤖',
  DDOS: '🌊',
  ANOMALY: '🔍',
}

export const ATTACK_COLOR: Record<string, string> = {
  SQL_INJECTION: '#ef4444',
  BRUTE_FORCE: '#f97316',
  PATH_TRAVERSAL: '#a855f7',
  XSS: '#eab308',
  COMMAND_INJECTION: '#ec4899',
  BOT_SCAN: '#3b82f6',
  DDOS: '#06b6d4',
  ANOMALY: '#84cc16',
}

export function fmtTime(ts: string) {
  if (!ts) return ''
  try { return new Date(ts).toLocaleTimeString() } catch { return ts }
}

export function fmtDate(ts: string) {
  if (!ts) return ''
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

export function clsx(...classes: (string | undefined | false | null)[]) {
  return classes.filter(Boolean).join(' ')
}
