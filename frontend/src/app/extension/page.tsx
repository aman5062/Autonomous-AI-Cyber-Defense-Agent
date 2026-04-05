'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import { usePoll } from '@/hooks/useLiveData'
import { api, ExtScan } from '@/lib/api'
import { clsx } from '@/lib/utils'

const RISK_COLOR: Record<string, string> = {
  SAFE:     'text-green-400',
  LOW:      'text-lime-400',
  MEDIUM:   'text-yellow-400',
  HIGH:     'text-orange-400',
  CRITICAL: 'text-red-400',
  UNKNOWN:  'text-muted',
}
const RISK_BG: Record<string, string> = {
  SAFE:     'bg-green-900/30 border-green-700/40',
  LOW:      'bg-lime-900/30 border-lime-700/40',
  MEDIUM:   'bg-yellow-900/30 border-yellow-700/40',
  HIGH:     'bg-orange-900/30 border-orange-700/40',
  CRITICAL: 'bg-red-900/30 border-red-700/40',
  UNKNOWN:  'bg-surface border-border',
}
const RISK_ICON: Record<string, string> = {
  SAFE: '✅', LOW: '🟡', MEDIUM: '⚠️', HIGH: '🟠', CRITICAL: '🔴', UNKNOWN: '❓'
}

export default function ExtensionPage() {
  const { data: stats } = usePoll(() => api.extensionStats(), 3000)
  const { data: scansData } = usePoll(() => api.extensionScans(50), 3000)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [filter, setFilter] = useState('ALL')

  const scans = scansData?.scans ?? []
  const filtered = filter === 'ALL' ? scans : scans.filter(s => s.risk_level === filter)

  return (
    <AppShell>
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">🧩 Chrome Extension Monitor</h1>
            <p className="text-muted text-sm mt-1">Real-time website security scans from your browser</p>
          </div>
          <a
            href="#install"
            className="btn-primary text-sm px-4 py-2 rounded-md"
            onClick={e => { e.preventDefault(); document.getElementById('install')?.scrollIntoView({ behavior: 'smooth' }) }}
          >
            📦 Install Extension
          </a>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Total Scans', value: stats?.total_scans ?? 0, icon: '🔍', color: 'text-blue-400' },
            { label: 'Sites Blocked', value: stats?.blocked_count ?? 0, icon: '🚫', color: 'text-red-400' },
            { label: 'HTTP (Unsafe)', value: stats?.unsafe_http_count ?? 0, icon: '🔓', color: 'text-orange-400' },
            { label: 'Critical Sites', value: stats?.by_risk?.CRITICAL ?? 0, icon: '🔴', color: 'text-red-400' },
          ].map(s => (
            <div key={s.label} className="card flex items-center gap-4">
              <span className="text-3xl">{s.icon}</span>
              <div>
                <div className="text-muted text-xs uppercase tracking-wide">{s.label}</div>
                <div className={clsx('text-2xl font-bold', s.color)}>{s.value}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Risk distribution */}
        {stats && Object.keys(stats.by_risk).length > 0 && (
          <div className="card">
            <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Risk Distribution</h2>
            <div className="flex gap-3 flex-wrap">
              {Object.entries(stats.by_risk).sort((a, b) => {
                const order = ['CRITICAL','HIGH','MEDIUM','LOW','SAFE','UNKNOWN']
                return order.indexOf(a[0]) - order.indexOf(b[0])
              }).map(([risk, count]) => (
                <div key={risk} className={clsx('flex items-center gap-2 px-4 py-2 rounded-lg border', RISK_BG[risk])}>
                  <span>{RISK_ICON[risk]}</span>
                  <span className={clsx('font-bold', RISK_COLOR[risk])}>{risk}</span>
                  <span className="text-white font-bold text-lg">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent domains */}
        {stats?.recent_domains && stats.recent_domains.length > 0 && (
          <div className="card">
            <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Recently Scanned Domains</h2>
            <div className="flex flex-wrap gap-2">
              {stats.recent_domains.map((d, i) => (
                <div key={i} className={clsx('flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs', RISK_BG[d.risk_level])}>
                  <span>{RISK_ICON[d.risk_level]}</span>
                  <span className="font-mono text-white">{d.domain}</span>
                  <span className={clsx('font-bold', RISK_COLOR[d.risk_level])}>{d.score}/100</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Scan history */}
        <div className="card p-0 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-bg">
            <h2 className="text-sm font-semibold text-white">Scan History ({filtered.length})</h2>
            <div className="flex gap-1">
              {['ALL','CRITICAL','HIGH','MEDIUM','LOW','SAFE'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={clsx(
                    'text-xs px-2 py-1 rounded border transition-colors',
                    filter === f ? 'bg-red-900/40 border-red-700/50 text-red-300' : 'border-border text-muted hover:text-white'
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted">
              <div className="text-4xl mb-3">🧩</div>
              <div>No scan data yet.</div>
              <div className="text-xs mt-1">Install the extension and browse some websites.</div>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map((scan, i) => (
                <div key={scan.id ?? i}>
                  <button
                    onClick={() => setExpanded(expanded === i ? null : i)}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/2 text-left transition-colors"
                  >
                    <span className="text-lg">{RISK_ICON[scan.risk_level] || '❓'}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm text-white">{scan.domain}</span>
                        <span className={clsx('text-xs px-1.5 py-0.5 rounded border', RISK_BG[scan.risk_level], RISK_COLOR[scan.risk_level])}>
                          {scan.risk_level}
                        </span>
                        {!scan.is_https && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-orange-900/40 border border-orange-700/40 text-orange-300">🔓 HTTP</span>
                        )}
                        {scan.action === 'BLOCKED' && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/40 border border-red-700/40 text-red-300">🚫 BLOCKED</span>
                        )}
                      </div>
                      <div className="text-xs text-muted mt-0.5 truncate">{scan.url}</div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className={clsx('font-bold text-lg', RISK_COLOR[scan.risk_level])}>{scan.score}/100</div>
                      <div className="text-xs text-muted">{new Date(scan.scanned_at).toLocaleTimeString()}</div>
                    </div>
                    <span className="text-muted text-xs ml-2">{expanded === i ? '▲' : '▼'}</span>
                  </button>

                  {expanded === i && (
                    <div className="px-4 pb-4 border-t border-border/50">
                      {Array.isArray(scan.issues) && scan.issues.length > 0 ? (
                        <div className="space-y-2 mt-3">
                          <div className="text-xs text-muted uppercase tracking-wide mb-2">Issues Found ({scan.issues.length})</div>
                          {scan.issues.map((issue, j) => (
                            <div key={j} className={clsx('flex gap-3 p-3 rounded-lg border', RISK_BG[issue.severity])}>
                              <span className={clsx('text-xs font-bold px-2 py-0.5 rounded self-start whitespace-nowrap', RISK_BG[issue.severity], RISK_COLOR[issue.severity])}>
                                {issue.severity}
                              </span>
                              <div>
                                <div className="text-sm text-white">{issue.description}</div>
                                <div className="text-xs text-muted mt-1">→ {issue.recommendation}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-muted mt-3">No issues detected on this scan.</div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Install guide */}
        <div id="install" className="card space-y-4">
          <h2 className="font-bold text-white text-lg">📦 Install the Chrome Extension</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Installation Steps</h3>
              <ol className="space-y-3 text-sm">
                {[
                  'Open Chrome and go to chrome://extensions/',
                  'Enable "Developer mode" (toggle in top-right)',
                  'Click "Load unpacked"',
                  'Select the extension/ folder from this project',
                  'The 🛡️ shield icon will appear in your toolbar',
                  'Click it on any website to see the security scan',
                ].map((step, i) => (
                  <li key={i} className="flex gap-3">
                    <span className="w-6 h-6 rounded-full bg-red-900/40 border border-red-700/40 text-red-300 text-xs flex items-center justify-center shrink-0 font-bold">{i+1}</span>
                    <span className="text-muted">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">What It Detects</h3>
              <div className="space-y-2 text-sm">
                {[
                  ['🔓', 'HTTP sites (no encryption)', 'HIGH'],
                  ['💳', 'Payment forms on HTTP pages', 'CRITICAL'],
                  ['🎣', 'Phishing domain patterns', 'CRITICAL'],
                  ['🔀', 'Mixed content (HTTP on HTTPS)', 'MEDIUM'],
                  ['📝', 'Suspicious form actions', 'HIGH'],
                  ['⛏️', 'Cryptominer / keylogger scripts', 'CRITICAL'],
                  ['🖼️', 'Clickjacking (iframe embedding)', 'MEDIUM'],
                  ['📥', 'Malicious file downloads', 'HIGH'],
                  ['🌐', 'High-risk domain extensions', 'MEDIUM'],
                ].map(([icon, desc, sev]) => (
                  <div key={desc} className="flex items-center gap-3">
                    <span>{icon}</span>
                    <span className="text-muted flex-1">{desc}</span>
                    <span className={clsx('text-xs px-1.5 py-0.5 rounded border', RISK_BG[sev as string], RISK_COLOR[sev as string])}>{sev}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="bg-bg rounded-lg p-4 border border-border text-xs text-muted">
            <strong className="text-white">Note:</strong> Make sure the backend is running at <code className="text-green-400">localhost:8000</code> for scan data to sync to this dashboard. The extension works offline too — data syncs when the backend is available.
          </div>
        </div>

      </div>
    </AppShell>
  )
}
