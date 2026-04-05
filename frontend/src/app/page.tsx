'use client'
import AppShell from '@/components/AppShell'
import StatCard from '@/components/StatCard'
import { AttackTypePie, SeverityBar, AttackTimeline } from '@/components/Charts'
import { useHealth, useStats, useMetrics, useWebSocket } from '@/hooks/useLiveData'
import { ATTACK_ICON, SEV_COLOR, fmtTime } from '@/lib/utils'

export default function Overview() {
  const { data: health } = useHealth()
  const { data: stats } = useStats(7)
  const { data: metrics } = useMetrics()
  const { liveAttacks, connected } = useWebSocket()

  const risk = (() => {
    if (!stats) return 'UNKNOWN'
    const c = stats.by_severity?.CRITICAL || 0
    const t = stats.total_attacks || 0
    if (c > 10 || t > 100) return 'CRITICAL'
    if (c > 5 || t > 50) return 'HIGH'
    if (t > 10) return 'MEDIUM'
    return 'LOW'
  })()

  const riskColor: Record<string, string> = {
    CRITICAL: 'text-red-400', HIGH: 'text-orange-400',
    MEDIUM: 'text-yellow-400', LOW: 'text-green-400', UNKNOWN: 'text-muted'
  }

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">🛡️ Autonomous AI Cyber Defense</h1>
            <p className="text-muted text-sm mt-1">Real-time threat detection & automated defense</p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
            <span className="text-muted">{connected ? 'WebSocket live' : 'Polling'}</span>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="System Status"
            value={health ? 'ACTIVE' : 'OFFLINE'}
            icon="🟢"
            color={health ? 'text-green-400' : 'text-red-400'}
          />
          <StatCard
            label="Risk Level"
            value={risk}
            icon="⚠️"
            color={riskColor[risk]}
          />
          <StatCard
            label="Attacks (7d)"
            value={stats?.total_attacks ?? '—'}
            icon="🚨"
            color="text-orange-400"
          />
          <StatCard
            label="Blocked (7d)"
            value={stats?.blocked_count ?? '—'}
            icon="🔒"
            color="text-red-400"
          />
        </div>

        {/* System metrics */}
        {metrics?.available && (
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'CPU', value: metrics.cpu_percent ?? 0, color: 'bg-blue-500' },
              { label: 'Memory', value: metrics.memory_percent ?? 0, color: 'bg-purple-500' },
              { label: 'Disk', value: metrics.disk_percent ?? 0, color: 'bg-green-500' },
            ].map(m => (
              <div key={m.label} className="card">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-muted">{m.label}</span>
                  <span className="font-mono text-white">{m.value.toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-bg rounded-full overflow-hidden">
                  <div className={`h-full ${m.color} rounded-full transition-all duration-500`} style={{ width: `${m.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Services */}
        {health && (
          <div className="card">
            <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Service Status</h2>
            <div className="flex flex-wrap gap-3">
              {Object.entries(health.services).map(([svc, status]) => {
                const ok = ['connected', 'ready', 'active'].includes(status)
                return (
                  <div key={svc} className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs ${ok ? 'border-green-800/50 bg-green-900/20 text-green-300' : 'border-yellow-800/50 bg-yellow-900/20 text-yellow-300'}`}>
                    <span>{ok ? '✅' : '⚠️'}</span>
                    <span className="capitalize">{svc.replace('_', ' ')}</span>
                    <span className="text-muted">· {status}</span>
                  </div>
                )
              })}
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs ${health.defense_mode.auto_block ? 'border-green-800/50 bg-green-900/20 text-green-300' : 'border-gray-700 bg-gray-900/20 text-muted'}`}>
                <span>🔒</span>
                <span>Auto-Block: {health.defense_mode.auto_block ? 'ON' : 'OFF'}</span>
              </div>
              {health.defense_mode.dry_run && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-blue-800/50 bg-blue-900/20 text-blue-300 text-xs">
                  <span>🔵</span><span>Dry-Run Mode</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Charts */}
        {stats && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="card">
              <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attack Types</h2>
              <AttackTypePie data={stats.by_type} />
            </div>
            <div className="card">
              <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">By Severity</h2>
              <SeverityBar data={stats.by_severity} />
            </div>
          </div>
        )}

        {stats?.timeline && stats.timeline.length > 0 && (
          <div className="card">
            <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attack Timeline (7d)</h2>
            <AttackTimeline data={stats.timeline} />
          </div>
        )}

        {/* Live WebSocket feed */}
        {liveAttacks.length > 0 && (
          <div className="card">
            <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">
              ⚡ Live Feed <span className="text-green-400 text-xs ml-2">● {liveAttacks.length} events</span>
            </h2>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {liveAttacks.slice(0, 20).map((a, i) => (
                <div key={i} className="flex items-center gap-3 text-xs py-1 border-b border-border/50">
                  <span>{ATTACK_ICON[a.attack_type] || '⚠️'}</span>
                  <span className={SEV_COLOR[a.severity]}>{a.severity}</span>
                  <span className="font-mono text-white">{a.ip}</span>
                  <span className="text-muted truncate flex-1">{a.path}</span>
                  <span className="text-muted">{fmtTime(a.timestamp)}</span>
                  {a.blocked && <span className="text-red-400">🔒</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
