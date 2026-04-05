'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import StatCard from '@/components/StatCard'
import { AttackTypePie, SeverityBar, AttackTimeline } from '@/components/Charts'
import { useStats, useBlockedIps } from '@/hooks/useLiveData'

export default function AnalyticsPage() {
  const [days, setDays] = useState(7)
  const { data: stats } = useStats(days)
  const { data: blocked } = useBlockedIps()

  return (
    <AppShell>
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-white">📊 Attack Analytics</h1>
          <div className="flex items-center gap-2">
            <span className="text-muted text-sm">Range:</span>
            <div className="flex rounded-md border border-border overflow-hidden text-xs">
              {[1, 7, 14, 30].map(d => (
                <button
                  key={d}
                  onClick={() => setDays(d)}
                  className={`px-3 py-1.5 ${days === d ? 'bg-red-900/40 text-red-300' : 'text-muted hover:text-white'}`}
                >
                  {d}d
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Attacks" value={stats?.total_attacks ?? '—'} icon="🚨" color="text-orange-400" />
          <StatCard label="Blocked" value={stats?.blocked_count ?? '—'} icon="🔒" color="text-red-400" />
          <StatCard label="Critical" value={stats?.by_severity?.CRITICAL ?? 0} icon="🔴" color="text-red-400" />
          <StatCard label="IPs Blocked Now" value={blocked?.total ?? '—'} icon="🚫" color="text-purple-400" />
        </div>

        {/* Charts */}
        {stats ? (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="card">
                <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attack Type Distribution</h2>
                <AttackTypePie data={stats.by_type} />
              </div>
              <div className="card">
                <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Severity Distribution</h2>
                <SeverityBar data={stats.by_severity} />
              </div>
            </div>

            <div className="card">
              <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attack Timeline</h2>
              <AttackTimeline data={stats.timeline} />
            </div>

            {/* Breakdown table */}
            <div className="card">
              <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">Attack Breakdown</h2>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted text-xs border-b border-border">
                    <th className="text-left py-2">Attack Type</th>
                    <th className="text-right py-2">Count</th>
                    <th className="text-right py-2">% of Total</th>
                    <th className="py-2">Distribution</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(stats.by_type).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
                    const pct = stats.total_attacks ? Math.round((count / stats.total_attacks) * 100) : 0
                    return (
                      <tr key={type} className="border-b border-border/50">
                        <td className="py-2 font-mono text-xs">{type.replace(/_/g, ' ')}</td>
                        <td className="text-right py-2 font-bold">{count}</td>
                        <td className="text-right py-2 text-muted">{pct}%</td>
                        <td className="py-2 pl-4">
                          <div className="h-2 bg-bg rounded-full overflow-hidden w-32">
                            <div className="h-full bg-red-500 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="card text-center py-12 text-muted">Loading analytics...</div>
        )}
      </div>
    </AppShell>
  )
}
