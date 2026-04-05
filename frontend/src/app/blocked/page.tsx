'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import { useBlockedIps } from '@/hooks/useLiveData'
import { api } from '@/lib/api'
import { SEV_BG, fmtDate } from '@/lib/utils'

export default function BlockedPage() {
  const { data, refetch } = useBlockedIps()
  const [msg, setMsg] = useState('')

  const ips = data?.blocked_ips ?? []

  async function unblock(ip: string) {
    const r = await api.unblockIp(ip)
    setMsg(r?.success ? `✅ ${ip} unblocked` : '❌ Failed')
    refetch()
    setTimeout(() => setMsg(''), 3000)
  }

  async function emergencyUnblock() {
    if (!confirm('Unblock ALL IPs?')) return
    const r = await api.emergencyUnblock()
    setMsg(r?.success ? '✅ All IPs unblocked' : '❌ Failed')
    refetch()
    setTimeout(() => setMsg(''), 3000)
  }

  return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-white">🚫 Blocked IPs <span className="text-muted text-base font-normal">({data?.total ?? 0} active)</span></h1>
          <button onClick={emergencyUnblock} className="btn-danger text-xs">
            🚨 Emergency Unblock All
          </button>
        </div>

        {msg && <div className="card text-sm">{msg}</div>}

        {!ips.length ? (
          <div className="card text-center py-12">
            <div className="text-4xl mb-3">✅</div>
            <div className="text-muted">No IPs currently blocked. System is clean.</div>
          </div>
        ) : (
          <div className="card overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-muted text-xs border-b border-border bg-bg">
                  <th className="text-left px-4 py-3">IP Address</th>
                  <th className="text-left px-4 py-3">Attack Type</th>
                  <th className="text-left px-4 py-3">Severity</th>
                  <th className="text-left px-4 py-3">Blocked At</th>
                  <th className="text-left px-4 py-3">Unblock At</th>
                  <th className="text-left px-4 py-3">Reason</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {ips.map(ip => (
                  <tr key={ip.id} className="border-b border-border/50 hover:bg-white/2">
                    <td className="px-4 py-3 font-mono text-white">{ip.ip}</td>
                    <td className="px-4 py-3 text-xs">{ip.attack_type?.replace(/_/g, ' ')}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded border ${SEV_BG[ip.severity] || ''}`}>{ip.severity}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">{fmtDate(ip.block_time)}</td>
                    <td className="px-4 py-3 text-xs text-muted">{ip.unblock_time ? fmtDate(ip.unblock_time) : '—'}</td>
                    <td className="px-4 py-3 text-xs text-muted max-w-xs truncate">{ip.reason || '—'}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => unblock(ip.ip)} className="text-xs text-blue-400 hover:text-blue-300 hover:underline">
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppShell>
  )
}
