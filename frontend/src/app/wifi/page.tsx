'use client'
import { useState, useEffect, useCallback } from 'react'
import AppShell from '@/components/AppShell'

interface Device {
  ip: string
  mac: string
  hostname: string
  first_seen: string
  last_seen: string
  is_trusted: boolean
  is_blocked: boolean
  open_ports: number[]
  risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
  notes: string[]
}

interface Summary {
  total_devices: number
  blocked_devices: number
  trusted_devices: number
  risky_devices: number
  local_ip: string
  subnet: string
  last_scan: string
}

const RISK_COLORS: Record<string, string> = {
  SAFE:     'bg-green-900/30 text-green-400 border-green-700/40',
  LOW:      'bg-blue-900/30 text-blue-400 border-blue-700/40',
  MEDIUM:   'bg-yellow-900/30 text-yellow-400 border-yellow-700/40',
  HIGH:     'bg-orange-900/30 text-orange-400 border-orange-700/40',
  CRITICAL: 'bg-red-900/30 text-red-400 border-red-700/40',
  UNKNOWN:  'bg-gray-800 text-gray-400 border-gray-700',
}

const RISK_ICONS: Record<string, string> = {
  SAFE: '✅', LOW: '🟢', MEDIUM: '🟡', HIGH: '🟠', CRITICAL: '🔴', UNKNOWN: '⚪',
}

export default function WiFiPage() {
  const [devices, setDevices] = useState<Device[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(false)
  const [rescanning, setRescanning] = useState(false)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const BASE = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000'

  const fetchData = useCallback(async () => {
    try {
      const [devRes, sumRes] = await Promise.all([
        fetch(`${BASE}/api/wifi/devices`),
        fetch(`${BASE}/api/wifi/summary`),
      ])
      if (devRes.ok) setDevices((await devRes.json()).devices ?? [])
      if (sumRes.ok) setSummary(await sumRes.json())
      setLastRefresh(new Date())
    } catch (_) {}
  }, [BASE])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 15000)
    return () => clearInterval(id)
  }, [fetchData])

  async function triggerRescan() {
    setRescanning(true)
    try {
      await fetch(`${BASE}/api/wifi/rescan`, { method: 'POST' })
      setTimeout(fetchData, 5000)
    } finally {
      setRescanning(false)
    }
  }

  const byRisk = (r: string) => devices.filter(d => d.risk_level === r).length

  return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Page header */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-white">📡 WiFi & LAN Protection</h1>
            <p className="text-muted text-sm mt-1">
              Monitor every device on the local network in real time.
              Devices performing attacks are automatically blocked by the defense engine.
            </p>
          </div>
          <button
            onClick={triggerRescan}
            disabled={rescanning}
            className="btn-secondary whitespace-nowrap"
          >
            {rescanning ? '⏳ Scanning…' : '🔄 Rescan Network'}
          </button>
        </div>

        {/* How-it-works banner */}
        <div className="card border-blue-900/40 bg-blue-950/20">
          <h2 className="font-semibold text-white mb-2">🏫 How This Protects Your Network</h2>
          <p className="text-sm text-muted leading-relaxed">
            This tool continuously scans your local WiFi/LAN subnet for connected devices.
            When any device performs a detected attack (SQL injection, command injection, XSS, brute force, etc.)
            the AI defense engine <strong className="text-white">automatically blocks their IP</strong> — even on local network traffic.
            Ideal for school, college, or office WiFi scenarios where multiple untrusted users share the same network.
          </p>
        </div>

        {/* Summary cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard icon="💻" label="Total Devices" value={summary.total_devices} />
            <StatCard icon="🔴" label="Blocked" value={summary.blocked_devices} color="text-red-400" />
            <StatCard icon="✅" label="Trusted" value={summary.trusted_devices} color="text-green-400" />
            <StatCard icon="⚠️" label="Risky" value={summary.risky_devices} color="text-orange-400" />
          </div>
        )}

        {/* Network info */}
        {summary && (
          <div className="card flex flex-wrap gap-6 text-sm">
            <InfoItem label="Local IP" value={summary.local_ip} mono />
            <InfoItem label="Subnet" value={summary.subnet} mono />
            <InfoItem label="Last Scan" value={lastRefresh ? lastRefresh.toLocaleTimeString() : 'Never'} />
          </div>
        )}

        {/* Risk breakdown */}
        <div className="grid grid-cols-5 gap-2 text-center text-xs">
          {(['SAFE','LOW','MEDIUM','HIGH','CRITICAL'] as const).map(r => (
            <div key={r} className={`card border ${RISK_COLORS[r]} py-3`}>
              <div className="text-lg">{RISK_ICONS[r]}</div>
              <div className="font-bold mt-1">{byRisk(r)}</div>
              <div className="text-muted mt-0.5">{r}</div>
            </div>
          ))}
        </div>

        {/* Device table */}
        <div className="card overflow-x-auto">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold text-white">Connected Devices</h2>
            <span className="text-xs text-muted">{devices.length} discovered</span>
          </div>

          {devices.length === 0 ? (
            <p className="text-muted text-sm py-6 text-center">
              No devices discovered yet. The network scanner runs every 30 s — or click &ldquo;Rescan Network&rdquo;.
            </p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left border-b border-border">
                  <th className="pb-2 text-muted font-medium pr-4">Risk</th>
                  <th className="pb-2 text-muted font-medium pr-4">IP Address</th>
                  <th className="pb-2 text-muted font-medium pr-4">Hostname / MAC</th>
                  <th className="pb-2 text-muted font-medium pr-4">Status</th>
                  <th className="pb-2 text-muted font-medium">Notes</th>
                </tr>
              </thead>
              <tbody>
                {devices.map(d => (
                  <tr key={d.ip} className="border-b border-border/40 hover:bg-white/2">
                    <td className="py-2 pr-4">
                      <span className={`px-2 py-0.5 rounded border text-xs font-bold ${RISK_COLORS[d.risk_level]}`}>
                        {RISK_ICONS[d.risk_level]} {d.risk_level}
                      </span>
                    </td>
                    <td className="py-2 pr-4 font-mono font-bold text-white">{d.ip}</td>
                    <td className="py-2 pr-4 text-muted">
                      {d.hostname && <div>{d.hostname}</div>}
                      {d.mac && <div className="font-mono text-muted/60">{d.mac}</div>}
                    </td>
                    <td className="py-2 pr-4">
                      {d.is_blocked && (
                        <span className="px-2 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-700/40 text-xs font-bold">
                          🚫 BLOCKED
                        </span>
                      )}
                      {d.is_trusted && !d.is_blocked && (
                        <span className="px-2 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-700/40 text-xs">
                          ✅ Trusted
                        </span>
                      )}
                      {!d.is_blocked && !d.is_trusted && (
                        <span className="text-muted">Active</span>
                      )}
                    </td>
                    <td className="py-2 text-muted">
                      {d.notes.slice(0,2).join(' · ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Security tips */}
        <div className="card border-yellow-900/30 bg-yellow-950/10">
          <h2 className="font-semibold text-white mb-3">🔒 Network Security Best Practices</h2>
          <ul className="text-sm text-muted space-y-2 list-disc list-inside">
            <li>Enable WPA3 encryption on your router for strongest protection</li>
            <li>Isolate IoT devices on a separate VLAN or guest network</li>
            <li>Change default router credentials (admin/admin is easily guessable)</li>
            <li>Enable MAC address filtering for trusted-only device access</li>
            <li>Monitor blocked IPs regularly — repeat offenders may indicate a real threat actor</li>
            <li>Use the <strong className="text-white">Whitelist</strong> feature to mark trusted devices so they&apos;re never accidentally blocked</li>
          </ul>
        </div>
      </div>
    </AppShell>
  )
}

function StatCard({
  icon, label, value, color = 'text-white',
}: { icon: string; label: string; value: number; color?: string }) {
  return (
    <div className="card text-center">
      <div className="text-2xl">{icon}</div>
      <div className={`text-2xl font-bold mt-1 ${color}`}>{value}</div>
      <div className="text-xs text-muted mt-0.5">{label}</div>
    </div>
  )
}

function InfoItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted mb-0.5">{label}</div>
      <div className={`text-sm font-semibold text-white ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  )
}
