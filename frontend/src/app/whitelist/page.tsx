'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import { usePoll } from '@/hooks/useLiveData'
import { api } from '@/lib/api'

export default function WhitelistPage() {
  const { data, refetch } = usePoll(() => api.whitelist(), 5000)
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [msg, setMsg] = useState('')

  const list = data?.whitelist ?? []
  const notify = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 3000) }

  async function add() {
    if (!ip) return notify('Enter an IP')
    const r = await api.addWhitelist(ip, reason)
    notify(r?.success ? `✅ ${ip} added` : '❌ Failed')
    setIp(''); setReason(''); refetch()
  }

  async function remove(target: string) {
    const r = await api.removeWhitelist(target)
    notify(r?.success ? `✅ ${target} removed` : '❌ Failed')
    refetch()
  }

  return (
    <AppShell>
      <div className="max-w-2xl mx-auto space-y-6">
        <h1 className="text-xl font-bold text-white">✅ IP Whitelist</h1>
        <p className="text-muted text-sm">IPs on this list are never blocked, regardless of attack detection.</p>

        {msg && <div className="card text-sm">{msg}</div>}

        {/* Add form */}
        <div className="card space-y-3">
          <h2 className="font-semibold text-white text-sm">Add IP to Whitelist</h2>
          <div className="flex gap-3">
            <input className="input" placeholder="IP address" value={ip} onChange={e => setIp(e.target.value)} />
            <input className="input" placeholder="Reason (optional)" value={reason} onChange={e => setReason(e.target.value)} />
            <button onClick={add} className="btn-primary whitespace-nowrap">➕ Add</button>
          </div>
        </div>

        {/* List */}
        <div className="card p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-bg text-xs text-muted uppercase tracking-wide">
            {list.length} whitelisted IPs
          </div>
          {list.length === 0 ? (
            <div className="text-center py-8 text-muted text-sm">No IPs whitelisted (localhost is always protected)</div>
          ) : (
            <div className="divide-y divide-border">
              {list.map(wip => (
                <div key={wip} className="flex items-center justify-between px-4 py-3">
                  <span className="font-mono text-sm text-white">{wip}</span>
                  <button onClick={() => remove(wip)} className="text-xs text-red-400 hover:text-red-300 hover:underline">
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  )
}
