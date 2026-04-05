'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import { useHealth } from '@/hooks/useLiveData'
import { api } from '@/lib/api'

export default function ControlsPage() {
  const { data: health, refetch } = useHealth()
  const defense = health?.defense_mode
  const [msg, setMsg] = useState('')
  const [blockIp, setBlockIp] = useState('')
  const [blockReason, setBlockReason] = useState('Manual block')
  const [blockDur, setBlockDur] = useState(3600)
  const [unblockIp, setUnblockIp] = useState('')
  const [confirmEmergency, setConfirmEmergency] = useState(false)

  const notify = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 4000) }

  async function toggleAutoBlock() {
    await api.setDefenseMode(!defense?.auto_block, undefined)
    refetch(); notify(`Auto-block ${!defense?.auto_block ? 'enabled' : 'disabled'}`)
  }

  async function toggleDryRun() {
    await api.setDefenseMode(undefined, !defense?.dry_run)
    refetch(); notify(`Dry-run ${!defense?.dry_run ? 'enabled' : 'disabled'}`)
  }

  async function doBlock() {
    if (!blockIp) return notify('Enter an IP address')
    const r = await api.blockIp(blockIp, blockReason, blockDur)
    notify(r?.success ? `✅ ${blockIp} blocked` : '❌ Block failed')
    setBlockIp('')
  }

  async function doUnblock() {
    if (!unblockIp) return notify('Enter an IP address')
    const r = await api.unblockIp(unblockIp)
    notify(r?.success ? `✅ ${unblockIp} unblocked` : '❌ Unblock failed')
    setUnblockIp('')
  }

  async function doEmergency() {
    const r = await api.emergencyUnblock()
    notify(r?.success ? '✅ All IPs unblocked' : '❌ Failed')
    setConfirmEmergency(false)
  }

  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        <h1 className="text-xl font-bold text-white">⚙️ Defense Controls</h1>

        {msg && <div className="card text-sm border-blue-800/50 bg-blue-900/20 text-blue-200">{msg}</div>}

        {/* Defense Mode */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-white">Defense Mode</h2>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-bg rounded-lg p-4 border border-border">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <div className="font-medium text-sm">Auto-Block</div>
                  <div className="text-xs text-muted mt-0.5">Automatically block attacker IPs</div>
                </div>
                <button
                  onClick={toggleAutoBlock}
                  className={`relative w-12 h-6 rounded-full transition-colors ${defense?.auto_block ? 'bg-green-600' : 'bg-gray-700'}`}
                >
                  <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${defense?.auto_block ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
              <div className={`text-xs ${defense?.auto_block ? 'text-green-400' : 'text-muted'}`}>
                {defense?.auto_block ? '✅ Active' : '⚪ Disabled'}
              </div>
            </div>

            <div className="bg-bg rounded-lg p-4 border border-border">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <div className="font-medium text-sm">Dry-Run Mode</div>
                  <div className="text-xs text-muted mt-0.5">Log only, no real blocks</div>
                </div>
                <button
                  onClick={toggleDryRun}
                  className={`relative w-12 h-6 rounded-full transition-colors ${defense?.dry_run ? 'bg-blue-600' : 'bg-gray-700'}`}
                >
                  <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${defense?.dry_run ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>
              <div className={`text-xs ${defense?.dry_run ? 'text-blue-400' : 'text-muted'}`}>
                {defense?.dry_run ? '🔵 Dry-run active' : '⚫ Real blocking'}
              </div>
            </div>
          </div>
        </div>

        {/* Manual Block */}
        <div className="card space-y-3">
          <h2 className="font-semibold text-white">🔒 Manual Block IP</h2>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted mb-1 block">IP Address</label>
              <input className="input" placeholder="e.g. 1.2.3.4" value={blockIp} onChange={e => setBlockIp(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-muted mb-1 block">Reason</label>
              <input className="input" value={blockReason} onChange={e => setBlockReason(e.target.value)} />
            </div>
          </div>
          <div>
            <label className="text-xs text-muted mb-1 block">Duration</label>
            <select className="input w-48" value={blockDur} onChange={e => setBlockDur(Number(e.target.value))}>
              <option value={3600}>1 hour</option>
              <option value={21600}>6 hours</option>
              <option value={86400}>24 hours</option>
              <option value={604800}>7 days</option>
            </select>
          </div>
          <button onClick={doBlock} className="btn-primary">🔒 Block IP</button>
        </div>

        {/* Manual Unblock */}
        <div className="card space-y-3">
          <h2 className="font-semibold text-white">🔓 Manual Unblock IP</h2>
          <div className="flex gap-3">
            <input className="input" placeholder="IP address to unblock" value={unblockIp} onChange={e => setUnblockIp(e.target.value)} />
            <button onClick={doUnblock} className="btn-secondary whitespace-nowrap">🔓 Unblock</button>
          </div>
        </div>

        {/* Emergency */}
        <div className="card border-red-900/50 space-y-3">
          <h2 className="font-semibold text-red-400">🚨 Emergency Controls</h2>
          <p className="text-xs text-muted">This will immediately unblock ALL currently blocked IPs.</p>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={confirmEmergency} onChange={e => setConfirmEmergency(e.target.checked)} className="w-4 h-4" />
            I understand this will unblock all IPs
          </label>
          <button onClick={doEmergency} disabled={!confirmEmergency} className="btn-danger disabled:opacity-40 disabled:cursor-not-allowed">
            🚨 Emergency Unblock ALL
          </button>
        </div>
      </div>
    </AppShell>
  )
}
