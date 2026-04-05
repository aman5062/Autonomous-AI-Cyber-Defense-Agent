'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'
import AttackCard from '@/components/AttackCard'
import { useAttacks, useWebSocket } from '@/hooks/useLiveData'

export default function AttacksPage() {
  const [limit, setLimit] = useState(30)
  const [mode, setMode] = useState<'poll' | 'ws'>('poll')
  const { data: attacks, loading } = useAttacks(limit)
  const { liveAttacks, connected } = useWebSocket()

  const displayed = mode === 'ws' ? liveAttacks : (attacks ?? [])

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-white">🚨 Live Attack Feed</h1>
          <div className="flex items-center gap-3">
            <div className="flex rounded-md border border-border overflow-hidden text-xs">
              <button onClick={() => setMode('poll')} className={`px-3 py-1.5 ${mode === 'poll' ? 'bg-red-900/40 text-red-300' : 'text-muted hover:text-white'}`}>
                Polling (1s)
              </button>
              <button onClick={() => setMode('ws')} className={`px-3 py-1.5 flex items-center gap-1 ${mode === 'ws' ? 'bg-green-900/40 text-green-300' : 'text-muted hover:text-white'}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
                WebSocket
              </button>
            </div>
            {mode === 'poll' && (
              <select
                value={limit}
                onChange={e => setLimit(Number(e.target.value))}
                className="input w-24 text-xs"
              >
                {[10, 20, 30, 50, 100].map(n => <option key={n} value={n}>Last {n}</option>)}
              </select>
            )}
          </div>
        </div>

        {loading && !displayed.length && (
          <div className="text-center text-muted py-12">Loading attacks...</div>
        )}

        {!loading && !displayed.length && (
          <div className="card text-center py-12">
            <div className="text-4xl mb-3">🛡️</div>
            <div className="text-muted">No attacks detected yet.</div>
            <div className="text-xs text-muted mt-1">
              Go to <a href="/launcher" className="text-red-400 hover:underline">Attack Launcher</a> to generate test attacks.
            </div>
          </div>
        )}

        <div className="space-y-2">
          {displayed.map((attack, i) => (
            <AttackCard key={attack.id ?? i} attack={attack} />
          ))}
        </div>
      </div>
    </AppShell>
  )
}
