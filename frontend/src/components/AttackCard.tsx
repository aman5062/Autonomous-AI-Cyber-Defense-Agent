'use client'
import { useState } from 'react'
import { Attack } from '@/lib/api'
import { SEV_BG, ATTACK_ICON, fmtDate, clsx } from '@/lib/utils'

export default function AttackCard({ attack }: { attack: Attack }) {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'request' | 'ai' | 'raw'>('request')

  const sev = attack.severity || 'LOW'
  const icon = ATTACK_ICON[attack.attack_type] || '⚠️'

  return (
    <div className={clsx('border rounded-lg overflow-hidden transition-all', SEV_BG[sev])}>
      {/* Header row */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
      >
        <span className="text-lg">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm">{attack.attack_type?.replace(/_/g, ' ')}</span>
            <span className={clsx('text-xs px-1.5 py-0.5 rounded font-bold', SEV_BG[sev])}>{sev}</span>
            {attack.blocked && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/60 text-red-300 border border-red-700/50">🔒 BLOCKED</span>
            )}
          </div>
          <div className="text-xs text-muted mt-0.5 truncate">
            IP: <span className="font-mono text-white">{attack.ip}</span>
            {' · '}{fmtDate(attack.timestamp)}
          </div>
        </div>
        <span className="text-muted text-xs">{open ? '▲' : '▼'}</span>
      </button>

      {/* Expanded */}
      {open && (
        <div className="border-t border-white/10">
          {/* Tabs */}
          <div className="flex border-b border-white/10">
            {(['request', 'ai', 'raw'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={clsx(
                  'px-4 py-2 text-xs font-medium capitalize transition-colors',
                  tab === t ? 'text-white border-b-2 border-red-500' : 'text-muted hover:text-white'
                )}
              >
                {t === 'ai' ? 'AI Analysis' : t === 'raw' ? 'Raw JSON' : 'Request'}
              </button>
            ))}
          </div>

          <div className="p-4">
            {tab === 'request' && (
              <div className="space-y-2 text-sm">
                <div className="grid grid-cols-2 gap-2">
                  <div><span className="text-muted">Method:</span> <span className="font-mono">{attack.method}</span></div>
                  <div><span className="text-muted">Status:</span> <span className="font-mono">{attack.status}</span></div>
                  <div><span className="text-muted">IP:</span> <span className="font-mono">{attack.ip}</span></div>
                  <div><span className="text-muted">Blocked:</span> {attack.blocked ? '✅ Yes' : '❌ No'}</div>
                </div>
                <div>
                  <div className="text-muted text-xs mb-1">Path:</div>
                  <code className="block bg-bg rounded p-2 text-xs text-green-300 break-all">{attack.path}</code>
                </div>
                {attack.user_agent && (
                  <div className="text-xs text-muted">UA: {attack.user_agent}</div>
                )}
              </div>
            )}

            {tab === 'ai' && (
              <div className="space-y-3 text-sm">
                {attack.explanation ? (
                  <>
                    <div>
                      <div className="text-muted text-xs mb-1">Explanation</div>
                      <div className="bg-blue-900/20 border border-blue-800/40 rounded p-3 text-blue-200 text-xs">{attack.explanation}</div>
                    </div>
                    {attack.impact && (
                      <div>
                        <div className="text-muted text-xs mb-1">Impact</div>
                        <div className="bg-orange-900/20 border border-orange-800/40 rounded p-3 text-orange-200 text-xs">{attack.impact}</div>
                      </div>
                    )}
                    {attack.mitigation && (
                      <div>
                        <div className="text-muted text-xs mb-1">Mitigation</div>
                        <ul className="space-y-1">
                          {(Array.isArray(attack.mitigation) ? attack.mitigation : [attack.mitigation]).map((m, i) => (
                            <li key={i} className="text-xs text-green-300 flex gap-2"><span>•</span><span>{m}</span></li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {attack.code_fix && (
                      <div className="grid grid-cols-2 gap-2">
                        {attack.code_fix.vulnerable && (
                          <div>
                            <div className="text-xs text-red-400 mb-1">❌ Vulnerable</div>
                            <code className="block bg-bg rounded p-2 text-xs text-red-300 break-all">{attack.code_fix.vulnerable}</code>
                          </div>
                        )}
                        {attack.code_fix.secure && (
                          <div>
                            <div className="text-xs text-green-400 mb-1">✅ Secure</div>
                            <code className="block bg-bg rounded p-2 text-xs text-green-300 break-all">{attack.code_fix.secure}</code>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-muted text-xs">AI analysis pending — Ollama may still be loading.</div>
                )}
              </div>
            )}

            {tab === 'raw' && (
              <pre className="text-xs text-green-300 bg-bg rounded p-3 overflow-auto max-h-64">
                {JSON.stringify(attack, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
