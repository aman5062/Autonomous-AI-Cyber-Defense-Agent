'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { clsx } from '@/lib/utils'

const NAV = [
  { href: '/',           icon: '🏠', label: 'Overview' },
  { href: '/attacks',    icon: '🚨', label: 'Live Attacks' },
  { href: '/analytics',  icon: '📊', label: 'Analytics' },
  { href: '/blocked',    icon: '🚫', label: 'Blocked IPs' },
  { href: '/controls',   icon: '⚙️',  label: 'Controls' },
  { href: '/whitelist',  icon: '✅', label: 'Whitelist' },
  { href: '/launcher',   icon: '🚀', label: 'Attack Launcher' },
  { href: '/guide',      icon: '📖', label: 'Attack Guide' },
  { href: '/extension',  icon: '🧩', label: 'Browser Extension' },
]

export default function Sidebar({ health }: { health: any }) {
  const path = usePathname()
  const online = !!health
  const autoBlock = health?.defense_mode?.auto_block
  const dryRun = health?.defense_mode?.dry_run

  return (
    <aside className="w-56 shrink-0 bg-surface border-r border-border flex flex-col h-screen sticky top-0">
      {/* Logo */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🛡️</span>
          <div>
            <div className="font-bold text-sm text-white">Cyber Defense</div>
            <div className="text-xs text-muted">AI Agent</div>
          </div>
        </div>
      </div>

      {/* Status */}
      <div className="p-3 border-b border-border">
        <div className="flex items-center gap-2 mb-1">
          <span className={clsx('w-2 h-2 rounded-full', online ? 'bg-green-500 animate-pulse' : 'bg-red-500')} />
          <span className="text-xs text-muted">{online ? 'Backend Online' : 'Backend Offline'}</span>
        </div>
        {online && (
          <div className="flex gap-2 mt-1">
            <span className={clsx('text-xs px-1.5 py-0.5 rounded', autoBlock ? 'bg-green-900/50 text-green-400' : 'bg-gray-800 text-muted')}>
              {autoBlock ? '🔒 Auto-Block' : '⚪ Manual'}
            </span>
            {dryRun && <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-400">Dry-Run</span>}
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 p-2 overflow-y-auto">
        {NAV.map(({ href, icon, label }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              'flex items-center gap-3 px-3 py-2 rounded-md text-sm mb-0.5 transition-colors',
              path === href
                ? 'bg-red-900/30 text-red-300 border border-red-800/50'
                : 'text-muted hover:text-white hover:bg-white/5'
            )}
          >
            <span>{icon}</span>
            <span>{label}</span>
          </Link>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-border text-xs text-muted">
        <div>Updates every 1s</div>
        <div className="mt-1">
          <a href="http://localhost:8000/docs" target="_blank" className="text-blue-400 hover:underline">
            API Docs ↗
          </a>
        </div>
      </div>
    </aside>
  )
}
