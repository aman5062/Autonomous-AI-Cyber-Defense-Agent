'use client'
import Sidebar from './Sidebar'
import { useHealth } from '@/hooks/useLiveData'

export default function AppShell({ children }: { children: React.ReactNode }) {
  const { data: health } = useHealth()
  return (
    <div className="flex min-h-screen">
      <Sidebar health={health} />
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  )
}
