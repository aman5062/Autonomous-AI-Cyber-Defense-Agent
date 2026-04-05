import { clsx } from '@/lib/utils'

interface Props {
  label: string
  value: string | number
  sub?: string
  color?: string
  icon?: string
}

export default function StatCard({ label, value, sub, color, icon }: Props) {
  return (
    <div className="card flex items-center gap-4">
      {icon && <span className="text-3xl">{icon}</span>}
      <div>
        <div className="text-muted text-xs uppercase tracking-wide">{label}</div>
        <div className={clsx('text-2xl font-bold mt-0.5', color || 'text-white')}>{value}</div>
        {sub && <div className="text-xs text-muted mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}
