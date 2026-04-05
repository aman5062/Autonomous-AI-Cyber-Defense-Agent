'use client'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  LineChart, Line, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'
import { Stats } from '@/lib/api'
import { ATTACK_COLOR } from '@/lib/utils'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e'
}

const TOOLTIP_STYLE = {
  backgroundColor: '#161b22', border: '1px solid #30363d',
  borderRadius: '6px', color: '#e6edf3', fontSize: 12
}

export function AttackTypePie({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).map(([name, value]) => ({ name, value }))
  if (!entries.length) return <Empty text="No attack data" />
  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie data={entries} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={2}>
          {entries.map(e => <Cell key={e.name} fill={ATTACK_COLOR[e.name] || '#6b7280'} />)}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function SeverityBar({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).map(([name, value]) => ({ name, value }))
  if (!entries.length) return <Empty text="No severity data" />
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={entries} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
        <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 11 }} />
        <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {entries.map(e => <Cell key={e.name} fill={SEV_COLORS[e.name] || '#6b7280'} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function AttackTimeline({ data }: { data: { date: string; count: number }[] }) {
  if (!data.length) return <Empty text="No timeline data" />
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
        <XAxis dataKey="date" tick={{ fill: '#8b949e', fontSize: 10 }} />
        <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Line type="monotone" dataKey="count" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444', r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  )
}

function Empty({ text }: { text: string }) {
  return <div className="h-40 flex items-center justify-center text-muted text-sm">{text}</div>
}
