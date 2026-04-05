'use client'
import { useEffect, useRef, useState, useCallback } from 'react'
import { api, Attack, Health, Stats, BlockedIP, SystemMetrics, WS_URL } from '@/lib/api'

// Generic polling hook
export function usePoll<T>(
  fetcher: () => Promise<T | null>,
  interval = 1000,
  deps: unknown[] = []
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const timerRef = useRef<NodeJS.Timeout>()

  const fetch = useCallback(async () => {
    const result = await fetcher()
    if (result !== null) setData(result)
    setLoading(false)
  }, deps) // eslint-disable-line

  useEffect(() => {
    fetch()
    timerRef.current = setInterval(fetch, interval)
    return () => clearInterval(timerRef.current)
  }, [fetch, interval])

  return { data, loading, refetch: fetch }
}

// Health — every 2s, only goes offline after 3 consecutive failures
export function useHealth() {
  const [data, setData] = useState<Health | null>(null)
  const [loading, setLoading] = useState(true)
  const failCount = useRef(0)
  const timerRef = useRef<NodeJS.Timeout>()

  const fetch = useCallback(async () => {
    const result = await api.health()
    if (result !== null) {
      failCount.current = 0
      setData(result)
    } else {
      failCount.current++
      // Only mark offline after 3 consecutive failures (6 seconds)
      if (failCount.current >= 3) setData(null)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetch()
    timerRef.current = setInterval(fetch, 2000)
    return () => clearInterval(timerRef.current)
  }, [fetch])

  return { data, loading, refetch: fetch }
}

// Stats — every 3s
export function useStats(days = 7) {
  return usePoll<Stats>(() => api.stats(days), 3000, [days])
}

// Recent attacks — every 1s
export function useAttacks(limit = 30) {
  return usePoll(
    () => api.attacks(limit).then(d => d?.attacks ?? null),
    1000,
    [limit]
  )
}

// Blocked IPs — every 2s
export function useBlockedIps() {
  return usePoll(
    () => api.blockedIps().then(d => d ?? null),
    2000
  )
}

// System metrics — every 3s
export function useMetrics() {
  return usePoll<SystemMetrics>(() => api.metrics(), 3000)
}

// WebSocket live attack feed
export function useWebSocket() {
  const [liveAttacks, setLiveAttacks] = useState<Attack[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket>()

  useEffect(() => {
    function connect() {
      try {
        const ws = new WebSocket(WS_URL)
        wsRef.current = ws

        ws.onopen = () => setConnected(true)
        ws.onclose = () => {
          setConnected(false)
          setTimeout(connect, 3000) // reconnect
        }
        ws.onerror = () => ws.close()
        ws.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data)
            if (msg.type === 'new_attack' && msg.data) {
              setLiveAttacks(prev => [msg.data, ...prev].slice(0, 50))
            }
          } catch {}
        }
      } catch {}
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  return { liveAttacks, connected }
}
