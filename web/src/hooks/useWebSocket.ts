import { useEffect, useRef } from 'react'

interface WSMessage {
  type: string
  scan_id?: string
  result?: any
  error?: string
  percent?: number
  message?: string
  source?: string
}

type Handler = (msg: WSMessage) => void

export function useWebSocket(scanId: string | null, handler: Handler) {
  const wsRef = useRef<WebSocket | null>(null)
  const handlerRef = useRef<Handler>(handler)
  handlerRef.current = handler

  useEffect(() => {
    if (!scanId) return

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/ws`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.scan_id && msg.scan_id !== scanId) return
        handlerRef.current(msg)
      } catch {}
    }

    ws.onerror = () => {
      let cancelled = false
      let i = 0
      const poll = async () => {
        while (i < 60 && !cancelled) {
          await new Promise(r => setTimeout(r, 2000))
          i++
          try {
            const resp = await fetch(`/api/scan/${scanId}`)
            if (resp.ok) {
              const data = await resp.json()
              if (data.status !== 'running') {
                handlerRef.current({ type: 'poll_completed', result: data })
                cancelled = true
                return
              }
            }
          } catch {}
        }
      }
      poll()
    }

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [scanId])
}
