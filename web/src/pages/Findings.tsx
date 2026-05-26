import { useState, useEffect } from 'react'
import { Search, Filter, AlertTriangle } from 'lucide-react'
import { apiFetch } from '../hooks/useAuthFetch'

const STATUS_STYLES: Record<string, { color: string; bg: string }> = {
  open: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)' },
  fixed: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)' },
  false_positive: { color: '#64748b', bg: 'rgba(100,116,139,0.1)' },
  acknowledged: { color: '#eab308', bg: 'rgba(234,179,8,0.1)' },
}

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#52525b',
}

export function Findings() {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [stats, setStats] = useState<any>(null)

  const fetchFindings = () => {
    setLoading(true)
    const params = new URLSearchParams()
    if (statusFilter) params.set('status', statusFilter)
    if (severityFilter) params.set('severity', severityFilter)
    apiFetch(`/api/findings?${params}`).then(r => r.json()).then(d => {
      setFindings(d.findings || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(() => { fetchFindings() }, [statusFilter, severityFilter])
  useEffect(() => {
    apiFetch('/api/stats').then(r => r.json()).then(setStats).catch(() => {})
  }, [findings.length])

  const updateStatus = async (id: string, newStatus: string) => {
    await apiFetch(`/api/finding/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    })
    fetchFindings()
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#dc2626] to-[#ef4444] flex items-center justify-center shadow-lg shadow-red-500/20">
          <AlertTriangle size={20} className="text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">All Findings</h1>
          <p className="text-sm text-[#64748b]">Browse, filter, and manage security findings</p>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
            <div key={sev} className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-3 text-center">
              <p className="text-lg font-bold" style={{ color: SEV_COLORS[sev] }}>{stats.severity_counts?.[sev] || 0}</p>
              <p className="text-[10px] text-[#64748b] uppercase">{sev}</p>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <Filter size={14} className="text-[#64748b]" />
        {['', 'open', 'fixed', 'false_positive', 'acknowledged'].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              statusFilter === s
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                : 'bg-[#1e2d45] text-[#64748b] border border-[#2d3a56] hover:border-[#3b4a6b]'
            }`}>
            {s || 'All'}
          </button>
        ))}
        <div className="w-px h-5 bg-[#1e2d45]" />
        {['', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
          <button key={s} onClick={() => setSeverityFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              severityFilter === s
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                : 'bg-[#1e2d45] text-[#64748b] border border-[#2d3a56] hover:border-[#3b4a6b]'
            }`}>
            {s || 'All Severity'}
          </button>
        ))}
      </div>

      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] overflow-hidden">
        {loading ? (
          <div className="text-center py-12 text-[#475569] text-sm">Loading...</div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12 text-[#475569]">
            <Search size={32} className="mx-auto mb-3 opacity-50" />
            <p className="text-sm">No findings match your filters</p>
          </div>
        ) : (
          <div className="divide-y divide-[#1e2d45]">
            {findings.map((f, i) => {
              const st = STATUS_STYLES[f.status] || STATUS_STYLES.open
              return (
                <div key={f.id || i} className="p-4 hover:bg-[#0a0e17]/50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-1 h-full min-h-[40px] rounded-full mt-1" style={{ background: SEV_COLORS[f.severity] || '#52525b' }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-medium text-white truncate">{f.name}</h3>
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-medium uppercase"
                          style={{ background: `${SEV_COLORS[f.severity]}20`, color: SEV_COLORS[f.severity] }}>
                          {f.severity}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1"
                          style={{ color: st.color, background: st.bg }}>
                          {f.status}
                        </span>
                      </div>
                      <p className="text-xs text-[#64748b] mt-1 truncate">{f.description}</p>
                      <div className="flex items-center gap-1.5 mt-2">
                        {f.url && <code className="text-[10px] text-[#475569] bg-[#0a0e17] px-1.5 py-0.5 rounded">{f.url}</code>}
                        {f.source && <span className="text-[10px] text-[#475569]">/{f.source}</span>}
                        <div className="ml-auto flex items-center gap-1">
                          {(['open', 'fixed', 'false_positive', 'acknowledged'] as const).map(s => {
                            if (s === f.status) return null
                            return (
                              <button key={s} onClick={() => updateStatus(f.id, s)}
                                className="text-[10px] px-1.5 py-0.5 rounded opacity-60 hover:opacity-100 transition-opacity text-[#64748b] hover:text-white">
                                {s.replace('_', ' ')}
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}