import { useState, useCallback } from 'react'
import { Gauge, Globe, XCircle, CheckCircle, Download } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { useWebSocket } from '../hooks/useWebSocket'
import { apiFetch } from '../hooks/useAuthFetch'
import { FindingAccordion } from '../components/FindingAccordion'
import { StatCard } from '../components/StatCard'

export function LinkScan() {
  const [url, setUrl] = useState('')
  const [comprehensiveSources, setComprehensiveSources] = useState({ cve: true, dns: true, subdomains: true, tech: true })

  const {
    scanId, setScanId, comprehensiveScanning, setComprehensiveScanning,
    comprehensiveResult, setComprehensiveResult, error, setError, setNoirProgress,
  } = useScanStore()

  useWebSocket(scanId, useCallback((msg: any) => {
    if (msg.type === 'comprehensive_completed' && msg.result) {
      setComprehensiveResult(msg.result); setComprehensiveScanning(false)
    } else if (msg.type === 'comprehensive_failed') {
      setError(msg.error || 'Comprehensive scan failed'); setComprehensiveScanning(false)
    } else if (msg.type === 'comprehensive_progress') {
      setNoirProgress({ percent: 25 * ['tech', 'subdomains', 'cve', 'dns'].indexOf(msg.source) + 25, message: `Scanning ${msg.source}...` })
    } else if (msg.type === 'poll_completed') {
      const d = msg.result
      if (d.sources) { setComprehensiveResult(d); setComprehensiveScanning(false) }
    }
  }, [setComprehensiveResult, setComprehensiveScanning, setError, setNoirProgress]))

  const startScan = useCallback(async () => {
    if (!url.trim()) return
    setComprehensiveScanning(true); setError(''); setComprehensiveResult(null); setNoirProgress(null)
    try {
      const r = await apiFetch('/api/link/scan-comprehensive', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), ...comprehensiveSources }),
      })
      setScanId((await r.json()).scan_id)
    } catch { setError('Failed to start comprehensive scan'); setComprehensiveScanning(false) }
  }, [url, comprehensiveSources, setComprehensiveScanning, setError, setComprehensiveResult, setNoirProgress, setScanId])

  const exportReport = async (format: string) => {
    if (!scanId) return
    const url = `/api/scan/${scanId}/report?format=${format}`
    if (format === 'html') { window.open(url, '_blank'); return }
    try {
      const r = await apiFetch(url)
      if (!r.ok) return
      const text = await r.text()
      const blob = new Blob([text], { type: 'text/plain' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `vulnscout-report-${scanId}.${format === 'json' ? 'json' : 'md'}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    } catch {}
  }

  return (
    <div className="fade-in space-y-6">
      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 card-glow">
        <div className="flex items-center gap-3 mb-4">
          <Gauge size={20} className="text-cyan-400" />
          <h2 className="text-lg font-semibold">Comprehensive Link Scanner</h2>
        </div>
        <p className="text-sm text-[#64748b] mb-4">Multi-source scanning: technology detection, subdomain discovery, CVE lookup, DNS enumeration.</p>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input type="text" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com"
              disabled={comprehensiveScanning}
              className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-3 pl-10 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" />
            <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#475569]" />
          </div>
          <button onClick={startScan} disabled={comprehensiveScanning || !url.trim()}
            className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 disabled:from-cyan-800/50 disabled:to-cyan-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-cyan-500/20 disabled:shadow-none">
            {comprehensiveScanning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Gauge size={16} /> Scan</>}
          </button>
        </div>
        <div className="mt-4 flex flex-wrap gap-3">
          {[{ key: 'tech', label: 'Technology Detection' }, { key: 'subdomains', label: 'Subdomain Discovery' }, { key: 'cve', label: 'CVE Lookup' }, { key: 'dns', label: 'DNS Enumeration' }].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={(comprehensiveSources as any)[key]} onChange={e => setComprehensiveSources(s => ({ ...s, [key]: e.target.checked }))} className="accent-cyan-500" />
              {label}
            </label>
          ))}
        </div>
        {error && <p className="text-red-400 text-sm mt-2 flex items-center gap-1"><XCircle size={14} /> {error}</p>}
      </div>

      {comprehensiveScanning && !comprehensiveResult && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6">
          <div className="text-center">
            <div className="w-10 h-10 border-2 border-[#1e2d45] border-t-cyan-500 rounded-full animate-spin mx-auto mb-4" />
            <p className="text-[#94a3b8]">Running multi-source scan...</p>
          </div>
        </div>
      )}

      {comprehensiveResult && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 fade-in">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Comprehensive Results</h2>
            <div className="flex items-center gap-2">
              {scanId && (
                <button onClick={() => exportReport('html')} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> Report</button>
              )}
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${comprehensiveResult.status === 'completed' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>{comprehensiveResult.status}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
            <StatCard label="Target" value={comprehensiveResult.target} mono small />
            <StatCard label="Sources" value={String((comprehensiveResult.sources || []).length)} />
            <StatCard label="Findings" value={String(comprehensiveResult.total_findings || 0)} color={comprehensiveResult.total_findings > 0 ? '#ef4444' : '#22c55e'} />
          </div>
          {comprehensiveResult.sources && (
            <div className="flex flex-wrap gap-2 mb-4">
              {comprehensiveResult.sources.map(s => <span key={s} className="px-3 py-1 bg-[#0a0e17] border border-[#1e2d45] rounded-lg text-xs text-[#64748b]">{s}</span>)}
            </div>
          )}
          {comprehensiveResult.findings?.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold text-[#94a3b8] uppercase tracking-wider mb-4">Findings ({comprehensiveResult.findings.length})</h3>
              {comprehensiveResult.findings.map((v, i) => <FindingAccordion key={i} v={v} />)}
            </div>
          ) : (
            <div className="text-center py-12">
              <CheckCircle size={48} className="mx-auto text-green-500 mb-4" />
              <p className="text-green-400 text-lg font-semibold">No findings from any source</p>
            </div>
          )}
        </div>
      )}

      {!comprehensiveResult && !comprehensiveScanning && (
        <div className="text-center py-16">
          <Gauge size={56} className="mx-auto text-[#1e2d45] mb-4" />
          <p className="text-[#475569]">Run a comprehensive multi-source scan</p>
        </div>
      )}
    </div>
  )
}
