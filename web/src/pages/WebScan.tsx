import { useState, useEffect } from 'react'
import { Globe, Play, XCircle, CheckCircle, Shield, Download, Sliders, Bot } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { useWebSocket } from '../hooks/useWebSocket'
import { apiFetch } from '../hooks/useAuthFetch'
import { FindingAccordion } from '../components/FindingAccordion'
import { StatCard } from '../components/StatCard'

interface Check { name: string; description: string }

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: '#450a0a', text: '#fca5a5', border: '#dc2626', label: 'CRITICAL' },
  high: { bg: '#431407', text: '#fdba74', border: '#ea580c', label: 'HIGH' },
  medium: { bg: '#422006', text: '#fde68a', border: '#ca8a04', label: 'MEDIUM' },
  low: { bg: '#0c1929', text: '#93c5fd', border: '#2563eb', label: 'LOW' },
  info: { bg: '#1c1917', text: '#a1a1aa', border: '#52525b', label: 'INFO' },
}

function getSeverity(sev: string) { return SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info }

export function WebScan() {
  const [url, setUrl] = useState('')
  const [checks, setChecks] = useState<Check[]>([])
  const [selectedChecks, setSelectedChecks] = useState<Set<string>>(new Set(['all']))
  const [maxPages, setMaxPages] = useState(10)
  const [showOptions, setShowOptions] = useState(false)
  const [enriching, setEnriching] = useState(false)
  const [aiSummary, setAiSummary] = useState<string | null>(null)
  const [aiPaths, setAiPaths] = useState<any[]>([])
  const [showPaths, setShowPaths] = useState(false)
  const { scanId, setScanId, scanning, setScanning, result, setResult, error, setError } = useScanStore()
  const isScanning = scanning

  useEffect(() => {
    apiFetch('/api/checks').then(r => r.json()).then(d => setChecks(d.checks || [])).catch(() => {})
  }, [])

  useWebSocket(scanId, (msg) => {
    if (msg.type === 'scan_completed' && msg.result) {
      setResult(msg.result); setScanning(false)
    } else if (msg.type === 'scan_failed') {
      setError(msg.error || 'Scan failed'); setScanning(false)
    } else if (msg.type === 'poll_completed') {
      const d = msg.result
      if (d.target?.url && !d.project_path && !d.sources) {
        setResult(d); setScanning(false)
      }
    }
  })

  const startScan = async () => {
    if (!url.trim()) return
    setScanning(true); setError(''); setResult(null)
    try {
      const body = { url: url.trim(), checks: selectedChecks.has('all') ? ['all'] : Array.from(selectedChecks), max_pages: maxPages }
      const r = await apiFetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      const data = await r.json()
      setScanId(data.scan_id)
    } catch { setError('Failed to start scan'); setScanning(false) }
  }

  const enrichWithAI = async () => {
    if (!scanId) return
    setEnriching(true)
    try {
      const r = await apiFetch(`/api/ai/enrich/${scanId}`, { method: 'POST' })
      if (r.ok) {
        const scanR = await apiFetch(`/api/scan/${scanId}`)
        if (scanR.ok) {
          const updated = await scanR.json()
          setResult(updated)
          setAiSummary(updated.ai_summary || null)
        }
      }
    } catch {} finally { setEnriching(false) }
  }

  const loadAttackPaths = async () => {
    if (!scanId) return
    try {
      const r = await apiFetch(`/api/ai/attack-paths/${scanId}`)
      if (r.ok) {
        const data = await r.json()
        setAiPaths(data.attack_paths || [])
      }
    } catch {}
  }

  const exportReport = async (format: string) => {
    if (!scanId) return
    const u = `/api/scan/${scanId}/report?format=${format}`
    if (format === 'html') { window.open(u, '_blank'); return }
    try {
      const r = await apiFetch(u)
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

  const toggleCheck = (name: string) => {
    const next = new Set(selectedChecks)
    if (name === 'all') { setSelectedChecks(new Set(['all'])); return }
    next.delete('all')
    if (next.has(name)) next.delete(name); else next.add(name)
    if (next.size === 0) next.add('all')
    setSelectedChecks(next)
  }

  const totalVulns = (result?.vulnerabilities?.length || 0)

  return (
    <div className="fade-in space-y-6">
      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 card-glow">
        <div className="flex items-center gap-3 mb-4">
          <Globe size={20} className="text-blue-400" />
          <h2 className="text-lg font-semibold">Web Vulnerability Scanner</h2>
        </div>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input type="text" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com"
              disabled={isScanning}
              className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-3 pl-10 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all"
              onKeyDown={e => e.key === 'Enter' && startScan()} />
            <Globe size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#475569]" />
          </div>
          <button onClick={startScan} disabled={isScanning || !url.trim()}
            className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 disabled:from-blue-800/50 disabled:to-blue-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/20 disabled:shadow-none">
            {isScanning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Play size={16} /> Start Scan</>}
          </button>
        </div>
        <div className="mt-4">
          <button onClick={() => setShowOptions(!showOptions)} className="flex items-center gap-2 text-xs text-[#64748b] hover:text-[#94a3b8] transition-colors">
            <Sliders size={14} /> {showOptions ? 'Hide' : 'Show'} Scan Options
          </button>
          {showOptions && (
            <div className="mt-3 p-4 bg-[#0a0e17] rounded-lg border border-[#1e2d45] space-y-4 fade-in">
              <div>
                <p className="text-xs text-[#64748b] mb-2">Checks to run:</p>
                <div className="flex flex-wrap gap-2">
                  <button onClick={() => setSelectedChecks(new Set(['all']))}
                    className={`px-3 py-1.5 rounded-lg text-xs border transition-all ${selectedChecks.has('all') ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-[#0a0e17] border-[#1e2d45] text-[#64748b] hover:border-blue-500/30'}`}>All</button>
                  {checks.map(c => (
                    <button key={c.name} onClick={() => toggleCheck(c.name)}
                      className={`px-3 py-1.5 rounded-lg text-xs border transition-all ${selectedChecks.has(c.name) ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-[#0a0e17] border-[#1e2d45] text-[#64748b] hover:border-blue-500/30'}`}>{c.name}</button>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div>
                  <p className="text-xs text-[#64748b] mb-1">Max pages:</p>
                  <input type="number" value={maxPages} onChange={e => setMaxPages(Math.max(1, Math.min(100, Number(e.target.value))))}
                    className="w-20 bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-3 py-1.5 text-xs text-white" />
                </div>
              </div>
            </div>
          )}
        </div>
        {error && <p className="text-red-400 text-sm mt-2 flex items-center gap-1"><XCircle size={14} /> {error}</p>}
      </div>

      {scanning && !result && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6">
          <div className="text-center">
            <div className="w-10 h-10 border-2 border-[#1e2d45] border-t-blue-500 rounded-full animate-spin mx-auto mb-4" />
            <p className="text-[#94a3b8]">Scanning {url}...</p>
          </div>
        </div>
      )}

      {result && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 fade-in">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold">Scan Results</h2>
            <div className="flex items-center gap-2">
              {result.vulnerabilities?.length > 0 && scanId && (
                <button onClick={enrichWithAI} disabled={enriching}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 disabled:from-blue-800/50 disabled:to-blue-700/50 transition-all">
                  {enriching ? 'Enriching...' : 'AI Analyze'}
                </button>
              )}
              {result.vulnerabilities?.length > 0 && scanId && (
                <button onClick={async () => {
                  const r = await apiFetch(`/api/ai/remediation-plan/${scanId}`, { method: 'POST' })
                  const data = await r.json()
                  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
                  const a = document.createElement('a')
                  a.href = URL.createObjectURL(blob); a.download = `remediation-plan-${scanId}.json`; a.click()
                }} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors">
                  <Bot size={12} /> Remediation Plan
                </button>
              )}
              {scanId && (
                <div className="flex gap-1">
                  <button onClick={() => exportReport('html')} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> HTML</button>
                  <button onClick={() => exportReport('json')} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> JSON</button>
                  <button onClick={() => exportReport('markdown')} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> MD</button>
                </div>
              )}
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${result.status === 'completed' ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>{result.status}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard label="Target" value={result.target.url} mono small />
            <StatCard label="Duration" value={`${result.duration_seconds?.toFixed(1) || '?'}s`} />
            <StatCard label="URLs" value={String(result.total_urls_scanned)} />
            <StatCard label="Findings" value={String(totalVulns)} color={totalVulns > 0 ? '#ef4444' : '#22c55e'} />
          </div>
          {result.summary && totalVulns > 0 && (
            <div className="flex flex-wrap gap-2 mb-6">
              {SEVERITY_ORDER.map(sev => {
                const count = result.summary![sev]
                if (!count) return null
                const cfg = getSeverity(sev)
                return <span key={sev} className="px-4 py-1.5 rounded-full text-xs font-bold border" style={{ background: cfg.bg, color: cfg.text, borderColor: cfg.border }}>{cfg.label} {count}</span>
              })}
            </div>
          )}
          {result.vulnerabilities?.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold text-[#94a3b8] uppercase tracking-wider mb-4">Findings</h3>
              {result.vulnerabilities.map((v, i) => <FindingAccordion key={i} v={v} />)}
            </div>
          ) : (
            <div className="text-center py-12">
              <CheckCircle size={48} className="mx-auto text-green-500 mb-4" />
              <p className="text-green-400 text-lg font-semibold">No vulnerabilities found</p>
              <p className="text-[#64748b] text-sm mt-1">The target appears to be well-secured.</p>
            </div>
          )}

          {aiSummary && (
            <div className="mt-6 p-4 bg-blue-500/5 border border-blue-500/10 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Bot size={16} className="text-blue-400" />
                <p className="text-sm font-semibold text-blue-400">AI Executive Summary</p>
              </div>
              <p className="text-sm text-[#94a3b8] whitespace-pre-wrap">{aiSummary}</p>
            </div>
          )}

          {aiPaths.length > 0 && (
            <div className="mt-6">
              <button onClick={() => { loadAttackPaths(); setShowPaths(!showPaths) }}
                className="flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                <Shield size={16} /> {showPaths ? 'Hide' : 'Show'} Attack Paths ({aiPaths.length})
              </button>
              {showPaths && (
                <div className="mt-3 space-y-3 fade-in">
                  {aiPaths.map((path, i) => (
                    <div key={i} className="bg-[#0a0e17] border border-[#1e2d45] rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          path.probability === 'high' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                          path.probability === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}>{path.probability} probability</span>
                      </div>
                      <div className="space-y-2 text-xs">
                        <p><span className="text-[#64748b]">Entry:</span> <span className="text-white">{path.entry_point}</span></p>
                        <p><span className="text-[#64748b]">Exploitation:</span> <span className="text-white">{path.exploitation}</span></p>
                        {path.pivot && <p><span className="text-[#64748b]">Pivot:</span> <span className="text-white">{path.pivot}</span></p>}
                        <p><span className="text-[#64748b]">Impact:</span> <span className="text-white">{path.impact}</span></p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {!result && !scanning && (
        <div className="text-center py-16">
          <Shield size={56} className="mx-auto text-[#1e2d45] mb-4" />
          <p className="text-[#475569]">Enter a target URL and start a scan</p>
        </div>
      )}
    </div>
  )
}
