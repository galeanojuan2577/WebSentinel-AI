import { useState } from 'react'
import { ChevronDown, ChevronUp, AlertTriangle, Bot, CheckCircle, XCircle, Eye } from 'lucide-react'
import { apiFetch } from '../hooks/useAuthFetch'

interface AIVulnerability {
  id?: string
  name: string; description: string; severity: string; url: string
  evidence: string | null; remediation: string; references: string[]
  ai_analysis?: { impact?: string; exploitability?: string; risk_context?: string; cvss_estimate?: number } | null
  ai_remediation?: string | null
  status?: string
}

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: '#450a0a', text: '#fca5a5', border: '#dc2626', label: 'CRITICAL' },
  high: { bg: '#431407', text: '#fdba74', border: '#ea580c', label: 'HIGH' },
  medium: { bg: '#422006', text: '#fde68a', border: '#ca8a04', label: 'MEDIUM' },
  low: { bg: '#0c1929', text: '#93c5fd', border: '#2563eb', label: 'LOW' },
  info: { bg: '#1c1917', text: '#a1a1aa', border: '#52525b', label: 'INFO' },
}

function getSeverity(sev: string) {
  return SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info
}

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; icon: any }> = {
  open: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.2)', icon: AlertTriangle },
  fixed: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', border: 'rgba(34,197,94,0.2)', icon: CheckCircle },
  false_positive: { color: '#64748b', bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.2)', icon: XCircle },
  acknowledged: { color: '#eab308', bg: 'rgba(234,179,8,0.1)', border: 'rgba(234,179,8,0.2)', icon: Eye },
}

export function FindingAccordion({ v, defaultOpen }: { v: AIVulnerability; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen || false)
  const [status, setStatus] = useState(v.status || 'open')
  const [updating, setUpdating] = useState(false)
  const sev = getSeverity(v.severity)
  const ai = v.ai_analysis
  const st = STATUS_STYLES[status] || STATUS_STYLES.open

  const updateStatus = async (newStatus: string) => {
    if (newStatus === status || updating) return
    setUpdating(true)
    const id = v.id
    if (id) {
      try {
        await apiFetch(`/api/finding/${id}`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        })
        setStatus(newStatus)
      } catch {}
    } else {
      setStatus(newStatus)
    }
    setUpdating(false)
  }

  return (
    <div className="mb-3 rounded-lg overflow-hidden border" style={{ borderColor: `${sev.border}30` }}>
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 bg-[#0a0e17] hover:bg-[#0f1729] transition-colors text-left">
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-8 rounded-full" style={{ background: sev.border }} />
          <span className="font-medium">{v.name}</span>
          {ai && <Bot size={14} className="text-blue-400" />}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ color: st.color, background: st.bg, border: `1px solid ${st.border}` }}>
            <st.icon size={10} />
            {status.replace('_', ' ')}
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
            style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}>
            {sev.label}
          </span>
          {open ? <ChevronUp size={16} className="text-[#475569]" /> : <ChevronDown size={16} className="text-[#475569]" />}
        </div>
      </button>
      {open && (
        <div className="px-5 py-4 border-t border-[#1e2d45] space-y-3 text-sm">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] text-[#64748b]">Status:</span>
            {(['open', 'fixed', 'false_positive', 'acknowledged'] as const).map(s => {
              const sst = STATUS_STYLES[s]
              const isActive = status === s
              return (
                <button key={s} onClick={() => updateStatus(s)} disabled={updating || isActive}
                  className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium transition-all"
                  style={{
                    color: isActive ? sst.color : '#64748b',
                    background: isActive ? sst.bg : 'transparent',
                    border: `1px solid ${isActive ? sst.border : 'transparent'}`,
                  }}>
                  <sst.icon size={10} /> {s.replace('_', ' ')}
                </button>
              )
            })}
          </div>

          <p><span className="text-[#64748b]">URL:</span> <code className="text-[#e2e8f0] bg-[#0a0e17] px-2 py-0.5 rounded text-xs">{v.url}</code></p>
          <p className="text-[#94a3b8]">{v.description}</p>

          {ai && (
            <div className="bg-blue-500/5 border border-blue-500/10 rounded-lg p-4">
              <p className="text-blue-400 text-xs font-semibold mb-2 flex items-center gap-1"><Bot size={12} /> AI Analysis</p>
              <div className="space-y-2 text-xs">
                {ai.exploitability && ai.exploitability !== 'unknown' && (
                  <p><span className="text-[#64748b]">Exploitability:</span>{' '}
                    <span className={`font-medium ${
                      ai.exploitability === 'easy' ? 'text-red-400' :
                      ai.exploitability === 'moderate' ? 'text-amber-400' : 'text-green-400'
                    }`}>{ai.exploitability}</span>
                  </p>
                )}
                {ai.cvss_estimate && ai.cvss_estimate > 0 && (
                  <p><span className="text-[#64748b]">CVSS Estimate:</span> <span className="text-white font-mono">{ai.cvss_estimate.toFixed(1)}</span></p>
                )}
                {ai.impact && <p><span className="text-[#64748b]">Impact:</span> <span className="text-white">{ai.impact}</span></p>}
                {ai.risk_context && <p><span className="text-[#64748b]">Risk Context:</span> <span className="text-white">{ai.risk_context}</span></p>}
              </div>
            </div>
          )}

          {v.remediation && (
            <div className="bg-amber-500/5 border border-amber-500/10 rounded-lg p-4">
              <p className="text-amber-400 text-xs font-semibold mb-1 flex items-center gap-1"><AlertTriangle size={12} /> Remediation</p>
              <pre className="text-xs text-[#94a3b8] whitespace-pre-wrap font-mono">{v.remediation}</pre>
            </div>
          )}

          {v.ai_remediation && (
            <div className="bg-blue-500/5 border border-blue-500/10 rounded-lg p-4">
              <p className="text-blue-400 text-xs font-semibold mb-1 flex items-center gap-1"><Bot size={12} /> AI Remediation</p>
              <pre className="text-xs text-[#94a3b8] whitespace-pre-wrap font-mono">{v.ai_remediation}</pre>
            </div>
          )}

          {v.evidence && (
            <div className="bg-[#0a0e17] border border-[#1e2d45] rounded-lg p-4">
              <p className="text-[#64748b] text-xs font-semibold mb-1">Evidence</p>
              <pre className="text-xs text-[#e2e8f0] whitespace-pre-wrap font-mono">{v.evidence}</pre>
            </div>
          )}
          {v.references?.length > 0 && (
            <div>
              <p className="text-[#64748b] text-xs font-semibold mb-1">References</p>
              <ul className="list-disc list-inside space-y-0.5">
                {v.references.map((ref, j) => (
                  <li key={j}><a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 text-xs">{ref}</a></li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
