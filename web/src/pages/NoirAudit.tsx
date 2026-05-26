import { useState, useEffect, useCallback } from 'react'
import { FileSearch, Bug, Folder, Search, Upload, XCircle, CheckCircle, AlertTriangle, Download } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { useWebSocket } from '../hooks/useWebSocket'
import { apiFetch } from '../hooks/useAuthFetch'
import { ProgressBar } from '../components/ProgressBar'

export function NoirAudit() {
  const [noirProjectPath, setNoirProjectPath] = useState('')
  const [noirInstalled, setNoirInstalled] = useState<boolean | null>(null)
  const [projectCandidates, setProjectCandidates] = useState<string[]>([])

  const { scanId, setScanId, noirScanning, setNoirScanning, noirResult, setNoirResult, noirError, setNoirError, noirProgress, setNoirProgress } = useScanStore()

  useEffect(() => {
    apiFetch('/api/noir/check').then(r => r.json()).then(d => setNoirInstalled(d.installed)).catch(() => setNoirInstalled(false))
  }, [])

  useWebSocket(scanId, useCallback((msg: any) => {
    if (msg.type === 'noir_audit_completed' && msg.result) { setNoirResult(msg.result); setNoirScanning(false); setNoirProgress(null) }
    else if (msg.type === 'noir_audit_failed') { setNoirError(msg.error || 'Noir audit failed'); setNoirScanning(false); setNoirProgress(null) }
    else if (msg.type === 'noir_progress') { setNoirProgress({ percent: msg.percent, message: msg.message }) }
    else if (msg.type === 'poll_completed') {
      const d = msg.result
      if (d.project_path) { setNoirResult(d); setNoirScanning(false); setNoirProgress(null) }
    }
  }, [setNoirResult, setNoirScanning, setNoirError, setNoirProgress]))

  const findProjects = async () => {
    try {
      const resp = await apiFetch('/api/projects/find')
      if (resp.ok) { const d = await resp.json(); setProjectCandidates(d.projects || []); if (d.projects?.length > 0 && !noirProjectPath) setNoirProjectPath(d.projects[0]) }
    } catch {}
  }

  const startNoirScan = useCallback(async () => {
    if (!noirProjectPath.trim()) return
    setNoirScanning(true); setNoirError(''); setNoirResult(null); setNoirProgress(null)
    try {
      const r = await apiFetch('/api/noir/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ project_path: noirProjectPath.trim(), output_format: 'json' }) })
      setScanId((await r.json()).scan_id)
    } catch { setNoirError('Failed to start Noir audit'); setNoirScanning(false) }
  }, [noirProjectPath, setNoirScanning, setNoirError, setNoirResult, setNoirProgress, setScanId])

  const uploadProject = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setNoirScanning(true); setNoirError(''); setNoirResult(null); setNoirProgress(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const r = await apiFetch('/api/noir/upload', { method: 'POST', body: formData })
      const data = await r.json()
      setScanId(data.scan_id)
    } catch { setNoirError('Upload failed'); setNoirScanning(false) }
  }

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
          <FileSearch size={20} className="text-emerald-400" />
          <h2 className="text-lg font-semibold">OWASP Noir Audit</h2>
        </div>
        {noirInstalled === false && (
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 mb-4">
            <p className="text-amber-400 text-sm flex items-center gap-2"><AlertTriangle size={16} /> OWASP Noir is not installed. Install it: <code className="ml-1 px-2 py-0.5 bg-[#0a0e17] rounded text-xs">snap install noir</code></p>
          </div>
        )}
        {noirInstalled === true && (
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-4">
            <p className="text-green-400 text-sm flex items-center gap-2"><CheckCircle size={16} /> OWASP Noir is installed and ready.</p>
          </div>
        )}

        <div className="flex gap-3 mb-4">
          <div className="relative flex-1">
            <input type="text" value={noirProjectPath} onChange={e => setNoirProjectPath(e.target.value)} placeholder="/path/to/project" disabled={noirScanning}
              className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-3 pl-10 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all" />
            <Folder size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#475569]" />
          </div>
          <button onClick={findProjects} className="flex items-center gap-2 px-4 py-3 bg-[#1e2d45] hover:bg-[#2a3a55] rounded-lg text-sm font-medium transition-all" title="Find projects"><Search size={16} /></button>
          <button onClick={startNoirScan} disabled={noirScanning || !noirProjectPath.trim() || noirInstalled === false}
            className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 disabled:from-emerald-800/50 disabled:to-emerald-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-emerald-500/20 disabled:shadow-none">
            {noirScanning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Auditing...</> : <><Bug size={16} /> Run Audit</>}
          </button>
        </div>

        <div className="flex items-center gap-3 mb-4">
          <label className="flex items-center gap-2 px-4 py-3 bg-[#1e2d45] hover:bg-[#2a3a55] rounded-lg text-sm font-medium cursor-pointer transition-all">
            <Upload size={16} />
            <span>Upload Project</span>
            <input type="file" accept=".zip,.7z,.tar.gz,.tar.bz2" onChange={uploadProject} className="hidden" disabled={noirScanning} />
          </label>
          <span className="text-xs text-[#64748b]">Upload a .zip, .7z, or .tar.gz with source code</span>
        </div>

        {projectCandidates.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-[#64748b] mb-2">Detected projects:</p>
            <div className="flex flex-wrap gap-2">
              {projectCandidates.map(p => (
                <button key={p} onClick={() => setNoirProjectPath(p)}
                  className={`px-3 py-1.5 rounded-lg text-xs border transition-all ${noirProjectPath === p ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-[#0a0e17] border-[#1e2d45] text-[#64748b] hover:border-emerald-500/30'}`}>
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
        {noirError && <p className="text-red-400 text-sm flex items-center gap-1"><XCircle size={14} /> {noirError}</p>}

        {noirScanning && !noirResult && (
          <div className="mt-4 p-4 bg-[#0a0e17] rounded-lg border border-[#1e2d45]">
            {noirProgress ? (
              <ProgressBar percent={noirProgress.percent} label={noirProgress.message} />
            ) : (
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-[#1e2d45] border-t-emerald-500 rounded-full animate-spin mx-auto mb-2" />
                <p className="text-sm text-[#94a3b8]">Starting Noir audit...</p>
              </div>
            )}
          </div>
        )}
      </div>

      {noirResult && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 fade-in">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Audit Results</h2>
            <div className="flex items-center gap-2">
              {scanId && (
                <button onClick={() => exportReport('html')} className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> Report</button>
              )}
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${noirResult.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>{noirResult.status}</span>
            </div>
          </div>
          {noirResult.findings?.length > 0 ? (
            <div className="space-y-3">
              {noirResult.findings.map((f, i) => (
                <div key={i} className="bg-[#0a0e17] border border-[#1e2d45] rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <FileSearch size={14} className="text-emerald-400" />
                    <span className="font-medium text-sm">{f.name}</span>
                    <span className="ml-auto px-2 py-0.5 rounded-full text-[10px] font-bold uppercase" style={{ background: '#1c1917', color: '#a1a1aa', border: '1px solid #52525b' }}>{f.severity}</span>
                  </div>
                  <p className="text-xs text-[#94a3b8]">{f.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <CheckCircle size={36} className="mx-auto text-emerald-500 mb-3" />
              <p className="text-[#94a3b8]">No issues detected in audit.</p>
            </div>
          )}
          {noirResult.raw_output && (
            <details className="mt-4">
              <summary className="text-sm text-[#64748b] cursor-pointer hover:text-[#94a3b8]">Raw Output</summary>
              <pre className="mt-2 p-4 bg-[#0a0e17] rounded-lg text-xs text-[#64748b] overflow-x-auto font-mono max-h-60 overflow-y-auto">{JSON.stringify(noirResult.raw_output, null, 2)}</pre>
            </details>
          )}
        </div>
      )}

      {!noirResult && !noirScanning && (
        <div className="text-center py-16">
          <FileSearch size={56} className="mx-auto text-[#1e2d45] mb-4" />
          <p className="text-[#475569]">Enter a project path or upload an archive to start an audit</p>
        </div>
      )}
    </div>
  )
}
