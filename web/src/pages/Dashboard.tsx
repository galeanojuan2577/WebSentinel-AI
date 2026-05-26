import { useState, useEffect } from 'react'
import { Globe, Gauge, Wifi, FileSearch, Activity } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { useNavigate } from 'react-router-dom'
import { DashboardCard } from '../components/DashboardCard'
import { apiFetch } from '../hooks/useAuthFetch'

export function DashboardHome() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<any>(null)
  const { result, comprehensiveResult, networkResult, noirResult } = useScanStore()

  useEffect(() => {
    apiFetch('/api/stats').then(r => r.json()).then(setStats).catch(() => {})
  }, [])

  const severityColors: Record<string, string> = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#52525b',
  }

  return (
    <div className="fade-in space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <DashboardCard icon={Globe} label="Web Scans" value="Ready" color="blue" onClick={() => navigate('/web')} />
        <DashboardCard icon={Gauge} label="Link Scanner" value="Multi-source" color="cyan" onClick={() => navigate('/link')} />
        <DashboardCard icon={Wifi} label="Network Scans" value="Ready" color="purple" onClick={() => navigate('/network')} />
        <DashboardCard icon={FileSearch} label="Noir Audits" value="Available" color="emerald" onClick={() => navigate('/noir')} />
      </div>

      {stats && (stats.total_findings > 0 || stats.total_scans > 0) && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-4 text-center">
              <p className="text-2xl font-bold text-white">{stats.total_scans}</p>
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider">Total Scans</p>
            </div>
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-4 text-center">
              <p className="text-2xl font-bold text-white">{stats.total_findings}</p>
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider">Total Findings</p>
            </div>
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{stats.status_counts?.fixed || 0}</p>
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider">Fixed</p>
            </div>
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-4 text-center">
              <p className="text-2xl font-bold text-yellow-400">{stats.status_counts?.acknowledged || 0}</p>
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider">Acknowledged</p>
            </div>
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-4 text-center">
              <p className="text-2xl font-bold text-red-400">{stats.status_counts?.open || 0}</p>
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider">Open</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Severity Distribution</h3>
              <div className="space-y-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                  const cnt = stats.severity_counts?.[sev] || 0
                  const maxCount = Math.max(...Object.values(stats.severity_counts || {}).map(Number), 1)
                  return cnt > 0 ? (
                    <div key={sev} className="flex items-center gap-3">
                      <span className="text-[11px] text-[#64748b] w-16 uppercase">{sev}</span>
                      <div className="flex-1 h-5 bg-[#0a0e17] rounded overflow-hidden">
                        <div style={{ width: `${(cnt / maxCount) * 100}%`, background: severityColors[sev], height: '100%', borderRadius: '4px', transition: 'width 0.5s' }} />
                      </div>
                      <span className="text-xs text-[#e2e8f0] w-8 text-right">{cnt}</span>
                    </div>
                  ) : null
                })}
              </div>
            </div>
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Resolution Status</h3>
              {stats.status_counts && (() => {
                const vals: number[] = Object.values(stats.status_counts).map(Number)
                const total = vals.reduce((a, b) => a + b, 0)
                const segments = (['open', 'fixed', 'acknowledged', 'false_positive'] as const)
                  .filter(s => (stats.status_counts[s] || 0) > 0)
                  .map((s, i, arr) => {
                    const pct = ((stats.status_counts[s] || 0) / total) * 100
                    const colors: Record<string, string> = { open: '#ef4444', fixed: '#22c55e', acknowledged: '#eab308', false_positive: '#64748b' }
                    return `<div style="width:${pct}%;background:${colors[s]};height:100%;${i === 0 ? 'border-radius:6px 0 0 6px' : ''}${i === arr.length - 1 ? 'border-radius:0 6px 6px 0' : ''}"></div>`
                  }).join('')
                return (
                  <>
                    <div className="h-3 bg-[#0a0e17] rounded-full overflow-hidden mb-3" dangerouslySetInnerHTML={{ __html: `<div style="display:flex;height:100%">${segments}</div>` }} />
                    <div className="space-y-1.5">
                      {(['open', 'fixed', 'acknowledged', 'false_positive'] as const).map(s => {
                        const cnt = stats.status_counts[s] || 0
                        if (!cnt) return null
                        const colors: Record<string, string> = { open: '#ef4444', fixed: '#22c55e', acknowledged: '#eab308', false_positive: '#64748b' }
                        return (
                          <div key={s} className="flex items-center gap-2 text-xs">
                            <div className="w-2.5 h-2.5 rounded-full" style={{ background: colors[s] }} />
                            <span className="text-[#64748b] capitalize">{s.replace('_', ' ')}</span>
                            <span className="text-[#e2e8f0] ml-auto">{cnt}</span>
                          </div>
                        )
                      })}
                    </div>
                  </>
                )
              })()}
            </div>
          </div>
        </>
      )}

      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6">
        <h2 className="text-lg font-semibold mb-4">Recent Activity</h2>
        <div className="space-y-3">
          {result && (
            <div className="flex items-center gap-3 p-3 bg-[#0a0e17] rounded-lg border border-[#1e2d45]">
              <Globe size={16} className="text-blue-400" />
              <div className="flex-1"><p className="text-sm font-medium">{result.target.url}</p><p className="text-xs text-[#64748b]">{result.status} | {result.vulnerabilities.length} findings</p></div>
              <span className="text-xs text-[#475569]">{result.duration_seconds?.toFixed(0)}s</span>
            </div>
          )}
          {comprehensiveResult && (
            <div className="flex items-center gap-3 p-3 bg-[#0a0e17] rounded-lg border border-[#1e2d45]">
              <Gauge size={16} className="text-cyan-400" />
              <div className="flex-1"><p className="text-sm font-medium">{comprehensiveResult.target}</p><p className="text-xs text-[#64748b]">{comprehensiveResult.status} | {comprehensiveResult.total_findings} findings</p></div>
            </div>
          )}
          {networkResult && (
            <div className="flex items-center gap-3 p-3 bg-[#0a0e17] rounded-lg border border-[#1e2d45]">
              <Wifi size={16} className="text-purple-400" />
              <div className="flex-1"><p className="text-sm font-medium">{networkResult.target}</p><p className="text-xs text-[#64748b]">{networkResult.status} | {networkResult.findings?.length || 0} findings</p></div>
            </div>
          )}
          {!result && !networkResult && !noirResult && !comprehensiveResult && (
            <div className="text-center py-8 text-[#475569]">
              <Activity size={36} className="mx-auto mb-3 text-[#1e2d45]" />
              <p className="text-sm">No scans yet. Start from the tabs above.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
