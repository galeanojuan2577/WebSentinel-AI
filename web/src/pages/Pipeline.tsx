import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, CheckCircle, XCircle, Clock, SkipForward, Loader2, AlertTriangle, ArrowRight, Layers, Globe, Search, Network, FileSearch, Brain, Bot, ChevronDown, ChevronRight, Download, ExternalLink } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { apiFetch } from '../hooks/useAuthFetch'

const STEP_ICONS: Record<string, any> = {
  web_scan: Globe,
  link_scan: Search,
  network_scan: Network,
  noir_audit: FileSearch,
  ai_enrich: Brain,
  ai_decision: Bot,
}

const STATUS_ICONS: Record<string, any> = {
  pending: Clock,
  running: Loader2,
  completed: CheckCircle,
  failed: XCircle,
  skipped: SkipForward,
}

export function Pipeline() {
  const [name, setName] = useState('')
  const [target, setTarget] = useState('')
  const [pipelineList, setPipelineList] = useState<any[]>([])
  const [activePipelineId, setActivePipelineId] = useState<string | null>(null)
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set())
  const { pipelineScanning, setPipelineScanning, pipelineState, setPipelineState } = useScanStore()
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const navigate = useNavigate()

  const toggleStep = (stepId: string) => {
    setExpandedSteps(prev => {
      const next = new Set(prev)
      if (next.has(stepId)) next.delete(stepId); else next.add(stepId)
      return next
    })
  }

  const exportReport = () => {
    if (!pipelineState) return
    const report = {
      pipeline: pipelineState.name,
      target: pipelineState.target,
      status: pipelineState.status,
      generated_at: new Date().toISOString(),
      steps: pipelineState.steps.map(s => ({
        label: s.label,
        type: s.step_type,
        status: s.status,
        finding_count: s.finding_count,
        error: s.error,
        ai_decision: s.ai_decision,
        findings: s.result?.findings || s.result?.vulnerabilities || s.result?.enriched_findings || [],
      })),
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `pipeline-${pipelineState.pipeline_id}.json`
    a.click()
  }

  useEffect(() => {
    apiFetch('/api/pipelines').then(r => r.json()).then(d => setPipelineList(d.pipelines || [])).catch(() => {})
  }, [pipelineState?.pipeline_id])

  useEffect(() => {
    if (activePipelineId) {
      const fetchState = async () => {
        try {
          const r = await apiFetch(`/api/pipeline/${activePipelineId}`)
          const state = await r.json()
          setPipelineState(state)
          if (state.status === 'completed' || state.status === 'failed' || state.status === 'cancelled') {
            setPipelineScanning(false)
            setActivePipelineId(null)
            setPipelineList(prev => {
              const exists = prev.some(p => p.pipeline_id === state.pipeline_id)
              return exists ? prev : [...prev, state]
            })
          }
        } catch {}
      }
      fetchState()
      pollRef.current = setInterval(fetchState, 2000)
      return () => { if (pollRef.current) clearInterval(pollRef.current) }
    }
  }, [activePipelineId, setPipelineState, setPipelineScanning])

  const startPipeline = async () => {
    if (!target.trim()) return
    setPipelineScanning(true)
    setPipelineState(null)
    setActivePipelineId(null)
    try {
      const r = await apiFetch('/api/pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim() || `Pipeline ${new Date().toLocaleTimeString()}`,
          target: target.trim(),
          steps: [],
        }),
      })
      const data = await r.json()
      setActivePipelineId(data.pipeline_id)
    } catch {
      setPipelineScanning(false)
    }
  }

  const isRunning = pipelineScanning || pipelineState?.status === 'running'

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#7c3aed] to-[#3b82f6] flex items-center justify-center shadow-lg shadow-purple-500/20">
          <Layers size={20} className="text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">Purple Team Orchestrator</h1>
          <p className="text-sm text-[#64748b]">AI-driven multi-stage scan pipeline</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Play size={14} className="text-blue-400" /> Start New Pipeline
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder="Pipeline name (optional)"
                className="bg-[#1e2d45] border border-[#2d3a56] rounded-lg px-4 py-2.5 text-sm text-white placeholder-[#64748b] focus:outline-none focus:border-blue-500 transition-colors" />
              <input value={target} onChange={e => setTarget(e.target.value)}
                placeholder="Target URL (e.g. https://example.com)"
                className="bg-[#1e2d45] border border-[#2d3a56] rounded-lg px-4 py-2.5 text-sm text-white placeholder-[#64748b] focus:outline-none focus:border-blue-500 transition-colors" />
            </div>
            <button onClick={startPipeline} disabled={!target.trim() || isRunning}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm font-medium hover:from-blue-500 hover:to-purple-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 shadow-lg shadow-blue-600/20">
              {isRunning ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
              {isRunning ? 'Pipeline Running...' : 'Start Pipeline'}
            </button>

            <div className="bg-[#0a0e17] rounded-lg p-3 border border-[#1e2d45]">
              <p className="text-xs text-[#64748b] mb-2 font-medium">Pipeline steps:</p>
              <div className="flex flex-wrap gap-2">
                {[{icon: Globe, label: 'Web Scan'}, {icon: Brain, label: 'AI Analysis'}, {icon: Bot, label: 'AI Decision'},
                  {icon: Search, label: 'Link Scan'}, {icon: Brain, label: 'AI Analysis'}, {icon: Bot, label: 'Final Report'}]
                  .map((s, i) => (
                    <div key={i} className="flex items-center gap-1">
                      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1e2d45] border border-[#2d3a56]">
                        <s.icon size={12} className="text-purple-400" />
                        <span className="text-[11px] text-[#94a3b8]">{s.label}</span>
                      </div>
                      {i < 5 && <ArrowRight size={12} className="text-[#475569]" />}
                    </div>
                  ))}
              </div>
            </div>
          </div>

          {pipelineState && (
            <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                  <h2 className="text-sm font-semibold text-white">
                    Pipeline: {pipelineState.name}
                    <span className="ml-2 text-xs text-[#64748b] font-normal">({pipelineState.target})</span>
                  </h2>
                  {pipelineState.status === 'completed' && (
                    <p className="text-xs text-green-400 mt-1">
                      {pipelineState.steps.reduce((a, s) => a + s.finding_count, 0)} total findings |
                      {pipelineState.steps.filter(s => s.status === 'completed').length}/{pipelineState.steps.length} steps completed
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {pipelineState.status === 'completed' && (
                    <div className="flex items-center gap-2">
                      <button onClick={() => window.open(`/api/pipeline/${pipelineState.pipeline_id}/report?format=html`, '_blank')}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d45] hover:bg-[#2d3a56] text-xs text-[#94a3b8] transition-colors border border-[#2d3a56]">
                        <Download size={12} /> HTML Report
                      </button>
                      <button onClick={exportReport}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d45] hover:bg-[#2d3a56] text-xs text-[#94a3b8] transition-colors border border-[#2d3a56]">
                        <Download size={12} /> JSON
                      </button>
                    </div>
                  )}
                  <span className={`px-3 py-1.5 rounded-full text-xs font-medium border ${
                    pipelineState.status === 'completed' ? 'bg-green-500/10 border-green-500/20 text-green-400' :
                    pipelineState.status === 'failed' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
                    pipelineState.status === 'running' ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' :
                    'bg-yellow-500/10 border-yellow-500/20 text-yellow-400'
                  }`}>
                    {pipelineState.status.toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                {pipelineState.steps.map((step, i) => {
                  const Icon = STEP_ICONS[step.step_type] || Layers
                  const StatusIcon = STATUS_ICONS[step.status] || Clock
                  const isActive = step.status === 'running'
                  const isDone = step.status === 'completed'
                  const isFailed = step.status === 'failed'
                  const isSkipped = step.status === 'skipped'
                  const isExpanded = expandedSteps.has(step.step_id)
                  const stepFindings = step.result?.findings || step.result?.vulnerabilities || step.result?.enriched_findings || []
                  const hasDetails = isDone && (stepFindings.length > 0 || step.result?.scan_id || step.result?.ai_decision)

                  return (
                    <div key={step.step_id}
                      className={`rounded-lg border transition-all duration-300 ${
                        isActive ? 'border-blue-500/50 bg-blue-500/5' :
                        isDone ? 'border-green-500/30 bg-green-500/5' :
                        isFailed ? 'border-red-500/30 bg-red-500/5' :
                        isSkipped ? 'border-yellow-500/30 bg-yellow-500/5' :
                        'border-[#1e2d45] bg-[#0a0e17]'
                      }`}>
                      <div className="relative flex items-start gap-4 p-4">
                        {i < pipelineState.steps.length - 1 && (
                          <div className={`absolute left-7 top-14 bottom-0 w-px ${
                            step.status === 'completed' ? 'bg-green-500/30' : 'bg-[#1e2d45]'
                          }`} />
                        )}
                        <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center border transition-colors ${
                          isActive ? 'border-blue-500 bg-blue-500/10' :
                          isDone ? 'border-green-500 bg-green-500/10' :
                          isFailed ? 'border-red-500 bg-red-500/10' :
                          isSkipped ? 'border-yellow-500 bg-yellow-500/10' :
                          'border-[#2d3a56] bg-[#1e2d45]'
                        }`}>
                          {isActive ? (
                            <StatusIcon size={18} className="animate-spin text-blue-400" />
                          ) : (
                            <Icon size={18} className={
                              isDone ? 'text-green-400' : isFailed ? 'text-red-400' : isSkipped ? 'text-yellow-400' : 'text-[#64748b]'
                            } />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <h3 className={`text-sm font-medium ${
                              isDone ? 'text-green-300' : isFailed ? 'text-red-300' : isSkipped ? 'text-yellow-300' : 'text-white'
                            }`}>
                              {step.label}
                            </h3>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                              step.status === 'completed' ? 'border-green-500/20 text-green-400 bg-green-500/10' :
                              step.status === 'running' ? 'border-blue-500/20 text-blue-400 bg-blue-500/10' :
                              step.status === 'failed' ? 'border-red-500/20 text-red-400 bg-red-500/10' :
                              step.status === 'skipped' ? 'border-yellow-500/20 text-yellow-400 bg-yellow-500/10' :
                              'border-[#2d3a56] text-[#64748b] bg-[#1e2d45]'
                            }`}>
                              {step.status.toUpperCase()}
                            </span>
                          </div>
                          {step.error && <p className="text-xs text-red-400 mt-1">{step.error}</p>}
                          {step.ai_decision && step.ai_decision !== 'Skipped by AI gate' && (
                            <p className="text-xs text-purple-400 mt-1">AI: {step.ai_decision}</p>
                          )}
                          {isDone && step.finding_count > 0 && (
                            <div className="flex items-center gap-3 mt-2">
                              <span className="text-xs text-[#94a3b8]">{step.finding_count} findings</span>
                              {step.high_finding_count > 0 && (
                                <span className="text-xs text-red-400">{step.high_finding_count} high/critical</span>
                              )}
                            </div>
                          )}
                          <div className="flex items-center gap-2 mt-1">
                            {step.started_at && (
                              <p className="text-[10px] text-[#475569]">
                                {new Date(step.started_at).toLocaleTimeString()}
                                {step.finished_at && ` - ${new Date(step.finished_at).toLocaleTimeString()}`}
                              </p>
                            )}
                            {hasDetails && (
                              <button onClick={() => toggleStep(step.step_id)}
                                className="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 transition-colors">
                                {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                                {isExpanded ? 'Hide details' : 'View details'}
                              </button>
                            )}
                            {step.result?.scan_id && (
                              <button onClick={() => navigate('/web')}
                                className="flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors">
                                <ExternalLink size={10} /> Open scan
                              </button>
                            )}
                          </div>
                        </div>
                      </div>

                      {isExpanded && hasDetails && (
                        <div className="px-4 pb-4 pt-0 border-t border-[#1e2d45]/50 mx-4 space-y-2">
                          {step.result?.ai_decision && (
                            <div className="p-2 rounded bg-[#0a0e17] border border-[#1e2d45]">
                              <p className="text-xs text-purple-300">
                                <span className="font-medium text-purple-400">Decision:</span> {step.result.reason || step.result.ai_decision}
                                {step.result.next_step_type && (
                                  <span className="text-[#64748b]"> → Next: {step.result.next_step_type}</span>
                                )}
                                {step.result.next_target && (
                                  <span className="text-[#64748b]"> → {step.result.next_target}</span>
                                )}
                              </p>
                            </div>
                          )}
                          {stepFindings.length > 0 && (
                            <div className="space-y-1 max-h-48 overflow-y-auto">
                              {stepFindings.slice(0, 20).map((f: any, fi: number) => (
                                <div key={fi} className="p-2 rounded bg-[#0a0e17] border border-[#1e2d45]">
                                  <div className="flex items-center justify-between">
                                    <p className="text-xs text-[#e2e8f0] truncate">{f.name || f.title || 'Finding'}</p>
                                    {f.severity && (
                                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                        f.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                                        f.severity === 'high' ? 'bg-orange-500/10 text-orange-400' :
                                        f.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-400' :
                                        'bg-blue-500/10 text-blue-400'
                                      }`}>{f.severity}</span>
                                    )}
                                  </div>
                                  {f.description && <p className="text-[10px] text-[#64748b] mt-1 truncate">{f.description}</p>}
                                </div>
                              ))}
                              {stepFindings.length > 20 && (
                                <p className="text-[10px] text-[#475569] text-center">...and {stepFindings.length - 20} more</p>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              {pipelineState.error && (
                <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                  <AlertTriangle size={14} className="text-red-400 mt-0.5" />
                  <p className="text-xs text-red-300">{pipelineState.error}</p>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Clock size={14} className="text-[#64748b]" /> Recent Pipelines
            </h2>
            {pipelineList.length === 0 ? (
              <p className="text-xs text-[#64748b] text-center py-8">No pipelines yet</p>
            ) : (
              <div className="space-y-2">
                {pipelineList.slice(-5).reverse().map(p => (
                  <button key={p.pipeline_id} onClick={() => {
                    apiFetch(`/api/pipeline/${p.pipeline_id}`).then(r => r.json()).then(setPipelineState)
                  }}
                    className="w-full text-left p-3 rounded-lg bg-[#0a0e17] border border-[#1e2d45] hover:border-[#2d3a56] transition-colors space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-white truncate">{p.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        p.status === 'completed' ? 'text-green-400' :
                        p.status === 'failed' ? 'text-red-400' :
                        p.status === 'running' ? 'text-blue-400' : 'text-yellow-400'
                      }`}>{p.status}</span>
                    </div>
                    <p className="text-[10px] text-[#64748b] truncate">{p.target}</p>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <Bot size={14} className="text-purple-400" /> How It Works
            </h2>
            <div className="space-y-2 text-xs text-[#64748b]">
              <p>1. Scans target with web checks</p>
              <p>2. AI analyzes findings</p>
              <p>3. AI decides next action</p>
              <p>4. Runs link analysis if needed</p>
              <p>5. AI re-analyzes new findings</p>
              <p>6. Generates executive summary</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}