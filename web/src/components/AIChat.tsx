import { useState, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { MessageCircle, X, Send, Bot } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'

export function AIChat() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<{ role: string; content: string }[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const location = useLocation()
  const { result, comprehensiveResult, networkResult, noirResult, pipelineState } = useScanStore()

  const page = location.pathname.split('/')[1] || 'dashboard'

  const buildContext = () => {
    const ctx: any[] = []
    if (page === 'web' && result) {
      ctx.push({ type: 'web_scan', target: result.target?.url, findings: result.vulnerabilities?.length || 0, summary: result.summary })
    } else if (page === 'link' && comprehensiveResult) {
      ctx.push({ type: 'link_scan', target: comprehensiveResult.target, findings: comprehensiveResult.findings?.length || 0, sources: comprehensiveResult.sources })
    } else if (page === 'network' && networkResult) {
      ctx.push({ type: 'network_scan', target: networkResult.target, findings: networkResult.findings?.length || 0 })
    } else if (page === 'noir' && noirResult) {
      ctx.push({ type: 'noir_audit', project: noirResult.project_path, findings: noirResult.findings?.length || 0 })
    } else if (page === 'pipeline' && pipelineState) {
      ctx.push({
        type: 'pipeline',
        name: pipelineState.name,
        target: pipelineState.target,
        status: pipelineState.status,
        steps: pipelineState.steps.map(s => ({
          label: s.label,
          status: s.status,
          step_type: s.step_type,
          finding_count: s.finding_count,
          error: s.error,
        })),
      })
    }
    return ctx
  }

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages])

  const sendMessage = async () => {
    if (!input.trim() || loading) return
    const msg = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: msg }])
    setLoading(true)

    try {
      const context = buildContext()
      const body: any = { message: msg }
      if (context.length > 0) {
        body.context = context
      }
      const r = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await r.json()
      setMessages(prev => [...prev, { role: 'ai', content: data.response || 'No response' }])
    } catch {
      setMessages(prev => [...prev, { role: 'ai', content: 'Error connecting to AI service.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)}
          className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full bg-gradient-to-br from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 shadow-lg shadow-blue-500/30 flex items-center justify-center transition-all duration-200 hover:scale-110">
          <Bot size={24} className="text-white" />
        </button>
      )}

      {open && (
        <div className="fixed bottom-6 right-6 z-50 w-80 md:w-96 bg-[#0f1729] border border-[#1e2d45] rounded-xl shadow-2xl shadow-black/50 flex flex-col overflow-hidden fade-in">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d45] bg-[#0a0e17]">
            <div className="flex items-center gap-2">
              <Bot size={18} className="text-blue-400" />
              <span className="text-sm font-semibold text-white">AI Assistant</span>
            </div>
            <button onClick={() => setOpen(false)} className="text-[#64748b] hover:text-white transition-colors">
              <X size={18} />
            </button>
          </div>

          <div className="flex-1 p-4 space-y-3 overflow-y-auto max-h-80 min-h-[200px]">
            {messages.length === 0 && (
              <div className="text-center text-[#475569] text-xs py-8">
                <MessageCircle size={24} className="mx-auto mb-2 opacity-50" />
                <p>Ask about vulnerabilities, remediation,</p>
                <p>or scan results</p>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                  m.role === 'user'
                    ? 'bg-blue-600/20 text-blue-300 border border-blue-500/20'
                    : 'bg-[#1e2d45] text-[#e2e8f0] border border-[#2a3a55]'
                }`}>
                  <p className="whitespace-pre-wrap break-words">{m.content}</p>
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-[#1e2d45] rounded-lg px-3 py-2 text-sm border border-[#2a3a55]">
                  <div className="flex gap-1">
                    <div className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div className="p-3 border-t border-[#1e2d45]">
            <div className="flex gap-2">
              <input type="text" value={input} onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sendMessage()}
                placeholder="Ask about security..."
                className="flex-1 bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-3 py-2 text-xs text-white placeholder-[#475569] focus:outline-none focus:border-blue-500/50" />
              <button onClick={sendMessage} disabled={loading || !input.trim()}
                className="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800/50 rounded-lg transition-colors">
                <Send size={14} className="text-white" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
