import { useCallback } from 'react'
import { Wifi, Server, Scan, XCircle, CheckCircle, Download } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'
import { useWebSocket } from '../hooks/useWebSocket'
import { apiFetch } from '../hooks/useAuthFetch'
import { useState } from 'react'

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: '#450a0a', text: '#fca5a5', border: '#dc2626' },
  high: { bg: '#431407', text: '#fdba74', border: '#ea580c' },
  medium: { bg: '#422006', text: '#fde68a', border: '#ca8a04' },
  low: { bg: '#0c1929', text: '#93c5fd', border: '#2563eb' },
  info: { bg: '#1c1917', text: '#a1a1aa', border: '#52525b' },
}

function getSeverity(sev: string) { return SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info }

export function NetworkScan() {
  const [networkTarget, setNetworkTarget] = useState('192.168.1.0/24')

  const { scanId, setScanId, networkScanning, setNetworkScanning, networkResult, setNetworkResult, networkError, setNetworkError } = useScanStore()
  const { wifiScanning, setWifiScanning, wifiResult, setWifiResult, wifiError, setWifiError } = useScanStore()

  useWebSocket(scanId, useCallback((msg: any) => {
    if (msg.type === 'network_scan_completed' && msg.result) { setNetworkResult(msg.result); setNetworkScanning(false) }
    else if (msg.type === 'network_scan_failed') { setNetworkError(msg.error || 'Network scan failed'); setNetworkScanning(false) }
    else if (msg.type === 'wifi_scan_completed' && msg.result) { setWifiResult(msg.result); setWifiScanning(false) }
    else if (msg.type === 'wifi_scan_failed') { setWifiError(msg.error || 'WiFi scan failed'); setWifiScanning(false) }
    else if (msg.type === 'poll_completed') {
      const d = msg.result
      if (d.target === 'wifi://local') setWifiResult(d)
      else if (d.findings) setNetworkResult(d)
      setNetworkScanning(false); setWifiScanning(false)
    }
  }, [setNetworkResult, setNetworkScanning, setNetworkError, setWifiResult, setWifiScanning, setWifiError]))

  const startNetworkScan = useCallback(async () => {
    setNetworkScanning(true); setNetworkError(''); setNetworkResult(null)
    try {
      const r = await apiFetch('/api/network/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: networkTarget, scan_type: 'quick' }) })
      setScanId((await r.json()).scan_id)
    } catch { setNetworkError('Failed to start network scan'); setNetworkScanning(false) }
  }, [networkTarget, setNetworkScanning, setNetworkError, setNetworkResult, setScanId])

  const startWifiScan = useCallback(async () => {
    setWifiScanning(true); setWifiError(''); setWifiResult(null)
    try {
      const r = await apiFetch('/api/network/wifi-scan', { method: 'POST' })
      setScanId((await r.json()).scan_id)
    } catch { setWifiError('Failed to start WiFi scan'); setWifiScanning(false) }
  }, [setWifiScanning, setWifiError, setWifiResult, setScanId])

  const FindingItem = ({ f }: { f: any }) => (
    <div className="bg-[#0a0e17] border border-[#1e2d45] rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <Server size={14} className="text-purple-400" />
        <span className="font-medium text-sm">{f.name}</span>
        <span className="ml-auto px-2 py-0.5 rounded-full text-[10px] font-bold uppercase"
          style={{ background: getSeverity(f.severity).bg, color: getSeverity(f.severity).text }}>{f.severity}</span>
      </div>
      <p className="text-xs text-[#94a3b8]">{f.description}</p>
      {f.evidence && <pre className="mt-2 text-xs text-[#64748b] font-mono">{f.evidence}</pre>}
    </div>
  )

  return (
    <div className="fade-in space-y-6">
      {/* Network Scan */}
      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 card-glow">
        <div className="flex items-center gap-3 mb-4">
          <Wifi size={20} className="text-purple-400" />
          <h2 className="text-lg font-semibold">Network Scanner</h2>
        </div>
        <p className="text-sm text-[#64748b] mb-4">Detect active hosts, open ports, and services on your local network.</p>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input type="text" value={networkTarget} onChange={e => setNetworkTarget(e.target.value)} placeholder="192.168.1.0/24" disabled={networkScanning}
              className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-3 pl-10 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition-all" />
            <Server size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#475569]" />
          </div>
          <button onClick={startNetworkScan} disabled={networkScanning || !networkTarget.trim()}
            className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 disabled:from-purple-800/50 disabled:to-purple-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-purple-500/20 disabled:shadow-none">
            {networkScanning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Scan size={16} /> Scan Network</>}
          </button>
        </div>
        {networkError && <p className="text-red-400 text-sm mt-2 flex items-center gap-1"><XCircle size={14} /> {networkError}</p>}
      </div>

      {networkResult && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 fade-in">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Network Scan Results</h2>
            {scanId && (
              <button className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1e2d45] hover:bg-[#2a3a55] transition-colors"><Download size={12} /> Report</button>
            )}
          </div>
          {networkResult.findings?.length > 0 ? (
            <div className="space-y-3">{networkResult.findings.map((f, i) => <FindingItem key={i} f={f} />)}</div>
          ) : (
            <div className="text-center py-8"><CheckCircle size={36} className="mx-auto text-purple-500 mb-3" /><p className="text-[#94a3b8]">No hosts detected or scan completed with no findings.</p></div>
          )}
        </div>
      )}

      {networkScanning && !networkResult && (
        <div className="text-center py-16">
          <div className="w-10 h-10 border-2 border-[#1e2d45] border-t-purple-500 rounded-full animate-spin mx-auto mb-4" />
          <p className="text-[#94a3b8]">Scanning network {networkTarget}...</p>
          <p className="text-xs text-[#475569] mt-1">This may take a few moments</p>
        </div>
      )}

      {/* WiFi Scanner */}
      <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 card-glow">
        <div className="flex items-center gap-3 mb-4">
          <Wifi size={20} className="text-pink-400" />
          <h2 className="text-lg font-semibold">WiFi Network Scanner</h2>
        </div>
        <p className="text-sm text-[#64748b] mb-4">Escanea redes WiFi cercanas y analiza su seguridad (WEP, WPA2, WPA3, WPS, señal).</p>
        <button onClick={startWifiScan} disabled={wifiScanning}
          className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-pink-600 to-pink-500 hover:from-pink-500 hover:to-pink-400 disabled:from-pink-800/50 disabled:to-pink-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-pink-500/20 disabled:shadow-none">
          {wifiScanning ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Wifi size={16} /> Scan WiFi</>}
        </button>
        {wifiError && <p className="text-red-400 text-sm mt-2 flex items-center gap-1"><XCircle size={14} /> {wifiError}</p>}
      </div>

      {wifiResult && (
        <div className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 fade-in">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">WiFi Scan Results</h2>
          </div>
          {wifiResult.findings?.length > 0 ? (
            <div className="space-y-3">{wifiResult.findings.map((f, i) => (
              <div key={i} className="bg-[#0a0e17] border border-[#1e2d45] rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Wifi size={14} className="text-pink-400" />
                  <span className="font-medium text-sm">{f.name}</span>
                  <span className="ml-auto px-2 py-0.5 rounded-full text-[10px] font-bold uppercase"
                    style={{ background: getSeverity(f.severity).bg, color: getSeverity(f.severity).text }}>{f.severity}</span>
                </div>
                <p className="text-xs text-[#94a3b8]">{f.description}</p>
                {f.evidence && <pre className="mt-2 text-xs text-[#64748b] font-mono">{f.evidence}</pre>}
              </div>
            ))}</div>
          ) : (
            <div className="text-center py-8"><CheckCircle size={36} className="mx-auto text-pink-500 mb-3" /><p className="text-[#94a3b8]">No WiFi networks detected or scan completed.</p></div>
          )}
        </div>
      )}

      {wifiScanning && !wifiResult && (
        <div className="text-center py-8">
          <div className="w-10 h-10 border-2 border-[#1e2d45] border-t-pink-500 rounded-full animate-spin mx-auto mb-4" />
          <p className="text-[#94a3b8]">Scanning WiFi networks...</p>
        </div>
      )}
    </div>
  )
}
