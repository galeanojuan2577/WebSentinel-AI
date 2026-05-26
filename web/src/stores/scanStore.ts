import { create } from 'zustand'

interface Vulnerability {
  name: string; description: string; severity: string; url: string
  evidence: string | null; remediation: string; references: string[]
}

export interface ScanResult {
  scan_id: string; target: { url: string }; status: string
  started_at: string; finished_at: string | null
  vulnerabilities: Vulnerability[]; total_urls_scanned: number
  summary: Record<string, number>; duration_seconds: number | null
}

export interface NetworkResult {
  scan_id: string; status: string; target: string; findings: Vulnerability[]
}

export interface NoirResult {
  scan_id: string; status: string; project_path: string; findings: Vulnerability[]; raw_output?: any
}

export interface ComprehensiveResult {
  scan_id: string; status: string; target: string
  sources: string[]; findings: Vulnerability[]; total_findings: number
}

export interface PipelineStepResult {
  step_id: string; step_type: string; label: string
  status: string; started_at: string | null; finished_at: string | null
  result: any; error: string | null; ai_decision: string | null
  summary: Record<string, number> | null
  finding_count: number; high_finding_count: number
}

export interface PipelineState {
  pipeline_id: string; name: string; target: string
  status: string; steps: PipelineStepResult[]
  current_step_index: number
  created_at: string; finished_at: string | null; error: string | null
}

interface ScanState {
  scanId: string | null
  scanning: boolean
  result: ScanResult | null
  error: string
  networkScanning: boolean
  networkResult: NetworkResult | null
  networkError: string
  noirScanning: boolean
  noirResult: NoirResult | null
  noirError: string
  noirProgress: { percent: number; message: string } | null
  comprehensiveScanning: boolean
  comprehensiveResult: ComprehensiveResult | null
  wifiScanning: boolean
  wifiResult: NetworkResult | null
  wifiError: string
  pipelineScanning: boolean
  pipelineState: PipelineState | null
  setScanId: (id: string | null) => void
  setScanning: (v: boolean) => void
  setResult: (r: ScanResult | null) => void
  setError: (e: string) => void
  setNetworkScanning: (v: boolean) => void
  setNetworkResult: (r: NetworkResult | null) => void
  setNetworkError: (e: string) => void
  setNoirScanning: (v: boolean) => void
  setNoirResult: (r: NoirResult | null) => void
  setNoirError: (e: string) => void
  setNoirProgress: (p: { percent: number; message: string } | null) => void
  setComprehensiveScanning: (v: boolean) => void
  setComprehensiveResult: (r: ComprehensiveResult | null) => void
  setWifiScanning: (v: boolean) => void
  setWifiResult: (r: NetworkResult | null) => void
  setWifiError: (e: string) => void
  setPipelineScanning: (v: boolean) => void
  setPipelineState: (s: PipelineState | null) => void
  resetAll: () => void
}

export const useScanStore = create<ScanState>((set) => ({
  scanId: null,
  scanning: false,
  result: null,
  error: '',
  networkScanning: false,
  networkResult: null,
  networkError: '',
  noirScanning: false,
  noirResult: null,
  noirError: '',
  noirProgress: null,
  comprehensiveScanning: false,
  comprehensiveResult: null,
  wifiScanning: false,
  wifiResult: null,
  wifiError: '',
  pipelineScanning: false,
  pipelineState: null,
  setScanId: (scanId) => set({ scanId }),
  setScanning: (scanning) => set({ scanning }),
  setResult: (result) => set({ result }),
  setError: (error) => set({ error }),
  setNetworkScanning: (networkScanning) => set({ networkScanning }),
  setNetworkResult: (networkResult) => set({ networkResult }),
  setNetworkError: (networkError) => set({ networkError }),
  setNoirScanning: (noirScanning) => set({ noirScanning }),
  setNoirResult: (noirResult) => set({ noirResult }),
  setNoirError: (noirError) => set({ noirError }),
  setNoirProgress: (noirProgress) => set({ noirProgress }),
  setComprehensiveScanning: (comprehensiveScanning) => set({ comprehensiveScanning }),
  setComprehensiveResult: (comprehensiveResult) => set({ comprehensiveResult }),
  setWifiScanning: (wifiScanning) => set({ wifiScanning }),
  setWifiResult: (wifiResult) => set({ wifiResult }),
  setWifiError: (wifiError) => set({ wifiError }),
  setPipelineScanning: (pipelineScanning) => set({ pipelineScanning }),
  setPipelineState: (pipelineState) => set({ pipelineState }),
  resetAll: () => set({
    scanId: null, scanning: false, result: null, error: '',
    networkScanning: false, networkResult: null, networkError: '',
    noirScanning: false, noirResult: null, noirError: '', noirProgress: null,
    comprehensiveScanning: false, comprehensiveResult: null,
    wifiScanning: false, wifiResult: null, wifiError: '',
    pipelineScanning: false, pipelineState: null,
  }),
}))
