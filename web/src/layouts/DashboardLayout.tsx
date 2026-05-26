import { useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Shield, Globe, Gauge, Wifi, FileSearch, Activity, LogOut, User, Layers, AlertTriangle } from 'lucide-react'
import { AIChat } from '../components/AIChat'
import { useAuthStore } from '../stores/authStore'
import { useScanStore } from '../stores/scanStore'

const tabs = [
  { id: '/dashboard', label: 'Dashboard', icon: Activity },
  { id: '/web', label: 'Web Scanner', icon: Globe },
  { id: '/link', label: 'Link Scanner', icon: Gauge },
  { id: '/network', label: 'Network', icon: Wifi },
  { id: '/noir', label: 'Noir Audit', icon: FileSearch },
  { id: '/pipeline', label: 'Pipeline', icon: Layers },
  { id: '/findings', label: 'Findings', icon: AlertTriangle },
]

export function DashboardLayout() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const { username, logout } = useAuthStore()
  const { scanning, networkScanning, noirScanning, comprehensiveScanning } = useScanStore()

  const isScanning = scanning || networkScanning || noirScanning || comprehensiveScanning

  return (
    <div className="min-h-screen bg-[#0a0e17] text-[#e2e8f0]">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: #0a0e17; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #131a2b; }
        ::-webkit-scrollbar-thumb { background: #2d3a56; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #3b4a6b; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 5px rgba(59,130,246,.3); } 50% { box-shadow: 0 0 20px rgba(59,130,246,.5); } }
        .fade-in { animation: fadeIn .4s ease-out; }
        .tab-active { background: linear-gradient(135deg, rgba(59,130,246,0.15), rgba(99,102,241,0.1)); border-color: #3b82f6; color: #3b82f6; }
        .card-glow:hover { animation: glow 2s ease-in-out infinite; }
      `}</style>

      <header className="sticky top-0 z-50 bg-[#0f1729]/95 backdrop-blur-md border-b border-[#1e2d45]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#1e40af] to-[#3b82f6] flex items-center justify-center shadow-lg shadow-blue-500/20">
                <Shield size={20} className="text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white tracking-tight">VulnScout</h1>
                <p className="text-[11px] text-[#64748b] tracking-widest uppercase">Security Platform</p>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-1">
              {tabs.map(tab => {
                const isActive = tab.id === '/' ? location.pathname === '/' : location.pathname.startsWith(tab.id)
                return (
                  <button key={tab.id} onClick={() => { navigate(tab.id); setMobileMenuOpen(false) }}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${isActive ? 'tab-active' : 'text-[#64748b] hover:text-[#94a3b8] hover:bg-[#1e2d45]'}`}>
                    <tab.icon size={16} /> {tab.label}
                  </button>
                )
              })}
            </nav>

            <div className="hidden md:flex items-center gap-3">
              {isScanning && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
                  <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                  <span className="text-xs text-green-400 font-medium">Live</span>
                </div>
              )}
              {username && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#1e2d45]">
                  <User size={14} className="text-[#64748b]" />
                  <span className="text-xs text-[#94a3b8]">{username}</span>
                  <button onClick={() => { logout(); navigate('/') }} className="text-[#64748b] hover:text-red-400 transition-colors ml-1">
                    <LogOut size={14} />
                  </button>
                </div>
              )}
            </div>

            <button className="md:hidden flex items-center justify-center w-9 h-9 rounded-lg hover:bg-[#1e2d45] transition-colors"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
              <div className="space-y-1">
                <div className={`w-5 h-0.5 bg-[#94a3b8] transition-all ${mobileMenuOpen ? 'rotate-45 translate-y-1.5' : ''}`} />
                <div className={`w-5 h-0.5 bg-[#94a3b8] transition-all ${mobileMenuOpen ? 'opacity-0' : ''}`} />
                <div className={`w-5 h-0.5 bg-[#94a3b8] transition-all ${mobileMenuOpen ? '-rotate-45 -translate-y-1.5' : ''}`} />
              </div>
            </button>
          </div>

          {mobileMenuOpen && (
            <div className="md:hidden pb-3 space-y-1">
              {tabs.map(tab => (
                <button key={tab.id} onClick={() => { navigate(tab.id); setMobileMenuOpen(false) }}
                  className={`flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${location.pathname.startsWith(tab.id) ? 'tab-active' : 'text-[#64748b] hover:bg-[#1e2d45]'}`}>
                  <tab.icon size={18} /> {tab.label}
                </button>
              ))}
              {isScanning && (
                <div className="flex items-center gap-2 px-3 py-2 text-xs text-green-400">
                  <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" /> Live scan running
                </div>
              )}
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        <Outlet />
      </main>

      <footer className="mt-12 text-center py-6 border-t border-[#1e2d45]">
        <p className="text-xs text-[#475569]">VulnScout Security Platform v0.4.0</p>
      </footer>
      <AIChat />
    </div>
  )
}
