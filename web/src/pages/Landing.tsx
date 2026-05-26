import { Shield, Globe, Wifi, FileSearch, Gauge, Activity, ArrowRight, LogOut, LayoutDashboard } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuthStore } from '../stores/authStore'

const features = [
  { icon: Globe, title: 'Web Scanner', desc: 'Headers, SSL, XSS, SQLi, cookies, directories, and ports analysis', color: 'from-blue-600 to-blue-400' },
  { icon: Gauge, title: 'Multi-Source Recon', desc: 'Tech detection, subdomain discovery, CVE lookup, DNS enumeration', color: 'from-cyan-600 to-cyan-400' },
  { icon: Wifi, title: 'Network & WiFi', desc: 'Host discovery, port scanning, WiFi security analysis with WEP/WPA detection', color: 'from-purple-600 to-purple-400' },
  { icon: FileSearch, title: 'OWASP Noir', desc: 'SAST audit integration for source code vulnerability analysis', color: 'from-emerald-600 to-emerald-400' },
  { icon: Activity, title: 'AI Orchestration', desc: 'Local LLM-driven vulnerability triage, attack path mapping, and remediation', color: 'from-amber-600 to-amber-400' },
  { icon: Shield, title: 'Executive Reporting', desc: 'PDF/HTML/JSON reports with severity scoring and compliance mapping', color: 'from-pink-600 to-pink-400' },
]

const container = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } }
const item = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0 } }

export function Landing() {
  const navigate = useNavigate()
  const { token, username, logout } = useAuthStore()
  const loggedIn = !!token

  return (
    <div className="min-h-screen bg-[#0a0e17]">
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
            <div className="flex items-center gap-3">
              {loggedIn ? (
                <>
                  <span className="text-sm text-[#94a3b8]">{username}</span>
                  <button onClick={() => navigate('/dashboard')}
                    className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/20">
                    <LayoutDashboard size={16} /> Dashboard
                  </button>
                  <button onClick={() => { logout(); navigate('/') }}
                    className="px-3 py-2 text-sm text-[#64748b] hover:text-red-400 transition-colors">
                    <LogOut size={16} />
                  </button>
                </>
              ) : (
                <>
                  <button onClick={() => navigate('/login')}
                    className="px-4 py-2 text-sm text-[#64748b] hover:text-white transition-colors">
                    Sign In
                  </button>
                  <button onClick={() => navigate('/login')}
                    className="px-5 py-2 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/20">
                    Get Started
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </header>

      <section className="max-w-7xl mx-auto px-4 sm:px-6 pt-24 pb-16 text-center">
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-6">
            <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            AI-Powered Security Analysis
          </div>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">
            Intelligent{' '}
            <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
              Vulnerability
            </span>{' '}
            Scouting
          </h1>
          <p className="text-lg text-[#94a3b8] max-w-2xl mx-auto mb-10">
            Automated web reconnaissance, network analysis, and AI-driven vulnerability assessment
            platform. Scan targets, discover attack surfaces, and get actionable remediation.
          </p>
          <div className="flex items-center justify-center gap-4">
            {loggedIn ? (
              <button onClick={() => navigate('/dashboard')}
                className="flex items-center gap-2 px-8 py-3.5 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 rounded-xl text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/30">
                Go to Dashboard <ArrowRight size={16} />
              </button>
            ) : (
              <>
                <button onClick={() => navigate('/login')}
                  className="flex items-center gap-2 px-8 py-3.5 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 rounded-xl text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/30">
                  Launch Dashboard <ArrowRight size={16} />
                </button>
                <button onClick={() => navigate('/login')}
                  className="px-8 py-3.5 bg-[#1e2d45] hover:bg-[#2a3a55] rounded-xl text-sm font-semibold transition-all duration-200">
                  Sign In
                </button>
              </>
            )}
          </div>
        </motion.div>
      </section>

      <section className="max-w-7xl mx-auto px-4 sm:px-6 py-16">
        <motion.div variants={container} initial="hidden" whileInView="show" viewport={{ once: true }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f, i) => (
            <motion.div key={i} variants={item}
              className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-6 hover:border-blue-500/30 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/5">
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${f.color} flex items-center justify-center mb-4 shadow-lg`}>
                <f.icon size={22} className="text-white" />
              </div>
              <h3 className="text-white font-semibold mb-2">{f.title}</h3>
              <p className="text-sm text-[#64748b]">{f.desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </section>

      <footer className="border-t border-[#1e2d45] py-8 text-center">
        <p className="text-xs text-[#475569]">VulnScout Security Platform &mdash; AI-Powered Vulnerability Assessment</p>
      </footer>
    </div>
  )
}
