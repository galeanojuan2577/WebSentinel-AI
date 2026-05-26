import { useState } from 'react'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { useAuthStore } from '../stores/authStore'
import { useNavigate } from 'react-router-dom'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const login = useAuthStore(s => s.login)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    const ok = await login(username, password)
    setLoading(false)
    if (ok) {
      navigate('/dashboard')
    } else {
      setError('Invalid credentials')
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0e17] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-600 to-blue-400 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-blue-500/30">
            <Shield size={32} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">VulnScout</h1>
          <p className="text-[#64748b] text-sm mt-1">Security Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-[#0f1729] rounded-xl border border-[#1e2d45] p-8 space-y-5">
          <h2 className="text-lg font-semibold text-center">Sign In</h2>

          <div>
            <label className="block text-xs text-[#64748b] font-medium mb-1.5">Username</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)}
              className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-2.5 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all"
              placeholder="admin" autoFocus />
          </div>

          <div>
            <label className="block text-xs text-[#64748b] font-medium mb-1.5">Password</label>
            <div className="relative">
              <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                className="w-full bg-[#0a0e17] border border-[#1e2d45] rounded-lg px-4 py-2.5 pr-10 text-sm text-white placeholder-[#475569] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all"
                placeholder="••••••" />
              <button type="button" onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#475569] hover:text-[#94a3b8]">
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <p className="text-red-400 text-sm text-center">{error}</p>
          )}

          <button type="submit" disabled={loading || !username || !password}
            className="w-full py-2.5 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 disabled:from-blue-800/50 disabled:to-blue-700/50 rounded-lg text-sm font-semibold transition-all duration-200 shadow-lg shadow-blue-500/20 disabled:shadow-none">
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
