import { create } from 'zustand'

interface AuthState {
  token: string | null
  username: string | null
  loading: boolean
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  checkAuth: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: localStorage.getItem('vulnscout_token'),
  username: localStorage.getItem('vulnscout_username'),
  loading: true,

  login: async (username, password) => {
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (!r.ok) return false
      const data = await r.json()
      localStorage.setItem('vulnscout_token', data.access_token)
      localStorage.setItem('vulnscout_username', username)
      set({ token: data.access_token, username })
      return true
    } catch {
      return false
    }
  },

  logout: () => {
    localStorage.removeItem('vulnscout_token')
    localStorage.removeItem('vulnscout_username')
    set({ token: null, username: null })
  },

  checkAuth: async () => {
    const token = get().token
    if (!token) {
      set({ loading: false })
      return
    }
    try {
      const r = await fetch('/api/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      })
      const data = await r.json()
      if (!data.authenticated) {
        localStorage.removeItem('vulnscout_token')
        localStorage.removeItem('vulnscout_username')
        set({ token: null, username: null })
      }
    } catch {
      // offline is fine
    } finally {
      set({ loading: false })
    }
  },
}))
