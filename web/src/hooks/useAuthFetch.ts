import { useAuthStore } from '../stores/authStore'

export function useAuthHeaders(): Record<string, string> {
  const token = useAuthStore(s => s.token)
  if (!token) return {}
  return { Authorization: `Bearer ${token}` }
}

export async function apiFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const token = useAuthStore.getState().token
  const headers: Record<string, string> = { ...(options.headers as Record<string, string> || {}) }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return fetch(url, { ...options, headers })
}
