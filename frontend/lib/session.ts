import { useCallback, useEffect, useState } from 'react'

export type SessionRole = 'admin' | 'dev' | 'user'

export interface SessionPayload {
  token: string
  id: string
  email: string
  role: SessionRole
  mustChangePassword: boolean
}

const STORAGE_KEY = 'w9-session'
const SESSION_EVENT = 'w9-session-event'

const isBrowser = () => typeof window !== 'undefined'

export function loadSession(): SessionPayload | null {
  if (!isBrowser()) return null
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as SessionPayload) : null
  } catch {
    return null
  }
}

function persistSession(session: SessionPayload | null) {
  if (!isBrowser()) return
  if (session) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
  } else {
    window.localStorage.removeItem(STORAGE_KEY)
  }
  window.dispatchEvent(new Event(SESSION_EVENT))
}

export function useSession() {
  const [session, setSession] = useState<SessionPayload | null>(() => loadSession())

  useEffect(() => {
    if (!isBrowser()) return
    const signalHandler = () => setSession(loadSession())
    const storageHandler = (event: StorageEvent) => {
      if (!event.key || event.key === STORAGE_KEY) {
        setSession(loadSession())
      }
    }
    window.addEventListener(SESSION_EVENT, signalHandler as EventListener)
    window.addEventListener('storage', storageHandler)
    return () => {
      window.removeEventListener(SESSION_EVENT, signalHandler as EventListener)
      window.removeEventListener('storage', storageHandler)
    }
  }, [])

  const save = useCallback((next: SessionPayload | null) => {
    persistSession(next)
    setSession(next)
  }, [])

  const logout = useCallback(() => {
    persistSession(null)
    setSession(null)
  }, [])

  const update = useCallback(
    (updates: Partial<SessionPayload>) => {
      setSession((prev) => {
        if (!prev) return prev
        const merged = { ...prev, ...updates }
        persistSession(merged)
        return merged
      })
    },
    []
  )

  return { session, saveSession: save, logout, updateSession: update }
}

