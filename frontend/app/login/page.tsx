'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useSession } from '../../lib/session'
import Nav from '../components/Nav'
import Link from 'next/link'
import Turnstile from '../components/Turnstile'

export default function LoginPage() {
  const router = useRouter()
  const { session, saveSession, updateSession, logout } = useSession()
  const [form, setForm] = useState({ email: '', password: '' })
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const [changingPassword, setChangingPassword] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ current: '', next: '' })
  const [showReset, setShowReset] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetLoading, setResetLoading] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null)
  const [resetTurnstileToken, setResetTurnstileToken] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    if (session.mustChangePassword) {
      setChangingPassword(true)
      setPasswordForm((prev) => ({ ...prev, current: prev.current || form.password }))
      setMessage({
        type: 'error',
        text: 'Update your password before continuing.'
      })
      return
    }
    router.push(session.role === 'admin' ? '/manage' : '/')
  }, [session, router, form.password])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY
    if (siteKey && !turnstileToken) {
      setMessage({ type: 'error', text: 'Please complete the security check' })
      return
    }
    setLoading(true)
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, turnstile_token: turnstileToken })
      })
      if (!response.ok) {
        setMessage({ type: 'error', text: 'Invalid credentials' })
        return
      }
      const data = await response.json()
      saveSession({
        token: data.token,
        id: data.id,
        email: data.email,
        role: data.role,
        mustChangePassword: data.mustChangePassword
      })
      if (data.mustChangePassword) {
        setChangingPassword(true)
        setPasswordForm({ current: form.password, next: '' })
      } else {
        setMessage({ type: 'success', text: 'Signed in' })
      }
    } catch (error) {
      console.error('Failed to login:', error)
      setMessage({ type: 'error', text: 'Network error' })
    } finally {
      setLoading(false)
    }
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    if (!passwordForm.next.trim()) {
      setMessage({ type: 'error', text: 'New password required' })
      return
    }

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          current_password: passwordForm.current,
          new_password: passwordForm.next
        })
      })
      if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Failed to change password' }))
        setMessage({ type: 'error', text: error.message || 'Failed to change password' })
        return
      }
      updateSession({ mustChangePassword: false })
      setMessage({ type: 'success', text: 'Password updated. Redirecting…' })
      setTimeout(() => {
        router.push(session.role === 'admin' ? '/manage' : '/')
      }, 800)
    } catch (error) {
      console.error('Failed to change password:', error)
      setMessage({ type: 'error', text: 'Network error' })
    }
  }

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault()
    const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY
    if (siteKey && !resetTurnstileToken) {
      setMessage({ type: 'error', text: 'Please complete the security check' })
      return
    }
    setResetLoading(true)
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/auth/password-reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail, turnstile_token: resetTurnstileToken })
      })
      const data = await response.json().catch(() => ({ message: 'Request sent' }))
      if (response.ok) {
        setMessage({ type: 'success', text: data.message || 'If the email exists, a reset link was sent.' })
        setShowReset(false)
        setResetEmail('')
      } else {
        setMessage({ type: 'error', text: data.message || 'Unable to send reset email.' })
      }
    } catch (error) {
      console.error('Failed to request reset:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setResetLoading(false)
    }
  }

  return (
    <main className="app">
      <header className="header">
        <h1>W9 Mail / Access</h1>
        <p>Admins steer the Microsoft relay. Normal users send mail after authenticating.</p>
      </header>

      <Nav active="login" />

      {message && <div className={`status ${message.type}`}>{message.text}</div>}

      {!session && (
        <section className="box">
          <h2 className="section-title">Sign in</h2>
          <form className="form" onSubmit={handleLogin}>
            <div className="row">
              <label>Email</label>
              <input
                type="email"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                required
              />
            </div>
            <div className="row">
              <label>Password</label>
              <input
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                required
              />
            </div>
            <Turnstile 
              onVerify={(token) => setTurnstileToken(token)}
              onError={() => setTurnstileToken(null)}
            />
            <button className="button" type="submit" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <p className="hint">
            New here? <Link href="/signup">Create an account</Link>.
          </p>
          <p className="hint">
            <a href="#" onClick={(e) => { e.preventDefault(); setShowReset(true); setResetEmail(form.email); }}>Forgot password?</a>
          </p>
        </section>
      )}

      {!session && showReset && (
        <section className="box">
          <h2 className="section-title">Reset Password</h2>
          <form className="form" onSubmit={handlePasswordReset}>
            <div className="row">
              <label>Email</label>
              <input
                type="email"
                value={resetEmail}
                onChange={(e) => setResetEmail(e.target.value)}
                required
              />
            </div>
            <Turnstile 
              onVerify={(token) => setResetTurnstileToken(token)}
              onError={() => setResetTurnstileToken(null)}
            />
            <button className="button" type="submit" disabled={resetLoading}>
              {resetLoading ? 'Sending…' : 'Send Reset Link'}
            </button>
          </form>
          <p className="hint">
            <a href="#" onClick={(e) => { e.preventDefault(); setShowReset(false); setResetEmail(''); setMessage(null); }}>Back to login</a>
          </p>
        </section>
      )}

      {session && changingPassword && (
        <section className="box warning">
          <h2 className="section-title">Reset required</h2>
          <form className="form" onSubmit={handlePasswordChange}>
            <div className="row">
              <label>Current password</label>
              <input
                type="password"
                value={passwordForm.current}
                onChange={(e) => setPasswordForm({ ...passwordForm, current: e.target.value })}
                required
              />
            </div>
            <div className="row">
              <label>New password</label>
              <input
                type="password"
                value={passwordForm.next}
                onChange={(e) => setPasswordForm({ ...passwordForm, next: e.target.value })}
                required
              />
            </div>
            <button className="button" type="submit">
              Update password
            </button>
          </form>
          <button className="button subtle" onClick={logout}>
            Sign out
          </button>
        </section>
      )}
    </main>
  )
}

