'use client'

import { useState } from 'react'
import React from 'react'
import Link from 'next/link'
import { useSession } from '../../lib/session'
import Nav from '../components/Nav'

interface ApiToken {
  id: string
  name?: string | null
  createdAt: string
  lastUsedAt?: string | null
}

export default function ProfilePage() {
  const { session, logout } = useSession()
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [changingPassword, setChangingPassword] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ old: '', new: '', confirm: '' })
  const [changing, setChanging] = useState(false)
  const [apiTokens, setApiTokens] = useState<ApiToken[]>([])
  const [loadingTokens, setLoadingTokens] = useState(false)
  const [creatingToken, setCreatingToken] = useState(false)
  const [newTokenName, setNewTokenName] = useState('')
  const [newlyCreatedToken, setNewlyCreatedToken] = useState<{ id: string; token: string; name?: string | null } | null>(null)

  const fetchApiTokens = async () => {
    if (!session?.token) return
    setLoadingTokens(true)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/api-tokens`, {
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        const data = await response.json()
        setApiTokens(data)
      } else if (response.status === 401) {
        logout()
      }
    } catch (error) {
      console.error('Failed to fetch API tokens:', error)
    } finally {
      setLoadingTokens(false)
    }
  }

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    setCreatingToken(true)
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/api-tokens`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ name: newTokenName || null })
      })
      const data = await response.json()
      if (response.ok) {
        setNewlyCreatedToken({ id: data.id, token: data.token, name: data.name })
        setNewTokenName('')
        setMessage({ type: 'success', text: data.message || 'API token created successfully' })
        fetchApiTokens()
      } else {
        setMessage({ type: 'error', text: data.message || data.error || 'Failed to create API token' })
      }
    } catch (error) {
      console.error('Failed to create API token:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setCreatingToken(false)
    }
  }

  const handleDeleteToken = async (tokenId: string) => {
    if (!session?.token) return
    if (!confirm('Are you sure you want to delete this API token? This action cannot be undone.')) {
      return
    }
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/api-tokens/${tokenId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        setMessage({ type: 'success', text: 'API token deleted successfully' })
        fetchApiTokens()
      } else {
        const data = await response.json().catch(() => ({ error: 'Failed to delete API token' }))
        setMessage({ type: 'error', text: data.error || 'Failed to delete API token' })
      }
    } catch (error) {
      console.error('Failed to delete API token:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  React.useEffect(() => {
    if (session) {
      fetchApiTokens()
    }
  }, [session])

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    
    if (passwordForm.new !== passwordForm.confirm) {
      setMessage({ type: 'error', text: 'New passwords do not match' })
      return
    }
    if (passwordForm.new.length < 8) {
      setMessage({ type: 'error', text: 'Password must be at least 8 characters' })
      return
    }

    setChanging(true)
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          current_password: passwordForm.old,
          new_password: passwordForm.new
        })
      })
      const data = await response.json().catch(() => ({ message: 'Failed to change password' }))
      if (response.ok) {
        setMessage({ type: 'success', text: data.message || 'Password updated successfully' })
        setPasswordForm({ old: '', new: '', confirm: '' })
        setChangingPassword(false)
      } else {
        setMessage({ type: 'error', text: data.message || data.error || 'Failed to change password' })
      }
    } catch (error) {
      console.error('Failed to change password:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setChanging(false)
    }
  }

  return (
    <main className="app">
      <header className="header">
        <h1>W9 Mail / Profile</h1>
        <p>Review your access and trigger password resets.</p>
      </header>

      <Nav active="profile" />

      {message && <div className={`status ${message.type}`}>{message.text}</div>}

      {!session ? (
        <section className="box">
          <h2 className="section-title">Authentication required</h2>
          <p>Sign in to see your profile.</p>
          <Link className="button" href="/login">
            Go to login
          </Link>
        </section>
      ) : (
        <>
          <section className="box">
            <h2 className="section-title">Account details</h2>
            <ul className="list">
              <li>Email: {session.email}</li>
              <li>Role: {session.role}</li>
              <li>Must change password: {session.mustChangePassword ? 'Yes' : 'No'}</li>
            </ul>
            <div className="actions">
              <button className="button subtle" onClick={logout}>
                Sign out
              </button>
            </div>
          </section>

          <section className="box">
            <h2 className="section-title">Change Password</h2>
            {!changingPassword ? (
              <>
                <p>Update your password. You&apos;ll need to provide your current password.</p>
                <button className="button" onClick={() => setChangingPassword(true)}>
                  Change Password
                </button>
              </>
            ) : (
              <form className="form" onSubmit={handleChangePassword}>
                <div className="row">
                  <label>Old Password</label>
                  <input
                    type="password"
                    value={passwordForm.old}
                    onChange={(e) => setPasswordForm({ ...passwordForm, old: e.target.value })}
                    required
                  />
                </div>
                <div className="row">
                  <label>New Password</label>
                  <input
                    type="password"
                    value={passwordForm.new}
                    onChange={(e) => setPasswordForm({ ...passwordForm, new: e.target.value })}
                    required
                    minLength={8}
                  />
                </div>
                <div className="row">
                  <label>Confirm New Password</label>
                  <input
                    type="password"
                    value={passwordForm.confirm}
                    onChange={(e) => setPasswordForm({ ...passwordForm, confirm: e.target.value })}
                    required
                    minLength={8}
                  />
                </div>
                <button className="button" type="submit" disabled={changing}>
                  {changing ? 'Changing…' : 'Change Password'}
                </button>
                <button
                  className="button subtle"
                  type="button"
                  onClick={() => {
                    setChangingPassword(false)
                    setPasswordForm({ old: '', new: '', confirm: '' })
                    setMessage(null)
                  }}
                >
                  Cancel
                </button>
              </form>
            )}
            <p className="hint">
              Forgot your password? Go to the <Link href="/login">login page</Link> to request a reset.
            </p>
          </section>

          <section className="box">
            <h2 className="section-title">API Tokens</h2>
            <p>Create API tokens to authenticate API requests. Tokens are only shown once when created.</p>
            
            {newlyCreatedToken && (
              <div className="box" style={{ backgroundColor: '#1a1a1a', border: '2px solid #4a9eff', marginBottom: '1rem' }}>
                <p style={{ margin: '0 0 0.5rem 0', color: '#fff', fontWeight: 'bold' }}>
                  ⚠️ Save this token now - you won&apos;t be able to see it again!
                </p>
                <div style={{ backgroundColor: '#000', padding: '0.75rem', borderRadius: '4px', marginBottom: '0.5rem' }}>
                  <code style={{ color: '#4a9eff', wordBreak: 'break-all', fontSize: '14px' }}>
                    {newlyCreatedToken.token}
                  </code>
                </div>
                <button
                  className="button subtle"
                  onClick={() => {
                    navigator.clipboard.writeText(newlyCreatedToken.token)
                    setMessage({ type: 'success', text: 'Token copied to clipboard!' })
                  }}
                >
                  Copy Token
                </button>
                <button
                  className="button subtle"
                  onClick={() => setNewlyCreatedToken(null)}
                  style={{ marginLeft: '0.5rem' }}
                >
                  I&apos;ve Saved It
                </button>
              </div>
            )}

            <form className="form" onSubmit={handleCreateToken} style={{ marginBottom: '1.5rem' }}>
              <div className="row">
                <label>Token Name (optional)</label>
                <input
                  type="text"
                  value={newTokenName}
                  onChange={(e) => setNewTokenName(e.target.value)}
                  placeholder="e.g., Production API, Development"
                />
              </div>
              <button className="button" type="submit" disabled={creatingToken}>
                {creatingToken ? 'Creating…' : 'Create API Token'}
              </button>
            </form>

            <h3 style={{ marginTop: '1.5rem', marginBottom: '0.5rem' }}>Your API Tokens</h3>
            {loadingTokens ? (
              <p>Loading tokens...</p>
            ) : apiTokens.length === 0 ? (
              <p>No API tokens created yet.</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #333' }}>
                    <th style={{ textAlign: 'left', padding: '0.5rem' }}>Name</th>
                    <th style={{ textAlign: 'left', padding: '0.5rem' }}>Created</th>
                    <th style={{ textAlign: 'left', padding: '0.5rem' }}>Last Used</th>
                    <th style={{ textAlign: 'right', padding: '0.5rem' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {apiTokens.map((token) => (
                    <tr key={token.id} style={{ borderBottom: '1px solid #222' }}>
                      <td style={{ padding: '0.5rem' }}>{token.name || '—'}</td>
                      <td style={{ padding: '0.5rem' }}>{new Date(token.createdAt).toLocaleString()}</td>
                      <td style={{ padding: '0.5rem' }}>
                        {token.lastUsedAt ? new Date(token.lastUsedAt).toLocaleString() : 'Never'}
                      </td>
                      <td style={{ padding: '0.5rem', textAlign: 'right' }}>
                        <button
                          className="button subtle"
                          onClick={() => handleDeleteToken(token.id)}
                          style={{ color: '#ff4444' }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </main>
  )
}

