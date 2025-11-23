'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useSession } from '../lib/session'
import Nav from './components/Nav'

interface EmailAccount {
  id: string
  email: string
  displayName: string
  isActive: boolean
}

interface EmailAlias {
  id: string
  aliasEmail: string
  displayName?: string | null
  isActive: boolean
  accountEmail: string
  accountDisplayName: string
  accountIsActive: boolean
}

export default function Home() {
  const { session, logout } = useSession()
  const [accounts, setAccounts] = useState<EmailAccount[]>([])
  const [aliases, setAliases] = useState<EmailAlias[]>([])
  const [loadingAccounts, setLoadingAccounts] = useState(false)
  const [loadingAliases, setLoadingAliases] = useState(false)
  const [sending, setSending] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [formData, setFormData] = useState({
    from: '',
    to: '',
    cc: '',
    bcc: '',
    subject: '',
    body: ''
  })

  const canCompose =
    session &&
    (session.role === 'user' || session.role === 'dev' || session.role === 'admin') &&
    !session.mustChangePassword

  useEffect(() => {
    if (!session?.token) {
      setAccounts([])
      setLoadingAccounts(false)
      return
    }

    const fetchAccounts = async () => {
      setLoadingAccounts(true)
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
        // Use public endpoint to get public accounts + owned accounts
        const response = await fetch(`${apiUrl}/accounts/public`, {
          headers: { Authorization: `Bearer ${session.token}` }
        })
        if (response.ok) {
          const data = await response.json()
          // Already filtered to active and (public or owned) by backend
          setAccounts(data)
          setFormData((prev) => {
            if (data.length && !prev.from) {
              return { ...prev, from: data[0].email }
            }
            return prev
          })
        } else if (response.status === 401) {
          logout()
        }
      } catch (error) {
        console.error('Failed to fetch accounts:', error)
      } finally {
        setLoadingAccounts(false)
      }
    }

    fetchAccounts()
  }, [session?.token, logout])

  useEffect(() => {
    if (!session?.token) {
      setAliases([])
      setLoadingAliases(false)
      return
    }

    const fetchAliases = async () => {
      setLoadingAliases(true)
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
        // Use public endpoint to get public aliases + owned aliases
        const response = await fetch(`${apiUrl}/aliases/public`, {
          headers: { Authorization: `Bearer ${session.token}` }
        })
        if (response.ok) {
          const data = await response.json()
          // Already filtered to active and (public or owned) by backend
          setAliases(data)
          setFormData((prev) => {
            if (data.length && !prev.from) {
              return { ...prev, from: data[0].aliasEmail }
            }
            return prev
          })
        } else if (response.status === 401) {
          logout()
        }
      } catch (error) {
        console.error('Failed to fetch aliases:', error)
      } finally {
        setLoadingAliases(false)
      }
    }

    fetchAliases()
  }, [session?.token, logout])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) {
      setMessage({ type: 'error', text: 'Sign in to send mail.' })
      return
    }
    setSending(true)
    setMessage(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          from: formData.from,
          to: formData.to,
          subject: formData.subject,
          body: formData.body,
          cc: formData.cc || undefined,
          bcc: formData.bcc || undefined,
          isHtml: true
        })
      })

      if (response.ok) {
        setMessage({ type: 'success', text: 'Email sent successfully!' })
        setFormData((prev) => ({
          ...prev,
          to: '',
          cc: '',
          bcc: '',
          subject: '',
          body: ''
        }))
      } else if (response.status === 403) {
        setMessage({ type: 'error', text: 'You are not allowed to send email yet.' })
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to send email' }))
        setMessage({ type: 'error', text: error.message || 'Failed to send email' })
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setSending(false)
    }
  }

  const senderOptions = [
    ...accounts.map((account) => ({ value: account.email, label: `${account.displayName} (${account.email})` })),
    ...aliases.map((alias) => ({ value: alias.aliasEmail, label: `${alias.displayName || alias.aliasEmail} · via ${alias.accountEmail}` }))
  ]

  const isLoadingSenders = loadingAccounts || loadingAliases
  const heroSubtitle = 'Open-source → move the world forward. W9 Mail keeps Microsoft SMTP/IMAP/POP3 programmable so teams can ship automations with confidence.'

  return (
    <main className="app">
      <header className="header">
        <h1>W9 Mail · Open-source mail rail</h1>
        <p>{heroSubtitle}</p>
        <div className="actions">
          <a className="button ghost" href="https://github.com/ShayNeeo/w9-mail" target="_blank" rel="noreferrer">/GitHub</a>
          {session ? (
            <>
              <Link className="button ghost" href="/profile">Profile</Link>
              <button className="button subtle" onClick={logout}>Sign out ({session.email})</button>
            </>
          ) : (
            <Link className="button" href="/login">Sign in</Link>
          )}
        </div>
      </header>

      <Nav active="home" />

      {message && <div className={`status ${message.type}`}>{message.text}</div>}

      {!session && (
        <section className="box">
          <h2 className="section-title">Authentication required</h2>
          <p>Sign in to unlock the composer. Admins can dispatch mail and manage senders.</p>
          <Link className="button" href="/login">Sign in</Link>
        </section>
      )}

      {session && session.mustChangePassword && (
        <section className="box warning">
          <h2 className="section-title">Password update required</h2>
          <p>Change your password from the login portal before sending email.</p>
        </section>
      )}

      {session && (
        <section className="box">
          <h2 className="section-title">Email Composer</h2>
          {!canCompose && <p className="status error">Update your password before sending email.</p>}
          {loadingAccounts ? (
            <div>Loading accounts…</div>
          ) : (
            <form className="form" onSubmit={handleSubmit}>
              <div className="row">
                <label htmlFor="from">From (sender)</label>
                <select
                  id="from"
                  value={formData.from}
                  onChange={(e) => setFormData({ ...formData, from: e.target.value })}
                  required
                  disabled={!senderOptions.length}
                >
                  <option value="">Select sender</option>
                  {senderOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
                {isLoadingSenders && <small>Loading senders…</small>}
                {!isLoadingSenders && !senderOptions.length && <small>Add an account or alias from Manage to start sending.</small>}
              </div>

              <div className="row">
                <label htmlFor="to">To (receiver)</label>
                <input
                  type="text"
                  id="to"
                  value={formData.to}
                  onChange={(e) => setFormData({ ...formData, to: e.target.value })}
                  placeholder="recipient@example.com"
                  required
                />
                <small>Separate multiple emails with commas</small>
              </div>

              <div className="row">
                <label htmlFor="cc">CC</label>
                <input
                  type="text"
                  id="cc"
                  value={formData.cc}
                  onChange={(e) => setFormData({ ...formData, cc: e.target.value })}
                  placeholder="cc@example.com"
                />
              </div>

              <div className="row">
                <label htmlFor="bcc">BCC</label>
                <input
                  type="text"
                  id="bcc"
                  value={formData.bcc}
                  onChange={(e) => setFormData({ ...formData, bcc: e.target.value })}
                  placeholder="bcc@example.com"
                />
              </div>

              <div className="row">
                <label htmlFor="subject">Title</label>
                <input
                  type="text"
                  id="subject"
                  value={formData.subject}
                  onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
                  placeholder="Email subject"
                  required
                />
              </div>

              <div className="row">
                <label htmlFor="body">Contents</label>
                <textarea
                  id="body"
                  value={formData.body}
                  onChange={(e) => setFormData({ ...formData, body: e.target.value })}
                  placeholder="Email content"
                  required
                />
              </div>

              <button
                className="button"
                type="submit"
                disabled={!canCompose || sending || !formData.from || !formData.to || !formData.subject || !formData.body}
              >
                {sending ? 'Sending…' : 'Send Email'}
              </button>
            </form>
          )}
        </section>
      )}

      <section className="box">
        <h2 className="section-title">Console Notes</h2>
        <ul className="list">
          <li>Principle: Open-source pipes move the world forward.</li>
          <li>Sender accounts and aliases live under Manage → Admin only.</li>
          <li>Team members authenticate and dispatch through this composer.</li>
          <li>GitHub issues power the roadmap—drop ideas at /ShayNeeo/w9-mail.</li>
        </ul>
      </section>
    </main>
  )
}
