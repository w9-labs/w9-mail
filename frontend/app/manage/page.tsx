'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useSession } from '../../lib/session'
import Nav from '../components/Nav'

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
  accountId: string
  accountEmail: string
  accountDisplayName: string
  accountIsActive: boolean
}

interface DefaultSender {
  senderType: 'account' | 'alias'
  senderId: string
  email: string
  displayLabel: string
  viaDisplay?: string | null
  isActive: boolean
}

interface UserSummary {
  id: string
  email: string
  role: RoleOption
  mustChangePassword: boolean
}

type RoleOption = 'admin' | 'dev' | 'user'

export default function ManagePage() {
  const { session, logout } = useSession()
  const [accounts, setAccounts] = useState<EmailAccount[]>([])
  const [defaultSender, setDefaultSender] = useState<DefaultSender | null>(null)
  const [aliases, setAliases] = useState<EmailAlias[]>([])
  const [users, setUsers] = useState<UserSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)
  const [editingPassword, setEditingPassword] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [formData, setFormData] = useState({
    email: '',
    displayName: '',
    password: '',
    isActive: true
  })
  const [aliasForm, setAliasForm] = useState({
    accountId: '',
    aliasEmail: '',
    displayName: '',
    isActive: true
  })
  const [defaultSelection, setDefaultSelection] = useState('')
  const [savingDefault, setSavingDefault] = useState(false)
  const [loadingAliases, setLoadingAliases] = useState(false)
  const [userForm, setUserForm] = useState<{
    email: string
    password: string
    role: RoleOption
  }>({
    email: '',
    password: '',
    role: 'user'
  })
  const [editingUserPassword, setEditingUserPassword] = useState<string | null>(null)
  const [userPassword, setUserPassword] = useState('')

  useEffect(() => {
    if (!session?.token) {
      setLoading(false)
      return
    }
    const bootstrap = async () => {
      await Promise.all([fetchAccounts(), fetchAliases(), fetchUsers(), fetchDefaultSender()])
      setLoading(false)
    }
    bootstrap()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.token])

  const fetchAccounts = async () => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/accounts`, {
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        const data = await response.json()
        setAccounts(data)
      } else if (response.status === 401) {
        logout()
      }
    } catch (error) {
      console.error('Failed to fetch accounts:', error)
    }
  }

  const fetchAliases = async () => {
    if (!session?.token) return
    setLoadingAliases(true)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/aliases`, {
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        const data = await response.json()
        setAliases(data)
      } else if (response.status === 401) {
        logout()
      }
    } catch (error) {
      console.error('Failed to fetch aliases:', error)
    } finally {
      setLoadingAliases(false)
    }
  }

  const fetchDefaultSender = async () => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/settings/default-sender`, {
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        const data = await response.json().catch(() => null)
        setDefaultSender(data)
        if (data) {
          setDefaultSelection(`${data.senderType}:${data.senderId}`)
        }
      } else if (response.status === 401) {
        logout()
      }
    } catch (error) {
      console.error('Failed to fetch default sender:', error)
    }
  }

  useEffect(() => {
    if (!aliasForm.accountId && accounts.length) {
      setAliasForm((prev) => ({ ...prev, accountId: accounts[0].id }))
    }
  }, [accounts, aliasForm.accountId])

  useEffect(() => {
    if (defaultSender) {
      setDefaultSelection(`${defaultSender.senderType}:${defaultSender.senderId}`)
    }
  }, [defaultSender])

  const fetchUsers = async () => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users`, {
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok) {
        const data = await response.json()
        setUsers(data)
      }
    } catch (error) {
      console.error('Failed to fetch users:', error)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/accounts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify(formData)
      })
      const data = await response.json()

      if (response.ok && data.status === 'success') {
        setMessage({ type: 'success', text: data.message || 'Account created successfully!' })
        fetchAccounts()
        setFormData({ email: '', displayName: '', password: '', isActive: true })
      } else {
        setMessage({ type: 'error', text: data.message || 'Failed to create account' })
      }
    } catch (error) {
      console.error('Failed to create account:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleAliasSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    if (!aliasForm.accountId || !aliasForm.aliasEmail.trim()) {
      setMessage({ type: 'error', text: 'Alias email and credential are required' })
      return
    }
    setMessage(null)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const payload = {
        accountId: aliasForm.accountId,
        aliasEmail: aliasForm.aliasEmail.trim(),
        displayName: aliasForm.displayName.trim() ? aliasForm.displayName.trim() : undefined,
        isActive: aliasForm.isActive
      }
      const response = await fetch(`${apiUrl}/aliases`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify(payload)
      })
      if (response.ok) {
        const data = await response.json()
        setAliases((prev) => [...prev, data])
        setMessage({ type: 'success', text: 'Alias added successfully' })
        setAliasForm((prev) => ({
          ...prev,
          aliasEmail: '',
          displayName: ''
        }))
        await fetchAliases()
        await fetchDefaultSender()
      } else if (response.status === 409) {
        setMessage({ type: 'error', text: 'Alias email already exists' })
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to create alias' }))
        setMessage({ type: 'error', text: error.message || 'Failed to create alias' })
      }
    } catch (error) {
      console.error('Failed to create alias:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleDefaultSenderSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    if (!defaultSelection) {
      setMessage({ type: 'error', text: 'Pick a sender first' })
      return
    }
    const [senderType, senderId] = defaultSelection.split(':')
    if (!senderType || !senderId) {
      setMessage({ type: 'error', text: 'Invalid selection' })
      return
    }
    setSavingDefault(true)
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/settings/default-sender`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ senderType, senderId })
      })
      if (response.ok) {
        const data = await response.json()
        setDefaultSender(data)
        setMessage({ type: 'success', text: 'Default sender updated' })
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to set sender' }))
        setMessage({ type: 'error', text: error.message || 'Failed to set sender' })
      }
    } catch (error) {
      console.error('Failed to set default sender:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setSavingDefault(false)
    }
  }

  const toggleActive = async (id: string, isActive: boolean) => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/accounts/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ isActive: !isActive })
      })
      if (response.ok) {
        const data = await response.json()
        setAccounts((prev) => prev.map((acc) => (acc.id === id ? { ...acc, isActive: data.isActive } : acc)))
        setAliases((prev) =>
          prev.map((alias) =>
            alias.accountId === id ? { ...alias, accountIsActive: data.isActive } : alias
          )
        )
        setMessage({ type: 'success', text: `Account ${!isActive ? 'activated' : 'deactivated'} successfully` })
        await fetchDefaultSender()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to update account' }))
        setMessage({ type: 'error', text: error.message || 'Failed to update account' })
      }
    } catch (error) {
      console.error('Failed to update account:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const toggleAliasActive = async (id: string, isActive: boolean) => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/aliases/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ isActive: !isActive })
      })
      if (response.ok) {
        const data = await response.json()
        setAliases((prev) => prev.map((alias) => (alias.id === id ? data : alias)))
        setMessage({ type: 'success', text: `Alias ${!isActive ? 'activated' : 'deactivated'} successfully` })
        await fetchDefaultSender()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to update alias' }))
        setMessage({ type: 'error', text: error.message || 'Failed to update alias' })
      }
    } catch (error) {
      console.error('Failed to update alias:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleDeleteAlias = async (id: string) => {
    if (!session?.token) return
    if (!window.confirm('Delete this alias? This cannot be undone.')) {
      return
    }
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/aliases/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok || response.status === 204) {
        setAliases((prev) => prev.filter((alias) => alias.id !== id))
        setMessage({ type: 'success', text: 'Alias removed' })
        await fetchDefaultSender()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to delete alias' }))
        setMessage({ type: 'error', text: error.message || 'Failed to delete alias' })
      }
    } catch (error) {
      console.error('Failed to delete alias:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handlePasswordChange = async (id: string) => {
    if (!newPassword.trim()) {
      setMessage({ type: 'error', text: 'Password cannot be empty' })
      return
    }
    if (!session?.token) return

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/accounts/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ password: newPassword })
      })
      if (response.ok) {
        setMessage({ type: 'success', text: 'Password updated successfully' })
        setEditingPassword(null)
        setNewPassword('')
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to update password' }))
        setMessage({ type: 'error', text: error.message || 'Failed to update password' })
      }
    } catch (error) {
      console.error('Failed to update password:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleDeleteAccount = async (id: string) => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/accounts/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok || response.status === 204) {
        setAccounts((prev) => prev.filter((acc) => acc.id !== id))
        setAliases((prev) => prev.filter((alias) => alias.accountId !== id))
        setMessage({ type: 'success', text: 'Account removed' })
        await fetchDefaultSender()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to delete account' }))
        setMessage({ type: 'error', text: error.message || 'Failed to delete account' })
      }
    } catch (error) {
      console.error('Failed to delete account:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleUserCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify(userForm)
      })
      if (response.ok) {
        setMessage({ type: 'success', text: 'User created' })
        setUserForm({ email: '', password: '', role: 'user' })
        fetchUsers()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to create user' }))
        setMessage({ type: 'error', text: error.message || 'Failed to create user' })
      }
    } catch (error) {
      console.error('Failed to create user:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleUserPasswordChange = async (id: string) => {
    if (!session?.token) return
    if (!userPassword.trim()) {
      setMessage({ type: 'error', text: 'Password cannot be empty' })
      return
    }
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ password: userPassword })
      })
      if (response.ok) {
        setMessage({ type: 'success', text: 'User password updated' })
        setEditingUserPassword(null)
        setUserPassword('')
        fetchUsers()
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to update password' }))
        setMessage({ type: 'error', text: error.message || 'Failed to update password' })
      }
    } catch (error) {
      console.error('Failed to update user password:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleUserDelete = async (id: string) => {
    if (!session?.token) return
    if (!window.confirm('Delete this user? This cannot be undone.')) {
      return
    }
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.token}` }
      })
      if (response.ok || response.status === 204) {
        setMessage({ type: 'success', text: 'User deleted' })
        setUsers((prev) => prev.filter((u) => u.id !== id))
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to delete user' }))
        setMessage({ type: 'error', text: error.message || 'Failed to delete user' })
      }
    } catch (error) {
      console.error('Failed to delete user:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleRoleChange = async (userId: string, newRole: RoleOption) => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users/${userId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ role: newRole })
      })
      const data = await response.json()
      if (response.ok) {
        setMessage({ type: 'success', text: 'User role updated successfully!' })
        fetchUsers() // Refresh the user list
      } else {
        setMessage({ type: 'error', text: data.message || 'Failed to update user role' })
      }
    } catch (error) {
      console.error('Failed to update user role:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const handleMustChangePasswordToggle = async (userId: string, currentValue: boolean) => {
    if (!session?.token) return
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || '/api'
      const response = await fetch(`${apiUrl}/users/${userId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ mustChangePassword: !currentValue })
      })
      const data = await response.json()
      if (response.ok) {
        setMessage({ 
          type: 'success', 
          text: `User ${!currentValue ? 'will be required' : 'no longer required'} to change password on next login` 
        })
        fetchUsers() // Refresh the user list
      } else {
        setMessage({ type: 'error', text: data.message || 'Failed to update password change requirement' })
      }
    } catch (error) {
      console.error('Failed to update password change requirement:', error)
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    }
  }

  const defaultSenderOptions = [
    ...accounts.map((account) => ({
      value: `account:${account.id}`,
      label: `${account.displayName} (${account.email})`
    })),
    ...aliases.map((alias) => ({
      value: `alias:${alias.id}`,
      label: `${alias.aliasEmail} · via ${alias.accountEmail}`
    }))
  ]

  const isAdmin = session && session.role === 'admin'
  const isDevOrAdmin = session && (session.role === 'admin' || session.role === 'dev')

  if (loading) {
    return (
      <main className="app">
        <div className="box">Loading…</div>
      </main>
    )
  }

  if (!session) {
    return (
      <main className="app">
        <header className="header">
          <h1>W9 Mail / Accounts</h1>
          <p>Admin login required to touch the mailing database.</p>
        </header>
        <section className="box">
          <p>Authenticate before managing sender accounts.</p>
          <Link className="button" href="/login">
            Sign in
          </Link>
        </section>
      </main>
    )
  }

  if (!isDevOrAdmin) {
    return (
      <main className="app">
        <header className="header">
          <h1>W9 Mail / Accounts</h1>
          <p>Only dev users and admins can manage the Microsoft sender registry.</p>
        </header>
        <Nav active="manage" />
        <section className="box">
          <p>This section is locked. To add accounts and aliases, you need to apply to become a Dev user.</p>
          <p style={{ marginTop: '16px' }}>
            Send an email to <a href="mailto:hi@w9.nu" style={{ color: '#fff', textDecoration: 'underline' }}>hi@w9.nu</a> with valid reasons for your application.
          </p>
          <button className="button subtle" onClick={logout} style={{ marginTop: '16px' }}>
            Switch account
          </button>
        </section>
      </main>
    )
  }

  return (
    <main className="app">
      <header className="header">
        <h1>W9 Mail / Accounts</h1>
        <p>Register Microsoft senders, flip activation, rotate secrets.</p>
      </header>

      <Nav active="manage" />

      {message && <div className={`status ${message.type}`}>{message.text}</div>}

      <section className="box">
        <h2 className="section-title">Add Email Account</h2>
        <form className="form" onSubmit={handleSubmit}>
          <div className="row">
            <label>Email</label>
            <input
              type="email"
              placeholder="sender@domain.com"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
            />
          </div>
          <div className="row">
            <label>Display name</label>
            <input
              type="text"
              placeholder="Operations Bot"
              value={formData.displayName}
              onChange={(e) => setFormData({ ...formData, displayName: e.target.value })}
              required
            />
          </div>
          <div className="row">
            <label>Password / App password</label>
            <input
              type="password"
              placeholder="••••••••"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
            />
          </div>
          <label>
            <input
              type="checkbox"
              checked={formData.isActive}
              onChange={(e) => setFormData({ ...formData, isActive: e.target.checked })}
            />{' '}
            active
          </label>
          <button className="button" type="submit">
            Add account
          </button>
        </form>
      </section>

      {isAdmin && (
        <section className="box">
          <h2 className="section-title">System sender (verification + reset)</h2>
          <p>Automatic emails are dispatched through this sender. Pick an active credential or alias.</p>
          <form className="form" onSubmit={handleDefaultSenderSave}>
            <div className="row">
              <label>Sender</label>
              <select
                value={defaultSelection}
                onChange={(e) => setDefaultSelection(e.target.value)}
                disabled={!defaultSenderOptions.length || savingDefault}
              >
                <option value="">Select sender</option>
                {defaultSenderOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {!defaultSenderOptions.length && (
                <small>Add an account or alias to enable automatic emails.</small>
              )}
            </div>
            <button className="button" type="submit" disabled={!defaultSenderOptions.length || savingDefault}>
              {savingDefault ? 'Saving…' : defaultSender ? 'Update default' : 'Set default'}
            </button>
          </form>
          {defaultSender ? (
            <div className="status success">
              Default: {defaultSender.displayLabel} ({defaultSender.email})
              {defaultSender.viaDisplay && <span> · {defaultSender.viaDisplay}</span>}
            </div>
          ) : (
            <div className="status warning">System emails are disabled until a default sender is set.</div>
          )}
        </section>
      )}

      <section className="box">
        <h2 className="section-title">Sender aliases</h2>
        <form className="form" onSubmit={handleAliasSubmit}>
          <div className="row">
            <label>Credential</label>
            <select
              value={aliasForm.accountId}
              onChange={(e) => setAliasForm({ ...aliasForm, accountId: e.target.value })}
              required
              disabled={!accounts.length}
            >
              <option value="">Select credential</option>
              {accounts.map((account) => (
                <option key={account.id} value={account.id}>
                  {account.displayName} ({account.email})
                </option>
              ))}
            </select>
            {!accounts.length && <small>Add an account before creating aliases.</small>}
          </div>
          <div className="row">
            <label>Alias email</label>
            <input
              type="email"
              value={aliasForm.aliasEmail}
              onChange={(e) => setAliasForm({ ...aliasForm, aliasEmail: e.target.value })}
              placeholder="alias@domain.com"
              required
            />
          </div>
          <div className="row">
            <label>Display name (optional)</label>
            <input
              type="text"
              value={aliasForm.displayName}
              onChange={(e) => setAliasForm({ ...aliasForm, displayName: e.target.value })}
              placeholder="Marketing Bot"
            />
          </div>
          <label>
            <input
              type="checkbox"
              checked={aliasForm.isActive}
              onChange={(e) => setAliasForm({ ...aliasForm, isActive: e.target.checked })}
            />{' '}
            active
          </label>
          <button className="button" type="submit" disabled={!accounts.length}>
            Add alias
          </button>
        </form>

        {loadingAliases ? (
          <p>Loading aliases…</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Alias</th>
                  <th>Display</th>
                  <th>Credential</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {aliases.length === 0 && (
                  <tr>
                    <td colSpan={5}>No aliases yet.</td>
                  </tr>
                )}
                {aliases.map((alias) => (
                  <tr key={alias.id}>
                    <td>{alias.aliasEmail}</td>
                    <td>{alias.displayName || '—'}</td>
                    <td>{alias.accountEmail}</td>
                    <td>
                      {alias.isActive ? 'Active' : 'Inactive'}
                      {!alias.accountIsActive && <span className="status error">Credential inactive</span>}
                    </td>
                    <td>
                      {isAdmin ? (
                        <div className="actions">
                          <button onClick={() => toggleAliasActive(alias.id, alias.isActive)}>
                            {alias.isActive ? 'Deactivate' : 'Activate'}
                          </button>
                          <button onClick={() => handleDeleteAlias(alias.id)}>Delete</button>
                        </div>
                      ) : (
                        <span>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="box">
        <h2 className="section-title">Account registry</h2>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Display</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account) => (
                <tr key={account.id}>
                  <td>{account.email}</td>
                  <td>{account.displayName}</td>
                  <td>{account.isActive ? 'Active' : 'Inactive'}</td>
                  <td>
                    {isAdmin ? (
                      <div className="actions">
                        <button onClick={() => toggleActive(account.id, account.isActive)}>
                          {account.isActive ? 'Deactivate' : 'Activate'}
                        </button>
                        {editingPassword === account.id ? (
                          <div className="password-inline">
                            <input
                              type="password"
                              placeholder="New password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  handlePasswordChange(account.id)
                                }
                              }}
                            />
                            <button onClick={() => handlePasswordChange(account.id)}>Save</button>
                            <button
                              onClick={() => {
                                setEditingPassword(null)
                                setNewPassword('')
                              }}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => {
                              setEditingPassword(account.id)
                              setNewPassword('')
                            }}
                          >
                            Change password
                          </button>
                        )}
                        <button onClick={() => handleDeleteAccount(account.id)}>Delete</button>
                      </div>
                    ) : (
                      <span>—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {isAdmin && (
        <section className="box">
          <h2 className="section-title">User access</h2>
        <form className="form" onSubmit={handleUserCreate}>
          <div className="row">
            <label>User email</label>
            <input
              type="email"
              value={userForm.email}
              onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
              required
            />
          </div>
          <div className="row">
            <label>Temporary password</label>
            <input
              type="password"
              value={userForm.password}
              onChange={(e) => setUserForm({ ...userForm, password: e.target.value })}
              required
            />
          </div>
          <div className="row">
            <label>Role</label>
            <select
              value={userForm.role}
              onChange={(e) => setUserForm({ ...userForm, role: e.target.value as RoleOption })}
            >
              <option value="user">Normal user</option>
              <option value="dev">Developer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <button className="button" type="submit">
            Invite user
          </button>
        </form>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Must change password</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>
                    <select
                      value={user.role}
                      onChange={(e) => handleRoleChange(user.id, e.target.value as RoleOption)}
                      style={{ padding: '4px 8px', fontSize: '14px' }}
                    >
                      <option value="user">user</option>
                      <option value="dev">dev</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>
                    <button
                      onClick={() => handleMustChangePasswordToggle(user.id, user.mustChangePassword)}
                      style={{
                        padding: '4px 12px',
                        fontSize: '14px',
                        backgroundColor: user.mustChangePassword ? '#ff6b6b' : '#51cf66',
                        color: '#fff',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                    >
                      {user.mustChangePassword ? 'Yes (click to disable)' : 'No (click to require)'}
                    </button>
                  </td>
                  <td>
                    <div className="actions">
                      {editingUserPassword === user.id ? (
                        <>
                          <input
                            type="password"
                            placeholder="New password"
                            value={userPassword}
                            onChange={(e) => setUserPassword(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                handleUserPasswordChange(user.id)
                              }
                            }}
                          />
                          <button onClick={() => handleUserPasswordChange(user.id)}>Save</button>
                          <button
                            onClick={() => {
                              setEditingUserPassword(null)
                              setUserPassword('')
                            }}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={() => {
                            setEditingUserPassword(user.id)
                            setUserPassword('')
                          }}
                        >
                          Change password
                        </button>
                      )}
                      <button onClick={() => handleUserDelete(user.id)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </section>
      )}
    </main>
  )
}

