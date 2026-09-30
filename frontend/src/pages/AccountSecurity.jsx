import { useState } from 'react'
import { AuthAPI } from '../api/client'
import { useAuth, ROLE_LABELS, ROLE_COLORS } from '../context/AuthContext'
import { Card } from '../components/UI'

export default function AccountSecurity() {
  const { user, refreshMe } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    if (next !== confirm) {
      setError('New passwords do not match')
      return
    }
    setBusy(true)
    try {
      await AuthAPI.changePassword(current, next)
      setSuccess('Password updated successfully.')
      setCurrent(''); setNext(''); setConfirm('')
      await refreshMe()
    } catch (err) {
      setError(err.response?.data?.detail || 'Unable to update password')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-8 max-w-xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Account Security</h1>
        <p className="text-slate-400 text-sm mt-1">Manage your credentials for SecureMailScope</p>
      </div>

      <Card className="space-y-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-brand-600/30 flex items-center justify-center text-sm font-bold text-brand-200">
            {user?.full_name?.[0]?.toUpperCase()}
          </div>
          <div>
            <div className="text-slate-200 font-medium">{user?.full_name}</div>
            <div className="text-xs text-slate-500">{user?.email}</div>
          </div>
          <span className={`ml-auto px-2 py-1 rounded-md text-xs border ${ROLE_COLORS[user?.role]}`}>
            {ROLE_LABELS[user?.role]}
          </span>
        </div>
      </Card>

      {user?.must_change_password && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-sm px-4 py-3">
          Your account is using a temporary password. Please set a new one below before continuing.
        </div>
      )}

      <Card>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="text-xs uppercase tracking-wider text-slate-400 font-medium">Current password</label>
            <input
              type="password" required value={current} onChange={(e) => setCurrent(e.target.value)}
              className="mt-1 w-full bg-ink-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-brand-500"
            />
          </div>
          <div>
            <label className="text-xs uppercase tracking-wider text-slate-400 font-medium">New password</label>
            <input
              type="password" required value={next} onChange={(e) => setNext(e.target.value)}
              className="mt-1 w-full bg-ink-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-brand-500"
            />
            <p className="text-xs text-slate-500 mt-1">At least 10 characters, with upper/lowercase, a digit and a symbol.</p>
          </div>
          <div>
            <label className="text-xs uppercase tracking-wider text-slate-400 font-medium">Confirm new password</label>
            <input
              type="password" required value={confirm} onChange={(e) => setConfirm(e.target.value)}
              className="mt-1 w-full bg-ink-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-brand-500"
            />
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}
          {success && <p className="text-sm text-emerald-400">{success}</p>}

          <button
            type="submit" disabled={busy}
            className="w-full bg-brand-600 hover:bg-brand-500 disabled:opacity-60 text-white font-medium rounded-lg py-2.5 text-sm transition-colors"
          >
            {busy ? 'Updating…' : 'Update password'}
          </button>
        </form>
      </Card>
    </div>
  )
}
