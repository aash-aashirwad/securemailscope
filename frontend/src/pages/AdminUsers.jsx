import { useEffect, useState } from 'react'
import { AdminAPI } from '../api/client'
import { useAuth, ROLE_LABELS, ROLE_COLORS } from '../context/AuthContext'
import { Card, Button } from '../components/UI'

const ROLES = ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer']

export default function AdminUsers() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ full_name: '', email: '', password: '', role: 'soc_analyst', organization: 'NTRO' })
  const [createError, setCreateError] = useState('')
  const [creating, setCreating] = useState(false)

  const load = () => AdminAPI.listUsers().then((res) => setUsers(res.data)).finally(() => setLoading(false))
  useEffect(() => { load() }, [])

  const changeRole = async (userId, role) => {
    await AdminAPI.updateRole(userId, role)
    load()
  }

  const toggleStatus = async (userId, isActive) => {
    await AdminAPI.toggleStatus(userId, !isActive)
    load()
  }

  const createUser = async (e) => {
    e.preventDefault()
    setCreateError('')
    setCreating(true)
    try {
      await AdminAPI.createUser(form)
      setForm({ full_name: '', email: '', password: '', role: 'soc_analyst', organization: 'NTRO' })
      setShowCreate(false)
      load()
    } catch (err) {
      setCreateError(err.response?.data?.detail || 'Unable to create user')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-slate-400 text-sm mt-1">Manage roles and access for all SecureMailScope users</p>
        </div>
        <Button onClick={() => setShowCreate((s) => !s)}>{showCreate ? 'Cancel' : '+ New user'}</Button>
      </div>

      {showCreate && (
        <Card>
          <form onSubmit={createUser} className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Full name</label>
              <input required value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Email</label>
              <input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Temporary password</label>
              <input type="password" required minLength={10} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Role</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50">
                {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Organization</label>
              <input value={form.organization} onChange={(e) => setForm({ ...form, organization: e.target.value })}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50" />
            </div>
            {createError && <p className="col-span-2 text-sm text-red-400">{createError}</p>}
            <p className="col-span-2 text-xs text-slate-500">
              The user must change this password on first login.
            </p>
            <Button type="submit" disabled={creating} className="col-span-2">
              {creating ? 'Creating…' : 'Create user'}
            </Button>
          </form>
        </Card>
      )}

      <Card className="!p-0 overflow-hidden">
        {loading ? (
          <p className="text-sm text-slate-500 py-10 text-center">Loading…</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                <th className="px-5 py-3">User</th>
                <th className="px-5 py-3">Organization</th>
                <th className="px-5 py-3">Role</th>
                <th className="px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-5 py-3.5">
                    <div className="text-slate-200 font-medium">{u.full_name}</div>
                    <div className="text-xs text-slate-500">{u.email}</div>
                  </td>
                  <td className="px-5 py-3.5 text-slate-400">{u.organization}</td>
                  <td className="px-5 py-3.5">
                    <select
                      value={u.role} disabled={u.id === me.id}
                      onChange={(e) => changeRole(u.id, e.target.value)}
                      className={`text-xs rounded-lg px-2.5 py-1.5 border bg-transparent ${ROLE_COLORS[u.role]} disabled:opacity-60`}
                    >
                      {ROLES.map((r) => <option key={r} value={r} className="bg-ink-900 text-slate-200">{ROLE_LABELS[r]}</option>)}
                    </select>
                  </td>
                  <td className="px-5 py-3.5">
                    <button
                      disabled={u.id === me.id}
                      onClick={() => toggleStatus(u.id, u.is_active)}
                      className={`px-2.5 py-1 rounded-md text-xs font-semibold border disabled:opacity-60 ${
                        u.is_active
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-500/15 text-slate-400 border-slate-500/30'
                      }`}
                    >
                      {u.is_active ? 'Active' : 'Deactivated'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <SecurityPolicyCard />
    </div>
  )
}

function SecurityPolicyCard() {
  const [policy, setPolicy] = useState(null)
  const [form, setForm] = useState(null)
  const [bannedInput, setBannedInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const load = () => AdminAPI.getPolicy().then((res) => {
    setPolicy(res.data)
    setForm({ ...res.data })
    setBannedInput((res.data.banned_ciphers || []).join(', '))
  })
  useEffect(() => { load() }, [])

  const save = async (e) => {
    e.preventDefault()
    setSaving(true)
    setSaved(false)
    try {
      const banned_ciphers = bannedInput.split(',').map((s) => s.trim()).filter(Boolean)
      const res = await AdminAPI.updatePolicy({ ...form, banned_ciphers })
      setPolicy(res.data)
      setSaved(true)
    } finally {
      setSaving(false)
    }
  }

  if (!form) return null

  return (
    <Card>
      <h3 className="text-lg font-bold text-white mb-1">Cipher / TLS Security Policy</h3>
      <p className="text-slate-400 text-sm mb-4">
        Organization-defined minimum standard. Sessions weaker than this policy raise an
        additional "Organizational Policy Violation" finding on top of the built-in NIST/PCI-DSS baseline.
      </p>
      <form onSubmit={save} className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs font-medium text-slate-400 mb-1.5 block">Minimum TLS version</label>
          <select value={form.min_tls_version} onChange={(e) => setForm({ ...form, min_tls_version: e.target.value })}
            className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50">
            {['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={form.require_forward_secrecy}
              onChange={(e) => setForm({ ...form, require_forward_secrecy: e.target.checked })}
              className="rounded border-slate-700" />
            Require forward secrecy
          </label>
        </div>
        <div className="col-span-2">
          <label className="text-xs font-medium text-slate-400 mb-1.5 block">Banned cipher substrings (comma-separated)</label>
          <input value={bannedInput} onChange={(e) => setBannedInput(e.target.value)} placeholder="RC4, 3DES, NULL, EXPORT"
            className="w-full bg-ink-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50" />
        </div>
        <div className="col-span-2 flex items-center gap-3">
          <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save policy'}</Button>
          {saved && <span className="text-xs text-emerald-400">Saved — applies to future analyses.</span>}
        </div>
      </form>
    </Card>
  )
}
