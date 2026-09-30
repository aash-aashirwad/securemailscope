import { useEffect, useState } from 'react'
import { AdminAPI } from '../api/client'
import { Card } from '../components/UI'

const ACTION_COLORS = {
  login_success: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  login_failed: 'bg-red-500/15 text-red-300 border-red-500/30',
  login_blocked_locked: 'bg-red-500/15 text-red-300 border-red-500/30',
  login_blocked_inactive: 'bg-red-500/15 text-red-300 border-red-500/30',
  account_locked: 'bg-red-500/15 text-red-300 border-red-500/30',
  register: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  case_upload: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  case_deleted: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  role_changed: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  user_status_changed: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  admin_created_user: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  password_changed: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
}

export default function AuditLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    AdminAPI.auditLogs(500).then((res) => setLogs(res.data)).finally(() => setLoading(false))
  }, [])

  const filtered = logs.filter((l) =>
    !filter ||
    l.action.includes(filter.toLowerCase()) ||
    l.actor_email?.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Audit Trail</h1>
          <p className="text-slate-400 text-sm mt-1">
            Chain-of-custody log of authentication, case-handling, and admin actions across the system
          </p>
        </div>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by action or email…"
          className="bg-ink-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand-500"
        />
      </div>

      <Card className="!p-0 overflow-hidden">
        {loading ? (
          <p className="text-sm text-slate-500 py-10 text-center">Loading…</p>
        ) : filtered.length === 0 ? (
          <p className="text-sm text-slate-500 py-10 text-center">No matching audit events</p>
        ) : (
          <div className="max-h-[70vh] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-ink-900">
                <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                  <th className="px-5 py-3">Time</th>
                  <th className="px-5 py-3">Actor</th>
                  <th className="px-5 py-3">Action</th>
                  <th className="px-5 py-3">Resource</th>
                  <th className="px-5 py-3">Detail</th>
                  <th className="px-5 py-3">IP</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((l) => (
                  <tr key={l.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="px-5 py-3 text-slate-400 whitespace-nowrap">
                      {new Date(l.created_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3">
                      <div className="text-slate-200">{l.actor_email || '—'}</div>
                      <div className="text-xs text-slate-500">{l.actor_role}</div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`px-2 py-1 rounded-md text-xs font-semibold border ${ACTION_COLORS[l.action] || 'bg-slate-500/15 text-slate-300 border-slate-500/30'}`}>
                        {l.action}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-400">
                      {l.resource_type ? `${l.resource_type}:${(l.resource_id || '').slice(0, 8)}` : '—'}
                    </td>
                    <td className="px-5 py-3 text-slate-400 max-w-xs truncate" title={l.detail || ''}>
                      {l.detail || '—'}
                    </td>
                    <td className="px-5 py-3 text-slate-500">{l.ip_address || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
