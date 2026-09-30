import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, Trash2, Plus } from 'lucide-react'
import { CaseAPI } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { Card, GradeBadge, StatusPill, Button } from '../components/UI'

export default function CasesPage() {
  const { user } = useAuth()
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')

  const load = () => CaseAPI.list().then((res) => setCases(res.data)).finally(() => setLoading(false))

  useEffect(() => { load() }, [])

  const handleDelete = async (id, e) => {
    e.preventDefault(); e.stopPropagation()
    if (!confirm('Delete this case and all its analysis data?')) return
    await CaseAPI.delete(id)
    load()
  }

  const filtered = cases.filter((c) => c.name.toLowerCase().includes(query.toLowerCase()))
  const canUpload = ['admin', 'soc_analyst', 'forensic_investigator'].includes(user.role)
  const canDelete = ['admin', 'forensic_investigator'].includes(user.role)

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Cases</h1>
          <p className="text-slate-400 text-sm mt-1">All PCAP forensic analysis cases</p>
        </div>
        {canUpload && (
          <Link to="/upload">
            <Button className="flex items-center gap-2"><Plus size={16} /> New Case</Button>
          </Link>
        )}
      </div>

      <div className="relative max-w-sm">
        <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search cases…"
          className="w-full bg-ink-800 border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50"
        />
      </div>

      <Card className="!p-0 overflow-hidden">
        {loading ? (
          <p className="text-sm text-slate-500 py-10 text-center">Loading…</p>
        ) : filtered.length === 0 ? (
          <p className="text-sm text-slate-500 py-10 text-center">No cases found.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                <th className="px-5 py-3 font-medium">Case Name</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Grade</th>
                <th className="px-5 py-3 font-medium">Risk Score</th>
                <th className="px-5 py-3 font-medium">Sessions</th>
                <th className="px-5 py-3 font-medium">Findings</th>
                <th className="px-5 py-3 font-medium">Created</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                  <td className="px-5 py-3.5">
                    <Link to={`/cases/${c.id}`} className="text-slate-200 font-medium hover:text-brand-300">
                      {c.name}
                    </Link>
                    <div className="text-xs text-slate-500">{c.filename}</div>
                  </td>
                  <td className="px-5 py-3.5"><StatusPill status={c.status} /></td>
                  <td className="px-5 py-3.5"><GradeBadge grade={c.risk_grade} /></td>
                  <td className="px-5 py-3.5 text-slate-300">{c.overall_risk_score}</td>
                  <td className="px-5 py-3.5 text-slate-300">{c.total_sessions}</td>
                  <td className="px-5 py-3.5">
                    <span className="text-red-400 font-medium">{c.critical_findings}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span className="text-orange-400">{c.high_findings}</span>
                  </td>
                  <td className="px-5 py-3.5 text-slate-500 text-xs">{new Date(c.created_at).toLocaleDateString()}</td>
                  <td className="px-5 py-3.5">
                    {canDelete && (
                      <button onClick={(e) => handleDelete(c.id, e)} className="text-slate-500 hover:text-red-400">
                        <Trash2 size={15} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
