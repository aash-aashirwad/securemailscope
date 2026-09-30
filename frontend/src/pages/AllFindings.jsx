import { useEffect, useState } from 'react'
import { CaseAPI } from '../api/client'
import { Card, SeverityBadge } from '../components/UI'

export default function AllFindings() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    (async () => {
      const cases = await CaseAPI.list()
      const completed = cases.data.filter((c) => c.status === 'completed')
      const results = await Promise.all(completed.map(async (c) => {
        const f = await CaseAPI.findings(c.id)
        return f.data.map((item) => ({ ...item, caseName: c.name, caseId: c.id }))
      }))
      setFindings(results.flat())
      setLoading(false)
    })()
  }, [])

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
  const filtered = (filter === 'all' ? findings : findings.filter((f) => f.severity === filter))
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc }, {})

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">All Findings</h1>
        <p className="text-slate-400 text-sm mt-1">Aggregated cryptographic findings across every completed case</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
          <button key={s} onClick={() => setFilter(s)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              filter === s ? 'bg-brand-600/20 border-brand-600/40 text-brand-300' : 'border-slate-700 text-slate-400 hover:text-slate-200'
            }`}>
            {s === 'all' ? `All (${findings.length})` : `${s[0].toUpperCase() + s.slice(1)} (${counts[s] || 0})`}
          </button>
        ))}
      </div>

      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : filtered.length === 0 ? (
        <Card><p className="text-sm text-slate-500 text-center py-6">No findings match this filter.</p></Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((f) => (
            <Card key={f.id} className="!p-4">
              <div className="flex items-center gap-2 mb-1.5">
                <SeverityBadge severity={f.severity} />
                <span className="text-xs text-slate-500">{f.category}</span>
                <span className="text-xs text-slate-600">·</span>
                <span className="text-xs text-brand-400">{f.caseName}</span>
              </div>
              <h4 className="text-sm font-semibold text-slate-200">{f.title}</h4>
              <p className="text-xs text-slate-400 mt-1">{f.description}</p>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
