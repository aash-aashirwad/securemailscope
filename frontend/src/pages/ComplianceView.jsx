import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileCheck2 } from 'lucide-react'
import { CaseAPI, ReportAPI } from '../api/client'
import { Card, GradeBadge } from '../components/UI'

export default function ComplianceView() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    CaseAPI.list().then((res) => setCases(res.data.filter((c) => c.status === 'completed'))).finally(() => setLoading(false))
  }, [])

  const gradeFailing = cases.filter((c) => ['D', 'F'].includes(c.risk_grade))

  const downloadPdf = async (c) => {
    try {
      const res = await ReportAPI.fetchPdf(c.id)
      const blobUrl = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = blobUrl
      a.download = `${c.name}-report.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000)
    } catch (err) {
      console.error('Report export failed', err)
    }
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Compliance View</h1>
        <p className="text-slate-400 text-sm mt-1">
          Organization-wide cryptographic compliance posture for audit and regulatory reporting
          (NIST SP 800-52r2, PCI-DSS 4.0, CERT-In advisories).
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <div className="text-3xl font-bold text-white">{cases.length}</div>
          <div className="text-xs text-slate-500 mt-1">Assessed infrastructures</div>
        </Card>
        <Card>
          <div className="text-3xl font-bold text-red-400">{gradeFailing.length}</div>
          <div className="text-xs text-slate-500 mt-1">Non-compliant (Grade D/F)</div>
        </Card>
        <Card>
          <div className="text-3xl font-bold text-emerald-400">
            {cases.length ? Math.round(((cases.length - gradeFailing.length) / cases.length) * 100) : 0}%
          </div>
          <div className="text-xs text-slate-500 mt-1">Compliance rate</div>
        </Card>
      </div>

      <Card className="!p-0 overflow-hidden">
        {loading ? (
          <p className="text-sm text-slate-500 py-10 text-center">Loading…</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                <th className="px-5 py-3">Infrastructure / Case</th>
                <th className="px-5 py-3">Grade</th>
                <th className="px-5 py-3">Critical Issues</th>
                <th className="px-5 py-3">Assessed</th>
                <th className="px-5 py-3">Audit Export</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-5 py-3.5">
                    <Link to={`/cases/${c.id}`} className="text-slate-200 font-medium hover:text-brand-300">{c.name}</Link>
                  </td>
                  <td className="px-5 py-3.5"><GradeBadge grade={c.risk_grade} /></td>
                  <td className="px-5 py-3.5 text-red-400 font-medium">{c.critical_findings}</td>
                  <td className="px-5 py-3.5 text-slate-500 text-xs">{new Date(c.analyzed_at || c.created_at).toLocaleDateString()}</td>
                  <td className="px-5 py-3.5">
                    <button
                      onClick={() => downloadPdf(c)}
                      className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300"
                    >
                      <FileCheck2 size={13} /> PDF Report
                    </button>
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
