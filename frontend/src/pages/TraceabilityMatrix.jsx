import { useEffect, useState } from 'react'
import { ClipboardList, AlertTriangle } from 'lucide-react'
import { DashboardAPI } from '../api/client'
import { Card } from '../components/UI'

export default function TraceabilityMatrix() {
  const [data, setData] = useState(null)

  useEffect(() => { DashboardAPI.traceabilityMatrix().then((r) => setData(r.data)) }, [])

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ClipboardList size={22} className="text-brand-400" /> PS-26159 Traceability Matrix
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          Every outcome named in Problem Statement 26159, mapped to the concrete feature, API,
          and UI surface that implements it — pulled live from the running system.
        </p>
      </div>

      {!data ? (
        <Card><p className="text-sm text-slate-500 text-center py-6">Loading…</p></Card>
      ) : (
        <>
          <Card className="!p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-slate-800 bg-slate-800/30">
                    <th className="px-3 py-2.5 w-8">#</th>
                    <th className="px-3 py-2.5">PS Outcome</th>
                    <th className="px-3 py-2.5">Feature</th>
                    <th className="px-3 py-2.5">API</th>
                    <th className="px-3 py-2.5">UI</th>
                    <th className="px-3 py-2.5">Tests</th>
                  </tr>
                </thead>
                <tbody>
                  {data.matrix.map((row) => (
                    <tr key={row.id} className="border-b border-slate-800/50 hover:bg-slate-800/20">
                      <td className="px-3 py-2.5 text-slate-600 font-mono">{row.id}</td>
                      <td className="px-3 py-2.5 text-slate-200 font-medium">{row.outcome}</td>
                      <td className="px-3 py-2.5 text-slate-400">{row.feature}</td>
                      <td className="px-3 py-2.5 text-slate-400 font-mono text-[11px]">{row.api}</td>
                      <td className="px-3 py-2.5 text-slate-400">{row.ui}</td>
                      <td className="px-3 py-2.5 text-slate-600 font-mono text-[11px]">{row.tests}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card>
            <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <AlertTriangle size={15} className="text-amber-400" /> Known limitations (stated, not hidden)
            </h4>
            <ul className="space-y-1.5">
              {data.known_limitations.map((l, i) => (
                <li key={i} className="text-xs text-slate-400 flex gap-2">
                  <span className="text-amber-500 shrink-0">•</span>{l}
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  )
}
