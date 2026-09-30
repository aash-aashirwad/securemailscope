import { Users, ShieldCheck, XCircle, CheckCircle2 } from 'lucide-react'
import { useAuth, ROLE_LABELS, ROLE_COLORS, ROLE_DETAILS } from '../context/AuthContext'
import { Card } from '../components/UI'

const ROLE_ORDER = ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer']

export default function RolesAccess() {
  const { user } = useAuth()

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Users size={22} className="text-brand-400" /> Roles &amp; Access
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          What each role is responsible for, and exactly what it is and isn't authorized to do —
          enforced by <code className="text-[11px] bg-slate-800 px-1 py-0.5 rounded">require_roles()</code> on every sensitive endpoint, not just hidden in the UI.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {ROLE_ORDER.map((role) => {
          const details = ROLE_DETAILS[role]
          const isYou = user?.role === role
          return (
            <Card key={role} className={isYou ? '!border-brand-500/40' : ''}>
              <div className="flex items-center justify-between mb-3">
                <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${ROLE_COLORS[role]}`}>
                  {ROLE_LABELS[role]}
                </span>
                {isYou && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-brand-600/20 text-brand-300 border border-brand-600/30">
                    Your role
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-300 mb-3">{details.responsibility}</p>

              <h5 className="text-[11px] uppercase tracking-wider text-slate-500 font-medium mb-1.5">Authority</h5>
              <ul className="space-y-1 mb-3">
                {details.authority.map((a, i) => (
                  <li key={i} className="text-xs text-slate-400 flex gap-1.5">
                    <CheckCircle2 size={13} className="text-emerald-500 shrink-0 mt-0.5" />{a}
                  </li>
                ))}
              </ul>

              <h5 className="text-[11px] uppercase tracking-wider text-slate-500 font-medium mb-1.5">Working scope</h5>
              <p className="text-xs text-slate-400 mb-3">{details.workingScope}</p>

              {details.cannotDo.length > 0 && (
                <>
                  <h5 className="text-[11px] uppercase tracking-wider text-slate-500 font-medium mb-1.5">Explicitly restricted</h5>
                  <ul className="space-y-1">
                    {details.cannotDo.map((c, i) => (
                      <li key={i} className="text-xs text-slate-500 flex gap-1.5">
                        <XCircle size={13} className="text-red-500/70 shrink-0 mt-0.5" />{c}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </Card>
          )
        })}
      </div>

      <Card className="!bg-slate-800/20">
        <h4 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
          <ShieldCheck size={15} className="text-brand-400" /> How this is enforced
        </h4>
        <p className="text-xs text-slate-400">
          Every role boundary above is backed by a server-side check (<code className="text-[11px] bg-slate-800 px-1 py-0.5 rounded">require_roles()</code> in
          the API), not just hidden navigation items — a systematic test matrix
          (<code className="text-[11px] bg-slate-800 px-1 py-0.5 rounded">tests/test_rbac_matrix.py</code>) verifies every protected endpoint against
          every role.
        </p>
      </Card>
    </div>
  )
}
