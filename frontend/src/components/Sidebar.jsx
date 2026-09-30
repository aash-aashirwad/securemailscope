import { NavLink, useNavigate, Link } from 'react-router-dom'
import {
  LayoutDashboard, FolderSearch, Upload, FileText, ShieldAlert,
  Users, LogOut, ShieldCheck, Radio, ScrollText, KeyRound,
  ClipboardList, Gauge, UserCog,
} from 'lucide-react'
import { useAuth, ROLE_LABELS, ROLE_COLORS } from '../context/AuthContext'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
  { to: '/upload', label: 'Upload Capture', icon: Upload, roles: ['admin', 'soc_analyst', 'forensic_investigator'] },
  { to: '/cases', label: 'Cases', icon: FolderSearch, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
  { to: '/findings', label: 'All Findings', icon: ShieldAlert, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
  { to: '/compliance', label: 'Compliance View', icon: FileText, roles: ['compliance_officer', 'admin'] },
  { to: '/traceability', label: 'PS Traceability', icon: ClipboardList, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
  { to: '/admin/benchmark', label: 'Performance Benchmark', icon: Gauge, roles: ['admin', 'compliance_officer'] },
  { to: '/admin/users', label: 'User Management', icon: Users, roles: ['admin'] },
  { to: '/admin/audit-logs', label: 'Audit Trail', icon: ScrollText, roles: ['admin', 'compliance_officer'] },
  { to: '/roles', label: 'Roles & Access', icon: UserCog, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
  { to: '/account/security', label: 'Account Security', icon: KeyRound, roles: ['admin', 'soc_analyst', 'forensic_investigator', 'compliance_officer'] },
]

const ROLE_ACCENT = {
  admin: 'from-purple-500 to-purple-700',
  soc_analyst: 'from-blue-500 to-blue-700',
  forensic_investigator: 'from-amber-500 to-amber-700',
  compliance_officer: 'from-emerald-500 to-emerald-700',
}

export default function Sidebar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  if (!user) return null
  const items = NAV_ITEMS.filter((i) => i.roles.includes(user.role))

  return (
    <aside className="w-64 h-screen sticky top-0 flex flex-col border-r border-slate-800/60 bg-ink-900/60">
      <div className={`h-1 bg-gradient-to-r ${ROLE_ACCENT[user.role]}`} />
      <div className="p-5 flex items-center gap-2.5 border-b border-slate-800/60">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center">
          <ShieldCheck size={20} className="text-white" />
        </div>
        <div>
          <div className="font-bold text-white text-sm leading-tight">SecureMailScope</div>
          <div className="text-[10px] text-slate-500 tracking-wide">NTRO • PS-26159</div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-brand-600/20 text-brand-300 border border-brand-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`
            }
          >
            <item.icon size={17} />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-slate-800/60">
        <Link to="/roles" className="flex items-center gap-2 px-2 py-2 mb-1 rounded-xl hover:bg-slate-800/40 transition-colors">
          <div className="w-8 h-8 rounded-full bg-brand-600/30 flex items-center justify-center text-xs font-bold text-brand-200">
            {user.full_name?.[0]?.toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-slate-200 truncate">{user.full_name}</div>
            <span className={`inline-block mt-0.5 px-1.5 py-0.5 rounded text-[10px] border ${ROLE_COLORS[user.role]}`}>
              {ROLE_LABELS[user.role]}
            </span>
          </div>
        </Link>
        <button
          onClick={() => { logout(); navigate('/login') }}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-xl text-sm text-slate-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
        >
          <LogOut size={16} /> Sign out
        </button>
      </div>
    </aside>
  )
}
