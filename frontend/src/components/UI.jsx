export function SeverityBadge({ severity }) {
  const map = {
    critical: 'bg-red-500/15 text-red-300 border-red-500/30',
    high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    low: 'bg-lime-500/15 text-lime-300 border-lime-500/30',
    info: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  }
  return (
    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${map[severity] || map.info}`}>
      {severity?.toUpperCase()}
    </span>
  )
}

export function GradeBadge({ grade }) {
  const map = {
    A: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    B: 'bg-lime-500/15 text-lime-300 border-lime-500/30',
    C: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    D: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
    F: 'bg-red-500/15 text-red-300 border-red-500/30',
    'N/A': 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  }
  return (
    <span className={`inline-flex items-center justify-center w-9 h-9 rounded-lg text-sm font-bold border ${map[grade] || map['N/A']}`}>
      {grade}
    </span>
  )
}

export function StatCard({ label, value, icon: Icon, accent = 'brand', suffix = '' }) {
  const accentMap = {
    brand: 'text-brand-400', red: 'text-red-400', amber: 'text-amber-400',
    emerald: 'text-emerald-400', sky: 'text-sky-400',
  }
  return (
    <div className="glass rounded-2xl p-5 fade-in">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs uppercase tracking-wider text-slate-400 font-medium">{label}</span>
        {Icon && <Icon size={18} className={accentMap[accent]} />}
      </div>
      <div className={`text-3xl font-bold ${accentMap[accent]}`}>{value}{suffix}</div>
    </div>
  )
}

export function StatusPill({ status }) {
  const map = {
    uploaded: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
    analyzing: 'bg-blue-500/15 text-blue-300 border-blue-500/30 animate-pulse',
    completed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    failed: 'bg-red-500/15 text-red-300 border-red-500/30',
  }
  return (
    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${map[status] || map.uploaded}`}>
      {status}
    </span>
  )
}

export function Card({ children, className = '' }) {
  return <div className={`glass rounded-2xl p-6 fade-in ${className}`}>{children}</div>
}

export function Button({ children, variant = 'primary', className = '', ...props }) {
  const variants = {
    primary: 'bg-brand-600 hover:bg-brand-500 text-white shadow-lg shadow-brand-600/20',
    secondary: 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700',
    danger: 'bg-red-600/90 hover:bg-red-600 text-white',
    ghost: 'hover:bg-slate-800 text-slate-300',
  }
  return (
    <button
      className={`px-4 py-2.5 rounded-xl font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
