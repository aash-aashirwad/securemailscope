import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { FolderSearch, ShieldAlert, Lock, Unlock, TrendingUp, Activity } from 'lucide-react'
import { DashboardAPI } from '../api/client'
import { useAuth, ROLE_LABELS } from '../context/AuthContext'
import { Card, StatCard, GradeBadge, StatusPill } from '../components/UI'

const GRADE_COLORS = { A: '#10b981', B: '#84cc16', C: '#f59e0b', D: '#f97316', F: '#ef4444' }
const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#84cc16' }

export default function Dashboard() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [trend, setTrend] = useState(null)
  const [baseline, setBaseline] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    DashboardAPI.summary().then((res) => setData(res.data)).finally(() => setLoading(false))
    DashboardAPI.riskTrend().then((res) => setTrend(res.data))
    DashboardAPI.baseline().then((res) => setBaseline(res.data))
  }, [])

  if (loading) return <LoadingState />
  if (!data) return null

  const gradeData = Object.entries(data.grade_distribution)
    .filter(([, v]) => v > 0)
    .map(([grade, value]) => ({ name: grade, value, fill: GRADE_COLORS[grade] }))

  const severityData = [
    { name: 'Critical', value: data.findings_summary.critical, fill: SEV_COLORS.critical },
    { name: 'High', value: data.findings_summary.high, fill: SEV_COLORS.high },
    { name: 'Medium', value: data.findings_summary.medium, fill: SEV_COLORS.medium },
    { name: 'Low', value: data.findings_summary.low, fill: SEV_COLORS.low },
  ]

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Welcome back, {user.full_name.split(' ')[0]}</h1>
        <p className="text-slate-400 text-sm mt-1">
          {ROLE_LABELS[user.role]} overview — cryptographic posture across {data.total_cases} case{data.total_cases !== 1 ? 's' : ''}
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Cases" value={data.total_cases} icon={FolderSearch} accent="brand" />
        <StatCard label="Avg Risk Score" value={data.average_risk_score} icon={TrendingUp} accent="amber" />
        <StatCard label="Sessions Analyzed" value={data.total_sessions_analyzed} icon={Lock} accent="sky" />
        <StatCard label="Plaintext Sessions" value={data.total_plaintext_sessions} icon={Unlock} accent="red" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Security Grade Distribution</h3>
          {gradeData.length === 0 ? (
            <EmptyChart />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={gradeData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                  {gradeData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {severityData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Activity size={15} /> Risk Trend Over Time
          </h3>
          {!trend || trend.length < 2 ? (
            <div className="h-[200px] flex items-center justify-center text-sm text-slate-500">
              Need at least 2 completed cases to show a trend
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trend.map((t) => ({ ...t, label: new Date(t.date).toLocaleDateString() }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
                <Line type="monotone" dataKey="overall_risk_score" stroke="#6366f1" strokeWidth={2} dot={{ r: 3 }} name="Risk score" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Historical Baseline</h3>
          {!baseline || !baseline.baseline_available ? (
            <p className="text-xs text-slate-500">Not enough completed cases yet to establish a baseline.</p>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="text-3xl font-bold text-slate-200">{baseline.average_risk_score}</div>
                <div className="text-xs text-slate-500">Average risk score across {baseline.sample_size} case{baseline.sample_size !== 1 ? 's' : ''}</div>
              </div>
              <div className="flex justify-between text-xs text-slate-400">
                <span>Best: <span className="text-emerald-400 font-medium">{baseline.best_risk_score}</span></span>
                <span>Worst: <span className="text-red-400 font-medium">{baseline.worst_risk_score}</span></span>
              </div>
              {baseline.trend_vs_baseline && (
                <div className={`text-xs font-medium px-2.5 py-1.5 rounded-lg inline-block ${
                  baseline.trend_vs_baseline === 'improving' ? 'bg-emerald-500/10 text-emerald-300'
                    : baseline.trend_vs_baseline === 'worsening' ? 'bg-red-500/10 text-red-300'
                    : 'bg-slate-500/10 text-slate-300'
                }`}>
                  Latest case is {baseline.trend_vs_baseline} vs. baseline
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-300">Recent Cases</h3>
          <Link to="/cases" className="text-xs text-brand-400 hover:text-brand-300 font-medium">View all →</Link>
        </div>
        {data.recent_cases.length === 0 ? (
          <p className="text-sm text-slate-500 py-6 text-center">No cases yet. Upload a PCAP capture to get started.</p>
        ) : (
          <div className="space-y-2">
            {data.recent_cases.map((c) => (
              <Link key={c.id} to={`/cases/${c.id}`}
                className="flex items-center justify-between p-3 rounded-xl hover:bg-slate-800/50 transition-colors">
                <div className="flex items-center gap-3">
                  <GradeBadge grade={c.risk_grade} />
                  <div>
                    <div className="text-sm font-medium text-slate-200">{c.name}</div>
                    <div className="text-xs text-slate-500">{new Date(c.created_at).toLocaleString()}</div>
                  </div>
                </div>
                <StatusPill status={c.status} />
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function LoadingState() {
  return <div className="p-8 flex items-center justify-center h-96 text-slate-500 text-sm">Loading dashboard…</div>
}

function EmptyChart() {
  return <div className="h-[220px] flex items-center justify-center text-sm text-slate-500">No completed analyses yet</div>
}
