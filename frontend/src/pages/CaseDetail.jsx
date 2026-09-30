import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft, Download, FileText, RefreshCw, Lock, Unlock,
  ShieldAlert, Award, Clock, MessageSquare, Fingerprint, Send,
  ShieldCheck, Package, ChevronDown, ChevronUp,
} from 'lucide-react'
import { CaseAPI, ReportAPI } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { Card, GradeBadge, StatusPill, SeverityBadge, Button, StatCard } from '../components/UI'

const TABS = ['sessions', 'findings', 'timeline', 'certificates', 'custody', 'comments']
const TAB_LABELS = {
  sessions: 'Session Inventory', findings: 'Findings', timeline: 'Timeline',
  certificates: 'Certificates & IOCs', custody: 'Chain of Custody', comments: 'Investigator Notes',
}
const REMEDIATION_STEPS = ['open', 'assigned', 'fixed', 'verified']
const REMEDIATION_COLORS = {
  open: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  assigned: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  fixed: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  verified: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
}

export default function CaseDetail() {
  const { id } = useParams()
  const { user } = useAuth()
  const [caseData, setCaseData] = useState(null)
  const [sessions, setSessions] = useState([])
  const [findings, setFindings] = useState([])
  const [tab, setTab] = useState('sessions')
  const [selectedSession, setSelectedSession] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    const [c, s, f] = await Promise.all([
      CaseAPI.get(id), CaseAPI.sessions(id), CaseAPI.findings(id),
    ])
    setCaseData(c.data)
    setSessions(s.data)
    setFindings(f.data)
    setLoading(false)
    return c.data
  }

  useEffect(() => {
    load()
    const interval = setInterval(async () => {
      const c = await CaseAPI.get(id)
      setCaseData(c.data)
      if (c.data.status === 'completed' || c.data.status === 'failed') {
        clearInterval(interval)
        load()
      }
    }, 3000)
    return () => clearInterval(interval)
  }, [id])

  const openReport = async (format) => {
    try {
      const res = format === 'pdf' ? await ReportAPI.fetchPdf(id) : await ReportAPI.fetchHtml(id)
      const blobUrl = URL.createObjectURL(res.data)
      if (format === 'pdf') {
        const a = document.createElement('a')
        a.href = blobUrl
        a.download = `${caseData?.name || 'case'}-report.pdf`
        document.body.appendChild(a)
        a.click()
        a.remove()
      } else {
        window.open(blobUrl, '_blank', 'noopener,noreferrer')
      }
      // Revoke after a delay long enough for the new tab/download to load it.
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000)
    } catch (err) {
      console.error('Report export failed', err)
    }
  }

  const updateRemediation = async (findingId, status) => {
    await CaseAPI.updateRemediation(findingId, status)
    setFindings((prev) => prev.map((f) => f.id === findingId ? { ...f, remediation_status: status } : f))
  }

  if (loading) return <div className="p-8 text-slate-500 text-sm">Loading case…</div>
  if (!caseData) return null

  const isAnalyzing = caseData.status === 'analyzing' || caseData.status === 'uploaded'
  const canManageRemediation = ['admin', 'soc_analyst', 'forensic_investigator'].includes(user?.role)

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <Link to="/cases" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200">
        <ArrowLeft size={15} /> Back to cases
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">{caseData.name}</h1>
            <StatusPill status={caseData.status} />
          </div>
          <p className="text-slate-500 text-sm mt-1">{caseData.filename}</p>
          {caseData.file_sha256 && (
            <p className="text-[11px] text-slate-600 font-mono mt-1 flex items-center gap-1">
              <Fingerprint size={11} /> SHA-256: {caseData.file_sha256}
            </p>
          )}
        </div>

        {caseData.status === 'completed' && (
          <div className="flex gap-2">
            <Button variant="secondary" className="flex items-center gap-2" onClick={() => openReport('html')}>
              <FileText size={15} /> HTML Report
            </Button>
            <Button variant="secondary" className="flex items-center gap-2" onClick={() => openReport('pdf')}>
              <Download size={15} /> PDF
            </Button>
          </div>
        )}
      </div>

      {isAnalyzing && (
        <Card className="flex items-center gap-3 !py-4">
          <RefreshCw size={18} className="text-brand-400 animate-spin" />
          <div>
            <p className="text-sm text-slate-200 font-medium">Analysis in progress…</p>
            <p className="text-xs text-slate-500">Reconstructing TCP streams, parsing TLS handshakes, scoring risk. This page auto-refreshes.</p>
          </div>
        </Card>
      )}

      {caseData.status === 'failed' && (
        <Card className="!border-red-500/30 bg-red-500/5">
          <p className="text-sm text-red-300 font-medium">Analysis failed</p>
          <pre className="text-xs text-red-400/70 mt-2 whitespace-pre-wrap">{caseData.error_message}</pre>
        </Card>
      )}

      {caseData.status === 'completed' && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <Card className="!p-4 flex flex-col items-center justify-center">
              <GradeBadge grade={caseData.risk_grade} />
              <span className="text-xs text-slate-500 mt-2">Security Grade</span>
            </Card>
            <StatCard label="Risk Score" value={caseData.overall_risk_score} icon={Award} accent="amber" />
            <StatCard label="Total Sessions" value={caseData.total_sessions} icon={Lock} accent="brand" />
            <StatCard label="Encrypted" value={caseData.encrypted_sessions} icon={Lock} accent="emerald" />
            <StatCard label="Plaintext" value={caseData.plaintext_sessions} icon={Unlock} accent="red" />
          </div>

          {(caseData.capture_packet_count || caseData.capture_duration_seconds) && (
            <Card className="!p-4">
              <h4 className="text-xs uppercase tracking-wider text-slate-400 font-medium mb-2">Capture metadata</h4>
              <div className="flex flex-wrap gap-x-8 gap-y-1 text-xs text-slate-400">
                <span>Packets: <span className="text-slate-200">{caseData.capture_packet_count ?? '—'}</span></span>
                <span>Duration: <span className="text-slate-200">{caseData.capture_duration_seconds != null ? `${caseData.capture_duration_seconds}s` : '—'}</span></span>
                <span>Link type: <span className="text-slate-200">{caseData.capture_link_type || '—'}</span></span>
                <span>Window: <span className="text-slate-200">{caseData.capture_start?.slice(0, 19) || '—'} → {caseData.capture_end?.slice(0, 19) || '—'}</span></span>
              </div>
            </Card>
          )}

          <div className="flex gap-1 border-b border-slate-800 overflow-x-auto">
            {TABS.map((t) => (
              <button key={t} onClick={() => setTab(t)}
                className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                  tab === t ? 'border-brand-500 text-brand-300' : 'border-transparent text-slate-500 hover:text-slate-300'
                }`}>
                {TAB_LABELS[t]}
                {t === 'sessions' && ` (${sessions.length})`}
                {t === 'findings' && ` (${findings.length})`}
              </button>
            ))}
          </div>

          {tab === 'sessions' && (
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
              <Card className="!p-0 overflow-hidden lg:col-span-3">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                      <th className="px-4 py-3">Protocol</th>
                      <th className="px-4 py-3">Endpoint</th>
                      <th className="px-4 py-3">TLS</th>
                      <th className="px-4 py-3">Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((s) => (
                      <tr key={s.id} onClick={() => setSelectedSession(s)}
                        className={`border-b border-slate-800/50 cursor-pointer transition-colors ${
                          selectedSession?.id === s.id ? 'bg-brand-500/10' : 'hover:bg-slate-800/30'
                        }`}>
                        <td className="px-4 py-3 font-medium text-slate-200">
                          {s.protocol}
                          {s.non_standard_port && <span className="ml-1.5 text-[10px] text-amber-400" title="Non-standard port">⚠</span>}
                        </td>
                        <td className="px-4 py-3 text-slate-400 font-mono text-xs">{s.dst_ip}:{s.dst_port}</td>
                        <td className="px-4 py-3 text-slate-400 text-xs">
                          {s.tls_version || (s.implicit_tls ? 'Implicit' : 'None')}
                          {s.is_anomalous && <ShieldAlert size={12} className="inline ml-1.5 text-amber-400" />}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`font-semibold ${
                            s.risk_score >= 55 ? 'text-red-400' : s.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>{s.risk_score}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>

              <Card className="lg:col-span-2">
                {!selectedSession ? (
                  <p className="text-sm text-slate-500 text-center py-10">Select a session to view details</p>
                ) : (
                  <SessionDetail session={selectedSession} caseId={id} />
                )}
              </Card>
            </div>
          )}

          {tab === 'findings' && (
            <div className="space-y-3">
              {findings.length === 0 ? (
                <Card><p className="text-sm text-slate-500 text-center py-6">No findings — clean capture.</p></Card>
              ) : findings.map((f) => (
                <Card key={f.id} className="!p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-xs text-slate-500">{f.category}</span>
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-semibold border ${REMEDIATION_COLORS[f.remediation_status] || REMEDIATION_COLORS.open}`}>
                          {(f.remediation_status || 'open').toUpperCase()}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200">{f.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{f.description}</p>
                      <div className="mt-2.5 p-2.5 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                        <p className="text-xs text-emerald-300"><span className="font-semibold">Mitigation: </span>{f.recommendation}</p>
                      </div>
                      {f.compliance_refs && (
                        <p className="text-[11px] text-slate-600 mt-1.5">Compliance: {f.compliance_refs}</p>
                      )}
                      {canManageRemediation && f.severity !== 'info' && (
                        <div className="mt-3 flex items-center gap-1.5">
                          <span className="text-[11px] text-slate-500 mr-1">Remediation:</span>
                          {REMEDIATION_STEPS.map((step) => (
                            <button key={step} onClick={() => updateRemediation(f.id, step)}
                              className={`px-2 py-1 rounded-md text-[10px] font-medium border transition-colors ${
                                f.remediation_status === step
                                  ? REMEDIATION_COLORS[step]
                                  : 'border-slate-700 text-slate-500 hover:border-slate-600 hover:text-slate-300'
                              }`}>
                              {step}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {tab === 'timeline' && <TimelineTab caseId={id} />}
          {tab === 'certificates' && <CertificatesTab caseId={id} />}
          {tab === 'custody' && <CustodyTab caseId={id} />}
          {tab === 'comments' && <CommentsTab caseId={id} />}
        </>
      )}
    </div>
  )
}

function SessionDetail({ session: s, caseId }) {
  const [showPackets, setShowPackets] = useState(false)
  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Connection</h4>
        <DetailRow label="Protocol" value={s.protocol} />
        <DetailRow label="Source" value={`${s.src_ip}:${s.src_port}`} mono />
        <DetailRow label="Destination" value={`${s.dst_ip}:${s.dst_port}`} mono />
        <DetailRow label="Packets" value={s.packet_count} />
        <DetailRow label="Connection state" value={s.tcp_connection_state || '—'} />
        {s.non_standard_port && <DetailRow label="Non-standard port" value="Yes — identified via banner" />}
      </div>
      <div>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Encryption</h4>
        <DetailRow label="STARTTLS used" value={s.starttls_used ? 'Yes' : 'No'} />
        <DetailRow label="Implicit TLS" value={s.implicit_tls ? 'Yes' : 'No'} />
        <DetailRow label="TLS Version" value={s.tls_version || '—'} />
        <DetailRow label="Cipher Suite" value={s.cipher_suite || '—'} mono small />
        <DetailRow label="Key Exchange" value={s.key_exchange || '—'} />
        <DetailRow label="Forward Secrecy" value={s.forward_secrecy ? 'Yes' : 'No'} />
      </div>
      {s.cert_observable === false ? (
        <div className="p-3 rounded-lg bg-sky-500/5 border border-sky-500/20">
          <p className="text-xs text-sky-300">{s.observability_note}</p>
        </div>
      ) : s.cert_subject && (
        <div>
          <h4 className="text-sm font-semibold text-slate-200 mb-2">Certificate</h4>
          <DetailRow label="Subject" value={s.cert_subject} small />
          <DetailRow label="Issuer" value={s.cert_issuer} small />
          <DetailRow label="Valid to" value={s.cert_valid_to?.slice(0, 10)} />
          <DetailRow label="Expired" value={s.cert_expired ? 'Yes' : 'No'} />
          <DetailRow label="Self-signed" value={s.cert_self_signed ? 'Yes' : 'No'} />
          <DetailRow label="Key" value={`${s.cert_key_algo} ${s.cert_key_size}-bit`} />
          {s.cert_fingerprint_sha256 && (
            <DetailRow label="SHA-256 fingerprint" value={s.cert_fingerprint_sha256} small />
          )}
        </div>
      )}
      {s.weighted_reasons?.length > 0 ? (
        <div>
          <h4 className="text-sm font-semibold text-slate-200 mb-2">Risk factors (explainable)</h4>
          <ul className="space-y-1">
            {s.weighted_reasons.map((r, i) => (
              <li key={i} className="text-xs text-amber-300/90 flex justify-between gap-2">
                <span className="flex gap-1.5"><span className="text-amber-500">•</span>{r.reason}</span>
                <span className="text-amber-500/70 shrink-0">+{r.points}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : s.reasons?.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-slate-200 mb-2">Risk factors</h4>
          <ul className="space-y-1">
            {s.reasons.map((r, i) => (
              <li key={i} className="text-xs text-amber-300/90 flex gap-1.5">
                <span className="text-amber-500">•</span>{r}
              </li>
            ))}
          </ul>
        </div>
      )}
      {s.is_anomalous && s.anomaly_explanation && (
        <div className="p-2.5 rounded-lg bg-purple-500/5 border border-purple-500/20">
          <p className="text-xs text-purple-300"><span className="font-semibold">AI anomaly driver: </span>{s.anomaly_explanation}</p>
        </div>
      )}
      <div>
        <button onClick={() => setShowPackets((v) => !v)}
          className="flex items-center gap-1.5 text-xs font-medium text-brand-300 hover:text-brand-200">
          <Package size={13} /> Packet evidence
          {showPackets ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </button>
        {showPackets && <PacketEvidenceViewer caseId={caseId} sessionId={s.id} />}
      </div>
    </div>
  )
}

function PacketEvidenceViewer({ caseId, sessionId }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(() => {
    setData(null)
    CaseAPI.packets(caseId, sessionId).then((r) => setData(r.data)).catch(() => setErr(true))
  }, [caseId, sessionId])

  if (err) return <p className="text-xs text-red-400 mt-2">Could not load packet evidence.</p>
  if (!data) return <p className="text-xs text-slate-500 mt-2">Loading packet evidence…</p>
  return (
    <div className="mt-2 rounded-lg border border-slate-800 overflow-hidden">
      <div className="px-3 py-2 bg-slate-800/40 text-[11px] text-slate-400 flex justify-between">
        <span>{data.packet_evidence_captured} of {data.packet_count_total} packets captured as evidence</span>
        {data.truncated && <span className="text-amber-400">capped — long-lived session</span>}
      </div>
      <div className="max-h-64 overflow-y-auto">
        <table className="w-full text-[11px]">
          <thead className="sticky top-0 bg-ink-900">
            <tr className="text-left text-slate-500 border-b border-slate-800">
              <th className="px-2 py-1.5">#</th>
              <th className="px-2 py-1.5">Dir</th>
              <th className="px-2 py-1.5">Src → Dst</th>
              <th className="px-2 py-1.5">Len</th>
              <th className="px-2 py-1.5">Flags</th>
              <th className="px-2 py-1.5">Seq</th>
            </tr>
          </thead>
          <tbody>
            {data.packets.map((p) => (
              <tr key={p.packet_no} className="border-b border-slate-800/50">
                <td className="px-2 py-1 text-slate-500 font-mono">{p.packet_no}</td>
                <td className="px-2 py-1">
                  <span className={p.direction === 'c2s' ? 'text-blue-400' : 'text-emerald-400'}>
                    {p.direction === 'c2s' ? '→ server' : '← client'}
                  </span>
                </td>
                <td className="px-2 py-1 font-mono text-slate-400">{p.src} → {p.dst}</td>
                <td className="px-2 py-1 text-slate-400">{p.length}</td>
                <td className="px-2 py-1 font-mono text-slate-500">{p.tcp_flags}</td>
                <td className="px-2 py-1 font-mono text-slate-600">{p.seq}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono, small }) {
  return (
    <div className="flex justify-between items-start py-1 gap-3">
      <span className="text-xs text-slate-500 shrink-0">{label}</span>
      <span className={`text-xs text-slate-300 text-right ${mono ? 'font-mono' : ''} ${small ? 'text-[11px] break-all' : ''}`}>
        {value ?? '—'}
      </span>
    </div>
  )
}

function TimelineTab({ caseId }) {
  const [events, setEvents] = useState(null)
  useEffect(() => { CaseAPI.timeline(caseId).then((r) => setEvents(r.data)) }, [caseId])
  if (!events) return <Card><p className="text-sm text-slate-500 text-center py-6">Loading timeline…</p></Card>
  if (events.length === 0) return <Card><p className="text-sm text-slate-500 text-center py-6">No timeline events.</p></Card>
  return (
    <Card>
      <div className="space-y-0">
        {events.map((e, i) => (
          <div key={i} className="flex gap-3 py-2.5 border-b border-slate-800/50 last:border-0">
            <div className="flex flex-col items-center pt-0.5">
              <Clock size={13} className={
                e.severity === 'critical' || e.severity === 'high' ? 'text-red-400'
                  : e.severity === 'medium' ? 'text-amber-400' : 'text-slate-500'
              } />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-slate-200">{e.label}</p>
              <p className="text-[10px] text-slate-600 mt-0.5">{e.ts ? new Date(e.ts).toLocaleString() : '—'} · {e.type}</p>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

function CertificatesTab({ caseId }) {
  const [iocs, setIocs] = useState(null)
  const [reuse, setReuse] = useState(null)
  useEffect(() => {
    CaseAPI.iocs(caseId).then((r) => setIocs(r.data))
    CaseAPI.certReuse(caseId).then((r) => setReuse(r.data))
  }, [caseId])
  return (
    <div className="space-y-4">
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-3">Indicators of Compromise (extracted)</h4>
        {!iocs ? <p className="text-xs text-slate-500">Loading…</p> : (
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 mb-1.5">IP Addresses ({iocs.ip_addresses.length})</p>
              <div className="flex flex-wrap gap-1.5">
                {iocs.ip_addresses.map((ip) => (
                  <span key={ip} className="px-2 py-0.5 rounded bg-slate-800 text-[11px] font-mono text-slate-300">{ip}</span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-500 mb-1.5">Certificate Subjects ({iocs.certificate_subjects.length})</p>
              <div className="space-y-1">
                {iocs.certificate_subjects.map((s) => (
                  <p key={s} className="text-[11px] text-slate-400 break-all">{s}</p>
                ))}
              </div>
            </div>
          </div>
        )}
      </Card>
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Fingerprint size={15} /> Certificate reuse across cases
        </h4>
        {!reuse ? <p className="text-xs text-slate-500">Loading…</p> : reuse.length === 0 ? (
          <p className="text-xs text-slate-500">No certificate from this case was found reused in any other case visible to you.</p>
        ) : (
          <div className="space-y-3">
            {reuse.map((r) => (
              <div key={r.fingerprint_sha256} className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                <p className="text-[11px] font-mono text-amber-300 break-all">{r.fingerprint_sha256}</p>
                <p className="text-xs text-slate-400 mt-1">Seen in {r.seen_in_cases.length} cases: {r.seen_in_cases.map((c) => c.case_name).join(', ')}</p>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function CustodyTab({ caseId }) {
  const [custody, setCustody] = useState(null)
  useEffect(() => { CaseAPI.custody(caseId).then((r) => setCustody(r.data)) }, [caseId])
  if (!custody) return <Card><p className="text-sm text-slate-500 text-center py-6">Loading chain of custody…</p></Card>

  const Row = ({ e }) => (
    <div className="flex items-start gap-3 py-2 border-b border-slate-800/50 last:border-0 text-xs">
      <span className="text-slate-600 shrink-0 w-36 font-mono">{e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</span>
      <div className="flex-1 min-w-0">
        <span className="text-slate-200 font-medium">{e.action}</span>
        <span className="text-slate-500"> by {e.actor_email || 'system'} ({e.actor_role || '—'})</span>
        {e.detail && <p className="text-slate-600 mt-0.5">{e.detail}</p>}
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <ShieldCheck size={15} /> Evidence integrity
        </h4>
        <DetailRow label="Filename" value={custody.evidence_integrity.filename} />
        <DetailRow label="SHA-256" value={custody.evidence_integrity.file_sha256} small />
        <DetailRow label="Size" value={`${custody.evidence_integrity.file_size_bytes} bytes`} />
        <DetailRow label="Uploaded by" value={custody.evidence_integrity.uploaded_by} />
        <DetailRow label="Uploaded at" value={custody.evidence_integrity.uploaded_at?.slice(0, 19)} />
        <p className="text-[11px] text-slate-600 mt-2">{custody.note}</p>
      </Card>
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Access log ({custody.access_log.length})</h4>
        {custody.access_log.length === 0
          ? <p className="text-xs text-slate-500">No recorded access yet.</p>
          : custody.access_log.map((e, i) => <Row key={i} e={e} />)}
      </Card>
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Export log ({custody.export_log.length})</h4>
        {custody.export_log.length === 0
          ? <p className="text-xs text-slate-500">No reports exported yet.</p>
          : custody.export_log.map((e, i) => <Row key={i} e={e} />)}
      </Card>
      <Card>
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Remediation history ({custody.remediation_history.length})</h4>
        {custody.remediation_history.length === 0
          ? <p className="text-xs text-slate-500">No remediation status changes yet.</p>
          : custody.remediation_history.map((e, i) => <Row key={i} e={e} />)}
      </Card>
    </div>
  )
}

function CommentsTab({ caseId }) {
  const [comments, setComments] = useState(null)
  const [text, setText] = useState('')
  const [sending, setSending] = useState(false)

  const load = () => CaseAPI.comments(caseId).then((r) => setComments(r.data))
  useEffect(() => { load() }, [caseId])

  const submit = async (e) => {
    e.preventDefault()
    if (!text.trim()) return
    setSending(true)
    try {
      await CaseAPI.addComment(caseId, text.trim())
      setText('')
      load()
    } finally {
      setSending(false)
    }
  }

  return (
    <Card>
      <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
        <MessageSquare size={15} /> Investigator notes
      </h4>
      <div className="space-y-3 mb-4 max-h-96 overflow-y-auto">
        {!comments ? <p className="text-xs text-slate-500">Loading…</p> : comments.length === 0 ? (
          <p className="text-xs text-slate-500">No notes yet. Add the first one below.</p>
        ) : comments.map((c) => (
          <div key={c.id} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-medium text-slate-200">{c.author_name}</span>
              <span className="text-[10px] text-slate-500">{c.author_role}</span>
              <span className="text-[10px] text-slate-600 ml-auto">{new Date(c.created_at).toLocaleString()}</span>
            </div>
            <p className="text-xs text-slate-300 whitespace-pre-wrap">{c.body}</p>
          </div>
        ))}
      </div>
      <form onSubmit={submit} className="flex gap-2">
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Add an investigator note…"
          className="flex-1 bg-ink-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-brand-500" />
        <Button type="submit" disabled={sending || !text.trim()} className="!px-3 flex items-center gap-1.5">
          <Send size={14} /> Post
        </Button>
      </form>
    </Card>
  )
}
