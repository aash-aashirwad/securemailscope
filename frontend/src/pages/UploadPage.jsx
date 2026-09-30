import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { UploadCloud, FileArchive, X, AlertCircle } from 'lucide-react'
import { CaseAPI } from '../api/client'
import { Card, Button } from '../components/UI'

export default function UploadPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState(null)
  const [caseName, setCaseName] = useState('')
  const [dragging, setDragging] = useState(false)
  const [progress, setProgress] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const inputRef = useRef(null)

  const pick = (f) => {
    if (!f) return
    if (!/\.(pcap|pcapng|cap)$/i.test(f.name)) {
      setError('Only .pcap, .pcapng, or .cap files are supported')
      return
    }
    setError('')
    setFile(f)
    if (!caseName) setCaseName(f.name.replace(/\.(pcap|pcapng|cap)$/i, ''))
  }

  const handleSubmit = async () => {
    if (!file || !caseName) return
    setUploading(true)
    setError('')
    try {
      const res = await CaseAPI.upload(file, caseName, (evt) => {
        setProgress(Math.round((evt.loaded * 100) / evt.total))
      })
      navigate(`/cases/${res.data.case_id}`)
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed')
      setUploading(false)
    }
  }

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Upload Network Capture</h1>
        <p className="text-slate-400 text-sm mt-1">
          Submit a PCAP/PCAPNG capture containing SMTP, IMAP, or POP3 traffic for passive cryptographic
          posture analysis. Analysis runs automatically in the background.
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center gap-2 text-red-300 text-sm">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      <Card>
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files[0]) }}
          onClick={() => inputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-colors ${
            dragging ? 'border-brand-500 bg-brand-500/5' : 'border-slate-700 hover:border-slate-600'
          }`}
        >
          <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" className="hidden"
            onChange={(e) => pick(e.target.files[0])} />
          {!file ? (
            <>
              <UploadCloud size={40} className="mx-auto text-slate-500 mb-3" />
              <p className="text-slate-300 font-medium">Drop a .pcap file here or click to browse</p>
              <p className="text-slate-500 text-xs mt-1">Max 250MB · .pcap, .pcapng, .cap</p>
            </>
          ) : (
            <div className="flex items-center justify-center gap-3">
              <FileArchive size={28} className="text-brand-400" />
              <div className="text-left">
                <div className="text-slate-200 font-medium text-sm">{file.name}</div>
                <div className="text-slate-500 text-xs">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
              </div>
              {!uploading && (
                <button onClick={(e) => { e.stopPropagation(); setFile(null) }}
                  className="ml-2 text-slate-500 hover:text-red-400">
                  <X size={18} />
                </button>
              )}
            </div>
          )}
        </div>

        {file && (
          <div className="mt-5 space-y-4">
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Case name</label>
              <input
                value={caseName} onChange={(e) => setCaseName(e.target.value)} disabled={uploading}
                className="w-full bg-ink-800 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-brand-500/50"
                placeholder="e.g. Q3 Mail Gateway Audit"
              />
            </div>

            {uploading && (
              <div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-brand-500 transition-all" style={{ width: `${progress}%` }} />
                </div>
                <p className="text-xs text-slate-500 mt-1.5">{progress}% uploaded — analysis will begin automatically</p>
              </div>
            )}

            <Button onClick={handleSubmit} disabled={uploading || !caseName} className="w-full">
              {uploading ? 'Uploading…' : 'Upload & Analyze'}
            </Button>
          </div>
        )}
      </Card>

      <Card className="!p-5">
        <h4 className="text-sm font-semibold text-slate-300 mb-2">What gets analyzed</h4>
        <ul className="text-xs text-slate-500 space-y-1.5 list-disc list-inside">
          <li>TCP stream reconstruction for SMTP (25/587), IMAP (143/993), POP3 (110/995)</li>
          <li>STARTTLS negotiation detection and success validation</li>
          <li>TLS handshake parsing — negotiated version, cipher suite, key exchange</li>
          <li>X.509 certificate extraction — expiry, key strength, signature algorithm, self-signed detection</li>
          <li>AI-based risk scoring and statistical anomaly detection across all sessions in the capture</li>
        </ul>
      </Card>
    </div>
  )
}
