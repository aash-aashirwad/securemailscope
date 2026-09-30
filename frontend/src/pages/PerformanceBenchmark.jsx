import { useEffect, useState } from 'react'
import { Gauge, Cpu } from 'lucide-react'
import { CaseAPI } from '../api/client'
import { Card, StatCard } from '../components/UI'

export default function PerformanceBenchmark() {
  const [data, setData] = useState(null)

  useEffect(() => { CaseAPI.benchmark().then((r) => setData(r.data)) }, [])

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Gauge size={22} className="text-brand-400" /> Performance Benchmark
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          Capture size and packet count vs. processing time and peak memory, across every
          analyzed case — use this to size MAX_PACKETS_PER_CAPTURE / MAX_UPLOAD_SIZE_MB for
          your deployment tier rather than guessing.
        </p>
      </div>

      {!data ? (
        <Card><p className="text-sm text-slate-500 text-center py-6">Loading…</p></Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard label="Sample size" value={data.summary.sample_size} icon={Gauge} accent="brand" />
            <StatCard label="Avg packets/sec" value={data.summary.avg_packets_per_second ?? '—'} icon={Cpu} accent="emerald" />
            <StatCard label="Max peak memory" value={data.summary.max_peak_memory_mb ?? '—'} suffix=" MB" icon={Cpu} accent="amber" />
          </div>

          <Card className="!p-0 overflow-hidden">
            {data.cases.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-10">No analyzed cases yet — upload and analyze a capture to populate benchmarks.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-slate-500 border-b border-slate-800 bg-slate-800/30">
                      <th className="px-3 py-2.5">Case</th>
                      <th className="px-3 py-2.5">Size</th>
                      <th className="px-3 py-2.5">Packets</th>
                      <th className="px-3 py-2.5">Sessions</th>
                      <th className="px-3 py-2.5">Time</th>
                      <th className="px-3 py-2.5">Peak memory</th>
                      <th className="px-3 py-2.5">Packets/sec</th>
                      <th className="px-3 py-2.5">MB/sec</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.cases.map((c) => (
                      <tr key={c.case_id} className="border-b border-slate-800/50 hover:bg-slate-800/20">
                        <td className="px-3 py-2.5 text-slate-200 font-medium">{c.name}</td>
                        <td className="px-3 py-2.5 text-slate-400">{c.file_size_bytes ? `${(c.file_size_bytes / (1024 * 1024)).toFixed(2)} MB` : '—'}</td>
                        <td className="px-3 py-2.5 text-slate-400">{c.capture_packet_count ?? '—'}</td>
                        <td className="px-3 py-2.5 text-slate-400">{c.total_sessions}</td>
                        <td className="px-3 py-2.5 text-slate-400">{c.processing_time_seconds}s</td>
                        <td className="px-3 py-2.5 text-slate-400">{c.peak_memory_mb} MB</td>
                        <td className="px-3 py-2.5 text-emerald-400">{c.packets_per_second ?? '—'}</td>
                        <td className="px-3 py-2.5 text-emerald-400">{c.mb_per_second ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  )
}
