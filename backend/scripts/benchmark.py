"""Performance benchmark (SIH upgrade #7): measures actual processing time
and peak memory of the real analyze_pcap() pipeline across capture sizes,
so capacity/scaling claims are backed by numbers instead of guesses.

Run directly for a human-readable report:
    python scripts/benchmark.py

Also exercised (with a much smaller session count, for CI speed) by
tests/test_performance_benchmark.py, marked `benchmark` and excluded from
the default `pytest` run (see pytest.ini) since it's slower than a unit
test has any business being.
"""
import os
import sys
import time
import tracemalloc
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, Raw, wrpcap  # noqa: E402
from app.services.pcap_engine import analyze_pcap, extract_capture_metadata  # noqa: E402


def _build_smtp_session(src_ip, dst_ip, sport, dport, base_seq_c=1000, base_seq_s=5000, t0=0.0):
    """One realistic plaintext SMTP session: SYN/SYN-ACK/ACK, EHLO/banner/
    QUIT exchange, graceful FIN. Mirrors tests/fixtures generation."""
    pkts = []
    seq_c, seq_s = base_seq_c, base_seq_s
    t = t0
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1))
    seq_c += 1
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s + 1))
    seq_s += 1

    exchanges = [
        (b"220 mail.example.com ESMTP\r\n", b"EHLO client.example.com\r\n"),
        (b"250 OK\r\n", b"MAIL FROM:<a@example.com>\r\n"),
        (b"221 Bye\r\n", b"QUIT\r\n"),
    ]
    for server_msg, client_msg in exchanges:
        pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c) / Raw(load=server_msg))
        seq_s += len(server_msg)
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) / Raw(load=client_msg))
        seq_c += len(client_msg)

    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1))
    for p in pkts:
        p.time = t
        t += 0.001
    return pkts


def build_synthetic_capture(path: str, num_sessions: int):
    """Writes `num_sessions` independent SMTP sessions (distinct 4-tuples,
    since the reconstructor tracks streams by src/dst ip+port) into a
    single pcap at `path`."""
    all_pkts = []
    t = 0.0
    for i in range(num_sessions):
        src_ip = f"10.0.{(i >> 8) & 0xFF}.{i & 0xFF}"
        dst_ip = f"203.0.{113 + (i % 4)}.{10 + (i % 200)}"
        sport = 40000 + (i % 20000)
        pkts = _build_smtp_session(src_ip, dst_ip, sport, 25, t0=t)
        all_pkts.extend(pkts)
        t += 0.05
    wrpcap(path, all_pkts)
    return sum(len(bytes(p)) for p in all_pkts)


def run_benchmark(session_counts=(10, 50, 200, 500)):
    results = []
    for n in session_counts:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            approx_bytes = build_synthetic_capture(path, n)
            file_size_kb = os.path.getsize(path) / 1024

            tracemalloc.start()
            t_start = time.perf_counter()
            sessions = analyze_pcap(path)
            meta = extract_capture_metadata(path)
            elapsed = time.perf_counter() - t_start
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            results.append({
                "sessions_requested": n,
                "sessions_recovered": len(sessions),
                "file_size_kb": round(file_size_kb, 1),
                "packet_count": meta.get("packet_count"),
                "elapsed_seconds": round(elapsed, 4),
                "peak_memory_mb": round(peak / (1024 * 1024), 2),
                "packets_per_second": round(meta.get("packet_count", 0) / elapsed, 1) if elapsed > 0 else None,
            })
        finally:
            os.unlink(path)
    return results


def print_report(results):
    print(f"{'Sessions':>10} {'Packets':>9} {'Size(KB)':>10} {'Time(s)':>9} {'Peak MB':>9} {'Pkts/sec':>10}")
    for r in results:
        print(f"{r['sessions_recovered']:>10} {r['packet_count']:>9} {r['file_size_kb']:>10} "
              f"{r['elapsed_seconds']:>9} {r['peak_memory_mb']:>9} {r['packets_per_second']:>10}")


if __name__ == "__main__":
    report = run_benchmark()
    print_report(report)
