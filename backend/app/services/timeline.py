"""Builds a unified, chronologically-ordered forensic timeline for a case:
packet capture -> session -> TLS negotiation -> certificate -> finding.
(P1: Forensic evidence timeline.)"""
from datetime import datetime


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def build_case_timeline(case, sessions, findings) -> list:
    events = []

    if case.created_at:
        events.append({
            "ts": case.created_at.isoformat(), "type": "case_uploaded",
            "label": f"Capture '{case.name}' uploaded ({case.filename})",
            "severity": "info",
        })

    for s in sessions:
        if s.first_seen:
            label = f"{s.protocol} session opened: {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}"
            events.append({
                "ts": s.first_seen, "type": "session_start", "session_id": s.id,
                "label": label, "severity": "info",
            })
        if s.tls_version or s.implicit_tls:
            events.append({
                "ts": s.first_seen, "type": "tls_negotiated", "session_id": s.id,
                "label": f"TLS negotiated on {s.stream_id}: {s.tls_version or 'implicit TLS'} / {s.cipher_suite or 'n/a'}",
                "severity": "info",
            })
        if s.cert_subject:
            events.append({
                "ts": s.first_seen, "type": "certificate_presented", "session_id": s.id,
                "label": f"Certificate presented for {s.cert_subject}"
                         + (" (EXPIRED)" if s.cert_expired else "")
                         + (" (SELF-SIGNED)" if s.cert_self_signed else ""),
                "severity": "high" if (s.cert_expired or s.cert_self_signed) else "info",
            })
        if s.last_seen and s.last_seen != s.first_seen:
            state = s.tcp_connection_state or "unknown"
            events.append({
                "ts": s.last_seen, "type": "session_end", "session_id": s.id,
                "label": f"Session {s.stream_id} ended ({state})",
                "severity": "medium" if state == "reset" else "info",
            })

    for f in findings:
        events.append({
            "ts": f.created_at.isoformat() if f.created_at else None,
            "type": "finding_raised", "session_id": f.session_id, "finding_id": f.id,
            "label": f"Finding raised: {f.title}",
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        })

    if case.analyzed_at:
        events.append({
            "ts": case.analyzed_at.isoformat(), "type": "analysis_complete",
            "label": f"Analysis completed — grade {case.risk_grade}, "
                     f"{case.critical_findings} critical / {case.high_findings} high finding(s)",
            "severity": "info",
        })

    # Sort chronologically; events with no timestamp sink to the end in
    # upload order rather than crashing the sort.
    dated = [e for e in events if e.get("ts")]
    undated = [e for e in events if not e.get("ts")]
    dated.sort(key=lambda e: e["ts"])
    return dated + undated
