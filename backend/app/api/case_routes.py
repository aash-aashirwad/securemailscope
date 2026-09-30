import os
import traceback
from datetime import datetime

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.models.models import Case, CaseStatus, EmailSession, Finding, User, CaseComment, SecurityPolicy, AuditLog
from app.api.deps import get_current_user, require_roles
from app.services.pcap_engine import analyze_pcap, extract_capture_metadata
from app.ml.risk_engine import score_all_sessions, compute_case_summary
from app.services.findings_engine import generate_findings_for_session
from app.services.audit import record
from app.services.evidence import sha256_file
from app.services.timeline import build_case_timeline

router = APIRouter(prefix="/api/cases", tags=["cases"])

ALLOWED_UPLOAD_ROLES = ("admin", "soc_analyst", "forensic_investigator")

# Magic numbers for the capture formats we accept, checked against the
# actual file bytes after upload rather than trusting the client-supplied
# filename/extension, which is trivially spoofable.
_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",  # classic pcap, big-endian
    b"\xd4\xc3\xb2\xa1",  # classic pcap, little-endian
    b"\xa1\xb2\x3c\x4d",  # classic pcap, nanosecond-resolution, big-endian
    b"\x4d\x3c\xb2\xa1",  # classic pcap, nanosecond-resolution, little-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng block type (Section Header Block)
)


def _sanitize_filename(name: str) -> str:
    """Strips any directory components and restricts the name to a safe
    character set, so a crafted filename (path traversal via '../', a null
    byte, etc.) can't be used to write outside the per-user upload
    directory or collide with an unrelated path."""
    name = os.path.basename(name or "upload.pcap")
    name = name.replace("\x00", "")
    safe = "".join(c for c in name if c.isalnum() or c in "._-")
    safe = safe.lstrip(".") or "upload.pcap"
    return safe[:200]


def _looks_like_pcap(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        return any(head == magic for magic in _PCAP_MAGICS)
    except OSError:
        return False


def _get_policy(db: Session, organization: str) -> dict:
    row = db.query(SecurityPolicy).filter(SecurityPolicy.organization == organization).first()
    if not row:
        return None
    return {
        "min_tls_version": row.min_tls_version,
        "banned_ciphers": row.banned_ciphers or [],
        "require_forward_secrecy": row.require_forward_secrecy,
    }


def _run_analysis(case_id: str):
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return
        case.status = CaseStatus.ANALYZING
        db.commit()

        capture_meta = extract_capture_metadata(case.file_path)
        case.capture_packet_count = capture_meta.get("packet_count")
        case.capture_duration_seconds = capture_meta.get("duration_seconds")
        case.capture_link_type = capture_meta.get("link_type")
        if capture_meta.get("first_ts"):
            case.capture_start = datetime.utcfromtimestamp(capture_meta["first_ts"]).isoformat()
        if capture_meta.get("last_ts"):
            case.capture_end = datetime.utcfromtimestamp(capture_meta["last_ts"]).isoformat()

        policy = _get_policy(db, case.owner.organization if case.owner else "NTRO")

        # --- Performance benchmark: wall-clock time + peak memory for the
        # analysis phase (pcap parsing + risk scoring), the part of the
        # pipeline whose cost actually scales with capture size/packets. ---
        import time
        import tracemalloc
        tracemalloc.start()
        _t0 = time.perf_counter()

        raw_sessions = analyze_pcap(case.file_path)
        scored = score_all_sessions(raw_sessions)
        summary = compute_case_summary(scored)

        _current_bytes, _peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        case.processing_time_seconds = round(time.perf_counter() - _t0, 3)
        case.peak_memory_mb = round(_peak_bytes / (1024 * 1024), 2)

        crit = high = med = low = 0
        for s in scored:
            session_row = EmailSession(
                case_id=case.id,
                stream_id=s.get("stream_id"),
                protocol=s.get("protocol"),
                src_ip=s.get("src_ip"), dst_ip=s.get("dst_ip"),
                src_port=s.get("src_port"), dst_port=s.get("dst_port"),
                starttls_used=s.get("starttls_used", False),
                starttls_success=s.get("starttls_success", False),
                implicit_tls=s.get("implicit_tls", False),
                tls_version=s.get("tls_version"),
                cipher_suite=s.get("cipher_suite"),
                key_exchange=s.get("key_exchange"),
                forward_secrecy=s.get("forward_secrecy", False),
                cert_chain_valid=s.get("cert_chain_valid"),
                reassembly_gaps=s.get("reassembly_gaps", 0),
                cert_subject=s.get("cert_subject"),
                cert_issuer=s.get("cert_issuer"),
                cert_valid_from=s.get("cert_valid_from"),
                cert_valid_to=s.get("cert_valid_to"),
                cert_expired=s.get("cert_expired", False),
                cert_self_signed=s.get("cert_self_signed", False),
                cert_key_algo=s.get("cert_key_algo"),
                cert_key_size=s.get("cert_key_size"),
                cert_sig_algo=s.get("cert_sig_algo"),
                cert_fingerprint_sha256=s.get("cert_fingerprint_sha256"),
                cert_observable=s.get("cert_observable"),
                observability_note=s.get("observability_note"),
                non_standard_port=s.get("non_standard_port", False),
                tcp_connection_state=s.get("tcp_connection_state"),
                risk_score=s.get("risk_score", 0),
                anomaly_score=s.get("anomaly_score", 0),
                is_anomalous=s.get("is_anomalous", False),
                packet_count=s.get("packet_count", 0),
                first_seen=s.get("first_seen"),
                last_seen=s.get("last_seen"),
                raw_features=s,
            )
            db.add(session_row)
            db.flush()

            findings = generate_findings_for_session(s, policy=policy)
            for f in findings:
                db.add(Finding(
                    case_id=case.id, session_id=session_row.id,
                    category=f["category"], title=f["title"],
                    description=f["description"], severity=f["severity"],
                    recommendation=f["recommendation"],
                    compliance_refs=f.get("compliance_refs"),
                ))
                if f["severity"] == "critical":
                    crit += 1
                elif f["severity"] == "high":
                    high += 1
                elif f["severity"] == "medium":
                    med += 1
                else:
                    low += 1

        case.overall_risk_score = summary["overall_risk_score"]
        case.risk_grade = summary["risk_grade"]
        case.total_sessions = summary["total_sessions"]
        case.encrypted_sessions = summary["encrypted_sessions"]
        case.plaintext_sessions = summary["plaintext_sessions"]
        case.critical_findings = crit
        case.high_findings = high
        case.medium_findings = med
        case.low_findings = low
        case.status = CaseStatus.COMPLETED
        case.analyzed_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        db.rollback()
        case = db.query(Case).filter(Case.id == case_id).first()
        if case:
            case.status = CaseStatus.FAILED
            case.error_message = f"{e}\n{traceback.format_exc()[-1500:]}"
            db.commit()
    finally:
        db.close()


@router.post("/upload")
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    case_name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*ALLOWED_UPLOAD_ROLES)),
):
    safe_name = _sanitize_filename(file.filename)
    if not (safe_name.endswith(".pcap") or safe_name.endswith(".pcapng") or safe_name.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, or .cap files are accepted")

    dest_dir = os.path.join(settings.UPLOAD_DIR, current_user.id)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, f"{datetime.utcnow().timestamp()}_{safe_name}")
    # os.path.join with an absolute-looking safe_name is still safe here
    # because _sanitize_filename already strips path separators, but double
    # check the resolved path stays inside dest_dir (defense in depth
    # against any future change to _sanitize_filename).
    if os.path.commonpath([os.path.abspath(dest_path), os.path.abspath(dest_dir)]) != os.path.abspath(dest_dir):
        raise HTTPException(status_code=400, detail="Invalid filename")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    written = 0
    try:
        with open(dest_path, "wb") as buf:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    # Abort the write as soon as the limit is crossed instead
                    # of buffering the whole (potentially huge) upload to
                    # disk first and only checking afterward -- a DoS vector
                    # the previous version left open.
                    raise HTTPException(status_code=400, detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")
                buf.write(chunk)
    except HTTPException:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise

    if not _looks_like_pcap(dest_path):
        os.remove(dest_path)
        raise HTTPException(
            status_code=400,
            detail="File does not have a valid pcap/pcapng magic number -- refusing to "
                   "queue a mismatched or corrupted file for parsing.",
        )

    size = written
    file_hash = sha256_file(dest_path)
    case = Case(
        name=case_name, filename=safe_name, file_path=dest_path,
        file_size_bytes=size, file_sha256=file_hash,
        owner_id=current_user.id, status=CaseStatus.UPLOADED,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    record(db, "case_upload", user=current_user, resource_type="case", resource_id=case.id,
           detail=f"filename={safe_name} size={size} sha256={file_hash}")
    background_tasks.add_task(_run_analysis, case.id)
    return {"case_id": case.id, "status": "uploaded", "message": "Analysis started in background", "sha256": file_hash}


def _case_to_dict(c: Case) -> dict:
    return {
        "id": c.id, "name": c.name, "filename": c.filename, "status": c.status.value,
        "overall_risk_score": c.overall_risk_score, "risk_grade": c.risk_grade,
        "total_sessions": c.total_sessions, "encrypted_sessions": c.encrypted_sessions,
        "plaintext_sessions": c.plaintext_sessions, "critical_findings": c.critical_findings,
        "high_findings": c.high_findings, "medium_findings": c.medium_findings,
        "low_findings": c.low_findings, "created_at": c.created_at.isoformat(),
        "analyzed_at": c.analyzed_at.isoformat() if c.analyzed_at else None,
        "error_message": c.error_message,
        "file_sha256": c.file_sha256, "file_size_bytes": c.file_size_bytes,
        "capture_packet_count": c.capture_packet_count,
        "capture_duration_seconds": c.capture_duration_seconds,
        "capture_start": c.capture_start, "capture_end": c.capture_end,
        "capture_link_type": c.capture_link_type,
        "processing_time_seconds": c.processing_time_seconds,
        "peak_memory_mb": c.peak_memory_mb,
    }


def _get_authorized_case(db: Session, case_id: str, current_user: User) -> Case:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if current_user.role.value not in ("admin", "compliance_officer") and case.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this case")
    return case


@router.get("")
def list_cases(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(Case)
    if current_user.role.value not in ("admin", "compliance_officer"):
        q = q.filter(Case.owner_id == current_user.id)
    cases = q.order_by(Case.created_at.desc()).all()
    return [_case_to_dict(c) for c in cases]


@router.get("/benchmark")
def get_performance_benchmark(db: Session = Depends(get_db),
                               current_user: User = Depends(require_roles("admin", "compliance_officer"))):
    """Performance benchmark: capture size/packet count vs. processing time
    and peak memory, across every analyzed case, so ops can see how the
    engine scales and set MAX_PACKETS_PER_CAPTURE/MAX_UPLOAD_SIZE_MB with
    real data instead of guessing."""
    cases = (
        db.query(Case)
        .filter(Case.processing_time_seconds.isnot(None))
        .order_by(Case.analyzed_at.desc())
        .limit(200)
        .all()
    )
    rows = [{
        "case_id": c.id, "name": c.name,
        "file_size_bytes": c.file_size_bytes,
        "capture_packet_count": c.capture_packet_count,
        "total_sessions": c.total_sessions,
        "processing_time_seconds": c.processing_time_seconds,
        "peak_memory_mb": c.peak_memory_mb,
        "analyzed_at": c.analyzed_at.isoformat() if c.analyzed_at else None,
    } for c in cases]

    def _rate(row, key):
        return (row[key] / row["processing_time_seconds"]) if row["processing_time_seconds"] else None

    for r in rows:
        r["packets_per_second"] = round(_rate(r, "capture_packet_count"), 1) if r["capture_packet_count"] and r["processing_time_seconds"] else None
        r["mb_per_second"] = round((r["file_size_bytes"] / (1024 * 1024)) / r["processing_time_seconds"], 3) if r["file_size_bytes"] and r["processing_time_seconds"] else None

    avg_pps = [r["packets_per_second"] for r in rows if r["packets_per_second"]]
    return {
        "cases": rows,
        "summary": {
            "sample_size": len(rows),
            "avg_packets_per_second": round(sum(avg_pps) / len(avg_pps), 1) if avg_pps else None,
            "max_peak_memory_mb": max((r["peak_memory_mb"] for r in rows if r["peak_memory_mb"]), default=None),
        },
    }


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = _get_authorized_case(db, case_id, current_user)
    record(db, "case_viewed", user=current_user, resource_type="case", resource_id=case.id)
    return _case_to_dict(case)


@router.get("/{case_id}/sessions")
def get_case_sessions(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = _get_authorized_case(db, case_id, current_user)
    sessions = db.query(EmailSession).filter(EmailSession.case_id == case_id).all()
    return [{
        "id": s.id, "stream_id": s.stream_id, "protocol": s.protocol,
        "src_ip": s.src_ip, "dst_ip": s.dst_ip, "src_port": s.src_port, "dst_port": s.dst_port,
        "starttls_used": s.starttls_used, "starttls_success": s.starttls_success,
        "implicit_tls": s.implicit_tls, "tls_version": s.tls_version, "cipher_suite": s.cipher_suite,
        "key_exchange": s.key_exchange,
        "forward_secrecy": s.forward_secrecy, "cert_subject": s.cert_subject, "cert_issuer": s.cert_issuer,
        "cert_valid_from": s.cert_valid_from, "cert_valid_to": s.cert_valid_to,
        "cert_expired": s.cert_expired, "cert_self_signed": s.cert_self_signed,
        "cert_key_algo": s.cert_key_algo, "cert_key_size": s.cert_key_size, "cert_sig_algo": s.cert_sig_algo,
        "cert_fingerprint_sha256": s.cert_fingerprint_sha256,
        "cert_observable": s.cert_observable, "observability_note": s.observability_note,
        "non_standard_port": s.non_standard_port, "tcp_connection_state": s.tcp_connection_state,
        "cert_chain_valid": s.cert_chain_valid, "reassembly_gaps": s.reassembly_gaps,
        "cert_chain_errors": (s.raw_features or {}).get("cert_chain_errors", []),
        "risk_score": s.risk_score, "anomaly_score": s.anomaly_score, "is_anomalous": s.is_anomalous,
        "anomaly_explanation": (s.raw_features or {}).get("anomaly_explanation"),
        "packet_count": s.packet_count, "first_seen": s.first_seen, "last_seen": s.last_seen,
        "reasons": (s.raw_features or {}).get("reasons", []),
        "weighted_reasons": (s.raw_features or {}).get("weighted_reasons", []),
    } for s in sessions]


@router.get("/{case_id}/sessions/{session_id}/packets")
def get_session_packet_evidence(case_id: str, session_id: str, db: Session = Depends(get_db),
                                 current_user: User = Depends(get_current_user)):
    """PCAP Evidence Viewer: the exact packets that produced this session's
    reconstruction, so an investigator can see precisely which frames (by
    packet number, direction, timestamp, TCP flags, sequence number) a
    finding is based on -- not just the derived TLS/cert conclusion."""
    case = _get_authorized_case(db, case_id, current_user)
    session = db.query(EmailSession).filter(
        EmailSession.id == session_id, EmailSession.case_id == case_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    packets = (session.raw_features or {}).get("packet_evidence", [])
    record(db, "evidence_packet_view", user=current_user, resource_type="session",
           resource_id=session_id, detail=f"case={case_id}")
    return {
        "session_id": session_id, "stream_id": session.stream_id,
        "packet_count_total": session.packet_count,
        "packet_evidence_captured": len(packets),
        "truncated": session.packet_count > len(packets),
        "packets": packets,
    }


@router.get("/{case_id}/custody")
def get_chain_of_custody(case_id: str, db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user)):
    """Chain-of-custody: unifies evidence integrity (upload hash), every
    access/export touching this case, and the full remediation history,
    into one auditable record for a case -- pulled from the tamper-evident
    audit log (see /api/admin/audit-logs/verify) rather than kept as a
    separate, potentially-divergent log."""
    case = _get_authorized_case(db, case_id, current_user)
    events = (
        db.query(AuditLog)
        .filter(AuditLog.resource_type.in_(("case", "session", "finding")))
        .filter(
            (AuditLog.resource_id == case_id) |
            (AuditLog.detail.like(f"%case={case_id}%"))
        )
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    access_log = [e for e in events if e.action in ("case_upload", "case_viewed")]
    export_log = [e for e in events if e.action == "report_export"]
    remediation_history = [e for e in events if e.action == "finding_remediation_updated"]
    other_events = [e for e in events if e.action not in
                    ("case_upload", "case_viewed", "report_export", "finding_remediation_updated")]

    def _fmt(e):
        return {
            "action": e.action, "actor_email": e.actor_email, "actor_role": e.actor_role,
            "detail": e.detail, "ip_address": e.ip_address, "success": e.success,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "entry_hash": e.entry_hash,
        }

    return {
        "case_id": case.id,
        "evidence_integrity": {
            "filename": case.filename,
            "file_sha256": case.file_sha256,
            "file_size_bytes": case.file_size_bytes,
            "uploaded_by": case.owner.email if case.owner else None,
            "uploaded_at": case.created_at.isoformat() if case.created_at else None,
        },
        "access_log": [_fmt(e) for e in access_log],
        "export_log": [_fmt(e) for e in export_log],
        "remediation_history": [_fmt(e) for e in remediation_history],
        "other_events": [_fmt(e) for e in other_events],
        "note": "Every row above is a hash-chained audit_logs entry; verify the whole "
                "chain's integrity at GET /api/admin/audit-logs/verify.",
    }


@router.get("/{case_id}/findings")
def get_case_findings(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = _get_authorized_case(db, case_id, current_user)
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result = [{
        "id": f.id, "session_id": f.session_id, "category": f.category, "title": f.title,
        "description": f.description, "severity": f.severity.value,
        "recommendation": f.recommendation, "compliance_refs": f.compliance_refs,
        "remediation_status": f.remediation_status, "assigned_to": f.assigned_to,
        "remediation_updated_at": f.remediation_updated_at.isoformat() if f.remediation_updated_at else None,
    } for f in findings]
    result.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return result


@router.patch("/findings/{finding_id}/remediation")
def update_finding_remediation(finding_id: str, status: str, assigned_to: str = None,
                                db: Session = Depends(get_db),
                                current_user: User = Depends(require_roles(
                                    "admin", "soc_analyst", "forensic_investigator"))):
    """Remediation tracking: open -> assigned -> fixed -> verified."""
    if status not in ("open", "assigned", "fixed", "verified"):
        raise HTTPException(status_code=400, detail="Invalid status")
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    case = _get_authorized_case(db, finding.case_id, current_user)
    finding.remediation_status = status
    if assigned_to is not None:
        finding.assigned_to = assigned_to
    finding.remediation_updated_at = datetime.utcnow()
    db.commit()
    record(db, "finding_remediation_updated", user=current_user, resource_type="finding",
           resource_id=finding.id, detail=f"status={status} case={case.id}")
    return {"message": "Remediation status updated", "status": status}


@router.get("/{case_id}/timeline")
def get_case_timeline(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Forensic evidence timeline: packet capture -> session -> TLS ->
    certificate -> finding, chronologically ordered."""
    case = _get_authorized_case(db, case_id, current_user)
    sessions = db.query(EmailSession).filter(EmailSession.case_id == case_id).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    return build_case_timeline(case, sessions, findings)


@router.get("/{case_id}/iocs")
def get_case_iocs(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """IOC extraction: distinct domains(cert subjects)/IPs/certificate
    fingerprints observed in this case, for SOC triage/export."""
    case = _get_authorized_case(db, case_id, current_user)
    sessions = db.query(EmailSession).filter(EmailSession.case_id == case_id).all()
    ips, certs, subjects = set(), {}, set()
    for s in sessions:
        if s.src_ip:
            ips.add(s.src_ip)
        if s.dst_ip:
            ips.add(s.dst_ip)
        if s.cert_subject:
            subjects.add(s.cert_subject)
        if s.cert_fingerprint_sha256:
            certs.setdefault(s.cert_fingerprint_sha256, {
                "fingerprint_sha256": s.cert_fingerprint_sha256,
                "subject": s.cert_subject, "issuer": s.cert_issuer,
                "sessions": [],
            })["sessions"].append(s.stream_id)
    return {
        "ip_addresses": sorted(ips),
        "certificate_subjects": sorted(subjects),
        "certificate_fingerprints": list(certs.values()),
    }


@router.get("/{case_id}/certificates/reuse")
def get_certificate_reuse(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Certificate reuse detection: for each certificate fingerprint seen in
    this case, find every OTHER case (visible to this user) that also
    presented it — correlating infrastructure/relay reuse across captures."""
    case = _get_authorized_case(db, case_id, current_user)
    fingerprints = {
        s.cert_fingerprint_sha256
        for s in db.query(EmailSession).filter(EmailSession.case_id == case_id).all()
        if s.cert_fingerprint_sha256
    }
    if not fingerprints:
        return []

    visible_case_ids = None
    if current_user.role.value not in ("admin", "compliance_officer"):
        visible_case_ids = {c.id for c in db.query(Case.id).filter(Case.owner_id == current_user.id).all()}

    results = []
    for fp in fingerprints:
        rows = db.query(EmailSession).filter(EmailSession.cert_fingerprint_sha256 == fp).all()
        by_case = {}
        for r in rows:
            if visible_case_ids is not None and r.case_id not in visible_case_ids:
                continue
            by_case.setdefault(r.case_id, {"case_id": r.case_id, "stream_ids": []})["stream_ids"].append(r.stream_id)
        if len(by_case) > 1:
            case_names = {c.id: c.name for c in db.query(Case.id, Case.name).filter(Case.id.in_(by_case.keys())).all()}
            for entry in by_case.values():
                entry["case_name"] = case_names.get(entry["case_id"])
            results.append({"fingerprint_sha256": fp, "seen_in_cases": list(by_case.values())})
    return results


@router.get("/{case_id}/comments")
def list_case_comments(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = _get_authorized_case(db, case_id, current_user)
    comments = db.query(CaseComment).filter(CaseComment.case_id == case_id).order_by(CaseComment.created_at.asc()).all()
    return [{
        "id": c.id, "author_name": c.author_name, "author_role": c.author_role,
        "body": c.body, "created_at": c.created_at.isoformat(),
    } for c in comments]


@router.post("/{case_id}/comments")
def add_case_comment(case_id: str, body: str = Form(...), db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    """Case collaboration: investigator notes / comments thread."""
    case = _get_authorized_case(db, case_id, current_user)
    if not body or not body.strip():
        raise HTTPException(status_code=400, detail="Comment cannot be empty")
    comment = CaseComment(
        case_id=case.id, user_id=current_user.id, author_name=current_user.full_name,
        author_role=current_user.role.value, body=body.strip()[:4000],
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    record(db, "case_comment_added", user=current_user, resource_type="case", resource_id=case.id)
    return {"id": comment.id, "author_name": comment.author_name, "author_role": comment.author_role,
            "body": comment.body, "created_at": comment.created_at.isoformat()}


@router.delete("/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db),
                 current_user: User = Depends(require_roles("admin", "forensic_investigator"))):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if current_user.role.value != "admin" and case.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if os.path.exists(case.file_path):
        os.remove(case.file_path)
    record(db, "case_deleted", user=current_user, resource_type="case", resource_id=case.id,
           detail=f"name={case.name}")
    db.delete(case)
    db.commit()
    return {"message": "Case deleted"}
