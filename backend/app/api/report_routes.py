from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Case, EmailSession, Finding, User
from app.api.deps import get_current_user
from app.api.case_routes import _case_to_dict
from app.reports.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from app.services.audit import record

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _gather(case_id: str, db: Session, current_user: User):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if current_user.role.value not in ("admin", "compliance_officer") and case.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    sessions = db.query(EmailSession).filter(EmailSession.case_id == case_id).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()

    sessions_dicts = [{
        "stream_id": s.stream_id, "protocol": s.protocol, "src_ip": s.src_ip, "dst_ip": s.dst_ip,
        "src_port": s.src_port, "dst_port": s.dst_port, "tls_version": s.tls_version,
        "cipher_suite": s.cipher_suite, "implicit_tls": s.implicit_tls,
        "forward_secrecy": s.forward_secrecy, "cert_expired": s.cert_expired,
        "cert_self_signed": s.cert_self_signed, "risk_score": s.risk_score, "risk_grade":
        ("F" if s.risk_score >= 75 else "D" if s.risk_score >= 55 else "C" if s.risk_score >= 35 else "B" if s.risk_score >= 15 else "A"),
    } for s in sessions]
    findings_dicts = [{
        "category": f.category, "title": f.title, "description": f.description,
        "severity": f.severity.value, "recommendation": f.recommendation,
        "compliance_refs": f.compliance_refs,
    } for f in findings]
    return _case_to_dict(case), sessions_dicts, findings_dicts


@router.get("/{case_id}/json")
def report_json(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case, sessions, findings = _gather(case_id, db, current_user)
    record(db, "report_export", user=current_user, resource_type="case", resource_id=case_id, detail="format=json")
    return generate_json_report(case, sessions, findings)


@router.get("/{case_id}/html")
def report_html(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case, sessions, findings = _gather(case_id, db, current_user)
    html = generate_html_report(case, sessions, findings)
    record(db, "report_export", user=current_user, resource_type="case", resource_id=case_id, detail="format=html")
    return Response(content=html, media_type="text/html")


@router.get("/{case_id}/pdf")
def report_pdf(case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case, sessions, findings = _gather(case_id, db, current_user)
    pdf_bytes = generate_pdf_report(case, sessions, findings)
    record(db, "report_export", user=current_user, resource_type="case", resource_id=case_id, detail="format=pdf")
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case["name"]}_report.pdf"'},
    )
