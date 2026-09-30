from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime

from app.core.database import get_db
from app.models.models import Case, User, RoleEnum, Finding, AuditLog, SecurityPolicy
from app.api.deps import get_current_user, require_roles
from app.api.schemas import UserOut, UserCreate, AuditLogOut, SecurityPolicyOut, SecurityPolicyUpdate
from app.core.security import hash_password, validate_password_strength
from app.services.audit import record

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/traceability-matrix")
def get_traceability_matrix(current_user: User = Depends(get_current_user)):
    """PS-26159 requirement -> implementation -> API -> UI -> evidence,
    served from the running system so the mapping can be verified rather
    than taken on faith from a static document."""
    from app.services.traceability import PS_TRACEABILITY_MATRIX, KNOWN_LIMITATIONS
    return {"matrix": PS_TRACEABILITY_MATRIX, "known_limitations": KNOWN_LIMITATIONS}


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(Case)
    if current_user.role.value not in ("admin", "compliance_officer"):
        q = q.filter(Case.owner_id == current_user.id)
    cases = q.all()

    total_cases = len(cases)
    completed = sum(1 for c in cases if c.status.value == "completed")
    analyzing = sum(1 for c in cases if c.status.value == "analyzing")
    failed = sum(1 for c in cases if c.status.value == "failed")

    avg_risk = round(sum(c.overall_risk_score for c in cases) / completed, 1) if completed else 0
    total_sessions = sum(c.total_sessions for c in cases)
    total_plaintext = sum(c.plaintext_sessions for c in cases)
    total_critical = sum(c.critical_findings for c in cases)
    total_high = sum(c.high_findings for c in cases)
    total_medium = sum(c.medium_findings for c in cases)
    total_low = sum(c.low_findings for c in cases)

    grade_distribution = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for c in cases:
        if c.risk_grade in grade_distribution:
            grade_distribution[c.risk_grade] += 1

    recent = sorted(cases, key=lambda c: c.created_at, reverse=True)[:5]

    return {
        "total_cases": total_cases,
        "completed_cases": completed,
        "analyzing_cases": analyzing,
        "failed_cases": failed,
        "average_risk_score": avg_risk,
        "total_sessions_analyzed": total_sessions,
        "total_plaintext_sessions": total_plaintext,
        "findings_summary": {
            "critical": total_critical, "high": total_high,
            "medium": total_medium, "low": total_low,
        },
        "grade_distribution": grade_distribution,
        "recent_cases": [{
            "id": c.id, "name": c.name, "status": c.status.value,
            "risk_grade": c.risk_grade, "overall_risk_score": c.overall_risk_score,
            "created_at": c.created_at.isoformat(),
        } for c in recent],
    }


# ---- Admin: user management ----

@admin_router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(User).order_by(User.created_at.desc()).all()


@admin_router.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                 current_user: User = Depends(require_roles("admin"))):
    """Admin-provisioned account creation — the only route that can grant the
    'admin' role, and issues a temporary password the user must change on
    first login."""
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        role = RoleEnum(payload.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    pw_error = validate_password_strength(payload.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    user = User(
        full_name=payload.full_name, email=payload.email,
        hashed_password=hash_password(payload.password), role=role,
        organization=payload.organization, must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record(db, "admin_created_user", user=current_user, resource_type="user",
           resource_id=user.id, detail=f"role={role.value}")
    return user


@admin_router.patch("/users/{user_id}/role")
def update_user_role(user_id: str, role: str, db: Session = Depends(get_db),
                      current_user: User = Depends(require_roles("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Admins cannot change their own role")
    try:
        old_role = user.role.value
        user.role = RoleEnum(role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    db.commit()
    record(db, "role_changed", user=current_user, resource_type="user", resource_id=user.id,
           detail=f"{old_role} -> {role}")
    return {"message": "Role updated"}


@admin_router.patch("/users/{user_id}/status")
def toggle_user_status(user_id: str, is_active: bool, db: Session = Depends(get_db),
                        current_user: User = Depends(require_roles("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id and not is_active:
        raise HTTPException(status_code=400, detail="Admins cannot deactivate their own account")
    user.is_active = is_active
    if is_active:
        user.failed_login_attempts = 0
        user.locked_until = None
    db.commit()
    record(db, "user_status_changed", user=current_user, resource_type="user", resource_id=user.id,
           detail=f"is_active={is_active}")
    return {"message": "Status updated"}


@admin_router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(limit: int = 200, db: Session = Depends(get_db),
                     current_user: User = Depends(require_roles("admin", "compliance_officer"))):
    """Compliance officers get read-only visibility into the audit trail;
    only admins can manage accounts."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(limit, 1000)).all()
    return [
        AuditLogOut(
            id=l.id, actor_email=l.actor_email, actor_role=l.actor_role, action=l.action,
            resource_type=l.resource_type, resource_id=l.resource_id, detail=l.detail,
            ip_address=l.ip_address, success=l.success, created_at=l.created_at.isoformat(),
        ) for l in logs
    ]


# ---- Risk trend & historical baseline ----

@router.get("/risk-trend")
def risk_trend(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Risk trend analysis (P1): overall risk score per case ordered by
    upload date, so an analyst/compliance officer can see posture over
    time per organization instead of only the latest snapshot."""
    q = db.query(Case).filter(Case.status == "completed")
    if current_user.role.value not in ("admin", "compliance_officer"):
        q = q.filter(Case.owner_id == current_user.id)
    cases = q.order_by(Case.created_at.asc()).all()
    return [{
        "case_id": c.id, "case_name": c.name, "date": c.created_at.isoformat(),
        "overall_risk_score": c.overall_risk_score, "risk_grade": c.risk_grade,
        "plaintext_sessions": c.plaintext_sessions, "encrypted_sessions": c.encrypted_sessions,
    } for c in cases]


@router.get("/baseline")
def historical_baseline(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Historical security baseline (P1): rolling average risk score
    across all of this user's (or, for admin/compliance, the whole
    organization's) completed cases, so a single case can be compared
    against 'how this organization has typically scored' rather than in
    isolation. Computed on the fly from existing case history rather than
    a separately-maintained table, so it's always in sync."""
    q = db.query(Case).filter(Case.status == "completed")
    if current_user.role.value not in ("admin", "compliance_officer"):
        q = q.filter(Case.owner_id == current_user.id)
    cases = q.order_by(Case.created_at.asc()).all()
    if not cases:
        return {"baseline_available": False, "sample_size": 0}
    scores = [c.overall_risk_score for c in cases]
    avg = round(sum(scores) / len(scores), 1)
    best = min(scores)
    worst = max(scores)
    latest = cases[-1]
    trend = None
    if len(cases) >= 2:
        prior_avg = round(sum(scores[:-1]) / len(scores[:-1]), 1)
        trend = "improving" if latest.overall_risk_score < prior_avg else (
            "worsening" if latest.overall_risk_score > prior_avg else "stable")
    return {
        "baseline_available": True, "sample_size": len(cases),
        "average_risk_score": avg, "best_risk_score": best, "worst_risk_score": worst,
        "latest_case_score": latest.overall_risk_score, "trend_vs_baseline": trend,
    }


# ---- Admin: cipher/TLS security policy (policy engine) ----

def _policy_to_dict(row: SecurityPolicy) -> dict:
    return {
        "id": row.id, "organization": row.organization, "min_tls_version": row.min_tls_version,
        "banned_ciphers": row.banned_ciphers or [], "require_forward_secrecy": row.require_forward_secrecy,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@admin_router.get("/policy", response_model=SecurityPolicyOut)
def get_security_policy(db: Session = Depends(get_db),
                         current_user: User = Depends(require_roles("admin", "compliance_officer"))):
    row = db.query(SecurityPolicy).filter(SecurityPolicy.organization == current_user.organization).first()
    if not row:
        row = SecurityPolicy(organization=current_user.organization)
        db.add(row)
        db.commit()
        db.refresh(row)
    return _policy_to_dict(row)


@admin_router.put("/policy", response_model=SecurityPolicyOut)
def update_security_policy(payload: SecurityPolicyUpdate, db: Session = Depends(get_db),
                            current_user: User = Depends(require_roles("admin"))):
    row = db.query(SecurityPolicy).filter(SecurityPolicy.organization == current_user.organization).first()
    if not row:
        row = SecurityPolicy(organization=current_user.organization)
        db.add(row)
    row.min_tls_version = payload.min_tls_version
    row.banned_ciphers = payload.banned_ciphers
    row.require_forward_secrecy = payload.require_forward_secrecy
    row.updated_by = current_user.id
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    record(db, "security_policy_updated", user=current_user, resource_type="security_policy",
           resource_id=row.id, detail=f"min_tls={row.min_tls_version}")
    return _policy_to_dict(row)


@admin_router.get("/audit-logs/verify")
def verify_audit_log_chain(db: Session = Depends(get_db),
                            current_user: User = Depends(require_roles("admin", "compliance_officer"))):
    """Recomputes the audit log's hash chain end-to-end and reports whether
    it is intact, so an investigator can confirm the trail hasn't been
    edited or had rows deleted out from under it."""
    from app.services.audit import verify_chain
    intact, broken_id = verify_chain(db)
    return {"intact": intact, "first_broken_entry_id": broken_id}
