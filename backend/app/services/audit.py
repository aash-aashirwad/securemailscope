"""Central helper for writing to the audit trail.

Every authentication event and every sensitive data-access/admin action
should call `record()` so the system has a tamper-evident trail suitable
for SOC review and compliance audits (PS 26159 requires accountability
for who accessed which case/report and when).

Tamper-evidence is implemented as a hash chain: each new entry's
`entry_hash` is SHA-256 over its own fields concatenated with the
previous entry's hash, so altering or deleting any historical row breaks
the chain from that point on. `verify_chain()` walks the table in
insertion order and reports the first broken link, if any.
"""
import hashlib
from sqlalchemy.orm import Session
from app.models.models import AuditLog

GENESIS_HASH = "0" * 64


def _compute_entry_hash(prev_hash: str, entry: AuditLog) -> str:
    payload = "|".join(str(x) for x in [
        prev_hash,
        entry.id, entry.user_id, entry.actor_email, entry.actor_role,
        entry.action, entry.resource_type, entry.resource_id,
        entry.detail, entry.ip_address, entry.success,
        entry.created_at.isoformat() if entry.created_at else "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(db: Session, action: str, user=None, resource_type: str = None,
           resource_id: str = None, detail: str = None, ip_address: str = None,
           success: bool = True, actor_email: str = None, actor_role: str = None):
    last = db.query(AuditLog).order_by(AuditLog.created_at.desc()).first()
    prev_hash = last.entry_hash if last and last.entry_hash else GENESIS_HASH

    entry = AuditLog(
        user_id=getattr(user, "id", None),
        actor_email=actor_email or getattr(user, "email", None),
        actor_role=actor_role or (user.role.value if user and getattr(user, "role", None) else None),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        ip_address=ip_address,
        success=success,
        prev_hash=prev_hash,
    )
    from datetime import datetime
    entry.created_at = entry.created_at or datetime.utcnow()
    db.add(entry)
    # Flush (not commit) first so the DB-assigned id default is populated
    # on the Python object -- entry.id is None until the INSERT actually
    # runs, and hashing it before that point would silently hash a
    # different value than what's ever read back, poisoning every
    # verification. Flushing without committing keeps this atomic with
    # the caller's transaction.
    db.flush()
    entry.entry_hash = _compute_entry_hash(prev_hash, entry)
    db.commit()
    return entry


def verify_chain(db: Session):
    """Walks the audit log in insertion order and recomputes each entry's
    hash from its stored fields + the previous entry's stored hash.
    Returns (is_intact: bool, first_broken_entry_id: str | None)."""
    entries = db.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
    prev_hash = GENESIS_HASH
    for entry in entries:
        expected = _compute_entry_hash(prev_hash, entry)
        if entry.entry_hash != expected:
            return False, entry.id
        prev_hash = entry.entry_hash
    return True, None
