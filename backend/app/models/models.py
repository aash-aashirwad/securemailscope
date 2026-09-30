import enum
import uuid
from datetime import datetime
from sqlalchemy import (Column, String, Integer, Float, Boolean, DateTime,
                         ForeignKey, Text, Enum, JSON)
from sqlalchemy.orm import relationship
from app.core.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class RoleEnum(str, enum.Enum):
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"
    FORENSIC_INVESTIGATOR = "forensic_investigator"
    COMPLIANCE_OFFICER = "compliance_officer"


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.SOC_ANALYST, nullable=False)
    organization = Column(String, default="NTRO")
    is_active = Column(Boolean, default=True)
    must_change_password = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    cases = relationship("Case", back_populates="owner")


class AuditLog(Base):
    """Tamper-evident trail of security-relevant actions, for SOC/compliance
    review. Each row stores a SHA-256 hash of its own fields chained to the
    previous row's hash (entry_hash = H(prev_hash || fields)), so any
    retroactive edit or deletion of a row breaks the chain from that point
    forward -- a verifier just recomputes the chain and compares. This does
    not physically prevent a row from being edited at the database layer
    (that requires DB-level permissions/WORM storage, a deployment concern);
    it makes such tampering *detectable*, which is the forensic
    requirement."""
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    actor_email = Column(String, nullable=True)
    actor_role = Column(String, nullable=True)
    action = Column(String, nullable=False)          # e.g. "login_success", "case_upload"
    resource_type = Column(String, nullable=True)     # e.g. "case", "user"
    resource_id = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    prev_hash = Column(String, nullable=True)
    entry_hash = Column(String, nullable=True, index=True)


class CaseStatus(str, enum.Enum):
    UPLOADED = "uploaded"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class Case(Base):
    __tablename__ = "cases"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_size_bytes = Column(Integer, default=0)
    file_sha256 = Column(String, nullable=True)  # evidence-integrity hash of the raw upload
    owner_id = Column(String, ForeignKey("users.id"))
    status = Column(Enum(CaseStatus), default=CaseStatus.UPLOADED)
    overall_risk_score = Column(Float, default=0.0)
    risk_grade = Column(String, default="N/A")  # A-F
    total_sessions = Column(Integer, default=0)
    encrypted_sessions = Column(Integer, default=0)
    plaintext_sessions = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    analyzed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    # Capture-level metadata (PCAP metadata extraction)
    capture_packet_count = Column(Integer, nullable=True)
    capture_duration_seconds = Column(Float, nullable=True)
    capture_start = Column(String, nullable=True)
    capture_end = Column(String, nullable=True)
    capture_link_type = Column(String, nullable=True)
    # Performance benchmark (processing time / memory vs capture size)
    processing_time_seconds = Column(Float, nullable=True)
    peak_memory_mb = Column(Float, nullable=True)

    owner = relationship("User", back_populates="cases")
    sessions = relationship("EmailSession", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    comments = relationship("CaseComment", back_populates="case", cascade="all, delete-orphan")


class EmailSession(Base):
    __tablename__ = "email_sessions"
    id = Column(String, primary_key=True, default=gen_uuid)
    case_id = Column(String, ForeignKey("cases.id"))
    stream_id = Column(String)
    protocol = Column(String)          # SMTP / IMAP / POP3
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    starttls_used = Column(Boolean, default=False)
    starttls_success = Column(Boolean, default=False)
    implicit_tls = Column(Boolean, default=False)
    tls_version = Column(String, nullable=True)
    cipher_suite = Column(String, nullable=True)
    key_exchange = Column(String, nullable=True)
    forward_secrecy = Column(Boolean, default=False)
    cert_chain_valid = Column(Boolean, nullable=True)
    reassembly_gaps = Column(Integer, default=0)
    cert_subject = Column(String, nullable=True)
    cert_issuer = Column(String, nullable=True)
    cert_valid_from = Column(String, nullable=True)
    cert_valid_to = Column(String, nullable=True)
    cert_expired = Column(Boolean, default=False)
    cert_self_signed = Column(Boolean, default=False)
    cert_key_algo = Column(String, nullable=True)
    cert_key_size = Column(Integer, nullable=True)
    cert_sig_algo = Column(String, nullable=True)
    cert_fingerprint_sha256 = Column(String, nullable=True, index=True)  # certificate fingerprinting/reuse detection
    cert_observable = Column(Boolean, nullable=True)   # TLS1.3 observability model: None=n/a, True/False
    observability_note = Column(String, nullable=True)
    non_standard_port = Column(Boolean, default=False)  # detected via banner, not in DEFAULT_PORTS
    tcp_connection_state = Column(String, nullable=True)  # established / fin_closed / reset / unknown
    risk_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    packet_count = Column(Integer, default=0)
    first_seen = Column(String, nullable=True)
    last_seen = Column(String, nullable=True)
    raw_features = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="sessions")


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    case_id = Column(String, ForeignKey("cases.id"))
    session_id = Column(String, nullable=True)
    category = Column(String)          # e.g. "Weak TLS Version", "Certificate", "Cipher Suite"
    title = Column(String)
    description = Column(Text)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    recommendation = Column(Text)
    cve_refs = Column(String, nullable=True)
    compliance_refs = Column(String, nullable=True)   # NIST/PCI-DSS/RBI etc
    remediation_status = Column(String, default="open")  # open -> assigned -> fixed -> verified
    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)
    remediation_updated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="findings")


class CaseComment(Base):
    """Investigator notes / case-collaboration thread, for DFIR workflow."""
    __tablename__ = "case_comments"
    id = Column(String, primary_key=True, default=gen_uuid)
    case_id = Column(String, ForeignKey("cases.id"))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    author_name = Column(String, nullable=True)
    author_role = Column(String, nullable=True)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="comments")


class SecurityPolicy(Base):
    """Organization-defined cipher/TLS policy (cipher/TLS policy engine).
    Single active row per organization; admin-editable. Sessions are
    checked against this in addition to the built-in NIST/PCI baseline,
    so an organization can enforce a stricter internal standard."""
    __tablename__ = "security_policies"
    id = Column(String, primary_key=True, default=gen_uuid)
    organization = Column(String, default="NTRO", unique=True)
    min_tls_version = Column(String, default="TLSv1.2")  # sessions below this are flagged
    banned_ciphers = Column(JSON, default=list)           # substrings matched against cipher_suite
    require_forward_secrecy = Column(Boolean, default=True)
    updated_by = Column(String, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
