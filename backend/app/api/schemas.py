import re
from typing import Optional, List
from pydantic import BaseModel, field_validator

# Deliberately not pydantic's EmailStr: it delegates to `email_validator`,
# which by default rejects RFC-2606 special-use/reserved TLDs (.local,
# .test, .internal, .lan, etc.) as a syntax error, not just a
# deliverability warning. That's exactly the kind of address a
# government/enterprise deployment on an internal or air-gapped network
# is likely to use (e.g. `analyst@ntro.local`), so the stricter
# public-internet-oriented check would incorrectly block legitimate
# accounts. This regex enforces basic shape only -- validity in the
# sense that matters here (does this org recognize the address) is an
# organizational policy question, not something the API should guess at.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_basic_email(value: str) -> str:
    value = value.strip()
    if not _EMAIL_RE.match(value):
        raise ValueError("must be a valid email address (user@domain.tld)")
    return value.lower()


class UserCreate(BaseModel):
    full_name: str
    email: str
    password: str
    role: str = "soc_analyst"
    organization: str = "NTRO"

    _validate_email = field_validator("email")(_validate_basic_email)


class UserOut(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    organization: str
    is_active: bool
    must_change_password: bool = False

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: str
    password: str

    _validate_email = field_validator("email")(_validate_basic_email)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserOut


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class SecurityPolicyOut(BaseModel):
    id: str
    organization: str
    min_tls_version: str
    banned_ciphers: list = []
    require_forward_secrecy: bool
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class SecurityPolicyUpdate(BaseModel):
    min_tls_version: str
    banned_ciphers: list = []
    require_forward_secrecy: bool = True


class AuditLogOut(BaseModel):
    id: str
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    detail: Optional[str] = None
    ip_address: Optional[str] = None
    success: bool
    created_at: str

    class Config:
        from_attributes = True


class CaseOut(BaseModel):
    id: str
    name: str
    filename: str
    status: str
    overall_risk_score: float
    risk_grade: str
    total_sessions: int
    encrypted_sessions: int
    plaintext_sessions: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    created_at: str
    analyzed_at: Optional[str] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True
