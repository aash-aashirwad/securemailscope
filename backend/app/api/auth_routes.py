from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    decode_token, validate_password_strength,
)
from app.core.limiter import limiter
from app.models.models import User, RoleEnum
from app.api.schemas import (
    UserCreate, UserOut, LoginRequest, TokenResponse, RefreshRequest,
    ChangePasswordRequest,
)
from app.api.deps import get_current_user
from app.services.audit import record

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Only these roles may be granted at self-registration time. "admin" accounts
# must be provisioned by an existing admin via /api/admin/users to prevent
# privilege self-escalation at signup.
SELF_REGISTERABLE_ROLES = ("soc_analyst", "forensic_investigator", "compliance_officer")


def _issue_tokens(user: User) -> TokenResponse:
    access = create_access_token({"sub": user.id, "role": user.role.value})
    refresh = create_refresh_token({"sub": user.id})
    return TokenResponse(access_token=access, refresh_token=refresh, user=UserOut.model_validate(user))


@router.post("/register", response_model=TokenResponse)
@limiter.limit("5/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        # Same generic message an invalid login would use, to avoid leaking
        # which emails are already registered.
        raise HTTPException(status_code=400, detail="Unable to register with the supplied details")

    if payload.role not in SELF_REGISTERABLE_ROLES:
        raise HTTPException(
            status_code=403,
            detail="This role cannot be self-assigned. Ask an administrator to create or promote the account.",
        )
    role = RoleEnum(payload.role)

    pw_error = validate_password_strength(payload.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    user = User(
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=role,
        organization=payload.organization,
        password_changed_at=datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record(db, "register", user=user, resource_type="user", resource_id=user.id,
           ip_address=request.client.host if request.client else None)
    return _issue_tokens(user)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.LOGIN_RATE_LIMIT)
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    user = db.query(User).filter(User.email == payload.email).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        record(db, "login_blocked_locked", user=user, ip_address=ip, success=False,
               detail=f"account locked, {remaining}m remaining")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account temporarily locked due to repeated failed logins. Try again in {remaining} minute(s).",
        )

    valid = bool(user) and verify_password(payload.password, user.hashed_password)

    if not valid:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
                record(db, "account_locked", user=user, ip_address=ip, success=False,
                       detail=f"{user.failed_login_attempts} consecutive failed attempts")
            db.commit()
        record(db, "login_failed", actor_email=payload.email, ip_address=ip, success=False)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        record(db, "login_blocked_inactive", user=user, ip_address=ip, success=False)
        raise HTTPException(status_code=403, detail="Account is deactivated. Contact your administrator.")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()
    record(db, "login_success", user=user, ip_address=ip)
    return _issue_tokens(user)


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    data = decode_token(payload.refresh_token)
    if not data or data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = db.query(User).filter(User.id == data.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    return _issue_tokens(user)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request,
                     db: Session = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    pw_error = validate_password_strength(payload.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)
    current_user.hashed_password = hash_password(payload.new_password)
    current_user.must_change_password = False
    current_user.password_changed_at = datetime.utcnow()
    db.commit()
    record(db, "password_changed", user=current_user,
           ip_address=request.client.host if request.client else None)
    return {"message": "Password updated successfully"}
