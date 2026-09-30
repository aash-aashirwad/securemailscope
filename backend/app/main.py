import secrets
import string

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.limiter import limiter
from app.models import models
from app.api import auth_routes, case_routes, report_routes, dashboard_routes
from app.core.security import hash_password

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications "
                "— Problem Statement 26159 (NTRO)",
    version="1.1.0",
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down and try again."})


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(auth_routes.router)
app.include_router(case_routes.router)
app.include_router(report_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(dashboard_routes.admin_router)


def _generate_temp_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(16))


@app.on_event("startup")
def seed_admin():
    """Creates a default admin account on first boot so the system is usable
    immediately after deployment. Unlike a fixed hardcoded password, a random
    one-time password is generated and printed to the server log ONCE; the
    account is flagged must_change_password so it cannot be used long-term
    without a real password being set."""
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(models.User.email == "admin@ntro.gov.in").first()
        if not existing:
            temp_password = _generate_temp_password()
            admin = models.User(
                full_name="System Administrator",
                email="admin@ntro.gov.in",
                hashed_password=hash_password(temp_password),
                role=models.RoleEnum.ADMIN,
                organization="NTRO",
                must_change_password=True,
            )
            db.add(admin)
            db.commit()
            print("=" * 72)
            print("SecureMailScope: bootstrap admin account created")
            print("  email   : admin@ntro.gov.in")
            print(f"  password: {temp_password}")
            print("  This password is shown ONLY here, ONCE. Log in and change it")
            print("  immediately — the account is locked to change-password-only")
            print("  behaviour until it is rotated.")
            print("=" * 72)
    finally:
        db.close()


@app.get("/")
def root():
    return {
        "service": "SecureMailScope",
        "status": "operational",
        "problem_statement": "26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {"status": "healthy"}
