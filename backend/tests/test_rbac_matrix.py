"""Systematic RBAC coverage: for every protected endpoint, verify that
allowed roles get through the role check (i.e. they're never rejected for
*lack of permission* -- they may still get a 404/other error further into
the handler, which is fine and expected) and that every other role is
rejected with 403 before the handler's own logic runs.

This complements the narrower unit tests elsewhere with a matrix that
walks the actual FastAPI dependency graph, using a real (in-memory) DB and
real JWTs -- as close to an integration test as this repo can run without
a browser.
"""
import os
import tempfile

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production-use-1234567890")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.models.models import User, RoleEnum

# --- shared in-memory DB wired into the FastAPI app for the whole module ---
engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
)
Base.metadata.create_all(bind=engine)
TestingSessionLocal = scoped_session(sessionmaker(bind=engine))


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)

ALL_ROLES = [r.value for r in RoleEnum]


@pytest.fixture(scope="module")
def tokens():
    """One user + bearer token per role, created directly in the DB
    (bypassing the self-registration role restriction, matching how an
    admin-provisioned account would look)."""
    db = TestingSessionLocal()
    toks = {}
    for role in ALL_ROLES:
        user = User(
            full_name=f"Test {role}", email=f"{role}@test.local",
            hashed_password=hash_password("Sup3r$ecretPW!"), role=RoleEnum(role),
            organization="NTRO",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        toks[role] = create_access_token({"sub": user.id})
    db.close()
    return toks


def auth(role, tokens):
    return {"Authorization": f"Bearer {tokens[role]}"}


# (method, path, allowed_roles) -- paths with no path params, hit directly.
# 401/403 (role rejection) is checked; a 404/422/500 past that point is not
# a test failure here since it just means the allowed role's request needs
# a real resource this smoke matrix doesn't set up (covered by narrower
# per-endpoint tests elsewhere).
ENDPOINT_MATRIX = [
    ("GET", "/api/cases", ("admin", "soc_analyst", "forensic_investigator", "compliance_officer")),
    ("GET", "/api/dashboard/summary", ("admin", "soc_analyst", "forensic_investigator", "compliance_officer")),
    ("GET", "/api/dashboard/risk-trend", ("admin", "soc_analyst", "forensic_investigator", "compliance_officer")),
    ("GET", "/api/admin/users", ("admin",)),
    ("GET", "/api/admin/audit-logs", ("admin", "compliance_officer")),
    ("GET", "/api/admin/audit-logs/verify", ("admin", "compliance_officer")),
    ("GET", "/api/admin/policy", ("admin", "compliance_officer")),
    ("GET", "/api/dashboard/traceability-matrix", ("admin", "soc_analyst", "forensic_investigator", "compliance_officer")),
    ("GET", "/api/cases/benchmark", ("admin", "compliance_officer")),
]


@pytest.mark.parametrize("method,path,allowed_roles", ENDPOINT_MATRIX)
def test_role_matrix(method, path, allowed_roles, tokens):
    for role in ALL_ROLES:
        resp = client.request(method, path, headers=auth(role, tokens))
        if role in allowed_roles:
            assert resp.status_code != 403, (
                f"{role} should be permitted on {method} {path} but got 403: {resp.text}"
            )
        else:
            assert resp.status_code == 403, (
                f"{role} should be FORBIDDEN on {method} {path} but got {resp.status_code}: {resp.text}"
            )


def test_no_token_is_rejected_on_protected_endpoint():
    resp = client.get("/api/cases")
    assert resp.status_code == 401


def test_invalid_token_is_rejected():
    resp = client.get("/api/cases", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_admin_only_user_management_rejects_all_non_admin(tokens):
    for role in ALL_ROLES:
        if role == "admin":
            continue
        resp = client.get("/api/admin/users", headers=auth(role, tokens))
        assert resp.status_code == 403


def test_upload_restricted_to_analyst_roles(tokens):
    # compliance_officer is read/oversight-only by design -- should not be
    # able to upload new evidence.
    resp = client.post(
        "/api/cases/upload",
        headers=auth("compliance_officer", tokens),
        files={"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "application/octet-stream")},
        data={"case_name": "should be rejected"},
    )
    assert resp.status_code == 403


def test_register_cannot_self_assign_admin_role():
    resp = client.post("/api/auth/register", json={
        "full_name": "Sneaky User", "email": "sneaky@test.local",
        "password": "Sup3r$ecretPW!", "role": "admin", "organization": "NTRO",
    })
    assert resp.status_code == 403


def test_login_with_wrong_password_is_rejected(tokens):
    resp = client.post("/api/auth/login", json={
        "email": "admin@test.local", "password": "definitely-wrong",
    })
    assert resp.status_code == 401


def test_me_endpoint_reflects_correct_role(tokens):
    for role in ALL_ROLES:
        resp = client.get("/api/auth/me", headers=auth(role, tokens))
        assert resp.status_code == 200
        assert resp.json()["role"] == role
