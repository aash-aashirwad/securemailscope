"""Verifies the audit log's hash-chain tamper-evidence: appending entries
keeps the chain intact, and retroactively editing a stored field breaks
verification from that point forward."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.models import AuditLog
from app.services.audit import record, verify_chain


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_chain_is_intact_after_normal_writes(db_session):
    record(db_session, "login_success", detail="user logged in")
    record(db_session, "case_upload", detail="uploaded capture.pcap")
    record(db_session, "report_export", detail="exported PDF")
    intact, broken_id = verify_chain(db_session)
    assert intact is True
    assert broken_id is None


def test_tampering_with_a_field_breaks_the_chain(db_session):
    record(db_session, "login_success", detail="user logged in")
    entry = record(db_session, "case_upload", detail="uploaded capture.pcap")
    record(db_session, "report_export", detail="exported PDF")

    # Simulate an attacker/insider rewriting a historical row's detail
    # directly in the database, bypassing record().
    row = db_session.query(AuditLog).filter(AuditLog.id == entry.id).first()
    row.detail = "uploaded something_else.pcap"
    db_session.commit()

    intact, broken_id = verify_chain(db_session)
    assert intact is False
    assert broken_id == entry.id


def test_deleting_a_row_breaks_the_chain(db_session):
    record(db_session, "login_success")
    entry = record(db_session, "case_upload")
    last = record(db_session, "report_export")

    db_session.query(AuditLog).filter(AuditLog.id == entry.id).delete()
    db_session.commit()

    intact, broken_id = verify_chain(db_session)
    assert intact is False
    # the next surviving entry's prev_hash no longer matches, so it's
    # reported as the first broken link
    assert broken_id == last.id
