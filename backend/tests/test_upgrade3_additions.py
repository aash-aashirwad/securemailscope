"""Covers three of the upgrade-3 additions directly:
- TLS 1.3 observability model (findings shouldn't fire false cert conclusions)
- Non-standard-port banner detection
- Evidence-integrity SHA-256 hashing
"""
import hashlib
import tempfile
import os

from app.services.findings_engine import generate_findings_for_session
from app.services.pcap_engine import _sniff_banner_protocol
from app.services.evidence import sha256_file


def test_tls13_with_no_certificate_produces_no_false_cert_finding():
    session = {
        "stream_id": "s1", "plaintext_only": False, "tls_negotiated": True,
        "tls_version": "TLSv1.3", "cert_observable": False,
        "observability_note": "TLS 1.3 negotiated: certificate data is encrypted.",
        "cert_expired": False, "cert_self_signed": False,
        "cert_weak_key": False, "cert_weak_signature": False,
        "cert_chain_valid": None, "protocol": "SMTP", "dst_port": 587,
    }
    findings = generate_findings_for_session(session)
    titles = [f["title"] for f in findings]
    assert not any("chain" in t.lower() or "expired" in t.lower() for t in titles)
    assert any("not observable" in t.lower() for t in titles)


def test_tls12_missing_certificate_is_still_flagged_when_observable():
    # cert_observable True/False only suppresses findings for TLS1.3's
    # structural encryption -- a TLS1.2 session with a genuinely invalid
    # chain must still be flagged.
    session = {
        "stream_id": "s2", "plaintext_only": False, "tls_negotiated": True,
        "tls_version": "TLSv1.2", "cert_observable": True,
        "cert_expired": True, "cert_self_signed": False,
        "cert_weak_key": False, "cert_weak_signature": False,
        "cert_chain_valid": True, "protocol": "IMAP", "dst_port": 993,
    }
    findings = generate_findings_for_session(session)
    assert any("expired" in f["title"].lower() for f in findings)


def test_banner_sniff_detects_smtp_on_nonstandard_port():
    assert _sniff_banner_protocol(b"220 mail.example.com ESMTP ready") == "SMTP"


def test_banner_sniff_detects_pop3():
    assert _sniff_banner_protocol(b"+OK POP3 server ready") == "POP3"


def test_banner_sniff_returns_none_for_unrelated_payload():
    assert _sniff_banner_protocol(b"GET / HTTP/1.1") is None


def test_sha256_file_matches_hashlib_reference():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"some pcap bytes for hashing")
        path = f.name
    try:
        expected = hashlib.sha256(b"some pcap bytes for hashing").hexdigest()
        assert sha256_file(path) == expected
    finally:
        os.unlink(path)
