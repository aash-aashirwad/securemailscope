"""PCAP test corpus (P0): small synthetic captures exercising the full
analyze_pcap() pipeline end-to-end, generated once via scapy (see
fixtures/ — regenerate with the snippet in git history if extended).
These complement the unit tests, which exercise individual functions in
isolation, by proving the pipeline works together on real packet bytes.
"""
import os
import pytest
from app.services.pcap_engine import analyze_pcap

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_plaintext_smtp_capture_is_flagged_high_risk():
    sessions = analyze_pcap(os.path.join(FIXTURES, "smtp_plaintext.pcap"))
    assert len(sessions) == 1
    s = sessions[0]
    assert s["protocol"] == "SMTP"
    assert s["plaintext_only"] is True
    assert s["dst_port"] == 25


def test_nonstandard_port_smtp_is_detected_via_banner():
    sessions = analyze_pcap(os.path.join(FIXTURES, "smtp_nonstandard_port.pcap"))
    assert len(sessions) == 1
    s = sessions[0]
    assert s["protocol"] == "SMTP"
    assert s["dst_port"] == 2525
    assert s["non_standard_port"] is True


def test_reset_connection_is_recorded_as_such():
    sessions = analyze_pcap(os.path.join(FIXTURES, "imap_reset.pcap"))
    assert len(sessions) == 1
    s = sessions[0]
    assert s["protocol"] == "IMAP"
    assert s["tcp_connection_state"] == "reset"


def test_genuine_tls_handshake_with_real_certificate_is_fully_parsed():
    """Exercises the actual TLS record/handshake parser and certificate
    extraction against REAL wire-format bytes (a genuine self-signed X.509
    cert encoded as real DER, inside real TLS record framing) end-to-end
    through analyze_pcap() -- not just the higher-level function calls
    that other tests exercise in isolation. This is what caught a real
    bug where cert.fingerprint() was called with a stdlib hashlib object
    instead of cryptography's own hashes.SHA256(), silently raising and
    causing every field after it (fingerprint, self-signed, key
    algorithm/size) to come back empty for every certificate ever
    analyzed -- a unit test calling analyze_certificate() directly with a
    pre-built cert object would still have shown the same failure, but
    nothing had actually run the real pipeline against real packet bytes
    to notice."""
    path = os.path.join(FIXTURES, "smtps_implicit_tls.pcap")
    if not os.path.exists(path):
        pytest.skip("run tests/fixtures/_generate_tls_fixture.py to (re)generate this fixture")
    sessions = analyze_pcap(path)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["implicit_tls"] is True
    assert s["tls_version"] == "TLSv1.2"
    assert s["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert s["forward_secrecy"] is True
    assert s["cert_subject"] == "CN=mail.example.com"
    assert s["cert_self_signed"] is True
    assert s["cert_expired"] is False
    assert s["cert_key_algo"] == "RSA"
    assert s["cert_key_size"] == 2048
    assert s["cert_fingerprint_sha256"] is not None
    assert len(s["cert_fingerprint_sha256"]) == 64  # hex-encoded SHA-256
