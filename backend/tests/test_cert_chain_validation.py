"""Builds a small in-memory CA -> intermediate -> leaf chain with the
`cryptography` library and checks that validate_certificate_chain()
correctly accepts a genuine chain and rejects a tampered one.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.pcap_engine import validate_certificate_chain


def _make_cert(subject_cn, issuer_cn, issuer_key, subject_key=None, is_ca=False,
                not_before_delta=-1, not_after_delta=365):
    subject_key = subject_key or issuer_key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_delta))
        .not_valid_after(now + datetime.timedelta(days=not_after_delta))
    )
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def genuine_chain():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_cert = _make_cert("Test Root CA", "Test Root CA", root_key, is_ca=True)
    leaf_cert = _make_cert("mail.example.org", "Test Root CA", root_key, subject_key=leaf_key)
    return [leaf_cert, root_cert]


def test_genuine_chain_validates_structurally(genuine_chain):
    valid, errors = validate_certificate_chain(genuine_chain)
    # trust-anchor errors (unknown/self-signed test root) are expected and
    # non-fatal; no *structural/signature* errors should be present.
    structural_errors = [e for e in errors if "signature does NOT verify" in e or "issuer DN does not match" in e]
    assert structural_errors == []


def test_tampered_leaf_signature_is_detected(genuine_chain):
    leaf_cert, root_cert = genuine_chain
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Re-sign an identical-looking leaf with the WRONG key, simulating a
    # forged/substituted intermediate presented on the wire.
    forged_leaf = _make_cert("mail.example.org", "Test Root CA", other_key)
    valid, errors = validate_certificate_chain([forged_leaf, root_cert])
    assert valid is False
    assert any("does NOT verify" in e for e in errors)


def test_expired_certificate_is_flagged():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_cert = _make_cert("Test Root CA", "Test Root CA", root_key, is_ca=True)
    expired_leaf = _make_cert(
        "mail.example.org", "Test Root CA", root_key,
        not_before_delta=-400, not_after_delta=-10,  # expired 10 days ago
    )
    valid, errors = validate_certificate_chain([expired_leaf, root_cert])
    assert valid is False
    assert any("expired" in e for e in errors)


def test_leaf_only_no_chain_is_flagged_incomplete():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = _make_cert("mail.example.org", "Some External CA", root_key, subject_key=leaf_key)
    valid, errors = validate_certificate_chain([leaf_cert])
    assert valid is False
    assert any("no intermediate/root" in e for e in errors)


def test_no_certificates_returns_none():
    valid, errors = validate_certificate_chain([])
    assert valid is None
    assert errors
