"""Generates tests/fixtures/smtps_implicit_tls.pcap: a synthetic capture
containing a GENUINE TLS 1.2 handshake (real record/handshake byte
framing, a real self-signed X.509 certificate encoded as real DER bytes)
on port 465 (implicit TLS SMTP). Unlike the other fixtures, this one
exercises the actual TLS record parser and certificate extraction code
path end-to-end from raw wire bytes -- not just the higher-level
"is TLS present" plumbing.

Run once to (re)generate the fixture:
    python tests/fixtures/_generate_tls_fixture.py
"""
import datetime
import struct
import time
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, Raw, wrpcap


def _build_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)


def _handshake_msg(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _tls_record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + len(body).to_bytes(2, "big") + body


def _build_client_hello() -> bytes:
    version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id = b""
    cipher_suites = b"\xc0\x2f"  # offer TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    cipher_suites_block = len(cipher_suites).to_bytes(2, "big") + cipher_suites
    compression = b"\x01\x00"  # 1 method, null
    body = version + random_bytes + bytes([len(session_id)]) + session_id + cipher_suites_block + compression
    return _handshake_msg(1, body)


def _build_server_hello() -> bytes:
    version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id = b""
    cipher_suite = b"\xc0\x2f"  # negotiated: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression = b"\x00"
    extensions = b""  # none, for simplicity
    body = (version + random_bytes + bytes([len(session_id)]) + session_id
            + cipher_suite + compression + len(extensions).to_bytes(2, "big") + extensions)
    return _handshake_msg(2, body)


def _build_certificate_message(cert_der: bytes) -> bytes:
    one_cert = len(cert_der).to_bytes(3, "big") + cert_der
    cert_list = one_cert  # single cert, no chain, for a minimal but genuine fixture
    body = len(cert_list).to_bytes(3, "big") + cert_list
    return _handshake_msg(11, body)


def _build_server_hello_done() -> bytes:
    return _handshake_msg(14, b"")


def build_stream(src_ip, dst_ip, sport, dport, c2s_records, s2c_records, base_seq_c=1000, base_seq_s=5000):
    pkts = []
    seq_c, seq_s = base_seq_c, base_seq_s
    t = time.time()
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1))
    seq_c += 1
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s + 1))
    seq_s += 1

    for i in range(max(len(c2s_records), len(s2c_records))):
        if i < len(c2s_records) and c2s_records[i]:
            data = c2s_records[i]
            pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) / Raw(load=data))
            seq_c += len(data)
        if i < len(s2c_records) and s2c_records[i]:
            data = s2c_records[i]
            pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c) / Raw(load=data))
            seq_s += len(data)

    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1))
    for p in pkts:
        p.time = t
        t += 0.01
    return pkts


def main():
    cert_der = _build_self_signed_cert()

    client_hello_record = _tls_record(0x16, _build_client_hello())
    server_hello_record = _tls_record(0x16, _build_server_hello())
    certificate_record = _tls_record(0x16, _build_certificate_message(cert_der))
    server_hello_done_record = _tls_record(0x16, _build_server_hello_done())

    # client -> server: ClientHello. server -> client: ServerHello,
    # Certificate, ServerHelloDone (each its own TCP segment, exercising
    # the parser's ability to find handshake messages across separate
    # reassembled bytes rather than needing them all in one write).
    pkts = build_stream(
        "10.0.0.9", "203.0.113.20", 51010, 465,
        c2s_records=[client_hello_record],
        s2c_records=[server_hello_record, certificate_record, server_hello_done_record],
    )
    out_path = os.path.join(os.path.dirname(__file__), "smtps_implicit_tls.pcap")
    wrpcap(out_path, pkts)
    print(f"wrote {out_path} ({os.path.getsize(out_path)} bytes)")


if __name__ == "__main__":
    main()
