"""
SecureMailScope Passive Forensic Engine
----------------------------------------
Reconstructs TCP streams from a PCAP, identifies SMTP/IMAP/POP3 sessions,
detects STARTTLS upgrades, parses raw TLS handshake records (ClientHello /
ServerHello / Certificate) without needing decryption keys (fully passive),
and extracts X.509 certificate metadata for cryptographic posture analysis.

This module intentionally parses TLS at the record/handshake byte level
(rather than relying on Scapy's TLS layer, which requires the optional
`scapy-ssl_tls` community layer) so it has zero extra runtime dependencies
beyond `scapy` + `cryptography`.
"""

import struct
from collections import defaultdict
from datetime import datetime

from scapy.all import TCP, IP, Raw
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.services.crypto_reference import (
    TLS_VERSION_MAP, CIPHER_SUITE_MAP, DEFAULT_PORTS, STARTTLS_COMMANDS,
    classify_cipher_strength, has_forward_secrecy, MIN_SECURE_RSA_KEY_SIZE,
    MIN_SECURE_EC_KEY_SIZE, WEAK_SIGNATURE_ALGOS, key_exchange_from_cipher,
    TLS_NAMED_GROUP_MAP,
)

TLS_HANDSHAKE_CONTENT_TYPE = 22
TLS_ALERT_CONTENT_TYPE = 21
CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11

# Per-stream cap on stored per-packet evidence rows -- enough for an
# investigator to see the STARTTLS/handshake exchange and the packets
# immediately around any finding without storing every packet of a large
# capture (which would blow up session storage for long-lived streams).
MAX_PACKET_EVIDENCE_PER_STREAM = 300


def _decode_tcp_flags(flags: int) -> str:
    names = []
    if flags & 0x01: names.append("FIN")
    if flags & 0x02: names.append("SYN")
    if flags & 0x04: names.append("RST")
    if flags & 0x08: names.append("PSH")
    if flags & 0x10: names.append("ACK")
    if flags & 0x20: names.append("URG")
    return ",".join(names) if names else "-"


class StreamBuffer:
    """Accumulates raw bytes for one direction of a TCP stream and performs
    real sequence-number-aware reassembly: out-of-order segments are sorted
    by seq, exact retransmissions are deduplicated, *overlapping*
    retransmissions are trimmed to the new segment's non-overlapping tail
    (last-write-wins on the overlap, matching how a real TCP receive buffer
    resolves a retransmitted/overlapping segment), and gaps left by dropped
    packets are recorded rather than silently concatenated across, so a
    reconstructed stream never silently splices unrelated regions together.
    32-bit sequence-number wraparound is handled via signed circular
    distance from an arbitrary reference segment (RFC 1982 serial-number
    arithmetic), not by assuming the numeric minimum sequence number is
    the earliest byte -- that assumption breaks exactly when a stream
    wraps through 0, since the wrapped segment's raw number is numerically
    smaller despite being chronologically later."""

    def __init__(self):
        self.raw = []          # list of (seq, payload) as observed, pre-normalization
        self._cache = None     # (bytes, gaps) memoized after first assembled() call

    def add(self, seq, payload):
        if not payload:
            return
        self._cache = None
        self.raw.append((seq, payload))

    def _signed_delta(self, seq, reference):
        # Signed circular distance from `reference` to `seq` on a 32-bit
        # sequence-number space, per RFC 1982 serial-number arithmetic:
        # shift into an unsigned mod-2^32 space, then re-center to a
        # signed range so "wrapped past 0" reads as a small POSITIVE
        # distance forward rather than a huge unsigned one. This only
        # requires `reference` to be *some* segment in the stream -- unlike
        # picking the numeric min() as a base, it doesn't break when the
        # numeric minimum is actually the LATEST segment because it
        # wrapped through 0 (e.g. reference=0xFFFFFFFE, seq=0x00000000:
        # numeric min is 0x0, but 0x0 is 2 bytes AFTER 0xFFFFFFFE, not
        # before it -- signed-delta correctly reports +2, not "smallest").
        # Valid as long as every segment in one stream lies within +/-2^31
        # of every other, which real TCP guarantees (a stream can't have
        # ~2GB of data in flight at once).
        return ((seq - reference + 0x80000000) & 0xFFFFFFFF) - 0x80000000

    def assembled(self) -> bytes:
        data, _ = self._assemble()
        return data

    def gap_count(self) -> int:
        """Number of byte-range gaps left by segments that were never
        captured (packet loss / capture start mid-stream). Exposed so
        callers can flag a session's reconstruction as incomplete."""
        _, gaps = self._assemble()
        return gaps

    def _assemble(self):
        if self._cache is not None:
            return self._cache
        if not self.raw:
            self._cache = (b"", 0)
            return self._cache

        reference = self.raw[0][0]  # arbitrary; see _signed_delta docstring
        deltas = [(self._signed_delta(s, reference), p) for s, p in self.raw]
        min_delta = min(d for d, _ in deltas)
        # Shift so the earliest segment starts at offset 0 -- a normal
        # unsigned byte offset from here on, regardless of where in the
        # 32-bit space the underlying sequence numbers actually sat.
        segments = sorted(
            ((d - min_delta, p) for d, p in deltas),
            key=lambda t: t[0],
        )

        out = bytearray()
        next_expected = segments[0][0]
        gaps = 0
        for seq, payload in segments:
            end = seq + len(payload)
            if seq > next_expected:
                # a real gap: a segment was never captured. Do not splice
                # across it -- that would corrupt TLS record offsets.
                gaps += 1
                out.extend(payload)
                next_expected = end
            elif end <= next_expected:
                continue  # fully-contained retransmission/duplicate, drop
            else:
                # overlaps [seq, next_expected) with already-written bytes;
                # only append the new, non-overlapping tail
                trim = next_expected - seq
                out.extend(payload[trim:])
                next_expected = end

        self._cache = (bytes(out), gaps)
        return self._cache


class TCPStream:
    def __init__(self, key, src_ip, dst_ip, src_port, dst_port):
        self.key = key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.c2s = StreamBuffer()  # client -> server
        self.s2c = StreamBuffer()  # server -> client
        self.packet_count = 0
        self.first_seen = None
        self.last_seen = None
        self.client_ip = src_ip
        self.client_port = src_port
        self.server_ip = dst_ip
        self.server_port = dst_port
        self.non_standard_port = False
        self.saw_fin = False
        self.saw_rst = False
        self.packet_evidence = []  # capped list of per-packet metadata, for the evidence viewer

    @property
    def connection_state(self):
        if self.saw_rst:
            return "reset"
        if self.saw_fin:
            return "closed"
        return "established"  # last packet observed mid-session or capture ended first


def _stream_key(ip_src, ip_dst, sport, dport):
    """Canonical bidirectional key so both directions map to one stream."""
    a = (ip_src, sport)
    b = (ip_dst, dport)
    return tuple(sorted([a, b]))


_BANNER_SIGNATURES = (
    (b"220 ", "SMTP"), (b"220-", "SMTP"),
    (b"* OK", "IMAP"),
    (b"+OK", "POP3"),
)


def _sniff_banner_protocol(payload: bytes):
    """Best-effort protocol identification from a server greeting banner,
    used to catch SMTP/IMAP/POP3 traffic running on a non-standard port
    (P2: non-standard port detection) that the DEFAULT_PORTS allow-list
    would otherwise silently skip. Only looks at the leading bytes of a
    single packet, so it's cheap enough to run on every unmatched stream's
    first payload without materially slowing down capture processing."""
    head = payload[:16]
    for sig, proto in _BANNER_SIGNATURES:
        if head.startswith(sig):
            return proto
    return None


def reconstruct_tcp_streams(pcap_path: str, max_packets: int = None):
    """Reads a pcap and reconstructs bidirectional TCP streams keyed by 4-tuple.

    Streams packets from disk via scapy's PcapReader rather than loading the
    whole capture into memory with rdpcap, and stops after `max_packets` if
    given -- a resource limit against a malicious or accidentally huge
    capture exhausting worker memory during passive analysis of an
    untrusted upload. When the cap is hit, `streams_truncated` is set on
    the return value's `.truncated` attribute-like dict marker (see
    `analyze_pcap`) so the caller can surface that results are partial.

    Streams on a non-DEFAULT_PORTS port are also tracked if their first
    payload-bearing packet matches a recognizable SMTP/IMAP/POP3 greeting
    banner (see _sniff_banner_protocol), so email traffic relayed on a
    non-standard port is not silently invisible to the analysis.
    """
    if max_packets is None:
        try:
            from app.core.config import settings
            max_packets = settings.MAX_PACKETS_PER_CAPTURE
        except Exception:
            max_packets = 500_000

    from scapy.all import PcapReader
    streams = {}
    packet_index = 0
    truncated = False

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            packet_index += 1
            if packet_index > max_packets:
                truncated = True
                break

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport

            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

            # Determine if this looks like an email-protocol port on either side
            relevant_port = None
            for p in (sport, dport):
                if p in DEFAULT_PORTS:
                    relevant_port = p
                    break

            key = _stream_key(ip.src, ip.dst, sport, dport)
            is_non_standard = False
            if relevant_port is None:
                if key in streams:
                    # Already promoted via an earlier banner match on this
                    # exact connection -- keep tracking it.
                    is_non_standard = True
                elif payload and _sniff_banner_protocol(payload):
                    is_non_standard = True
                else:
                    continue

            if key not in streams:
                # Determine "client" as the side connecting TO the well-known port
                if relevant_port is not None and dport in DEFAULT_PORTS:
                    client_ip, client_port = ip.src, sport
                    server_ip, server_port = ip.dst, dport
                elif relevant_port is not None:
                    client_ip, client_port = ip.dst, dport
                    server_ip, server_port = ip.src, sport
                else:
                    # Non-standard port, identified via banner: the side
                    # that SENT the banner is the server.
                    client_ip, client_port = ip.dst, dport
                    server_ip, server_port = ip.src, sport
                s = TCPStream(key, client_ip, server_ip, client_port, server_port)
                s.non_standard_port = is_non_standard
                streams[key] = s
            stream = streams[key]

            ts = float(pkt.time)
            if stream.first_seen is None:
                stream.first_seen = ts
            stream.last_seen = ts
            stream.packet_count += 1

            flags = int(tcp.flags)
            if flags & 0x04:  # RST
                stream.saw_rst = True
            if flags & 0x01:  # FIN
                stream.saw_fin = True

            if len(stream.packet_evidence) < MAX_PACKET_EVIDENCE_PER_STREAM:
                direction = "c2s" if (ip.src == stream.client_ip and sport == stream.client_port) else "s2c"
                stream.packet_evidence.append({
                    "packet_no": packet_index,
                    "timestamp": ts,
                    "direction": direction,
                    "src": f"{ip.src}:{sport}",
                    "dst": f"{ip.dst}:{dport}",
                    "length": len(payload),
                    "tcp_flags": _decode_tcp_flags(flags),
                    "seq": int(tcp.seq),
                })

            if not payload:
                continue

            if ip.src == stream.client_ip and sport == stream.client_port:
                stream.c2s.add(tcp.seq, payload)
            else:
                stream.s2c.add(tcp.seq, payload)

    result = list(streams.values())
    return result, truncated


def extract_capture_metadata(pcap_path: str) -> dict:
    """PCAP metadata extraction (P2): interface/link type, capture duration,
    total packet count (including non-TCP/non-email traffic, unlike the
    session-level packet_count fields), and start/end timestamps. Read as
    a separate lightweight pass so a corrupt/unusual capture that fails
    here doesn't block the main session analysis."""
    from scapy.all import PcapReader
    meta = {
        "packet_count": 0, "first_ts": None, "last_ts": None,
        "duration_seconds": None, "link_type": None,
    }
    try:
        with PcapReader(pcap_path) as reader:
            link_type = getattr(reader, "linktype", None)
            meta["link_type"] = {1: "Ethernet", 0: "Loopback/Null", 105: "IEEE 802.11"}.get(
                link_type, f"DLT {link_type}" if link_type is not None else None
            )
            for pkt in reader:
                meta["packet_count"] += 1
                ts = float(pkt.time)
                if meta["first_ts"] is None or ts < meta["first_ts"]:
                    meta["first_ts"] = ts
                if meta["last_ts"] is None or ts > meta["last_ts"]:
                    meta["last_ts"] = ts
        if meta["first_ts"] is not None and meta["last_ts"] is not None:
            meta["duration_seconds"] = round(meta["last_ts"] - meta["first_ts"], 3)
    except Exception:
        pass
    return meta


def detect_protocol(stream: TCPStream) -> str:
    port = stream.server_port
    if port in (25, 587, 465):
        return "SMTP"
    if port in (143, 993):
        return "IMAP"
    if port in (110, 995):
        return "POP3"
    if getattr(stream, "non_standard_port", False):
        banner_proto = _sniff_banner_protocol(stream.s2c.assembled()[:16])
        if banner_proto:
            return banner_proto
    return "UNKNOWN"


def is_implicit_tls_port(port: int) -> bool:
    return port in (465, 993, 995)


def detect_starttls(stream: TCPStream, protocol: str):
    """Scans the plaintext portion of a stream for STARTTLS/STLS negotiation
    and validates the *specific* server response line that immediately
    follows the command, rather than checking whether a generic success
    token appears anywhere later in the whole server buffer -- the naive
    "is b'OK' anywhere in the rest of the session" check produces false
    positives whenever the mailbox transcript itself later contains an OK
    response (e.g. a subsequent LOGIN/SELECT), which is common."""
    c2s = stream.c2s.assembled()
    s2c = stream.s2c.assembled()
    cmd = STARTTLS_COMMANDS.get(protocol)
    if not cmd:
        return False, False

    c2s_upper = c2s.upper()
    idx = c2s_upper.find(cmd)
    used = idx != -1
    if not used:
        return False, False

    # IMAP STARTTLS is tagged ("a1 STARTTLS"); find the tag so the matching
    # tagged response ("a1 OK ...") can be located instead of any OK line.
    imap_tag = None
    if protocol == "IMAP":
        line_start = c2s_upper.rfind(b"\r\n", 0, idx) + 2
        prefix = c2s[line_start:idx].strip()
        if prefix:
            imap_tag = prefix

    # Correlate against the response line(s) that follow: use the byte
    # offset of the command as an approximate cursor into the server
    # buffer (STARTTLS is a request/response protocol, so the server's
    # reply to it is the first unconsumed response after this point) and
    # only look at a bounded window right after it, not the whole buffer.
    # Approximate the server-side cursor by the STARTTLS command's relative
    # position in the client stream (both sides progress roughly in lockstep
    # for a request/response protocol) so the window checked is the reply
    # that follows the command, not an arbitrary later line in the session.
    approx_frac = idx / max(len(c2s_upper), 1)
    search_from = max(0, int(len(s2c) * approx_frac) - 32)
    window = s2c[search_from:search_from + 512]
    success = False
    if protocol == "SMTP":
        success = b"220" in window
    elif protocol == "IMAP":
        if imap_tag:
            success = (imap_tag + b" OK") in s2c.upper()
        else:
            success = b"OK" in window
    elif protocol == "POP3":
        success = b"+OK" in window
    return used, success


_VALID_CONTENT_TYPES = (20, 21, 22, 23)  # change_cipher_spec, alert, handshake, application_data


def _find_first_tls_record_offset(data: bytes) -> int:
    """STARTTLS sessions carry plaintext protocol chatter (EHLO/STLS/etc.)
    before the TLS handshake begins mid-stream, so record parsing cannot
    assume the buffer starts at a record boundary. This scans for the
    first byte sequence that looks like a plausible TLS record header
    (content type 20-23, version 0x03 0x0[0-4]) to locate the real start."""
    n = len(data)
    for i in range(n - 5):
        content_type = data[i]
        if content_type not in _VALID_CONTENT_TYPES:
            continue
        if data[i + 1] != 0x03 or data[i + 2] > 0x04:
            continue
        length = struct.unpack(">H", data[i + 3:i + 5])[0]
        if length == 0 or length > 20000:
            continue
        # plausible header — treat as the handshake start
        return i
    return -1


def _parse_tls_records(data: bytes):
    """Yields (content_type, tls_version_bytes, record_body) tuples from a raw
    stream buffer that may contain multiple concatenated TLS records, possibly
    preceded by plaintext protocol chatter (STARTTLS case)."""
    start = _find_first_tls_record_offset(data)
    if start == -1:
        return
    i = start
    n = len(data)
    while i + 5 <= n:
        content_type = data[i]
        if content_type not in _VALID_CONTENT_TYPES or data[i + 1] != 0x03:
            break
        version = struct.unpack(">H", data[i + 1:i + 3])[0]
        length = struct.unpack(">H", data[i + 3:i + 5])[0]
        body_start = i + 5
        body_end = body_start + length
        if body_end > n:
            break
        yield content_type, version, data[body_start:body_end]
        i = body_end


def _parse_handshake_messages(record_body: bytes):
    i = 0
    n = len(record_body)
    while i + 4 <= n:
        msg_type = record_body[i]
        length = int.from_bytes(record_body[i + 1:i + 4], "big")
        body_start = i + 4
        body_end = body_start + length
        if body_end > n:
            break
        yield msg_type, record_body[body_start:body_end]
        i = body_end


def _parse_client_hello(body: bytes):
    try:
        version = struct.unpack(">H", body[0:2])[0]
        return {"client_version": TLS_VERSION_MAP.get(version, hex(version))}
    except Exception:
        return {}


def _parse_server_hello(body: bytes):
    result = {}
    try:
        version = struct.unpack(">H", body[0:2])[0]
        result["negotiated_version"] = TLS_VERSION_MAP.get(version, hex(version))
        pos = 2 + 32  # version(2) + random(32)
        session_id_len = body[pos]
        pos += 1 + session_id_len
        cipher_code = struct.unpack(">H", body[pos:pos + 2])[0]
        result["cipher_suite"] = CIPHER_SUITE_MAP.get(cipher_code, f"UNKNOWN_0x{cipher_code:04X}")
        # TLS 1.3 negotiates real version via supported_versions extension;
        # if record shows 0x0303 but extension present, treat separately (best-effort)
        pos += 2  # cipher
        pos += 1  # compression method
        if pos + 2 <= len(body):
            ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_total_len
            while pos + 4 <= ext_end and pos + 4 <= len(body):
                ext_type = struct.unpack(">H", body[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", body[pos + 2:pos + 4])[0]
                ext_body = body[pos + 4: pos + 4 + ext_len]
                if ext_type == 0x002B and len(ext_body) >= 2:  # supported_versions
                    real_ver = struct.unpack(">H", ext_body[0:2])[0]
                    result["negotiated_version"] = TLS_VERSION_MAP.get(real_ver, result["negotiated_version"])
                pos += 4 + ext_len
    except Exception:
        pass
    return result


def _try_parse_cert_list(body: bytes, pos: int, has_tls13_ext_block: bool):
    """Attempts to parse a cert_list starting at `pos`. Returns list of
    x509 certs on structural success, or None if the layout doesn't fit
    (used to disambiguate TLS1.2 vs TLS1.3 Certificate message framing)."""
    try:
        if pos + 3 > len(body):
            return None
        cert_list_len = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        end = pos + cert_list_len
        if end > len(body):
            return None
        certs = []
        while pos + 3 <= end:
            cert_len = int.from_bytes(body[pos:pos + 3], "big")
            pos += 3
            if pos + cert_len > len(body):
                return None
            cert_der = body[pos:pos + cert_len]
            pos += cert_len
            try:
                certs.append(x509.load_der_x509_certificate(cert_der, default_backend()))
            except Exception:
                pass  # count as structurally fine even if a single cert fails to parse
            if has_tls13_ext_block:
                if pos + 2 > len(body):
                    return None
                ext_len = int.from_bytes(body[pos:pos + 2], "big")
                pos += 2 + ext_len
                if pos > end:
                    return None
        return certs if pos == end else None
    except Exception:
        return None


def _parse_certificates(body: bytes):
    """Parses the Certificate handshake message. Tries, in order:
    (1) TLS1.2 layout — cert_list starts at offset 0, no per-cert extensions
    (2) TLS1.3 layout — 1-byte certificate_request_context prefix, and a
        2-byte extensions block following each certificate entry.
    This structural try/fallback approach is more robust than guessing
    the TLS version from the record header, since middleboxes/relays can
    make that unreliable."""
    result = _try_parse_cert_list(body, pos=0, has_tls13_ext_block=False)
    if result is not None:
        return result

    if len(body) >= 1:
        ctx_len = body[0]
        result = _try_parse_cert_list(body, pos=1 + ctx_len, has_tls13_ext_block=True)
        if result is not None:
            return result

    return []


def analyze_certificate(cert: x509.Certificate) -> dict:
    info = {}
    try:
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
        info["valid_from"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
        info["valid_to"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        info["expired"] = datetime.now(not_after.tzinfo) > not_after if not_after.tzinfo else datetime.utcnow() > not_after
        info["self_signed"] = info["subject"] == info["issuer"]

        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            info["key_algorithm"] = "RSA"
            info["key_size"] = pub_key.key_size
            info["weak_key"] = pub_key.key_size < MIN_SECURE_RSA_KEY_SIZE
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            info["key_algorithm"] = "EC"
            info["key_size"] = pub_key.curve.key_size
            info["weak_key"] = pub_key.curve.key_size < MIN_SECURE_EC_KEY_SIZE
        else:
            info["key_algorithm"] = type(pub_key).__name__
            info["key_size"] = None
            info["weak_key"] = False

        sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "unknown"
        info["signature_algorithm"] = sig_algo
        info["weak_signature"] = any(w in sig_algo.lower() for w in WEAK_SIGNATURE_ALGOS)
    except Exception as e:
        info["parse_error"] = str(e)
    return info


def _handshake_stream_bytes(data: bytes):
    """Concatenates the payload of every TLS handshake-content-type (22)
    record in order, so that a handshake message fragmented across two or
    more TLS records (common for large Certificate messages) is reassembled
    into one contiguous buffer before message-level parsing runs. Parsing
    each record body in isolation, as a naive implementation does, silently
    truncates any handshake message that doesn't fit in a single record."""
    handshake_bytes = bytearray()
    any_handshake = False
    for content_type, _version, record_body in _parse_tls_records(data):
        if content_type != TLS_HANDSHAKE_CONTENT_TYPE:
            continue
        any_handshake = True
        handshake_bytes.extend(record_body)
    return bytes(handshake_bytes), any_handshake


def _extract_tls13_key_share_group(client_hello_body: bytes, server_hello_body: bytes):
    """Resolves the actual negotiated key-exchange group for TLS1.3 sessions
    by reading the key_share extension's selected group id out of the
    ServerHello (falling back to the group used in the client's first
    key_share entry if the server's extension can't be located, e.g. when
    only a HelloRetryRequest group was captured)."""
    def scan_key_share(body, server_side):
        try:
            pos = 2 + 32
            session_id_len = body[pos]
            pos += 1 + session_id_len
            if server_side:
                pos += 2 + 1  # cipher_suite + compression_method
            else:
                cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
                pos += 2 + cs_len
                comp_len = body[pos]
                pos += 1 + comp_len
            ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_total_len
            while pos + 4 <= ext_end and pos + 4 <= len(body):
                ext_type = struct.unpack(">H", body[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", body[pos + 2:pos + 4])[0]
                ext_body = body[pos + 4: pos + 4 + ext_len]
                if ext_type == 0x0033 and len(ext_body) >= 2:  # key_share
                    if server_side:
                        group_id = struct.unpack(">H", ext_body[0:2])[0]
                        return TLS_NAMED_GROUP_MAP.get(group_id, f"unknown_group_0x{group_id:04X}")
                    else:
                        # client key_share is a list; report the first entry offered
                        if len(ext_body) >= 4:
                            group_id = struct.unpack(">H", ext_body[2:4])[0]
                            return TLS_NAMED_GROUP_MAP.get(group_id, f"unknown_group_0x{group_id:04X}")
                pos += 4 + ext_len
        except Exception:
            return None
        return None

    group = scan_key_share(server_hello_body, server_side=True) if server_hello_body else None
    if group is None and client_hello_body:
        group = scan_key_share(client_hello_body, server_side=False)
    return group


_TRUSTED_ROOTS_CACHE = None


def _load_trusted_roots():
    """Loads the certifi CA bundle (Mozilla's root program list, the same
    trust store curated for browsers) once per process and indexes it by
    subject DN for fast lookup during chain validation. Returns {} if
    certifi isn't installed or the bundle can't be parsed, in which case
    trust-anchor checking is skipped gracefully (chain-internal signature
    validation still runs) rather than the whole assessment failing."""
    global _TRUSTED_ROOTS_CACHE
    if _TRUSTED_ROOTS_CACHE is not None:
        return _TRUSTED_ROOTS_CACHE
    roots = {}
    try:
        import certifi
        with open(certifi.where(), "rb") as f:
            bundle = f.read()
        for pem_block in bundle.split(b"-----END CERTIFICATE-----"):
            if b"-----BEGIN CERTIFICATE-----" not in pem_block:
                continue
            pem = pem_block[pem_block.index(b"-----BEGIN CERTIFICATE-----"):] + b"-----END CERTIFICATE-----\n"
            try:
                cert = x509.load_pem_x509_certificate(pem, default_backend())
                roots[cert.subject.rfc4514_string()] = cert
            except Exception:
                continue
    except Exception:
        roots = {}
    _TRUSTED_ROOTS_CACHE = roots
    return roots


def _check_trust_anchor(root_or_intermediate: x509.Certificate):
    """Checks whether the given certificate is issued by (or matches) a
    root in the bundled Mozilla trust store, and if a matching subject is
    found, cryptographically verifies the signature against that trusted
    root's public key rather than trusting the DN match alone."""
    roots = _load_trusted_roots()
    if not roots:
        return None  # trust store unavailable -- caller treats as "unknown", not "untrusted"
    issuer_dn = root_or_intermediate.issuer.rfc4514_string()
    trusted_root = roots.get(issuer_dn)
    if trusted_root is None:
        return False
    return _verify_issued_by(root_or_intermediate, trusted_root)


def _verify_issued_by(subject_cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Cryptographically verifies that `issuer_cert`'s public key actually
    produced `subject_cert`'s signature (not just that the Subject/Issuer
    Distinguished Names match textually, which an attacker-forged
    certificate could also satisfy)."""
    issuer_pub = issuer_cert.public_key()
    sig_hash_algo = subject_cert.signature_hash_algorithm
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            issuer_pub.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sig_hash_algo,
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(sig_hash_algo),
            )
        else:
            return False  # unsupported key type (e.g. Ed25519 handled separately below)
        return True
    except Exception:
        try:
            # Ed25519/Ed448 don't take a hash algorithm parameter
            issuer_pub.verify(subject_cert.signature, subject_cert.tbs_certificate_bytes)
            return True
        except Exception:
            return False


def validate_certificate_chain(cert_objects: list):
    """Validates the certificate chain as actually presented on the wire:
    - Confirms Subject/Issuer DN linkage between consecutive certificates.
    - Cryptographically verifies each certificate's signature against the
      next certificate's public key (catches a forged/substituted
      intermediate that a name-only check would miss).
    - Confirms every certificate in the chain is within its validity window.
    - Flags an incomplete chain (leaf presented with no issuing
      intermediate/root) rather than silently treating it as valid, since
      passive capture only sees what the server actually sent.
    Returns (is_valid: bool, errors: list[str])."""
    errors = []
    if not cert_objects:
        return None, ["No certificates presented"]

    now_checked = []
    for i, cert in enumerate(cert_objects):
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        now = datetime.now(not_after.tzinfo) if getattr(not_after, "tzinfo", None) else datetime.utcnow()
        if now > not_after:
            errors.append(f"Certificate #{i} ({cert.subject.rfc4514_string()}) is expired")
        if now < not_before:
            errors.append(f"Certificate #{i} ({cert.subject.rfc4514_string()}) is not yet valid")

    for i in range(len(cert_objects) - 1):
        subject_cert = cert_objects[i]
        issuer_cert = cert_objects[i + 1]
        if subject_cert.issuer != issuer_cert.subject:
            errors.append(
                f"Certificate #{i} issuer DN does not match certificate #{i + 1} subject DN "
                "(chain is not a well-formed path)"
            )
            continue
        if not _verify_issued_by(subject_cert, issuer_cert):
            errors.append(
                f"Certificate #{i} signature does NOT verify against certificate #{i + 1}'s "
                "public key -- possible forged/substituted intermediate"
            )

    leaf = cert_objects[0]
    is_self_signed_leaf = leaf.subject == leaf.issuer
    if len(cert_objects) == 1 and not is_self_signed_leaf:
        errors.append(
            "Server presented only a leaf certificate with no intermediate/root -- "
            "chain of trust cannot be established from this capture alone"
        )
    elif is_self_signed_leaf:
        errors.append("Leaf certificate is self-signed -- not issued by any CA")

    root = cert_objects[-1]
    if root.subject == root.issuer and len(cert_objects) > 1:
        if not _verify_issued_by(root, root):
            errors.append("Root certificate's self-signature does not verify (corrupt/forged root)")

    # is_valid is decided on structural/cryptographic correctness of the
    # presented chain only, computed before the trust-anchor check below.
    is_valid = len(errors) == 0

    # --- PKI trust-anchor check against the bundled Mozilla root store ---
    # Passive capture only ever sees the leaf + whatever intermediates the
    # server chose to send, never the root itself (roots are never
    # transmitted on the wire in a normal handshake) -- so "chain validated
    # against a trust store" means checking that the top of the presented
    # chain is issued by a root this trust store actually recognizes, not
    # that the root cert was seen on the wire. This is reported as an
    # informational notice, not folded into is_valid: a private/enterprise
    # CA is legitimate for internal mail infrastructure and shouldn't be
    # flagged as a structural chain failure, only surfaced for review.
    trust_result = _check_trust_anchor(cert_objects[-1])
    if trust_result is None:
        errors.append(
            "Trust-store check skipped: bundled CA trust store unavailable in this "
            "environment (install `certifi` to enable full PKI trust-path validation)"
        )
    elif trust_result is False:
        errors.append(
            "Top of presented chain is not issued by any CA in the trusted root store -- "
            "either a private/enterprise CA (expected for internal mail infra, but flag "
            "for review) or a genuinely untrusted issuer"
        )
    # trust_result is True: presented chain resolves to a recognized trust anchor,
    # no additional notice is appended.

    return is_valid, errors


def analyze_stream_tls(stream: TCPStream) -> dict:
    """Runs the full TLS record/handshake parse over both directions of a
    reconstructed stream (post-STARTTLS bytes included automatically since
    we scan the whole buffer for TLS record headers)."""
    result = {
        "tls_detected": False,
        "tls_version": None,
        "cipher_suite": None,
        "key_exchange": None,
        "certificates": [],
        "cert_chain_valid": None,
        "cert_chain_errors": [],
        "cert_observable": None,
        "observability_note": None,
        "reassembly_gaps": stream.s2c.gap_count() + stream.c2s.gap_count(),
    }
    combined = stream.s2c.assembled()  # ServerHello + Certificate come from server
    client_combined = stream.c2s.assembled()

    server_hs, server_has_hs = _handshake_stream_bytes(combined)
    client_hs, client_has_hs = _handshake_stream_bytes(client_combined)
    if server_has_hs or client_has_hs:
        result["tls_detected"] = True

    server_hello_body = None
    client_hello_body = None
    cert_objects = []  # raw x509.Certificate objects, in as-transmitted (leaf-first) order

    for msg_type, msg_body in _parse_handshake_messages(server_hs):
        if msg_type == SERVER_HELLO:
            server_hello_body = msg_body
            sh = _parse_server_hello(msg_body)
            result["tls_version"] = sh.get("negotiated_version")
            result["cipher_suite"] = sh.get("cipher_suite")
        elif msg_type == CERTIFICATE:
            certs = _parse_certificates(msg_body)
            cert_objects.extend(certs)
            for c in certs:
                result["certificates"].append(analyze_certificate(c))

    for msg_type, msg_body in _parse_handshake_messages(client_hs):
        if msg_type == CLIENT_HELLO:
            client_hello_body = msg_body
            ch = _parse_client_hello(msg_body)
            result["client_offered_version"] = ch.get("client_version")

    # --- Key exchange mechanism identification ---
    cipher = result.get("cipher_suite")
    kex = key_exchange_from_cipher(cipher) if cipher else None
    if kex is None and result.get("tls_version") == "TLSv1.3":
        kex = _extract_tls13_key_share_group(client_hello_body, server_hello_body)
    result["key_exchange"] = kex

    # --- Certificate chain validation ---
    if cert_objects:
        valid, errors = validate_certificate_chain(cert_objects)
        result["cert_chain_valid"] = valid
        result["cert_chain_errors"] = errors

    # --- TLS 1.3 observability model ---------------------------------
    # In real TLS1.3 (RFC 8446 §5.1), everything after ServerHello --
    # EncryptedExtensions, Certificate, CertificateVerify, Finished -- is
    # encrypted under the handshake traffic secret, which a passive
    # capture never has access to. So a TLS1.3 session with no parsed
    # certificate is the EXPECTED, secure outcome, not evidence of a
    # missing/invalid certificate -- treating it as "chain invalid" would
    # be a false, misleading conclusion from a capture that structurally
    # cannot see that data. This flag lets findings/UI distinguish the two.
    if result.get("tls_version") == "TLSv1.3":
        if cert_objects:
            # Some captures include a plaintext-adjacent cert only if the
            # session was decrypted upstream / mirrored post-decryption;
            # if we did manage to structurally parse a cert list here,
            # report it as observed and don't suppress the finding.
            result["cert_observable"] = True
        else:
            result["cert_observable"] = False
            result["observability_note"] = (
                "TLS 1.3 negotiated: certificate and post-ServerHello handshake data are "
                "encrypted under the handshake traffic secret and are not visible to a "
                "passive capture. This is expected, secure TLS 1.3 behavior -- not a "
                "missing or invalid certificate."
            )
            # No cert data to evaluate -- explicitly clear any accidental
            # signal so downstream findings don't fire on absence-of-data.
            result["cert_chain_valid"] = None
            result["cert_chain_errors"] = []
    elif result.get("tls_version") in ("TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"):
        result["cert_observable"] = bool(cert_objects)
        if not cert_objects and result["tls_detected"]:
            result["observability_note"] = (
                "TLS handshake observed but no Certificate message was captured -- likely "
                "a reassembly gap or a capture that started mid-handshake, not a protocol "
                "property. Findings based on certificate data are unavailable for this session."
            )

    return result


def build_session_record(stream: TCPStream) -> dict:
    protocol = detect_protocol(stream)
    implicit = is_implicit_tls_port(stream.server_port)
    starttls_used, starttls_success = (False, False)
    if not implicit:
        starttls_used, starttls_success = detect_starttls(stream, protocol)

    tls_info = analyze_stream_tls(stream)
    cert = tls_info["certificates"][0] if tls_info["certificates"] else {}

    cipher = tls_info.get("cipher_suite")
    record = {
        "stream_id": f"{stream.client_ip}:{stream.client_port}->{stream.server_ip}:{stream.server_port}",
        "protocol": protocol,
        "src_ip": stream.client_ip,
        "dst_ip": stream.server_ip,
        "src_port": stream.client_port,
        "dst_port": stream.server_port,
        "starttls_used": starttls_used,
        "starttls_success": starttls_success,
        "implicit_tls": implicit,
        "tls_version": tls_info.get("tls_version"),
        "client_offered_version": tls_info.get("client_offered_version"),
        "cipher_suite": cipher,
        "cipher_strength": classify_cipher_strength(cipher) if cipher else "n/a",
        "forward_secrecy": has_forward_secrecy(cipher) if cipher else False,
        "key_exchange": tls_info.get("key_exchange"),
        "cert_chain_length": len(tls_info.get("certificates", [])),
        "cert_chain_valid": tls_info.get("cert_chain_valid"),
        "cert_chain_errors": tls_info.get("cert_chain_errors", []),
        "cert_observable": tls_info.get("cert_observable"),
        "observability_note": tls_info.get("observability_note"),
        "reassembly_gaps": tls_info.get("reassembly_gaps", 0),
        "cert_subject": cert.get("subject"),
        "cert_issuer": cert.get("issuer"),
        "cert_valid_from": cert.get("valid_from"),
        "cert_valid_to": cert.get("valid_to"),
        "cert_expired": cert.get("expired", False),
        "cert_self_signed": cert.get("self_signed", False),
        "cert_key_algo": cert.get("key_algorithm"),
        "cert_key_size": cert.get("key_size"),
        "cert_sig_algo": cert.get("signature_algorithm"),
        "cert_fingerprint_sha256": cert.get("fingerprint_sha256"),
        "cert_weak_key": cert.get("weak_key", False),
        "cert_weak_signature": cert.get("weak_signature", False),
        "packet_count": stream.packet_count,
        "first_seen": datetime.utcfromtimestamp(stream.first_seen).isoformat() if stream.first_seen else None,
        "last_seen": datetime.utcfromtimestamp(stream.last_seen).isoformat() if stream.last_seen else None,
        "tls_negotiated": tls_info["tls_detected"] or implicit,
        "plaintext_only": not (tls_info["tls_detected"] or implicit),
        "non_standard_port": getattr(stream, "non_standard_port", False),
        "tcp_connection_state": getattr(stream, "connection_state", "unknown"),
        "packet_evidence": getattr(stream, "packet_evidence", []),
    }
    return record


def analyze_pcap(pcap_path: str) -> list:
    """Top-level entry point: pcap file path -> list of session dicts.

    If the capture exceeded MAX_PACKETS_PER_CAPTURE, every returned session
    dict carries `capture_truncated: True` so downstream findings/reports
    can flag that this is a partial analysis rather than presenting it as
    a complete posture assessment."""
    streams, truncated = reconstruct_tcp_streams(pcap_path)
    sessions = []
    for s in streams:
        if s.packet_count == 0:
            continue
        record = build_session_record(s)
        record["capture_truncated"] = truncated
        sessions.append(record)
    return sessions
