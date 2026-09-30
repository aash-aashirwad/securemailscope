"""
Reference knowledge base for cryptographic posture evaluation.
Based on: IETF RFC 8446 (TLS1.3), RFC 5246 (TLS1.2), NIST SP 800-52 Rev.2,
IANA TLS Cipher Suite Registry, OWASP TLS Cheat Sheet, RFC 3207 (SMTP STARTTLS).
"""

TLS_VERSION_MAP = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

DEPRECATED_TLS_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}
SECURE_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

# IANA TLS Cipher Suite registry subset (hex code -> name), covering the
# suites realistically negotiable by mainstream TLS stacks (OpenSSL,
# BoringSSL, GnuTLS, Windows SChannel, NSS) that an email server or client
# could offer. This is not the full ~350-entry IANA registry (much of which
# is legacy Kerberos/SRP/PSK-only suites never seen in the wild for
# SMTP/IMAP/POP3), but any code not covered here still resolves gracefully
# via the "UNKNOWN_0xXXXX" fallback in CIPHER_SUITE_MAP.get(...) rather than
# crashing, so coverage gaps degrade to an honest "unrecognized" label
# instead of a wrong one.
CIPHER_SUITE_MAP = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x008A: "TLS_PSK_WITH_RC4_128_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAB: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    # TLS 1.3 (RFC 8446 §B.4) — key exchange is negotiated separately via
    # the key_share extension, not encoded in the suite name; see
    # key_exchange_from_cipher() / TLS_NAMED_GROUP_MAP below.
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # GREASE values (RFC 8701) some clients send to test middlebox
    # tolerance; these are never actually negotiated, but surfacing the
    # label rather than "UNKNOWN" avoids a misleading "weak/unrecognized
    # cipher" finding when one shows up in a ClientHello offer list.
    0x0A0A: "GREASE", 0x1A1A: "GREASE", 0x2A2A: "GREASE", 0x3A3A: "GREASE",
    0x4A4A: "GREASE", 0x5A5A: "GREASE", 0x6A6A: "GREASE", 0x7A7A: "GREASE",
    0x8A8A: "GREASE", 0x9A9A: "GREASE", 0xAAAA: "GREASE", 0xBABA: "GREASE",
    0xCACA: "GREASE", 0xDADA: "GREASE", 0xEAEA: "GREASE", 0xFAFA: "GREASE",
}

WEAK_CIPHER_KEYWORDS = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon", "CBC_SHA$"]
FORWARD_SECRECY_KEYWORDS = ["ECDHE", "DHE", "TLS_AES", "TLS_CHACHA20"]

MIN_SECURE_RSA_KEY_SIZE = 2048
MIN_SECURE_EC_KEY_SIZE = 256
WEAK_SIGNATURE_ALGOS = ["md5", "sha1"]

DEFAULT_PORTS = {
    25: "SMTP", 587: "SMTP-Submission", 465: "SMTPS",
    143: "IMAP", 993: "IMAPS",
    110: "POP3", 995: "POP3S",
}

STARTTLS_COMMANDS = {
    "SMTP": b"STARTTLS",
    "IMAP": b"STARTTLS",
    "POP3": b"STLS",
}


def classify_cipher_strength(cipher_name: str) -> str:
    if not cipher_name:
        return "unknown"
    if cipher_name == "GREASE":
        return "n/a"  # RFC 8701 sentinel value, never an actually-negotiated cipher
    upper = cipher_name.upper()
    for kw in WEAK_CIPHER_KEYWORDS:
        if kw.replace("$", "") in upper:
            return "weak"
    if any(kw in upper for kw in FORWARD_SECRECY_KEYWORDS):
        return "strong"
    return "moderate"


def has_forward_secrecy(cipher_name: str) -> bool:
    if not cipher_name:
        return False
    return any(kw in cipher_name.upper() for kw in FORWARD_SECRECY_KEYWORDS)


# --- Key exchange mechanism identification -----------------------------
# TLS1.2-style suite names encode the key exchange directly
# (TLS_<kex>_WITH_...). TLS1.3 suites (TLS_AES_..., TLS_CHACHA20_...) don't
# encode it in the name -- the actual group is negotiated separately via the
# key_share/supported_groups extensions, so those are resolved from the
# named-group registry below rather than the cipher string.
KEY_EXCHANGE_FROM_CIPHER_NAME = [
    ("ECDHE_PSK", "ECDHE_PSK"),
    ("DHE_PSK", "DHE_PSK"),
    ("ECDHE", "ECDHE"),
    ("DHE", "DHE"),
    ("RSA_PSK", "RSA_PSK"),
    ("PSK", "PSK"),
    ("RSA", "RSA (static, no forward secrecy)"),
    ("ECDH_", "ECDH (static, no forward secrecy)"),
]

# IANA TLS Supported Groups registry (subset relevant to email deployments) --
# used to resolve the actual named group from the key_share extension in a
# TLS1.3 ServerHello, since TLS1.3 cipher-suite names no longer encode kex.
TLS_NAMED_GROUP_MAP = {
    0x0017: "secp256r1 (P-256, ECDHE)",
    0x0018: "secp384r1 (P-384, ECDHE)",
    0x0019: "secp521r1 (P-521, ECDHE)",
    0x001D: "x25519 (ECDHE)",
    0x001E: "x448 (ECDHE)",
    0x0100: "ffdhe2048 (DHE)",
    0x0101: "ffdhe3072 (DHE)",
    0x0102: "ffdhe4096 (DHE)",
    0x0103: "ffdhe6144 (DHE)",
    0x0104: "ffdhe8192 (DHE)",
}


def key_exchange_from_cipher(cipher_name: str):
    """Best-effort key-exchange mechanism label derived from a TLS<=1.2
    cipher-suite name. Returns None for TLS1.3 suites, whose kex must be
    resolved from the key_share extension instead (see TLS_NAMED_GROUP_MAP)."""
    if not cipher_name:
        return None
    upper = cipher_name.upper()
    if upper.startswith("TLS_AES") or upper.startswith("TLS_CHACHA20"):
        return None  # TLS1.3 -- resolved via key_share extension, not the name
    for token, label in KEY_EXCHANGE_FROM_CIPHER_NAME:
        if token in upper:
            return label
    return "unknown"
