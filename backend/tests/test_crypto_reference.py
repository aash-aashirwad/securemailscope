from app.services.crypto_reference import (
    CIPHER_SUITE_MAP, classify_cipher_strength, has_forward_secrecy,
    key_exchange_from_cipher, TLS_NAMED_GROUP_MAP,
)


def test_known_strong_suite_classified_strong():
    name = CIPHER_SUITE_MAP[0xC02F]  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    assert classify_cipher_strength(name) == "strong"
    assert has_forward_secrecy(name) is True


def test_known_weak_suite_classified_weak():
    name = CIPHER_SUITE_MAP[0x0005]  # TLS_RSA_WITH_RC4_128_SHA
    assert classify_cipher_strength(name) == "weak"


def test_null_cipher_is_weak():
    name = CIPHER_SUITE_MAP[0x0000]
    assert classify_cipher_strength(name) == "weak"


def test_unknown_cipher_code_does_not_crash_lookup():
    # a code with no entry should be handled by callers via .get(..., fallback),
    # not raise -- simulate the fallback pattern used in pcap_engine.
    fallback = CIPHER_SUITE_MAP.get(0xBEEF, "UNKNOWN_0xBEEF")
    assert fallback == "UNKNOWN_0xBEEF"
    assert classify_cipher_strength(fallback) in ("moderate", "unknown")


def test_grease_cipher_is_not_misclassified_as_weak_or_strong():
    assert classify_cipher_strength("GREASE") == "n/a"


def test_key_exchange_from_tls12_suite_name():
    assert key_exchange_from_cipher(CIPHER_SUITE_MAP[0xC02F]) == "ECDHE"
    assert key_exchange_from_cipher(CIPHER_SUITE_MAP[0x0035]).startswith("RSA")


def test_key_exchange_from_tls13_suite_returns_none_for_name_based_lookup():
    # TLS1.3 suites don't encode kex in the name; caller must resolve via
    # the key_share extension instead (see TLS_NAMED_GROUP_MAP).
    assert key_exchange_from_cipher(CIPHER_SUITE_MAP[0x1301]) is None


def test_named_group_map_covers_x25519():
    assert "x25519" in TLS_NAMED_GROUP_MAP[0x001D]
