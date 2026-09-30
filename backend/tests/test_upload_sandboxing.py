import os

from app.api.case_routes import _sanitize_filename, _looks_like_pcap


def test_sanitize_strips_path_traversal():
    assert _sanitize_filename("../../etc/passwd") == "etc_passwd" or "/" not in _sanitize_filename("../../etc/passwd")
    assert ".." not in _sanitize_filename("../../evil.pcap")


def test_sanitize_strips_null_bytes_and_odd_chars():
    result = _sanitize_filename("capture\x00.pcap;rm -rf.pcap")
    assert "\x00" not in result
    assert ";" not in result and " " not in result


def test_sanitize_empty_name_gets_default():
    assert _sanitize_filename("") == "upload.pcap"
    assert _sanitize_filename(None) == "upload.pcap"


def test_looks_like_pcap_accepts_real_magic(tmp_path):
    p = tmp_path / "sample.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    assert _looks_like_pcap(str(p)) is True


def test_looks_like_pcap_rejects_non_pcap_content(tmp_path):
    p = tmp_path / "fake.pcap"
    p.write_bytes(b"MZ\x90\x00")  # a Windows PE header, not a capture
    assert _looks_like_pcap(str(p)) is False


def test_looks_like_pcap_accepts_pcapng_magic(tmp_path):
    p = tmp_path / "sample.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    assert _looks_like_pcap(str(p)) is True
