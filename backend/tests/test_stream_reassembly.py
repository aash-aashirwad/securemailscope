"""Unit tests for app.services.pcap_engine.StreamBuffer.

These exercise the resource-limit-free, pure-Python reassembly logic
directly (no scapy/pcap I/O involved), covering the scenarios called out
in the project's own gap list: out-of-order delivery, exact
retransmission, overlapping retransmission, and dropped-packet gaps.
"""
import pytest

from app.services.pcap_engine import StreamBuffer


def test_in_order_concatenation():
    sb = StreamBuffer()
    sb.add(100, b"HELLO")
    sb.add(105, b"WORLD")
    assert sb.assembled() == b"HELLOWORLD"
    assert sb.gap_count() == 0


def test_out_of_order_delivery_is_reordered():
    sb = StreamBuffer()
    sb.add(105, b"WORLD")
    sb.add(100, b"HELLO")
    assert sb.assembled() == b"HELLOWORLD"
    assert sb.gap_count() == 0


def test_exact_retransmission_is_deduplicated():
    sb = StreamBuffer()
    sb.add(100, b"HELLOWORLD")
    sb.add(100, b"HELLOWORLD")  # exact duplicate (retransmit, no loss)
    assert sb.assembled() == b"HELLOWORLD"
    assert sb.gap_count() == 0


def test_overlapping_retransmission_is_trimmed_not_duplicated():
    sb = StreamBuffer()
    sb.add(100, b"HELLOWORLD")   # bytes 100-109
    sb.add(105, b"WORLDXY")      # retransmit of tail + 2 new bytes, 105-111
    assert sb.assembled() == b"HELLOWORLDXY"
    assert sb.gap_count() == 0


def test_fully_contained_retransmission_is_dropped():
    sb = StreamBuffer()
    sb.add(100, b"HELLOWORLD")
    sb.add(102, b"LLO")  # fully inside the first segment
    assert sb.assembled() == b"HELLOWORLD"


def test_gap_from_dropped_packet_is_counted_not_silently_spliced():
    sb = StreamBuffer()
    sb.add(200, b"AAAA")   # covers 200-203
    sb.add(220, b"CCCC")   # 204-219 never captured
    assert sb.assembled() == b"AAAACCCC"
    assert sb.gap_count() == 1


def test_empty_stream():
    sb = StreamBuffer()
    assert sb.assembled() == b""
    assert sb.gap_count() == 0


def test_sequence_wraparound_is_normalized():
    # A genuine wraparound: sequence numbers actually cross the 32-bit
    # boundary (0xFFFFFFFF -> 0), not just "large but still < 2^32". This
    # matters because a plain min()-based normalization breaks exactly
    # here: the wrapped segment's raw number (0) is numerically SMALLER
    # than the pre-wrap segment's (0xFFFFFFFE) despite being
    # chronologically later, which would put it first if you sorted on
    # raw values -- see also test_wraparound_is_correct_regardless_of_arrival_order below.
    near_max = 0xFFFFFFFE  # only 2 bytes of room before the boundary
    sb = StreamBuffer()
    sb.add(near_max, b"AA")                       # occupies [0xFFFFFFFE, 0x100000000)
    wrapped_seq = (near_max + 2) & 0xFFFFFFFF      # = 0 -- genuinely wrapped past the boundary
    sb.add(wrapped_seq, b"BB")
    assert sb.assembled() == b"AABB"
    assert sb.gap_count() == 0


def test_wraparound_is_correct_regardless_of_arrival_order():
    # Same genuine wraparound as above, but the numerically-smaller
    # (post-wrap) segment is added FIRST. A base-seq selection that
    # picks whichever segment is smallest, or whichever arrived first,
    # both fail this in different ways; only a signed-distance ordering
    # gets it right regardless of order added.
    sb = StreamBuffer()
    sb.add(0, b"BB")               # arrives first; numerically smallest; but is LATER in the stream
    sb.add(0xFFFFFFFE, b"AA")
    assert sb.assembled() == b"AABB"
    assert sb.gap_count() == 0
