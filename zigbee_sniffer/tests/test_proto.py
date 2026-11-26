import os
import random
import struct

import proto


def ref_crc16(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE, bit by bit (the firmware's sniffer_proto.h)."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def test_crc16_check_value():
    assert proto.crc16(b"123456789") == 0x29B1  # the catalogue check value of CRC-16/CCITT-FALSE


def test_crc16_matches_reference():
    rnd = random.Random(1)
    for n in (0, 1, 2, 7, 64, 150, 511):
        data = bytes(rnd.randrange(256) for _ in range(n))
        assert proto.crc16(data) == ref_crc16(data)


def test_encode_layout():
    msg = proto.encode(proto.T_SET_CHANNEL, bytes([25]))
    assert msg[:2] == proto.SYNC
    assert msg[2] == proto.T_SET_CHANNEL
    assert struct.unpack_from("<H", msg, 3)[0] == 1
    assert msg[5] == 25
    assert struct.unpack_from("<H", msg, 6)[0] == ref_crc16(msg[2:6])


def test_round_trip_whole_and_byte_by_byte():
    msgs = [(proto.T_FRAME, os.urandom(40)), (proto.T_HELLO, b'{"bridge":"0.3"}'), (proto.T_RADIO_STATUS, b""),
            (proto.T_FRAME_AT, os.urandom(proto.MAX_PAYLOAD))]
    stream = b"".join(proto.encode(t, p) for t, p in msgs)
    assert proto.Decoder().feed(stream) == msgs
    dec, out = proto.Decoder(), []
    for i in range(len(stream)):
        out += dec.feed(stream[i : i + 1])
    assert out == msgs
    assert dec.crc_errors == 0


def test_resync_after_garbage():
    good1 = proto.encode(proto.T_FRAME, b"\x01\x02\x03")
    good2 = proto.encode(proto.T_HELLO, b"{}")
    bad_crc = bytearray(proto.encode(proto.T_FRAME, b"abcdef"))
    bad_crc[-1] ^= 0xFF
    too_long = proto.SYNC + struct.pack("<BH", proto.T_FRAME, proto.MAX_PAYLOAD + 1)
    stream = b"\x00\xff\xa5garbage\x5a" + bytes(bad_crc) + too_long + b"\xa5" + good1 + b"\x5a\xa5\xa5" + good2
    dec = proto.Decoder()
    got = dec.feed(stream)
    assert got == [(proto.T_FRAME, b"\x01\x02\x03"), (proto.T_HELLO, b"{}")]
    assert dec.crc_errors >= 2


def test_sync_bytes_inside_payload():
    payload = proto.SYNC * 10 + b"\x00"
    stream = proto.encode(proto.T_FRAME, payload) + proto.encode(proto.T_FRAME, b"x")
    assert proto.Decoder().feed(stream) == [(proto.T_FRAME, payload), (proto.T_FRAME, b"x")]


def test_message_split_across_feeds_keeps_partial():
    msg = proto.encode(proto.T_FRAME, b"hello")
    dec = proto.Decoder()
    assert dec.feed(msg[:4]) == []
    assert dec.feed(msg[4:9]) == []
    assert dec.feed(msg[9:]) == [(proto.T_FRAME, b"hello")]
    assert dec.feed(b"") == []
