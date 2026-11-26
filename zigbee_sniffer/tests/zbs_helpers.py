"""Frame builders and a settable clock shared by the tests."""

import struct

import proto

PAN = 0x852C


def nwk(src: int, dst: int, seq: int, payload: bytes = b"\x00" * 8, ftype: int = 0, radius: int = 30,
        src64: str | None = None) -> bytes:
    """A Zigbee NWK header (protocol version 2, NWK security off) and its payload."""
    fc = ftype | (2 << 2) | (1 << 6) | (0x1000 if src64 else 0)
    hdr = struct.pack("<HHHBB", fc, dst, src, radius, seq)
    if src64:
        hdr += bytes.fromhex(src64)[::-1]
    return hdr + payload


def mac_data(src: int, dst: int, seq: int, payload: bytes = b"", ack: bool = True, pan: int = PAN) -> bytes:
    """An 802.15.4 data frame with short addresses and PAN ID compression."""
    fc = 1 | (0x20 if ack else 0) | 0x40 | (2 << 10) | (2 << 14)
    return struct.pack("<HBHHH", fc, seq, pan, dst, src) + payload


def mac_cmd(src: int, dst: int, seq: int, cmd: int, ack: bool = True, pan: int = PAN) -> bytes:
    fc = 3 | (0x20 if ack else 0) | 0x40 | (2 << 10) | (2 << 14)
    return struct.pack("<HBHHH", fc, seq, pan, dst, src) + bytes([cmd])


def ack(seq: int, pending: bool = False) -> bytes:
    return struct.pack("<HB", 0x0002 | (0x10 if pending else 0), seq)


def frame_at(bridge_us: int, psdu: bytes, radio_us: int = 0, channel: int = 25, rssi: int = -60, lqi: int = 200) -> bytes:
    """The payload of a T_FRAME_AT message."""
    return proto.FRAME_AT_TIME.pack(bridge_us) + proto.FRAME_HDR.pack(radio_us, channel, rssi, lqi, 0) + psdu


class Clock:
    """Stands in for the `time` module inside a module under test: time() returns .t."""

    def __init__(self, t: float) -> None:
        self.t = t

    def time(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.t
