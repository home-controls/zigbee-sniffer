"""Sniffer wire protocol (mirror of firmware/protocol/sniffer_proto.h).

    0xA5 0x5A | type u8 | length u16 LE | payload | crc16 u16 LE   (CRC-16/CCITT-FALSE)

The same framing comes from a bridge over TCP and from a radio on USB (usb.py).
"""

import binascii
import struct

SYNC = b"\xa5\x5a"
MAX_PAYLOAD = 512

T_FRAME = 0x01
T_RADIO_STATUS = 0x02
T_HELLO = 0x03  # first on every connection: JSON {"bridge", "bridge_us", "backlog_bytes"}
T_BRIDGE_STATUS = 0x04
T_FRAME_AT = 0x06  # u64 bridge_us (when the radio heard it, on the bridge's clock), then a T_FRAME payload
T_SET_CHANNEL = 0x10
T_CLIENT_HELLO = 0x12  # app -> bridge, right after connecting: u32 flags

# Between a radio and whoever plays the bridge: the S3 bridge, or this app for a radio on USB.
T_RADIO_BOOT = 0x05  # radio ->: version x3, fw state, then (radio 0.3+) u16 image chip id
T_PING = 0x11  # -> radio, every second: u8 flags (PING_RADIO_HEARD)
T_UPDATE_BEGIN = 0x20  # -> radio: u32 image size
T_UPDATE_DATA = 0x21  # -> radio: u32 offset, then 1..UPDATE_CHUNK image bytes
T_UPDATE_END = 0x22  # -> radio: check the image, reboot into it on trial
T_UPDATE_ABORT = 0x23
T_UPDATE_ACK = 0x24  # radio ->: stage, offset, esp_err_t

CLIENT_FRAME_AT = 0x01  # we take T_FRAME_AT and the frames buffered while we were away (bridge 0.3+)
PING_RADIO_HEARD = 0x01  # a radio status arrived in the last 3 s: a radio on trial keeps its new image
UPDATE_CHUNK = 480
FW_STATES = {0: "running", 1: "trial", 2: "confirmed", 3: "rolled_back"}  # SNIFF_FW_*

FRAME_HDR = struct.Struct("<QBbBB")  # timestamp_us, channel, rssi, lqi, flags
FRAME_AT_TIME = struct.Struct("<Q")  # bridge_us in front of a T_FRAME payload
CLIENT_HELLO = struct.Struct("<I")  # flags
RADIO_STATUS = struct.Struct("<IIIB3B")  # uptime_s, frames, dropped, channel, version x3
BRIDGE_STATUS = struct.Struct("<IIIIbB")  # uptime_s, uart_frames, uart_crc_errors, tcp_dropped, wifi_rssi, radio_link_ok
RADIO_BOOT = struct.Struct("<3BB")  # version x3, fw state (SNIFF_FW_*)
RADIO_BOOT_CHIP = struct.Struct("<H")  # after RADIO_BOOT (radio 0.3+): ESP-IDF image chip id
UPDATE_BEGIN = struct.Struct("<I")  # image size
UPDATE_DATA = struct.Struct("<I")  # offset, then the bytes
UPDATE_ACK = struct.Struct("<BIi")  # stage, offset (bytes the radio holds), esp_err_t


def crc16(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF): binascii's C version, ~250x the Python loop."""
    return binascii.crc_hqx(data, crc)


def encode(msg_type: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<BH", msg_type, len(payload)) + payload
    return SYNC + body + struct.pack("<H", crc16(body))


class Decoder:
    """Feed it TCP chunks; it returns complete, CRC-checked (type, payload) messages."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.crc_errors = 0

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self.buf += data
        out: list[tuple[int, bytes]] = []
        while True:
            start = self.buf.find(SYNC)
            if start < 0:
                del self.buf[:-1]  # keep a possible first sync byte
                return out
            if start:
                del self.buf[:start]
            if len(self.buf) < 5:
                return out
            msg_type, length = struct.unpack_from("<BH", self.buf, 2)
            if length > MAX_PAYLOAD:
                self.crc_errors += 1
                del self.buf[:2]
                continue
            total = 5 + length + 2
            if len(self.buf) < total:
                return out
            body = bytes(self.buf[2 : 5 + length])
            (want,) = struct.unpack_from("<H", self.buf, 5 + length)
            if crc16(body) == want:
                out.append((msg_type, body[3:]))
                del self.buf[:total]
            else:
                self.crc_errors += 1
                del self.buf[:2]
