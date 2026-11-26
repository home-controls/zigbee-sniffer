"""Read the parts of a Zigbee frame that travel in clear: the 802.15.4 MAC header and the
Zigbee NWK header. Who sent a frame over the air (MAC), who it really came from and is going
to (NWK), and the frame type need no key; only the payload (APS/ZCL, NWK commands) is encrypted.

MAC commands (data requests, beacon requests, association, orphan notifications) are never
encrypted either, so they can be read here too.

The MAC header also names the network (PAN ID). The sniffer hears every network on its
channel - neighbours' Zigbee, Thread - so the PAN ID is what tells our frames from theirs.
"""

import struct

MAC_TYPES = {0: "beacon", 1: "data", 2: "ack", 3: "command", 5: "multipurpose"}
NWK_TYPES = {0: "data", 1: "command", 3: "inter-pan"}
MAC_COMMANDS = {
    1: "Association Request", 2: "Association Response", 3: "Disassociation", 4: "Data Request",
    5: "PAN ID Conflict", 6: "Orphan Notification", 7: "Beacon Request", 8: "Coordinator Realignment",
    9: "GTS Request",
}
NWK_COMMANDS = {
    1: "Route Request", 2: "Route Reply", 3: "Network Status", 4: "Leave", 5: "Route Record",
    6: "Rejoin Request", 7: "Rejoin Response", 8: "Link Status", 9: "Network Report",
    10: "Network Update", 11: "End Device Timeout Request", 12: "End Device Timeout Response",
    13: "Link Power Delta",
}
BROADCAST_PAN = 0xFFFF


def _ext(raw: bytes) -> str:
    return "0x" + raw[::-1].hex()


def parse(psdu: bytes) -> dict:
    out: dict = {"len": len(psdu)}
    if len(psdu) < 3:
        out["type"] = "short"
        return out
    (fc,) = struct.unpack_from("<H", psdu, 0)
    ftype = fc & 0x7
    out["type"] = MAC_TYPES.get(ftype, f"type{ftype}")
    out["security"] = bool(fc & 0x08)
    out["pending"] = bool(fc & 0x10)
    out["ack_req"] = bool(fc & 0x20)
    pan_comp = bool(fc & 0x40)
    dst_mode = (fc >> 10) & 0x3
    src_mode = (fc >> 14) & 0x3
    out["seq"] = psdu[2]
    pos = 3
    try:
        if dst_mode:
            (out["dst_pan"],) = struct.unpack_from("<H", psdu, pos)
            pos += 2
            if dst_mode == 2:
                out["dst"] = f"0x{struct.unpack_from('<H', psdu, pos)[0]:04x}"
                pos += 2
            elif dst_mode == 3:
                out["dst"] = _ext(psdu[pos : pos + 8])
                pos += 8
        if src_mode:
            if not pan_comp:
                (out["src_pan"],) = struct.unpack_from("<H", psdu, pos)
                pos += 2
            if src_mode == 2:
                out["src"] = f"0x{struct.unpack_from('<H', psdu, pos)[0]:04x}"
                pos += 2
            elif src_mode == 3:
                out["src"] = _ext(psdu[pos : pos + 8])
                pos += 8
        if pos > len(psdu):
            raise struct.error("header past the end")
        if ftype == 1 and not out["security"] and len(psdu) >= pos + 8:
            out["nwk"] = _parse_nwk(psdu[pos:])
        elif ftype == 3 and not out["security"] and len(psdu) > pos:
            cmd = psdu[pos]
            out["cmd"] = cmd
            if cmd == 2 and len(psdu) >= pos + 4:  # association response: the new short address and a status
                out["assoc_addr"] = f"0x{struct.unpack_from('<H', psdu, pos + 1)[0]:04x}"
                out["assoc_status"] = psdu[pos + 3]
    except struct.error:
        out["truncated"] = True
    # The network: the destination PAN, or the source PAN when the destination is every
    # network (a beacon request) or absent (a beacon). An ACK names none.
    for pan in (out.get("dst_pan"), out.get("src_pan")):
        if pan is not None and pan != BROADCAST_PAN:
            out["pan"] = pan
            break
    return out


def _parse_nwk(p: bytes) -> dict:
    (fc,) = struct.unpack_from("<H", p, 0)
    ftype = fc & 0x3
    nwk: dict = {"type": NWK_TYPES.get(ftype, f"type{ftype}")}
    if ftype == 3:  # inter-PAN: no NWK addressing
        return nwk
    dst, src = struct.unpack_from("<HH", p, 2)
    nwk["dst"] = f"0x{dst:04x}"
    nwk["src"] = f"0x{src:04x}"
    nwk["radius"] = p[6]
    nwk["seq"] = p[7]
    nwk["security"] = bool(fc & 0x0200)
    nwk["source_route"] = bool(fc & 0x0400)
    nwk["discover_route"] = (fc >> 6) & 0x3
    pos = 8
    if fc & 0x0800 and len(p) >= pos + 8:
        nwk["dst64"] = _ext(p[pos : pos + 8])
        pos += 8
    if fc & 0x1000 and len(p) >= pos + 8:
        nwk["src64"] = _ext(p[pos : pos + 8])
        pos += 8
    if fc & 0x0100:  # multicast control
        pos += 1
    if fc & 0x0400 and len(p) > pos:  # source route: relay count, relay index, relays
        pos += 2 + 2 * p[pos]
    # A NWK command sent without NWK security (a trust-centre rejoin) shows its command id.
    if ftype == 1 and not nwk["security"] and len(p) > pos:
        nwk["cmd"] = p[pos]
    return nwk


def kind(m: dict) -> str:
    """A short name for what the frame is, from the clear headers alone."""
    t = m.get("type", "")
    if t == "command":
        return MAC_COMMANDS.get(m.get("cmd"), "MAC command")
    if t == "data":
        nwk = m.get("nwk")
        if not nwk:
            return "Data"
        if nwk.get("type") == "command":
            return NWK_COMMANDS.get(nwk.get("cmd"), "NWK command")
        return "NWK data" if nwk.get("type") == "data" else nwk.get("type", "Data")
    return t.capitalize() if t else ""


class PanTracker:
    """Which network each frame belongs to, in capture order.

    Data, command and beacon frames name their PAN. An ACK names none, so it takes the PAN of
    the frame it answers: the last frame that asked for an ACK, with the same sequence
    number, heard just before. Frames that name no network count as not ours.
    """

    ACK_WINDOW_S = 0.02

    def __init__(self, ours: int | None) -> None:
        self.ours = ours  # None: Zigbee2MQTT's PAN ID is unknown, so every frame counts as ours
        self._asked: tuple[int, int, float] | None = None  # (seq, pan, ts) of the last ACK request

    def pan(self, m: dict, ts: float) -> int | None:
        if m.get("type") == "ack":
            asked = self._asked
            if asked and asked[0] == m.get("seq") and 0 <= ts - asked[2] <= self.ACK_WINDOW_S:
                return asked[1]
            return None
        pan = m.get("pan")
        if m.get("ack_req") and pan is not None:
            self._asked = (m["seq"], pan, ts)
        return pan

    def is_ours(self, pan: int | None) -> bool:
        return self.ours is None or pan == self.ours
