"""Decode capture files for the Captures page.

Per frame: our own parse of the clear headers (time, RSSI/LQI, network, MAC + NWK addresses,
retransmissions) merged with tshark's protocol and summary columns, which use the network key
from tshark's key table, so encrypted APS/ZCL and NWK commands read in plain words.

A file is decoded once and kept (the two most recent files asked for); the file being written
grows, so only what was added since the last request is decoded (by byte offset). Rows are kept
as compact tuples (an hour can hold 700k frames when the channel is busy); names are put on the
rows of the page being shown. Parsing runs in a thread, so the page never stalls the frame path.
"""

import asyncio
import collections
import logging
import tempfile
from pathlib import Path

import mac
import pcap
from names import Names
from tshark import Tshark

log = logging.getLogger("decode")

BROADCASTS = {"0xffff": "broadcast", "0xfffd": "broadcast (awake)", "0xfffc": "broadcast (routers)",
              "0xfffb": "broadcast (low power routers)"}
MAX_FILES = 2
# row tuple
N, TS, RSSI, LQI, PAN, OURS, MTYPE, KIND, SEQ, RETRY, SRC, DST, NSRC, NDST, PROTO, INFO = range(16)


def label(addr: str | None, names: Names, ours: bool = True) -> str:
    """An address with its Zigbee2MQTT name - only in our network, where the names apply."""
    if not addr:
        return ""
    if addr in BROADCASTS:
        return BROADCASTS[addr]
    n = names.name(addr) if ours else None
    return f"{n} ({addr})" if n else addr


def pan_text(pan: int | None) -> str:
    return f"0x{pan:04x}" if pan is not None else ""


class _Decoded:
    def __init__(self, pan: int | None) -> None:
        self.pan = pan
        self.end = 0  # bytes decoded
        self.rows: list[tuple] = []
        self.pans = mac.PanTracker(pan)
        self.recent: dict[tuple, float] = {}  # (src, dst, seq) -> ts, for retransmissions
        self.recent_q: collections.deque = collections.deque()


_cache: "collections.OrderedDict[str, _Decoded]" = collections.OrderedDict()
_locks: dict[str, asyncio.Lock] = {}


def _read(path: Path, start: int) -> tuple[list, int]:
    packets, end = [], start
    for end, ts, data in pcap.iter_records(path, start):
        packets.append((ts, *pcap.parse_tap(data)))
    return packets, end


def _parse(packets: list, cols: list, first_n: int, st: _Decoded) -> list[tuple]:
    rows = []
    for i, (ts, _channel, rssi, lqi, psdu) in enumerate(packets):
        m = mac.parse(psdu)
        pan = st.pans.pan(m, ts)
        ours = st.pans.is_ours(pan)
        nwk = m.get("nwk") or {}
        src, dst = m.get("src"), m.get("dst")
        retry = False
        if m.get("ack_req") and dst and dst not in BROADCASTS:
            key = (src, dst, m.get("seq"))
            prev = st.recent.get(key)
            retry = prev is not None and 0 <= ts - prev <= 1.0
            st.recent[key] = ts
            st.recent_q.append((ts, key))
            while st.recent_q and ts - st.recent_q[0][0] > 2:
                old_ts, old = st.recent_q.popleft()
                if st.recent.get(old) == old_ts:
                    del st.recent[old]
        col = cols[i] if i < len(cols) else ("", "")
        rows.append((first_n + i, ts, rssi, lqi, pan, ours, m.get("type", ""), mac.kind(m), m.get("seq"), retry,
                     src or "", dst or "", nwk.get("src") or "", nwk.get("dst") or "", col[0], col[1]))
    return rows


async def _columns(path: Path, start: int, end: int, tshark: Tshark) -> list | None:
    if not tshark.enabled:
        return []
    with tempfile.TemporaryDirectory(prefix="zbs-") as tmp:
        chunk = Path(tmp) / "chunk.pcap"
        await asyncio.to_thread(pcap.copy_chunk, path, chunk, start, end)
        rows = await tshark.fields(chunk, ["_ws.col.protocol", "_ws.col.info"], occurrence="f")
    if rows is None:
        return None
    return [(r.get("_ws.col.protocol", ""), r.get("_ws.col.info", "")) for r in rows]


async def decoded(path: Path, tshark: Tshark, our_pan: int | None) -> list[tuple]:
    """Every frame of the file as row tuples (see N..INFO); only new records are decoded."""
    key = str(path)
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        st = _cache.get(key)
        size = path.stat().st_size
        if st is None or st.pan != our_pan or size < st.end:
            st = _Decoded(our_pan)
        start = max(st.end, len(pcap.GLOBAL_HEADER))
        rows = st.rows
        if size > start:
            packets, end = await asyncio.to_thread(_read, path, start)
            if packets:
                cols = await _columns(path, start, end, tshark)
                if cols is None:  # tshark failed: show what we have (parsed apart), decode it again next time
                    scratch = _Decoded(our_pan)
                    return st.rows + await asyncio.to_thread(_parse, packets, [], len(st.rows) + 1, scratch)
                new = await asyncio.to_thread(_parse, packets, cols, len(st.rows) + 1, st)
                st.rows.extend(new)
                st.end = end
        _cache[key] = st
        _cache.move_to_end(key)
        while len(_cache) > MAX_FILES:
            old, _ = _cache.popitem(last=False)
            _locks.pop(old, None)
        return rows


def as_dict(r: tuple, names: Names) -> dict:
    ours = r[OURS]
    return {
        "n": r[N], "ts": r[TS], "rssi": r[RSSI], "lqi": r[LQI], "pan": pan_text(r[PAN]), "ours": ours,
        "mac_type": r[MTYPE], "kind": r[KIND], "seq": r[SEQ], "retry": r[RETRY],
        "mac_src": label(r[SRC], names, ours), "mac_dst": label(r[DST], names, ours),
        "nwk_src": label(r[NSRC], names, ours), "nwk_dst": label(r[NDST], names, ours),
        "addrs": [a for a in (r[SRC], r[DST], r[NSRC], r[NDST]) if a], "proto": r[PROTO], "info": r[INFO],
    }


def _text(r: tuple, names: Names) -> str:
    ours = r[OURS]
    return " ".join((label(r[SRC], names, ours), label(r[DST], names, ours), label(r[NSRC], names, ours),
                     label(r[NDST], names, ours), r[KIND], r[MTYPE], r[PROTO], r[INFO], pan_text(r[PAN]),
                     str(r[SEQ]))).lower()


def page(rows: list[tuple], names: Names, others: bool = False, addr: str = "", q: str = "", retries: bool = False,
         around_n: int | None = None, at_ts: float | None = None, limit: int = 200, offset: int = 0) -> dict:
    """One page of a decoded file after the filters: the page that holds frame `around_n` or the
    first frame at or after `at_ts`, else the one at `offset`."""
    sel = rows if others else [r for r in rows if r[OURS]]
    if addr:
        sel = [r for r in sel if addr in (r[SRC], r[DST], r[NSRC], r[NDST])]
    if retries:
        sel = [r for r in sel if r[RETRY]]
    if q:
        sel = [r for r in sel if q in _text(r, names)]
    idx = None
    if around_n is not None:
        idx = next((i for i, r in enumerate(sel) if r[N] >= around_n), len(sel) - 1)
    elif at_ts is not None:
        idx = next((i for i, r in enumerate(sel) if r[TS] >= at_ts), len(sel) - 1)
    if idx is not None:
        offset = max(0, (idx // limit) * limit)
    return {"total": len(sel), "offset": offset, "rows": [as_dict(r, names) for r in sel[offset : offset + limit]],
            "focus": sel[idx][N] if idx is not None and 0 <= idx < len(sel) else None}
