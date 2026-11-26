"""pcap files in LINKTYPE_IEEE802_15_4_TAP (283): each frame carries RSSI, LQI and channel.

Wireshark shows those as columns/fields; the 802.15.4 frame itself has no FCS (the radio
checked it and replaced it with RSSI/LQI), which the TAP header says (FCS type 0).
"""

import array
import collections
import os
import re
import shutil
import struct
import threading
import time
from pathlib import Path

LINKTYPE_IEEE802_15_4_TAP = 283
GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_IEEE802_15_4_TAP)

TLV_FCS_TYPE = 0
TLV_RSS = 1
TLV_CHANNEL = 3
TLV_LQI = 10

MOVING = ".moving"  # suffix of a file half-way through rename_to_local_time
# Next to each capture (with several sniffers): which sniffers heard each frame and how loud, one
# line per frame number, "n sniffer:rssi sniffer:rssi". A copy that arrived after its frame was
# written adds another line for the same number. The pcap itself has room for one RSSI only.
COPIES = ".sniffers"
DAY_DIR = re.compile(r"\d{4}-\d{2}-\d{2}")


def capture_files(base: Path, pattern: str = "*.pcap") -> list[Path]:
    """The capture files: <base>/YYYY-MM-DD/<pattern>. Any other folder (.analysis, a backup set
    aside by hand) holds no captures: 0.6.3 took a backup folder's copy of an hour for a misnamed
    capture at startup and appended it to that hour's file (rename_to_local_time)."""
    return [f for f in base.glob(f"*/{pattern}") if DAY_DIR.fullmatch(f.parent.name)]


def _tlv(tlv_type: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", tlv_type, len(value)) + value + b"\0" * pad


def tap_packet(psdu: bytes, channel: int, rssi: int, lqi: int) -> bytes:
    tlvs = (
        _tlv(TLV_FCS_TYPE, b"\x00")
        + _tlv(TLV_RSS, struct.pack("<f", float(rssi)))
        + _tlv(TLV_CHANNEL, struct.pack("<HB", channel, 0))
        + _tlv(TLV_LQI, bytes([lqi & 0xFF]))
    )
    return struct.pack("<BBH", 0, 0, 4 + len(tlvs)) + tlvs + psdu


def record(ts: float, data: bytes) -> bytes:
    sec = int(ts)
    usec = int(round((ts - sec) * 1_000_000))
    if usec >= 1_000_000:
        sec, usec = sec + 1, usec - 1_000_000
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


def parse_tap(data: bytes) -> tuple[int, int, int, bytes]:
    """(channel, rssi, lqi, psdu) of one TAP packet."""
    (tap_len,) = struct.unpack_from("<H", data, 2)
    channel, rssi, lqi = 0, 0, 0
    pos = 4
    while pos + 4 <= tap_len:
        t, ln = struct.unpack_from("<HH", data, pos)
        val = data[pos + 4 : pos + 4 + ln]
        if t == TLV_RSS and ln == 4:
            rssi = round(struct.unpack("<f", val)[0])
        elif t == TLV_CHANNEL and ln >= 2:
            (channel,) = struct.unpack_from("<H", val)
        elif t == TLV_LQI and ln >= 1:
            lqi = val[0]
        pos += 4 + ln + ((-ln) % 4)
    return channel, rssi, lqi, data[tap_len:]


def iter_records(path: Path, offset: int = 0, limit: int | None = None):
    """(end offset, timestamp, packet) for each complete record from byte `offset` (0 or the
    header's end: the first record) up to `limit` bytes into the file."""
    with open(path, "rb") as f:
        if f.read(len(GLOBAL_HEADER))[:4] != GLOBAL_HEADER[:4]:
            return
        offset = max(offset, len(GLOBAL_HEADER))
        f.seek(offset)
        while limit is None or offset + 16 <= limit:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            sec, usec, incl, _ = struct.unpack("<IIII", hdr)
            if incl > 65535 or (limit is not None and offset + 16 + incl > limit):
                return
            data = f.read(incl)
            if len(data) < incl:
                return
            offset += 16 + incl
            yield offset, sec + usec / 1e6, data


def read_tap_meta(path: Path) -> list[tuple[float, int, int, int, bytes]]:
    """(timestamp, channel, rssi, lqi, psdu) for every packet in one of our files."""
    return [(ts, *parse_tap(data)) for _, ts, data in iter_records(path)]


def scan(path: Path) -> tuple[int, int]:
    """(frames, end of the last complete record) of a capture file."""
    frames, end = 0, len(GLOBAL_HEADER)
    for end, _, _ in iter_records(path):
        frames += 1
    return frames, end


_index: "collections.OrderedDict[str, tuple[array.array, int]]" = collections.OrderedDict()  # path -> (record starts, bytes indexed)
_index_lock = threading.Lock()


def read_record(path: Path, n: int) -> tuple[float, bytes] | None:
    """Record number `n` (1-based, as in Wireshark) of a capture file. Where each record starts is
    remembered (and extended as the file grows), so this doesn't scan the file every time."""
    key = str(path)
    with _index_lock:
        starts, done = _index.pop(key, (array.array("Q"), len(GLOBAL_HEADER)))
        size = path.stat().st_size
        if size < done:
            starts, done = array.array("Q"), len(GLOBAL_HEADER)
        if n > len(starts) and size > done:
            prev = done
            for end, _, _ in iter_records(path, done):
                starts.append(prev)
                prev = end
            done = prev
        _index[key] = (starts, done)
        while len(_index) > 6:
            _index.popitem(last=False)
    if not 1 <= n <= len(starts):
        return None
    with open(path, "rb") as f:
        f.seek(starts[n - 1])
        hdr = f.read(16)
        if len(hdr) < 16:
            return None
        sec, usec, incl, _ = struct.unpack("<IIII", hdr)
        data = f.read(incl)
    return (sec + usec / 1e6, data) if len(data) == incl else None


def chunk_end(path: Path, start: int, end: int, max_bytes: int) -> tuple[int, int | None]:
    """Where a stretch of at most `max_bytes` from `start` ends on a record boundary, and how many
    records it holds (None when the whole stretch up to `end` fits)."""
    if end - start <= max_bytes:
        return end, None
    last, n = start, 0
    for last, _, _ in iter_records(path, start, start + max_bytes):
        n += 1
    return last, n


def write_file(path: Path, records) -> int:
    """A capture file of (timestamp, packet) records; returns how many."""
    count = 0
    with open(path, "wb") as f:
        f.write(GLOBAL_HEADER)
        for ts, data in records:
            f.write(record(ts, data))
            count += 1
    return count


def copy_chunk(src: Path, dst: Path, start: int, end: int) -> None:
    """Records between two byte offsets of a capture file, as a capture file of their own."""
    with open(src, "rb") as f, open(dst, "wb") as out:
        out.write(GLOBAL_HEADER)
        f.seek(max(start, len(GLOBAL_HEADER)))
        remaining = end - max(start, len(GLOBAL_HEADER))
        while remaining > 0:
            buf = f.read(min(remaining, 1 << 20))
            if not buf:
                break
            out.write(buf)
            remaining -= len(buf)


def copies_path(path: Path) -> Path:
    return path.with_name(path.name + COPIES)


def parse_copies(lines, out: dict[int, list[tuple[str, int]]]) -> None:
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            n = int(parts[0])
        except ValueError:
            continue
        got = out.setdefault(n, [])
        for p in parts[1:]:
            sid, _, r = p.rpartition(":")
            try:
                if sid and not any(g[0] == sid for g in got):
                    got.append((sid, int(r)))
            except ValueError:
                pass


_copies: "collections.OrderedDict[str, tuple[int, dict]]" = collections.OrderedDict()  # path -> (bytes read, copies)
_copies_lock = threading.Lock()


def read_copies(path: Path) -> dict[int, list[tuple[str, int]]]:
    """Frame number -> [(sniffer, rssi)] for a capture (empty without a .sniffers file). Read
    incrementally: the file being written only grows."""
    side, key = copies_path(path), str(path)
    try:
        size = side.stat().st_size
    except OSError:
        return {}
    with _copies_lock:
        done, out = _copies.pop(key, (0, {}))
        if size < done:
            done, out = 0, {}
        if size > done:
            with open(side, "rb") as f:
                f.seek(done)
                chunk = f.read(size - done)
            cut = chunk.rfind(b"\n") + 1  # whole lines only (one may be half written)
            parse_copies(chunk[:cut].decode("ascii", "replace").splitlines(), out)
            done += cut
        _copies[key] = (done, out)
        while len(_copies) > 3:
            _copies.popitem(last=False)
    return out


def path_for(base: Path, ts: float) -> Path:
    """<base>/YYYY-MM-DD/zigbee_YYYY-MM-DD_HH.pcap for the local hour of `ts`."""
    lt = time.localtime(ts)
    return base / time.strftime("%Y-%m-%d", lt) / f"zigbee_{time.strftime('%Y-%m-%d_%H', lt)}.pcap"


def first_timestamp(path: Path) -> float | None:
    """When the first frame in a capture file was heard (None for an empty or foreign file)."""
    with open(path, "rb") as f:
        head = f.read(len(GLOBAL_HEADER) + 8)
    if len(head) < len(GLOBAL_HEADER) + 8 or head[:4] != GLOBAL_HEADER[:4]:
        return None
    sec, usec = struct.unpack_from("<II", head, len(GLOBAL_HEADER))
    return sec + usec / 1e6


def rename_to_local_time(base: Path) -> list[tuple[str, str, int | None]]:
    """Give every capture file the name of the local hour its first frame is from.

    0.1.0 ran without time-zone data, so it named files by UTC hour. Two passes: every
    misnamed file is first set aside, then moved to its hour, so a name freed by one move can
    take the next. If the hour's file exists already (the hour repeats when clocks go back),
    the frames are appended to it. Returns (old, new, where the appended records start in `new`
    or None when the file was simply moved), relative paths.
    """
    pending: list[tuple[Path, Path]] = []  # (original path, set-aside path)
    for path in sorted(capture_files(base, f"zigbee_*.pcap{MOVING}")):  # left by an interrupted run
        pending.append((path.with_name(path.name[: -len(MOVING)]), path))
    for path in sorted(capture_files(base, "zigbee_*.pcap")):
        ts = first_timestamp(path)
        if ts is not None and path_for(base, ts) != path:
            aside = path.with_name(path.name + MOVING)
            path.replace(aside)
            pending.append((path, aside))
    moved = []
    for original, aside in pending:
        ts = first_timestamp(aside)
        if ts is None:
            aside.replace(original)
            continue
        target = path_for(base, ts)
        target.parent.mkdir(parents=True, exist_ok=True)
        appended_at = None
        if target.exists():
            _, appended_at = scan(target)
            os.truncate(target, appended_at)
            with open(aside, "rb") as src, open(target, "ab") as dst:
                src.seek(len(GLOBAL_HEADER))
                shutil.copyfileobj(src, dst)
            aside.unlink()
        else:
            aside.replace(target)
        moved.append((str(original.relative_to(base)).replace("\\", "/"),
                      str(target.relative_to(base)).replace("\\", "/"), appended_at))
    for d in base.iterdir():
        if d.is_dir() and not d.name.startswith(".") and not any(d.iterdir()):
            shutil.rmtree(d, ignore_errors=True)
    return moved


class RotatingPcap:
    """One file per local hour: <base>/YYYY-MM-DD/zigbee_YYYY-MM-DD_HH.pcap.

    A few hour files stay open at once: frames a sniffer buffered during a Wi-Fi drop can belong
    to the previous hour while another sniffer is live in this one. `write` says where each frame
    went (file, frame number, end offset), so the history knows how far each file is counted and
    the pages can point back at the frame in its file."""

    MAX_OPEN = 3

    def __init__(self, base: Path) -> None:
        self.base = base
        self.base.mkdir(parents=True, exist_ok=True)
        self._open: dict[Path, dict] = {}  # path -> {"f", "frames", "size"}, least recently written first
        self._known: dict[Path, tuple[int, int]] = {}  # files we closed -> (frames, bytes), to reopen without a rescan
        self._side: dict[Path, object] = {}  # capture -> its open .sniffers file, least recently written first
        self._last_flush = 0.0
        self.current: Path | None = None  # the newest hour written to

    @property
    def rel(self) -> str:
        return self._rel(self.current) if self.current else ""

    def _rel(self, path: Path) -> str:
        return str(path.relative_to(self.base)).replace("\\", "/")

    def _get(self, path: Path) -> dict:
        st = self._open.pop(path, None)
        if st is None:
            while len(self._open) >= self.MAX_OPEN:
                self._close(next(iter(self._open)))
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size >= len(GLOBAL_HEADER):
                # Carry on after the last complete record (a crash can leave half of one).
                known = self._known.get(path)
                frames, end = known if known and known[1] == path.stat().st_size else scan(path)
                if path.stat().st_size != end:
                    os.truncate(path, end)
                    self._trim_copies(path, frames)
                st = {"f": open(path, "ab"), "frames": frames, "size": end}
            else:
                f = open(path, "wb")
                f.write(GLOBAL_HEADER)
                st = {"f": f, "frames": 0, "size": len(GLOBAL_HEADER)}
        self._open[path] = st
        return st

    def write(self, ts: float, packet: bytes) -> tuple[str, int, int]:
        """Append a frame; returns (file, frame number, byte offset where its record ends)."""
        path = path_for(self.base, ts)
        st = self._get(path)
        rec = record(ts, packet)
        st["f"].write(rec)
        st["frames"] += 1
        st["size"] += len(rec)
        if self.current is None or path > self.current:
            self.current = path
        now = time.monotonic()
        if now - self._last_flush > 1.0:
            self.flush()
        return self._rel(path), st["frames"], st["size"]

    def write_copies(self, rel: str, n: int, copies) -> None:
        """Which sniffers heard frame `n` of capture `rel` (all of them, or one more that came late)."""
        if not rel or not copies:
            return
        path = self.base / rel
        f = self._side.pop(path, None)
        if f is None:
            while len(self._side) >= self.MAX_OPEN + 1:
                self._side.pop(next(iter(self._side))).close()
            f = open(copies_path(path), "a", encoding="ascii")
        self._side[path] = f
        f.write(f"{n} " + " ".join(f"{c[0]}:{int(c[1])}" for c in copies) + "\n")

    def _trim_copies(self, path: Path, frames: int) -> None:
        """The capture was cut back to its last whole record (a crash): drop the lines about frames it
        no longer has, or the numbers written next would inherit them."""
        side = copies_path(path)
        if not side.exists():
            return
        f = self._side.pop(path, None)
        if f:
            f.close()
        keep = [ln for ln in side.read_text(encoding="ascii", errors="replace").splitlines()
                if ln.split(" ", 1)[0].isdigit() and int(ln.split(" ", 1)[0]) <= frames]
        side.write_text("".join(ln + "\n" for ln in keep), encoding="ascii")

    def flush(self) -> None:
        for st in self._open.values():
            st["f"].flush()
        for f in self._side.values():
            f.flush()
        self._last_flush = time.monotonic()

    def _close(self, path: Path) -> None:
        st = self._open.pop(path)
        st["f"].flush()
        os.fsync(st["f"].fileno())
        st["f"].close()
        self._known[path] = (st["frames"], st["size"])
        while len(self._known) > 48:
            self._known.pop(next(iter(self._known)))
        f = self._side.pop(path, None)
        if f:
            f.close()

    def close(self) -> None:
        for path in list(self._open):
            self._close(path)
        for f in self._side.values():
            f.close()
        self._side.clear()
