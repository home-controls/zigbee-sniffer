"""tshark jobs: what only the network key can show.

NWK commands travel encrypted, so leaves, rejoins, route errors (Network Status), route
discovery and the routers' Link Status (each router's neighbour table with the link cost in
both directions, every 15 s) are read by tshark, which decrypts them with the key from
tshark's key table (see names.write_tshark_keys). Three jobs:

- `events`: a stretch of a capture file -> events, NWK command counts, link costs
- `columns`: a few frames -> tshark's protocol and summary columns (the Live page)
- `detail`: one frame -> tshark's full protocol tree and hex dump
"""

import asyncio
import collections
import logging
import os
import re
import tempfile
from pathlib import Path

import pcap

log = logging.getLogger("tshark")

NWK_STATUS = {
    0x00: "no route available", 0x01: "tree link failure", 0x02: "link failure", 0x03: "low battery",
    0x04: "no routing capacity", 0x05: "no indirect capacity", 0x06: "indirect transaction expired",
    0x07: "target device unavailable", 0x08: "target address unallocated", 0x09: "parent link failure",
    0x0A: "validate route", 0x0B: "source route failure", 0x0C: "many-to-one route failure",
    0x0D: "address conflict", 0x0E: "verify addresses", 0x0F: "PAN ID update", 0x10: "network address update",
    0x11: "bad frame counter", 0x12: "bad key sequence number",
}
# NWK command id -> counter name in the history
CMD_NAMES = {1: "route_request", 2: "route_reply", 3: "network_status", 4: "leave", 5: "route_record",
             6: "rejoin_request", 7: "rejoin_response", 8: "link_status", 9: "network_report",
             10: "network_update", 11: "ed_timeout_request", 12: "ed_timeout_response"}

EVENT_FIELDS = [
    "frame.number", "frame.time_epoch", "wpan.src16", "zbee_nwk.src", "zbee_nwk.dst", "zbee_nwk.seqno",
    "zbee_nwk.src64", "zbee_nwk.cmd.id", "zbee_nwk.cmd.status", "zbee_nwk.cmd.addr", "zbee_nwk.cmd.route.dest",
    "zbee_nwk.cmd.route.opts.many2one", "zbee_nwk.cmd.leave.rejoin", "zbee_nwk.cmd.leave.request",
    "zbee_nwk.cmd.rejoin_status", "zbee_nwk.cmd.link.address", "zbee_nwk.cmd.link.incoming_cost",
    "zbee_nwk.cmd.link.outgoing_cost", "zbee_aps.zdp_cluster", "zbee_zdp.nwk_addr", "zbee_zdp.ext_addr",
    "zbee_aps.cluster", "zbee_zcl_general.ota.cmd.srv_rx.id", "zbee_zcl_general.ota.cmd.srv_tx.id",
    "zbee_zcl_general.ota.status", "zbee_zcl_general.ota.file.offset", "zbee_zcl_general.ota.image.size",
    "zbee_zcl_general.ota.data_size", "zbee_zcl_general.ota.file.version", "_ws.col.info",
]
_INFO_ALIASES = {"_ws.col.info": "_ws.col.Info", "_ws.col.protocol": "_ws.col.Protocol"}
DEDUP_S = 30.0


def fw_version(raw) -> str:
    """A Zigbee OTA file version (32 bits: application release, build, stack release, build) as
    "1.0.43.0"; "" when there is none."""
    v = _int(raw) if raw not in (None, "") else None
    if not v:
        return ""
    return ".".join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))
OTA_CLUSTER = 0x0019
OTA_STATUS = {0x00: "success", 0x95: "aborted", 0x96: "invalid image", 0x98: "no image available",
              0x99: "more of the image needed", 0x80: "malformed command", 0x7E: "not authorized"}

# tshark prints the key it decrypted a frame with ("[Key: ...]", "[Key Label: ...]") and the key a
# Transport Key command carries. None of that may leave the app (DOCS: the key is never shown).
_REDACT = [
    (re.compile(r"(\[Key: )[^\]\n]*(\])"), r"\1hidden\2"),
    (re.compile(r"(\[Key Label: )[^\]\n]*(\])"), r"\1hidden\2"),
    (re.compile(r"^(\s*Key: )(?:[0-9a-fA-F]{2}[:\s]?){16}\s*$", re.M), r"\1hidden"),
    (re.compile(r'("(?:zbee\.sec\.key|zbee\.sec\.decryption_key|zbee_aps\.cmd\.key)(?:_raw)?"\s*:\s*)'
                r'(\[[^\]]*\]|"[^"]*")'), r'\1"hidden"'),
]
_DECRYPTED_HEX = re.compile(r"^Decrypted .*\(\d+ bytes?\):\s*$")
_HEX_LINE = re.compile(r"^[0-9a-f]{4}\s")


def redact(text: str) -> str:
    """tshark's text or JSON with every key replaced by "hidden"."""
    for pattern, repl in _REDACT:
        text = pattern.sub(repl, text)
    if "Transport Key" in text:  # its decrypted payload holds a key: drop that hex dump too
        out, skip = [], False
        for line in text.splitlines(keepends=True):
            if _DECRYPTED_HEX.match(line):
                skip = True
                out.append(line.rstrip("\r\n") + " (hidden: it carries a key)\n")
                continue
            if skip and _HEX_LINE.match(line):
                continue
            skip = False
            out.append(line)
        text = "".join(out)
    return text


def _short(v: str) -> str:
    """tshark's 16-bit address ("0x1234" or "4660") as 0x1234."""
    v = (v or "").split(",")[0].strip()
    if not v:
        return ""
    try:
        return f"0x{int(v, 0):04x}"
    except ValueError:
        return ""


def _int(v: str) -> int | None:
    v = (v or "").split(",")[0].strip()
    try:
        return int(v, 0)
    except ValueError:
        return None


def _bool(v: str) -> bool:
    v = (v or "").split(",")[0].strip().lower()
    if v in ("true", "yes"):
        return True
    try:
        return int(v, 0) != 0
    except ValueError:
        return False


def _eui(v: str) -> str:
    """tshark's EUI-64 (00:11:...) as 0x0011..."""
    v = (v or "").split(",")[0].strip().replace(":", "").replace("-", "").lower()
    return "0x" + v if len(v) == 16 else ""


class Tshark:
    def __init__(self, home: Path, enabled: bool = True, binary: str | None = None) -> None:
        self.home = home
        self.enabled = enabled
        self.binary = binary or os.environ.get("TSHARK", "tshark")
        self.bad_fields: set[str] = set()
        self._bg = asyncio.Semaphore(1)  # the history's decode pass: one at a time
        self._fg = asyncio.Semaphore(3)  # someone is waiting on the page: never queued behind the pass
        self._seen: dict[tuple, float] = {}  # (nwk src, nwk seq, kind) -> ts: one count per broadcast, however many relays
        self._seen_q: collections.deque = collections.deque()  # (ts, key) in arrival order, for pruning
        self._ota_last: dict[tuple[str, str], float] = {}  # (addr, kind) -> ts of the last OTA event
        self.last_error = ""

    async def _spawn(self, args: list[str], stderr) -> asyncio.subprocess.Process | None:
        try:
            return await asyncio.create_subprocess_exec(
                self.binary, *args, stdout=asyncio.subprocess.PIPE, stderr=stderr,
                env=dict(os.environ, HOME=str(self.home)))
        except OSError as e:  # no tshark binary (or it can't run): the pages say so instead of failing
            self.last_error = f"can't run {self.binary}: {e}"
            log.warning(self.last_error)
            return None

    async def run(self, args: list[str], timeout: float = 300, background: bool = False) -> tuple[int, str, str]:
        async with self._bg if background else self._fg:
            proc = await self._spawn(args, asyncio.subprocess.PIPE)
            if proc is None:
                return -2, "", self.last_error
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return -1, "", "timed out"
            if proc.returncode == 0:
                self.last_error = ""
            return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    async def fields(self, path: Path, fields: list[str], dfilter: str = "", occurrence: str = "a",
                     background: bool = False, timeout: float = 300) -> list[dict] | None:
        """One dict per frame with the fields tshark knows (unknown ones are dropped and remembered).
        None when tshark failed (timed out, crashed, missing): the caller must not take that as
        "no frames"."""
        for _ in range(3):
            use = [f for f in fields if f not in self.bad_fields]
            args = ["-n", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", f"occurrence={occurrence}",
                    "-E", "aggregator=,", "-E", "quote=n"]
            if dfilter:
                args += ["-Y", dfilter]
            for f in use:
                args += ["-e", f]
            rc, out, err = await self.run(args, timeout=timeout, background=background)
            if "aren't valid" in err or "not valid" in err:
                bad = set(re.findall(r"^\s+(\S+)\s*$", err, re.M))
                if not bad - self.bad_fields:
                    break
                log.info("tshark doesn't know %s", ", ".join(sorted(bad)))
                self.bad_fields |= bad
                for b in bad:  # older tshark spells the columns with a capital
                    alias = _INFO_ALIASES.get(b)
                    if alias and alias not in fields:
                        fields = [alias if f == b else f for f in fields]
                continue
            if rc != 0 and (rc < 0 or not out):
                self.last_error = (err.strip() or f"exit {rc}")[:300]
                log.warning("tshark failed on %s: %s", path.name, self.last_error)
                return None
            rows = []
            for line in out.splitlines():
                vals = line.split("\t")
                row = dict(zip(use, vals))
                for orig, alias in _INFO_ALIASES.items():
                    if alias in row:
                        row[orig] = row.pop(alias)
                rows.append(row)
            return rows
        self.last_error = "tshark rejected the field list"
        return None

    # ------------------------------------------------------------ events

    async def events(self, path: Path, rel: str, start: int, end: int, first_frame: int, our_pan: int | None):
        """Events, NWK command counts, link costs and firmware-update blocks in the records between
        two byte offsets (`first_frame` is the number, in its file, of the first one). None when
        tshark failed, so the stretch is tried again instead of being marked done."""
        if not self.enabled:
            return [], {}, {}, {}
        with tempfile.TemporaryDirectory(prefix="zbs-") as tmp:
            chunk = Path(tmp) / "chunk.pcap"
            await asyncio.to_thread(pcap.copy_chunk, path, chunk, start, end)
            dfilter = f"(zbee_nwk.cmd.id || zbee_aps.zdp_cluster == 0x0013 || zbee_aps.cluster == 0x{OTA_CLUSTER:04x})"
            if our_pan is not None:
                dfilter += f" && wpan.dst_pan == 0x{our_pan:04x}"
            rows = await self.fields(chunk, EVENT_FIELDS, dfilter, background=True)
        if rows is None:
            return None
        return await asyncio.to_thread(self._digest, rows, rel, first_frame)

    def _ota(self, r: dict, ts: float, nsrc: str, ndst: str, seq, event, ota: dict) -> None:
        """A frame of the OTA Upgrade cluster: count image blocks per device and per minute (with the
        lowest and highest file offset and the image size: progress, and where a resumed download
        picked up), and note offers, starts and ends with the image's file version."""
        rx = _int(r.get("zbee_zcl_general.ota.cmd.srv_rx.id", ""))  # device -> server
        tx = _int(r.get("zbee_zcl_general.ota.cmd.srv_tx.id", ""))  # server -> device
        status = _int(r.get("zbee_zcl_general.ota.status", ""))
        minute = int(ts // 60) * 60

        def once(addr, kind, gap=600.0) -> bool:
            last = self._ota_last.get((addr, kind))
            self._ota_last[(addr, kind)] = ts
            return last is None or ts - last > gap

        if tx == 0x05 and status in (0, None):  # Image Block Response: one block of the image to the device
            off = _int(r.get("zbee_zcl_general.ota.file.offset", "")) or 0
            size = _int(r.get("zbee_zcl_general.ota.data_size", "")) or 0
            if not self._first(nsrc, seq, "ota_block", ts, f"{ndst}:{off}"):
                return  # the same block relayed by the next router
            rec = ota.setdefault((minute, ndst), [0, 0, 0, None])
            rec[0] += 1
            rec[1] = max(rec[1], off + size)
            rec[3] = off if rec[3] is None else min(rec[3], off)
            if once(ndst, "block"):
                event("ota_start", ndst, nsrc, "", "firmware download started" + (f" at {off // 1024} KB" if off else ""))
        elif tx == 0x02 and status == 0:  # Query Next Image Response: an image is on offer
            if not self._first(nsrc, seq, "ota_offer", ts):
                return
            size = _int(r.get("zbee_zcl_general.ota.image.size", "")) or 0
            if size:
                rec = ota.setdefault((minute, ndst), [0, 0, 0, None])
                rec[2] = size
            if once(ndst, "offer"):
                ver = fw_version(r.get("zbee_zcl_general.ota.file.version", ""))
                event("ota_offer", ndst, nsrc, "", "offered firmware" + (f" {ver}" if ver else "")
                      + (f" ({size // 1024} KB)" if size else ""))
        elif rx == 0x06:  # Upgrade End Request: the device finished (or gave up on) the download
            if not self._first(nsrc, seq, "ota_end", ts):
                return
            if status == 0:
                ver = fw_version(r.get("zbee_zcl_general.ota.file.version", ""))
                event("ota_done", nsrc, ndst, "", "firmware" + (f" {ver}" if ver else "")
                      + " downloaded; the device installs it and restarts")
            else:
                text = OTA_STATUS.get(status, f"status 0x{status:02x}" if status is not None else "no status")
                event("ota_failed", nsrc, ndst, "", f"firmware download ended: {text}")
        elif rx == 0x03:  # Image Block Request: keeps "updating" alive for devices whose responses we miss
            if not self._first(nsrc, seq, "ota_req", ts):
                return
            rec = ota.setdefault((minute, nsrc), [0, 0, 0, None])
            off = _int(r.get("zbee_zcl_general.ota.file.offset", "")) or 0
            rec[1] = max(rec[1], off)

    def _digest(self, rows: list[dict], rel: str, first_frame: int):
        events: list[dict] = []
        cmds: dict[tuple[int, str, str], int] = {}
        links: dict[tuple[int, str, str], list] = {}
        ota: dict[tuple[int, str], list] = {}  # (minute, device) -> [blocks, highest offset, image size, lowest block offset]
        for r in rows:
            try:
                ts = float(r.get("frame.time_epoch") or 0)
                n = first_frame + int(r.get("frame.number") or 1) - 1
            except ValueError:
                continue
            nsrc, ndst = _short(r.get("zbee_nwk.src", "")), _short(r.get("zbee_nwk.dst", ""))
            seq = _int(r.get("zbee_nwk.seqno", ""))
            info = (r.get("_ws.col.info") or "").strip()
            cmd = _int(r.get("zbee_nwk.cmd.id", ""))
            minute = int(ts // 60) * 60

            def event(kind, addr, other="", ieee="", detail=""):
                events.append({"ts": ts, "kind": kind, "addr": addr, "other": other, "ieee": ieee,
                               "detail": detail or info, "file": rel, "n": n})

            if cmd is None:
                if _int(r.get("zbee_aps.cluster", "")) == OTA_CLUSTER:
                    self._ota(r, ts, nsrc, ndst, seq, event, ota)
                elif _int(r.get("zbee_aps.zdp_cluster", "")) == 0x0013 and self._first(nsrc, seq, "announce", ts):
                    addr = _short(r.get("zbee_zdp.nwk_addr", "")) or nsrc
                    event("announce", addr, "", _eui(r.get("zbee_zdp.ext_addr", "")),
                          "announced itself (joined, rejoined or power-cycled)")
                continue
            if cmd == 8:  # Link Status: one per router every 15 s, never relayed
                hour = int(ts // 3600) * 3600
                addrs = [a for a in (r.get("zbee_nwk.cmd.link.address") or "").split(",") if a]
                ins = (r.get("zbee_nwk.cmd.link.incoming_cost") or "").split(",")
                outs = (r.get("zbee_nwk.cmd.link.outgoing_cost") or "").split(",")
                for i, a in enumerate(addrs):
                    c_in, c_out = _int(ins[i] if i < len(ins) else ""), _int(outs[i] if i < len(outs) else "")
                    if c_in is None or c_out is None:
                        continue
                    key = (hour, nsrc, _short(a))
                    rec = links.get(key)
                    if rec is None:
                        links[key] = [1, c_in, c_out, ts, c_in, c_out]
                    else:
                        rec[0] += 1
                        rec[1] += c_in
                        rec[2] += c_out
                        if ts >= rec[3]:
                            rec[3:] = [ts, c_in, c_out]
                name = "link_status"
            elif cmd == 1 and _bool(r.get("zbee_nwk.cmd.route.opts.many2one", "")):
                name = "mto_route_request"  # a concentrator (the coordinator) refreshing routes to itself
            else:
                name = CMD_NAMES.get(cmd, f"nwk_cmd_{cmd}")
            if cmd != 8 and not self._first(nsrc, seq, name, ts, ndst):
                continue  # a relay of a broadcast already counted
            cmds[(minute, nsrc, name)] = cmds.get((minute, nsrc, name), 0) + 1

            if cmd == 3:
                code = _int(r.get("zbee_nwk.cmd.status", ""))
                target = _short(r.get("zbee_nwk.cmd.route.dest", "")) or _short(r.get("zbee_nwk.cmd.addr", ""))
                text = NWK_STATUS.get(code, f"status 0x{code:02x}" if code is not None else "network status")
                if code == 0x0C:
                    # Many-to-one route failure: the reporter couldn't pass a frame from `target` up toward
                    # the concentrator (the coordinator). The trouble is the reporter's uplink, not `target`.
                    event("route_failure_up", nsrc, target, "",
                          f"couldn't forward {target or 'a device'}'s traffic toward the coordinator (many-to-one route failure)")
                elif code == 0x0D:
                    event("address_conflict", target or ndst, nsrc, "", f"address conflict (reported by {nsrc})")
                elif code == 0x11:
                    event("bad_frame_counter", target or ndst, nsrc, "",
                          f"sent a frame with a stale security frame counter (reported by {nsrc})")
                else:
                    event("network_status", target or ndst, nsrc, "", f"{text} (reported by {nsrc})")
            elif cmd == 4:
                if _bool(r.get("zbee_nwk.cmd.leave.request", "")):
                    event("leave", ndst, nsrc, "", f"was told to leave by {nsrc}")
                else:
                    rejoin = _bool(r.get("zbee_nwk.cmd.leave.rejoin", ""))
                    event("leave", nsrc, "", _eui(r.get("zbee_nwk.src64", "")),
                          "left the network" + (" (will rejoin)" if rejoin else ""))
            elif cmd == 6:
                event("rejoin", nsrc, ndst, _eui(r.get("zbee_nwk.src64", "")), f"asked {ndst} to rejoin")
            elif cmd == 7:
                status = _int(r.get("zbee_nwk.cmd.rejoin_status", ""))
                new = _short(r.get("zbee_nwk.cmd.addr", ""))
                if status in (0, None):
                    event("rejoin_response", new or ndst, nsrc, "", f"rejoined through {nsrc}" + (f", address {new}" if new else ""))
                else:
                    event("rejoin_response", ndst, nsrc, "", f"rejoin refused by {nsrc} (status {status})")
            elif cmd in (9, 10):
                event("network_report" if cmd == 9 else "network_update", nsrc, ndst)
            elif cmd == 11:
                event("ed_timeout", nsrc, ndst, "", f"(re)attached to parent {ndst}")
        return events, cmds, links, ota

    def _first(self, src: str, seq: int | None, kind: str, ts: float, extra: str = "") -> bool:
        """True the first time a message is heard: relays repeat it with the same NWK source and
        sequence (`extra` narrows it further: the destination, an OTA block's offset). The window
        runs from the first sighting; later sightings don't extend it, or a busy source whose
        sequence wraps every 256 messages would stop being counted."""
        if seq is None:
            return True
        key = (src, seq, kind, extra)
        last = self._seen.get(key)
        if last is not None and abs(ts - last) <= DEDUP_S:
            return False
        self._seen[key] = ts
        self._seen_q.append((ts, key))
        while self._seen_q and (ts - self._seen_q[0][0] > DEDUP_S or len(self._seen_q) > 200000):
            old_ts, old = self._seen_q.popleft()
            if self._seen.get(old) == old_ts:
                del self._seen[old]
        return True

    # ------------------------------------------------------------ the pages

    async def columns(self, records: list[tuple[float, bytes]]) -> list[tuple[str, str]]:
        """tshark's protocol and summary for each (timestamp, packet)."""
        if not self.enabled or not records:
            return []
        with tempfile.TemporaryDirectory(prefix="zbs-") as tmp:
            path = Path(tmp) / "live.pcap"
            await asyncio.to_thread(pcap.write_file, path, records)
            rows = await self.fields(path, ["_ws.col.protocol", "_ws.col.info"], occurrence="f", timeout=60)
        return [(r.get("_ws.col.protocol", ""), r.get("_ws.col.info", "")) for r in rows or []]

    async def detail(self, ts: float, packet: bytes) -> str:
        """tshark's protocol tree and hex dump of one frame (decrypted, keys hidden)."""
        if not self.enabled:
            return "Decoding is off (the app's `decode` option)."
        with tempfile.TemporaryDirectory(prefix="zbs-") as tmp:
            path = Path(tmp) / "frame.pcap"
            await asyncio.to_thread(pcap.write_file, path, [(ts, packet)])
            rc, out, err = await self.run(["-n", "-r", str(path), "-V", "-x"], timeout=30)
        return redact(out) if out else (err or "tshark printed nothing")

    async def stream(self, args: list[str]):
        """tshark's output in chunks as it comes (a whole capture decoded can be large), whole lines
        at a time so the keys can be hidden."""
        async with self._fg:
            proc = await self._spawn(args, asyncio.subprocess.DEVNULL)
            if proc is None:
                yield f"tshark isn't available: {self.last_error}\n".encode()
                return
            buf = b""
            try:
                while chunk := await proc.stdout.read(1 << 16):
                    buf += chunk
                    cut = buf.rfind(b"\n") + 1
                    if cut:
                        yield redact(buf[:cut].decode("utf-8", "replace")).encode()
                        buf = buf[cut:]
                if buf:
                    yield redact(buf.decode("utf-8", "replace")).encode()
            finally:
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
