"""Zigbee Sniffer app: collect frames from one or more sniffer bridges, store them, keep a history,
draw coverage maps, and serve the web page."""

import asyncio
import collections
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path

from aiohttp import web

import analysis
import bridge as bridge_mod
import decode
import hass as hass_mod
import mac
import mapping
import merge
import names as names_mod
import pcap
import proto
import recount
import report
import studio
from carryover import carry_over
from sniffers import H_HEARD, H_SOLO, H_TOTAL, Sniffer, slug
from usb import UsbSniffer
from store import Store
from tshark import Tshark


def setup_timezone() -> str:
    """Run in Home Assistant's time zone, so capture files and log lines carry local time.

    Supervisor passes the zone as TZ; the C library needs tzdata to read it (0.1.0's image had
    none and ran in UTC). Without TZ, fall back to Home Assistant's own setting.
    """
    tz = os.environ.get("TZ", "").strip()
    if not tz:
        try:
            tz = json.loads(Path("/homeassistant/.storage/core.config").read_text())["data"]["time_zone"]
        except (OSError, ValueError, KeyError, TypeError):
            tz = ""
    if tz:
        os.environ["TZ"] = tz
        if hasattr(time, "tzset"):
            time.tzset()
    return tz


TIME_ZONE = setup_timezone()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sniffer")

DATA_DIR = Path(os.environ.get("SNIFFER_DATA", "/data"))
# What the same add-on had when installed from the old store (history, floor maps, channel, ...):
# before anything below opens /data (see carryover.py)
carry_over(Path(os.environ.get("SNIFFER_CARRY", "/share/zigbee_sniffer/carry-over")), DATA_DIR)
CAPTURE_DIR = Path(os.environ.get("SNIFFER_CAPTURES", "/share/zigbee_captures"))
OPTIONS = json.loads((DATA_DIR / "options.json").read_text()) if (DATA_DIR / "options.json").exists() else {}
CHANNEL = int(OPTIONS.get("channel", 25))
RETENTION_DAYS = int(OPTIONS.get("retention_days", 7))
MAX_STORAGE_MB = int(OPTIONS.get("max_storage_mb", 2000))
USE_TSHARK = bool(OPTIONS.get("decode", True))
UPDATE_TOKEN = (OPTIONS.get("update_token") or "").strip()  # the bridges' CONFIG_BRIDGE_UPDATE_TOKEN
PUBLISH_HA = bool(OPTIONS.get("publish_to_ha", True))
DEVICE_SENSORS = bool(OPTIONS.get("device_sensors", True))
ZIGBEE_STUDIO = bool(OPTIONS.get("zigbee_studio", True))  # Zigbee Studio may read and set up maps (studio.py)
VERSION = "0.7.1"  # keep in step with config.yaml (tests/test_delivery_review.py checks)
WEB_PORT = int(os.environ.get("SNIFFER_WEB_PORT", 8099))
BIND = os.environ.get("SNIFFER_BIND", "0.0.0.0")
LIVE_PORT = int(os.environ.get("SNIFFER_LIVE_PORT", 17760))  # the live Wireshark stream
# Who may use the web port: Home Assistant's ingress proxy (and this machine, for development).
# Other containers on HA's internal network can reach the port too; they get nothing.
ALLOW = {a.strip() for a in os.environ.get("SNIFFER_ALLOW", "172.30.32.2,127.0.0.1,::1").split(",") if a.strip()}
STUDIO_KEY = ""  # set in main(): the key Zigbee Studio sends for its read-only answers

TSHARK_HOME = DATA_DIR / "tshark-home"
CHANNEL_FILE = DATA_DIR / "channel.json"  # a channel picked on the Sniffer page, over the option
KNOWN_FILE = DATA_DIR / "sniffers_known.json"  # sniffers that have connected before (a new one is an event)
MOVES_FILE = DATA_DIR / "sniffer_moves.json"  # when each sniffer was last moved (its signal normals start again)
FIRMWARE_DIR = CAPTURE_DIR.parent / "zigbee_sniffer" / "firmware"  # /share/zigbee_sniffer/firmware/*.bin
STATIC = Path(__file__).parent / "static"
FLUSH_S = 30  # live counters go to the history this often (each write rewrites every device's current-minute page)
DECODE_S = 60  # the tshark pass reads new frames this often
DECODE_CHUNK = 48 * 1024 * 1024  # at most this much of a capture per tshark run (a long backlog goes in parts)
LIVE_CLIENT_BUFFER = 4 * 1024 * 1024  # a Wireshark client this far behind is dropped


def sniffer_configs() -> list[dict]:
    """The sniffers to listen through: `sniffer_host` ("main"), `more_sniffers` (bridges) and
    `usb_sniffers` (radios plugged into this box: those have a `device` instead of a host)."""
    out, ids = [], set()
    host = (OPTIONS.get("sniffer_host") or "").strip()
    more = [s for s in OPTIONS.get("more_sniffers") or [] if (s.get("host") or "").strip()]
    usb = [s for s in OPTIONS.get("usb_sniffers") or [] if (s.get("device") or "").strip()]
    if host or not (more or usb):
        out.append({"id": "main", "name": (OPTIONS.get("sniffer_name") or "Main").strip() or "Main", "host": host,
                    "port": int(OPTIONS.get("sniffer_port", 6638)),
                    "http_port": int(os.environ.get("SNIFFER_BRIDGE_HTTP_PORT", 80))})
        ids.add("main")
    for i, s in enumerate(more, 2):
        name = (s.get("name") or "").strip() or f"Sniffer {i}"
        sid = slug(name) or f"sniffer{i}"
        while sid in ids:
            sid += "_"
        ids.add(sid)
        out.append({"id": sid, "name": name, "host": s["host"].strip(), "port": int(s.get("port") or 6638),
                    "http_port": int(s.get("http_port") or 80)})
    for i, s in enumerate(usb, 1):
        name = (s.get("name") or "").strip() or ("USB sniffer" if len(usb) == 1 else f"USB sniffer {i}")
        sid = slug(name) or f"usb{i}"
        while sid in ids:
            sid += "_"
        ids.add(sid)
        out.append({"id": sid, "name": name, "device": s["device"].strip()})
    return out


def make_sniffer(c: dict) -> Sniffer:
    if c.get("device"):
        return UsbSniffer(c["id"], c["name"], c["device"], on_sniffer_frame, on_dropped, lambda: S.channel)
    return Sniffer(c["id"], c["name"], c["host"], c["port"], c["http_port"], on_sniffer_frame, on_dropped,
                   lambda: S.channel)


class State:
    def __init__(self) -> None:
        self.frames_total = 0
        self.frames_ours = 0
        self.frames_other = 0  # another network's (its PAN named)
        self.frames_unnamed = 0  # naming no network: ACKs whose frame wasn't heard, beacon requests
        self.recent: collections.deque = collections.deque(maxlen=64)  # [second, transmissions] for the rate
        self.live: collections.deque = collections.deque(maxlen=3000)
        self.live_seq = 0
        self.ack_wait: tuple | None = None  # (seq, sender, receiver, ts) of the last frame that asked for an ACK
        self.seen: dict[str, tuple] = {}  # addr -> (last heard, rssi, lqi), our network
        self.msg_seen: dict[str, float] = {}  # addr -> its last own NWK message, heard at any hop
        self.last_frame_ts = 0.0  # the last frame of our network any sniffer heard
        self.listening = False  # any sniffer connected
        self.disk_error = ""  # writing the captures failed (disk full?)
        self.disk_error_at = 0.0
        self.traces: dict[str, dict] = {}  # addr -> {"until", "frames"}: frames kept for a Ping's trace
        self.fired_incidents: set[str] = set()
        self.unwritten: list = []  # history batches waiting to be written
        self.history_until = 0.0  # when the history was last written (the charts' newest bucket ends there)
        self.networks: dict[int | None, dict] = {}  # other PANs; None = frames that name no network
        self.key_loaded = False
        self.live_clients: set[asyncio.StreamWriter] = set()
        self.channel = CHANNEL  # the channel asked of the radios: the option, or the Sniffer page's choice
        self.events: list[dict] = []  # app-wide events (channel changes) since the last write
        self.catching_up = ""  # capture file being counted into the history after a restart
        self.ready = asyncio.Event()  # the latest captures are counted: live frames may follow


S = State()
NAMES = names_mod.Names()
ANALYZER = analysis.Analyzer(names_mod.our_pan(names_mod.load_z2m_config()))
PCAP = pcap.RotatingPcap(CAPTURE_DIR)
STORE = Store(DATA_DIR / "history.db")
TSHARK = Tshark(TSHARK_HOME, USE_TSHARK)
REPORT = report.Report(STORE, NAMES, S)
HA = hass_mod.HomeAssistant(PUBLISH_HA, DEVICE_SENSORS, VERSION, DATA_DIR)
MAPS = mapping.FloorMaps(DATA_DIR)


def our_pan() -> int | None:
    return ANALYZER.pans.ours


# ---------------------------------------------------------------- frames: sniffers -> merger -> everything

def on_sniffer_frame(sn: Sniffer, ts: float, channel: int, rssi: int, lqi: int, psdu: bytes, late: bool) -> None:
    MERGER.add(sn.id, ts, channel, rssi, lqi, psdu, late)


def on_dropped(ts: float, n: int) -> None:
    ANALYZER.add_dropped(ts, n)


def emit(tx: merge.Tx) -> None:
    """One transmission (heard by one or more sniffers): capture, history, live view."""
    sid, rssi, lqi = max(tx.copies, key=lambda c: c[1])  # the clearest copy stands for it
    ts, psdu = tx.ts, tx.psdu
    # The capture keeps every frame heard, whatever its network.
    packet = pcap.tap_packet(psdu, tx.channel, rssi, lqi)
    try:
        rel, n, end = PCAP.write(ts, packet)
        if S.disk_error and time.time() - S.disk_error_at > 60:
            log.info("Writing the captures works again")
            S.disk_error = ""
    except OSError as e:  # disk full: keep counting the history and showing frames, say so on the page
        rel, n, end = "", 0, 0
        if not S.disk_error or time.time() - S.disk_error_at > 300:
            log.error("Can't write the capture file: %s (frames are counted but not saved)", e)
            S.disk_error_at = time.time()
        S.disk_error = f"can't write the captures: {e}"
    if rel:
        tx.ref = (rel, n)
        if Sniffer.several:
            try:
                PCAP.write_copies(rel, n, tx.copies)
            except OSError:
                pass
    rec = pcap.record(ts, packet)
    for w in list(S.live_clients):
        try:
            if w.transport.get_write_buffer_size() > LIVE_CLIENT_BUFFER:
                log.info("A live Wireshark client fell too far behind: dropped")
                S.live_clients.discard(w)
                w.transport.abort()
                continue
            w.write(rec)
        except Exception:  # noqa: BLE001 - a gone Wireshark client
            S.live_clients.discard(w)

    info = ANALYZER.feed(ts, rssi, lqi, psdu, (rel, n) if rel else None, copies=list(tx.copies))
    if rel:
        ANALYZER.batch.files[rel] = (end, n)
    m, pan, ours = info["m"], info["pan"], info["ours"]
    if ours and m.get("src") and m.get("type") != "ack":
        tx.src = m["src"]
        if Sniffer.several:
            count_coverage(tx, ts)
    S.frames_total += 1
    sec = int(time.time())
    if not S.recent or S.recent[-1][0] != sec:
        S.recent.append([sec, 0])
    S.recent[-1][1] += 1
    S.live_seq += 1
    item = {"id": S.live_seq, "ts": ts, "rssi": rssi, "lqi": lqi, "mac": m, "pan": pan, "ours": ours,
            "retry": info["retry"], "file": rel, "n": n, "packet": packet, "late": tx.late, "copies": tx.copies}
    # An ACK carries no addresses: it comes from the receiver of the frame it answers.
    if m.get("type") == "ack":
        w = S.ack_wait
        if w and w[0] == m.get("seq") and 0 <= ts - w[3] <= 0.02:
            item["ack_of"] = (w[2], w[1])
        S.ack_wait = None
    elif m.get("ack_req"):
        S.ack_wait = (m.get("seq"), m.get("src"), m.get("dst"), ts)
    S.live.append(item)

    if not ours:
        if pan is None:
            S.frames_unnamed += 1
        else:
            S.frames_other += 1
        net = S.networks.setdefault(pan, {"count": 0, "rssi_sum": 0, "devices": set(), "last_seen": ts})
        net["count"] += 1
        net["rssi_sum"] += rssi
        net["last_seen"] = ts
        if m.get("src") and len(net["devices"]) < 1000:
            net["devices"].add(m["src"])
        return
    S.frames_ours += 1
    if ts > S.last_frame_ts:
        S.last_frame_ts = ts
    if tx.src:
        prev = S.seen.get(tx.src)
        if prev is None or prev[0] < ts:
            S.seen[tx.src] = (ts, rssi, lqi)
    nsrc = (m.get("nwk") or {}).get("src")
    if nsrc and ts > S.msg_seen.get(nsrc, 0):
        S.msg_seen[nsrc] = ts
    if S.traces:  # a Ping is being traced: keep its frames (and the ACK after each) apart from the live buffer
        addrs = frame_addrs(item)
        for addr, tr in list(S.traces.items()):
            if time.time() > tr["until"]:
                del S.traces[addr]
            elif addr in addrs or (m.get("type") == "ack" and tr.get("want_ack")):
                tr["frames"].append(item)
                tr["want_ack"] = bool(m.get("ack_req"))
            else:
                tr["want_ack"] = False


def count_coverage(tx: merge.Tx, ts: float) -> None:
    """What each sniffer adds: of our transmissions while it was connected, how many it heard and
    how many only it heard."""
    heard = {c[0] for c in tx.copies}
    for sn in SNIFFERS:
        if not sn.connected and sn.id not in heard:
            continue
        r = sn.rec(ts)
        r[H_TOTAL] += 1
        if sn.id in heard:
            r[H_HEARD] += 1
            if len(heard) == 1:
                r[H_SOLO] += 1
    tx.solo = next(iter(heard)) if len(heard) == 1 else None


def late_copy(tx: merge.Tx, sid: str, rssi: int, lqi: int) -> None:
    """Another sniffer heard a transmission already counted: only its signal is news (and the
    sniffer that seemed to be the only one to hear it wasn't)."""
    if tx.src:
        ANALYZER.sniffer_rssi(tx.ts, tx.src, sid, rssi)
        if sid in SNIFFER:
            SNIFFER[sid].rec(tx.ts)[H_HEARD] += 1
            if tx.solo and tx.solo != sid and tx.solo in SNIFFER:
                SNIFFER[tx.solo].rec(tx.ts)[H_SOLO] -= 1
            tx.solo = None
    if tx.ref:
        try:
            PCAP.write_copies(tx.ref[0], tx.ref[1], [(sid, rssi)])
        except OSError:
            pass


SNIFFERS = [make_sniffer(c) for c in sniffer_configs()]
SNIFFER = {s.id: s for s in SNIFFERS}
Sniffer.several = len(SNIFFERS) > 1
MERGER = merge.Merger(emit, late_copy, several=len(SNIFFERS) > 1, ref=SNIFFERS[0].id)
REPORT.sniffer_names = {s.id: s.name for s in SNIFFERS}


def load_known() -> set[str]:
    try:
        return set(json.loads(KNOWN_FILE.read_text()))
    except (OSError, ValueError, TypeError):
        known = STORE.sniffer_ids()  # first run of 0.5.3: the sniffers the history has heard from
        save_known(known)
        return known


def save_known(known: set[str]) -> None:
    try:
        KNOWN_FILE.write_text(json.dumps(sorted(known)))
    except OSError as e:
        log.warning("Can't remember the sniffers: %s", e)


KNOWN = load_known()


def load_moves() -> dict[str, float]:
    try:
        return {str(k): float(v) for k, v in json.loads(MOVES_FILE.read_text()).items()}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


REPORT.sniffer_moves = load_moves()


def sniffer_link(sn: Sniffer, up: bool) -> None:
    """A sniffer's connection opened or closed: the merger waits for (or stops waiting for) its
    frames, and a sniffer connecting for the first time is an event (it changes what is heard)."""
    MERGER.link(sn.id, up)
    if up and sn.id not in KNOWN:
        KNOWN.add(sn.id)
        save_known(KNOWN)
        sn.event("sniffer_added", f"started listening ({sn.host})")


for _sn in SNIFFERS:
    _sn.on_link = lambda up, sn=_sn: sniffer_link(sn, up)
    _sn.on_alive = lambda sn=_sn: MERGER.heard(sn.id)
    _sn.on_offset = lambda delta, sn=_sn: MERGER.offset_moved(sn.id, delta)
    _sn.on_clock_restart = lambda sn=_sn: MERGER.clock_restarted(sn.id)


def sniffer_name(sid: str) -> str:
    sn = SNIFFER.get(sid)
    return sn.name if sn else sid


def app_event(kind: str, detail: str) -> None:
    S.events.append({"ts": time.time(), "kind": kind, "addr": "sniffer", "other": "app", "ieee": "",
                     "detail": detail, "file": "", "n": 0})


async def ticker() -> None:
    """Release merged transmissions (every 0.1 s) and count each sniffer's connected time (every 5 s,
    by the clock: a busy event loop mustn't make the connected time look short)."""
    last = time.monotonic()
    failures = 0
    while True:
        await asyncio.sleep(0.1)
        try:
            MERGER.release()
        except Exception:  # noqa: BLE001
            failures += 1
            if failures <= 5 or failures % 1000 == 0:
                log.exception("merging the sniffers' frames failed (%d so far)", failures)
        now = time.monotonic()
        if now - last >= 5:
            for sn in SNIFFERS:
                sn.tick(now - last)
            last = now
            S.listening = any(s.connected for s in SNIFFERS)


# ---------------------------------------------------------------- history

def learn_addresses(pairs) -> None:
    for short, ieee in pairs:
        NAMES.learn(short, ieee)


def z2m_events() -> list[dict]:
    """Zigbee2MQTT's bridge events (from MQTT), as history events about the device they name."""
    out = []
    for e in HA.take_z2m_events():
        ieee = e["ieee"]
        if not ieee and e["name"]:
            ieee = next((i for i, n in NAMES.by_ieee.items() if n == e["name"]), "")
        addr = (NAMES.current_short(ieee) if ieee else None) or ("z2m" if not ieee else ieee)
        out.append({"ts": e["ts"], "kind": e["kind"], "addr": addr, "other": "z2m", "ieee": ieee,
                    "detail": e["detail"], "file": "", "n": 0, "name": e["name"]})
    return out


async def incident_events() -> list[dict]:
    """An event for each network-wide incident that started since the last look (for automations)."""
    now = time.time()
    try:
        incidents = await asyncio.to_thread(REPORT.incidents, now - 3600, now)
    except Exception:  # noqa: BLE001
        log.exception("looking for incidents failed")
        return []
    out = []
    for inc in incidents:
        if inc["id"] in S.fired_incidents or inc["end"] is not None:
            continue
        S.fired_incidents.add(inc["id"])
        out.append({"ts": inc["start"], "kind": "incident", "addr": "network", "other": "", "ieee": "",
                    "detail": inc["title"] + (f": {inc['cause']}" if inc["cause"] else "")
                    + (f" ({inc['detail']})" if inc["detail"] else ""), "file": "", "n": 0, "name": "Zigbee network"})
    if len(S.fired_incidents) > 500:
        S.fired_incidents = set(sorted(S.fired_incidents)[-200:])
    return out


async def flusher() -> None:
    """Live counters -> the history, every few seconds."""
    while True:
        await asyncio.sleep(FLUSH_S)
        try:
            await flush()
        except Exception:  # noqa: BLE001
            log.exception("writing the history failed")


async def flush() -> None:
    try:
        PCAP.flush()  # the offsets written below must be on disk
    except OSError as e:
        S.disk_error = f"can't write the captures: {e}"
    batch = ANALYZER.take()
    events = list(batch.events)
    if batch:
        learn_addresses(sorted(batch.ieee, key=lambda k: batch.ieee[k][1]))
        S.unwritten.append(batch)
    while S.unwritten:  # oldest first: a batch that couldn't be written (disk full, locked) is tried again
        try:
            await asyncio.to_thread(STORE.write, S.unwritten[0])
            S.unwritten.pop(0)
            REPORT.history_written()
            if not S.unwritten:
                S.history_until = time.time()
        except Exception:  # noqa: BLE001
            if len(S.unwritten) > 40:  # 20 minutes of history: give up on the oldest
                S.unwritten.pop(0)
                log.error("dropped 30 s of history that couldn't be written")
            log.exception("writing the history failed (%d batches waiting)", len(S.unwritten))
            break
    rows, sevents = {}, list(S.events) + z2m_events()
    S.events = []
    for sn in SNIFFERS:
        r, e = sn.take()
        rows.update(r)
        sevents += e
    if rows or sevents:
        await asyncio.to_thread(STORE.write_sniffer, rows, sevents)
        events += sevents
    events += await incident_events()
    if events:
        HA.queue_events(events, NAMES.name)


def replay(path: Path, rel: str, offset: int, frames: int, coverage: recount.Coverage | None = None) -> int:
    """Count frames of a capture file into the history from byte `offset` (they were written while
    the app wasn't counting: an older version, or the minutes before a restart). A file counted
    again from scratch (recount.py) also counts which sniffer heard what (`coverage`)."""
    an = analysis.Analyzer(our_pan())
    an.our_ieee = set(NAMES.by_ieee)
    an.seed_addresses(STORE.address_pairs())
    start = frames
    side = pcap.read_copies(path)  # which sniffers heard each frame, when several did
    for end, ts, data in pcap.iter_records(path, offset):
        frames += 1
        _, rssi, lqi, psdu = pcap.parse_tap(data)
        cp = side.get(frames)
        info = an.feed(ts, rssi, lqi, psdu, (rel, frames), copies=[(sid, r, 0) for sid, r in cp] if cp else None)
        an.batch.files[rel] = (end, frames)
        if coverage is not None:
            coverage.add(ts, info, cp)
        if frames % 20000 == 0:
            STORE.write(an.take())
            if coverage is not None:
                STORE.write_sniffer(coverage.take(), [])
    STORE.write(an.take())
    if coverage is not None:
        STORE.write_sniffer(coverage.take(), [])
    return frames - start


def seed_merger() -> int:
    """Remember what the end of the captures holds, so a bridge's backlog of frames from before a
    restart matches them instead of being written again."""
    if not Sniffer.several:
        return 0
    now = time.time()
    recs = []
    for path in sorted({pcap.path_for(CAPTURE_DIR, now - merge.MEMORY_S), pcap.path_for(CAPTURE_DIR, now)}):
        if not path.exists():
            continue
        rel = str(path.relative_to(CAPTURE_DIR)).replace("\\", "/")
        n = 0
        for _, ts, data in pcap.iter_records(path):
            n += 1
            if ts >= now - merge.MEMORY_S:
                recs.append((ts, pcap.parse_tap(data)[3], (rel, n)))
    return MERGER.seed(recs, now)


async def set_ready() -> None:
    """Live frames may come: seed the merger first (once)."""
    if S.ready.is_set():
        return
    try:
        n = await asyncio.to_thread(seed_merger)
        if n:
            log.info("Remembered %d transmissions from the end of the captures (a bridge's backlog from before "
                     "the restart isn't written twice)", n)
    except Exception:  # noqa: BLE001
        log.exception("reading the end of the captures for the merger failed")
    S.ready.set()


async def catch_up() -> None:
    """Count what the captures hold beyond the history: the current and the previous hour first
    (live frames, and frames a bridge buffered while we were down, are appended to those), then
    older files, newest first, while frames come in. Files asked to be counted again from scratch
    (recount.py) have their old counts taken out first."""
    try:
        again = await asyncio.to_thread(recount.start, CAPTURE_DIR, STORE)
        done = STORE.files()
        current = pcap.path_for(CAPTURE_DIR, time.time())
        paths = sorted(pcap.capture_files(CAPTURE_DIR), reverse=True)
        paths.sort(key=lambda p: p != current)
        for i, path in enumerate(paths):
            rel = str(path.relative_to(CAPTURE_DIR)).replace("\\", "/")
            rec = done.get(rel, {})
            offset, frames = rec.get("offset", 0), rec.get("frames", 0)
            size = path.stat().st_size
            if offset > size or rec.get("ev_offset", 0) > max(offset, size):
                # A hard reset can leave the history ahead of what reached the disk: line the
                # bookkeeping up with the file's last complete record (those frames are counted already).
                frames, end = await asyncio.to_thread(pcap.scan, path)
                log.warning("%s is shorter than the history thought (%d > %d bytes): realigned", rel, offset, size)
                await asyncio.to_thread(STORE.set_file, rel, offset=end, frames=frames,
                                        ev_offset=min(rec.get("ev_offset", 0), end),
                                        ev_frames=min(rec.get("ev_frames", 0), frames))
                offset = end
            if offset < size - 16:
                S.catching_up = rel
                cov = None
                if rel in again:
                    connected = await asyncio.to_thread(STORE.connected_minutes, again[rel], again[rel] + 3600)
                    cov = recount.Coverage(connected)
                n = await asyncio.to_thread(replay, path, rel, offset, frames, cov)
                if n:
                    log.info("Counted %d frames of %s into the history", n, rel)
            if i == 1:
                await set_ready()
        if again:
            recount.finish(CAPTURE_DIR)
            REPORT.invalidate()
            log.info("Counted %d capture files into the history again", len(again))
    except Exception:  # noqa: BLE001
        log.exception("counting the captures into the history failed")
    finally:
        S.catching_up = ""
        await set_ready()


async def decoder() -> None:
    """The tshark pass: events, NWK command counts and link costs from frames already counted."""
    await S.ready.wait()
    while True:
        try:
            await decode_pass()
        except Exception:  # noqa: BLE001
            log.exception("the decode pass failed")
        await asyncio.sleep(DECODE_S)


async def decode_pass() -> None:
    if not TSHARK.enabled:
        return
    files = await asyncio.to_thread(STORE.files)
    todo = [rel for rel in sorted(files, reverse=True) if files[rel]["ev_offset"] < files[rel]["offset"]]
    for rel in [r for r in todo for _ in range(4)]:  # up to 4 chunks of each file per pass
        rec = await asyncio.to_thread(STORE.file, rel)
        if not rec or rec["ev_offset"] >= rec["offset"]:
            continue
        path = CAPTURE_DIR / rel
        if not path.exists():
            continue
        start = max(rec["ev_offset"], len(pcap.GLOBAL_HEADER))
        end, n = await asyncio.to_thread(pcap.chunk_end, path, start, rec["offset"], DECODE_CHUNK)
        if end <= start:
            continue
        frames = rec["frames"] if n is None else rec["ev_frames"] + n
        found = await TSHARK.events(path, rel, start, end, rec["ev_frames"] + 1, our_pan())
        if found is None:  # tshark failed: leave the stretch to be decoded again, don't mark it done
            log.warning("The decode pass couldn't read %s (%s); it will try again", rel, TSHARK.last_error)
            break
        events, cmds, links, ota = found
        await asyncio.to_thread(STORE.write_decoded, rel, end, frames, events, cmds, links, ota)
        HA.queue_events(events, NAMES.name)
        REPORT.invalidate()


async def housekeeping() -> None:
    while True:
        try:
            NAMES.reload()
            ANALYZER.our_ieee = set(NAMES.by_ieee)
            cfg = names_mod.load_z2m_config()
            HA.z2m_base = names_mod.base_topic(cfg)
            S.key_loaded = names_mod.write_tshark_keys(TSHARK_HOME, names_mod.network_key(cfg))
            pan = names_mod.our_pan(cfg)
            if pan != ANALYZER.pans.ours:
                log.info("Our network: PAN %s", decode.pan_text(pan) or "unknown (showing every network)")
                ANALYZER.pans.ours = pan
            await asyncio.to_thread(enforce_retention)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")
        await asyncio.sleep(600)


def capture_bytes(f: Path) -> int:
    """A capture's size with its .sniffers file."""
    side = pcap.copies_path(f)
    return f.stat().st_size + (side.stat().st_size if side.exists() else 0)


def remove_capture(f: Path) -> None:
    f.unlink(missing_ok=True)
    pcap.copies_path(f).unlink(missing_ok=True)


def enforce_retention() -> None:
    cutoff = time.time() - RETENTION_DAYS * 86400
    files = sorted(pcap.capture_files(CAPTURE_DIR), key=lambda p: p.stat().st_mtime)
    for f in files:
        if f.stat().st_mtime < cutoff and f != PCAP.current:
            remove_capture(f)
    for side in pcap.capture_files(CAPTURE_DIR, f"*.pcap{pcap.COPIES}"):  # left behind by a capture deleted by hand
        if not side.with_name(side.name[: -len(pcap.COPIES)]).exists():
            side.unlink(missing_ok=True)
    files = [f for f in sorted(pcap.capture_files(CAPTURE_DIR), key=lambda p: p.stat().st_mtime) if f.exists()]
    total = sum(capture_bytes(f) for f in files)
    while files and total > MAX_STORAGE_MB * 1024 * 1024:
        f = files.pop(0)
        if f == PCAP.current:
            break
        total -= capture_bytes(f)
        remove_capture(f)
    for d in CAPTURE_DIR.iterdir():
        if d.is_dir() and not any(d.iterdir()):
            shutil.rmtree(d, ignore_errors=True)
    existing = {str(p.relative_to(CAPTURE_DIR)).replace("\\", "/") for p in pcap.capture_files(CAPTURE_DIR)}
    STORE.prune(cutoff, existing)


async def live_pcap_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Wireshark: Capture > Options > Manage Interfaces > Remote/TCP, or `wireshark -k -i TCP@host:17760`."""
    writer.write(pcap.GLOBAL_HEADER)
    S.live_clients.add(writer)
    log.info("Live Wireshark client connected")
    try:
        while await reader.read(4096):  # until the client closes (anything it sends is ignored)
            pass
    except (ConnectionError, OSError):
        pass
    finally:
        S.live_clients.discard(writer)
        writer.close()


# ---------------------------------------------------------------- Home Assistant

async def ha_publisher() -> None:
    """Home Assistant's entities, refreshed every minute."""
    await HA.start()
    while True:
        try:
            await publish_ha()
        except Exception:  # noqa: BLE001
            log.exception("publishing to Home Assistant failed")
        await asyncio.sleep(60)


def sniffer_state(sn: Sniffer, day: dict) -> dict:
    b = sn.web.status
    return {
        "connected": sn.connected, "radio_link": b.get("radio_link", sn.bridge.get("radio_link_ok", True)),
        "wifi_rssi": b.get("wifi_rssi") or sn.bridge.get("wifi_rssi"), "disconnects_24h": day["disconnects"],
        "buffered_frames": sn.buffered_frames,
        "radio_firmware": b.get("radio_firmware", "unknown"), "radio_version": b.get("radio") or sn.radio.get("version"),
        "bridge_firmware": b.get("bridge_firmware", "unknown"), "bridge_version": b.get("bridge") or sn.hello.get("bridge"),
        "bridge_partition": b.get("bridge_partition"),
    }


async def publish_ha() -> None:
    if not HA.connected:
        return
    devs = await REPORT.devices("1h")
    HA.publish_devices(devs["devices"])
    now = time.time()
    t10 = await asyncio.to_thread(STORE.net_totals, now - 600)
    t60 = await asyncio.to_thread(STORE.net_totals, now - 3600)
    problems = [{"device": d["name"] or d["addr"], "severity": hass_mod.HEALTH[d["sev"]], "finding": d["flags"][0]["text"]}
                for d in devs["devices"] if d["sev"] >= 2 and d["flags"]]
    minutes = max(1, t10["minutes"])
    first, *others = SNIFFERS
    day = await asyncio.to_thread(STORE.sniffer_totals, first.id, now - 86400)
    HA.publish_sniffer({
        **sniffer_state(first, day), "connected": any(s.connected for s in SNIFFERS),
        "frames_per_minute": round(t10["ours"] / minutes), "channel_busy": round(t10["air_all"] / (minutes * 60e6) * 100, 1),
        "resent": round(100 * t60["retry"] / t60["uni"], 1) if t60["uni"] else 0, "problems": len(problems),
        "channel": S.channel,
    }, problems)
    for sn in others:
        day = await asyncio.to_thread(STORE.sniffer_totals, sn.id, now - 86400)
        HA.publish_extra_sniffer(sn.id, sn.name, sniffer_state(sn, day))


# ---------------------------------------------------------------- web: basics

def capture_path(rel: str) -> Path | None:
    p = (CAPTURE_DIR / rel).resolve()
    return p if CAPTURE_DIR.resolve() in p.parents and p.suffix == ".pcap" and p.exists() else None


def want_others(request: web.Request) -> bool:
    return request.query.get("others") == "1"


def range_of(request: web.Request) -> str:
    r = request.query.get("range", "24h")
    return r if r in report.RANGES else "24h"


def frame_rate() -> float:
    now = int(time.time())
    n = sum(c for s, c in S.recent if now - 10 <= s < now)
    return round(n / 10, 1)


def sniffer_of(request: web.Request) -> Sniffer:
    """The sniffer a request is about (`sniffer=`), else the first one."""
    return SNIFFER.get(request.query.get("sniffer") or "", SNIFFERS[0])


async def page(request: web.Request) -> web.FileResponse:
    # no-cache: browsers check for a new page each time, so an update shows without a hard reload
    return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


async def static_file(request: web.Request) -> web.FileResponse:
    name = request.match_info["name"]
    path = (STATIC / name).resolve()
    if STATIC.resolve() not in path.parents or not path.is_file():
        raise web.HTTPNotFound()
    return web.FileResponse(path, headers={"Cache-Control": "no-cache"})


async def api_status(request: web.Request) -> web.Response:
    main = SNIFFERS[0]
    return web.json_response({
        "host": main.host, "port": main.port, "channel": S.channel, "version": VERSION,
        "sniffers": [s.summary() for s in SNIFFERS],
        "ha": {"enabled": HA.enabled, "connected": HA.connected, "error": HA.error},
        "connected": any(s.connected for s in SNIFFERS), "connected_since": main.connected_since,
        "last_error": main.last_error if not main.connected else "",
        "hello": main.hello, "radio": main.radio, "bridge": main.bridge,
        "pan_id": decode.pan_text(our_pan()) or None, "time_zone": TIME_ZONE or "UTC",
        "frames_total": S.frames_total, "frames_ours": S.frames_ours, "frames_other": S.frames_other,
        "frames_unnamed": S.frames_unnamed, "fps": frame_rate(), "merged_copies": MERGER.matched,
        "merge": {**MERGER.status(), "waiting_for_name": sniffer_name(MERGER.waiting[0]) if MERGER.waiting else None},
        "buffered_frames": sum(s.buffered_frames for s in SNIFFERS), "backlog_bytes": main.backlog_bytes,
        "key_loaded": S.key_loaded, "decode": USE_TSHARK, "tshark_error": TSHARK.last_error or None,
        "disk_error": S.disk_error or None, "history_recovered": STORE.recovered or None,
        "history_unwritten": len(S.unwritten), "history_until": S.history_until or None,
        "live_clients": len(S.live_clients), "catching_up": S.catching_up,
        "current_file": PCAP.rel or None, "retention_days": RETENTION_DAYS,
        "history_bytes": STORE.size_bytes(), "history_since": STORE.oldest(), "now": time.time(),
    })


async def api_overview(request: web.Request) -> web.Response:
    return web.json_response(await REPORT.overview(range_of(request), networks_rows()))


async def api_devices(request: web.Request) -> web.Response:
    return web.json_response(await REPORT.devices(range_of(request)))


async def api_device(request: web.Request) -> web.Response:
    addr = request.match_info["addr"].lower()
    rng = range_of(request)
    data = await REPORT.device(addr, rng)
    frames = [f for f in reversed(S.live) if addr in frame_addrs(f)][:150]
    if TSHARK.enabled:
        await decode_live(frames)
    data["frames"] = [live_row(f) for f in frames]
    return web.json_response(data)


async def api_device_hours(request: web.Request) -> web.Response:
    """The hours a device was heard in (frames to or from it), newest first, each with its capture
    file: where to search for its frames."""
    addr = request.match_info["addr"].lower()
    since = time.time() - report.RANGES[range_of(request)][0]
    rows = await asyncio.to_thread(STORE.device_hours, addr, since)
    out = []
    for hour, n in rows:
        path = pcap.path_for(CAPTURE_DIR, hour + 1)
        if path.exists():
            out.append({"file": str(path.relative_to(CAPTURE_DIR)).replace("\\", "/"), "start": hour, "frames": n})
    return web.json_response({"hours": out})


async def api_mesh(request: web.Request) -> web.Response:
    return web.json_response(await REPORT.mesh(range_of(request)))


def networks_rows() -> list[dict]:
    total = max(1, S.frames_total)
    rows = [{
        "pan": decode.pan_text(pan) or None, "count": n["count"], "share": round(100 * n["count"] / total, 1),
        "rssi_avg": round(n["rssi_sum"] / n["count"], 1), "devices": len(n["devices"]), "last_seen": n["last_seen"],
    } for pan, n in S.networks.items()]
    rows.sort(key=lambda r: -r["count"])
    return rows


async def api_networks(request: web.Request) -> web.Response:
    """Other networks on the channel (neighbours' Zigbee, Thread), busiest first, since the app started."""
    return web.json_response(networks_rows())


def frame_addrs(f: dict) -> tuple:
    m = f["mac"]
    nwk = m.get("nwk") or {}
    ack = f.get("ack_of") or (None, None)
    return m.get("src"), m.get("dst"), nwk.get("src"), nwk.get("dst"), *ack


def live_row(f: dict) -> dict:
    m, ours = f["mac"], f["ours"]
    nwk = m.get("nwk") or {}
    dec = f.get("dec") or ("", "")
    if "ack_of" in f:
        m = {**m, "src": f["ack_of"][0], "dst": f["ack_of"][1]}
    return {
        "id": f["id"], "ts": f["ts"], "rssi": f["rssi"], "lqi": f["lqi"], "type": m.get("type"), "kind": mac.kind(m),
        "pan": decode.pan_text(f["pan"]), "ours": ours, "seq": m.get("seq"), "retry": f["retry"], "len": m.get("len"),
        "src": m.get("src") or "", "dst": m.get("dst") or "", "nwk_src": nwk.get("src") or "", "nwk_dst": nwk.get("dst") or "",
        "src_name": NAMES.name(m.get("src")) if ours else None, "dst_name": NAMES.name(m.get("dst")) if ours else None,
        "nwk_src_name": NAMES.name(nwk.get("src")) if ours else None,
        "nwk_dst_name": NAMES.name(nwk.get("dst")) if ours else None,
        "proto": dec[0], "info": dec[1], "file": f["file"], "n": f["n"], "late": f.get("late", False),
        "heard_by": [{"sniffer": c[0], "name": sniffer_name(c[0]), "rssi": c[1]} for c in f.get("copies", ())]
        if len(SNIFFERS) > 1 else [],
    }


_decode_lock = asyncio.Lock()


async def decode_live(frames: list[dict]) -> None:
    """tshark's summary for live frames that don't have one yet (kept on the frame for later polls)."""
    async with _decode_lock:
        todo = [f for f in frames if "dec" not in f][-400:]
        if not todo:
            return
        cols = await TSHARK.columns([(f["ts"], f["packet"]) for f in todo])
        for f, c in zip(todo, cols):
            f["dec"] = c
        for f in todo:
            f.setdefault("dec", ("", ""))


async def api_live(request: web.Request) -> web.Response:
    after = int(request.query.get("after", 0))
    others = want_others(request)
    addr = request.query.get("addr", "").lower()
    frames = [f for f in S.live if f["id"] > after and (f["ours"] or others) and (not addr or addr in frame_addrs(f))]
    skipped = max(0, len(frames) - 300)
    if after and S.live and S.live[0]["id"] > after + 1:  # the buffer moved past `after` meanwhile
        skipped += S.live[0]["id"] - after - 1
    frames = frames[-300:]
    if request.query.get("decode") == "1" and TSHARK.enabled:
        await decode_live(frames)
    return web.json_response({"last_id": S.live_seq, "frames": [live_row(f) for f in frames], "skipped": skipped})


def capture_files() -> list[dict]:
    counted = STORE.files()
    files = []
    for f in sorted(pcap.capture_files(CAPTURE_DIR), reverse=True):
        st = f.stat()
        rel = str(f.relative_to(CAPTURE_DIR)).replace("\\", "/")
        side = pcap.copies_path(f)
        files.append({"file": rel, "size": st.st_size, "mtime": st.st_mtime, "current": f == PCAP.current,
                      "frames": counted.get(rel, {}).get("frames"), "start": pcap.first_timestamp(f),
                      "side_size": side.stat().st_size if side.exists() else 0})
    return files


async def api_captures(request: web.Request) -> web.Response:
    """The capture files, newest first, and what is kept: since when, how much of the limit."""
    files = await asyncio.to_thread(capture_files)
    starts = [f["start"] for f in files if f["start"]]
    return web.json_response({
        "files": files, "oldest": min(starts) if starts else None,
        "storage_mb": round(sum(f["size"] + f["side_size"] for f in files) / 1048576, 1), "limit_mb": MAX_STORAGE_MB,
        "retention_days": RETENTION_DAYS,
    })


async def api_decode(request: web.Request) -> web.Response:
    """A capture's frames, decoded: our network's only, unless `others=1`. `t` (unix time) picks the
    hour's file and opens the page holding that moment; `n` the page holding frame n."""
    q = request.query
    at_ts = float(q["t"]) if q.get("t") else None
    rel = q.get("file", "")
    if not rel and at_ts is not None:
        rel = str(pcap.path_for(CAPTURE_DIR, at_ts).relative_to(CAPTURE_DIR)).replace("\\", "/")
    path = capture_path(rel)
    if not path:
        raise web.HTTPNotFound(text="no capture for that hour" if at_ts else "no such capture")
    try:
        PCAP.flush()
    except OSError:
        pass
    rows = await decode.decoded(path, TSHARK, our_pan())
    limit = min(1000, max(1, int(q.get("limit", 200))))
    page = await asyncio.to_thread(
        decode.page, rows, NAMES, want_others(request), q.get("addr", "").strip().lower(), q.get("q", "").strip().lower(),
        q.get("retries") == "1", int(q["n"]) if q.get("n") else None, at_ts, limit, max(0, int(q.get("offset", 0))))
    if Sniffer.several:
        copies = await asyncio.to_thread(pcap.read_copies, path)
        for row in page["rows"]:
            row["heard_by"] = [{"sniffer": sid, "name": sniffer_name(sid), "rssi": r} for sid, r in copies.get(row["n"], ())]
    return web.json_response({**page, "file": rel})


async def api_frame(request: web.Request) -> web.Response:
    """One frame, fully dissected by tshark (decrypted), from the live buffer or a capture file."""
    live_id = request.query.get("live")
    rec = None
    if live_id:
        f = next((f for f in S.live if f["id"] == int(live_id)), None)
        if f:
            rec, rel, n = (f["ts"], f["packet"]), f["file"], f["n"]
    if rec is None:
        rel, n = request.query.get("file", ""), int(request.query.get("n", 0))
        path = capture_path(rel)
        if not path or n < 1:
            raise web.HTTPNotFound(text="no such frame")
        PCAP.flush()
        rec = await asyncio.to_thread(pcap.read_record, path, n)
        if rec is None:
            raise web.HTTPNotFound(text="no such frame")
    ts, packet = rec
    _, rssi, lqi, psdu = pcap.parse_tap(packet)
    text = await TSHARK.detail(ts, packet)
    return web.json_response({"ts": ts, "file": rel, "n": n, "rssi": rssi, "lqi": lqi, "len": len(psdu),
                              "kind": mac.kind(mac.parse(psdu)), "text": text, "hex": psdu.hex()})


async def download_decoded(request: web.Request) -> web.StreamResponse:
    """A whole capture decoded and decrypted by tshark: the full protocol tree of every frame
    (`format=text`) or tshark's JSON (`format=json`), optionally only one device's frames."""
    path = capture_path(request.match_info["rel"])
    if not path:
        raise web.HTTPNotFound()
    if not TSHARK.enabled:
        raise web.HTTPServiceUnavailable(text="decoding is off (the app's decode option)")
    PCAP.flush()
    as_json = request.query.get("format") == "json"
    args = ["-n", "-r", str(path)] + (["-T", "json"] if as_json else ["-V"])
    addr = request.query.get("addr", "").strip().lower()
    name = path.stem
    if addr:
        if not re.fullmatch(r"0x[0-9a-f]{4}", addr):
            raise web.HTTPBadRequest(text="addr must be a short address like 0x1a2b")
        args += ["-Y", f"wpan.src16 == {addr} || wpan.dst16 == {addr} || zbee_nwk.src == {addr} || zbee_nwk.dst == {addr}"]
        name += f"_{addr}"
    resp = web.StreamResponse(headers={
        "Content-Type": "application/json" if as_json else "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{name}_decoded.{"json" if as_json else "txt"}"'})
    await resp.prepare(request)
    async for chunk in TSHARK.stream(args):
        await resp.write(chunk)
    await resp.write_eof()
    return resp


async def download(request: web.Request) -> web.StreamResponse:
    path = capture_path(request.match_info["rel"])
    if not path:
        raise web.HTTPNotFound()
    PCAP.flush()
    return web.FileResponse(path, headers={"Content-Disposition": f'attachment; filename="{path.name}"'})


def load_channel() -> int:
    try:
        ch = json.loads(CHANNEL_FILE.read_text()).get("channel")
    except (OSError, ValueError, AttributeError):
        ch = None
    return ch if isinstance(ch, int) and 11 <= ch <= 26 else CHANNEL


async def api_channel(request: web.Request) -> web.Response:
    """Listen on another channel (every sniffer; kept across reconnects and restarts), or on the
    option's again (channel null)."""
    body = await request.json()
    ch = body.get("channel")
    if ch is None:
        CHANNEL_FILE.unlink(missing_ok=True)
        S.channel = CHANNEL
    else:
        ch = int(ch)
        if not 11 <= ch <= 26:
            raise web.HTTPBadRequest(text="channel must be 11-26")
        CHANNEL_FILE.write_text(json.dumps({"channel": ch}))
        S.channel = ch
    for sn in SNIFFERS:
        sn.send(proto.encode(proto.T_SET_CHANNEL, bytes([S.channel])))
    app_event("channel", f"listening on channel {S.channel}"
              + ("" if S.channel == CHANNEL else f" (the app's option says {CHANNEL})"))
    return web.json_response({"ok": True, "channel": S.channel, "configured": CHANNEL})


# ---------------------------------------------------------------- web: the sniffer page

def firmware_files() -> list[dict]:
    """Images waiting in /share/zigbee_sniffer/firmware, to flash from the Sniffer page."""
    out = []
    for f in sorted(FIRMWARE_DIR.glob("*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
        try:
            with open(f, "rb") as fh:
                info = bridge_mod.image_info(fh.read(256))
            info["size"] = f.stat().st_size
        except (OSError, ValueError) as e:
            info = {"error": str(e)}
        out.append({"name": f.name, "mtime": f.stat().st_mtime, **info})
    return out


def sniffer_findings(sn: Sniffer, totals: dict, events: list[dict], crc_minutes: list | None = None) -> list[dict]:
    out: list[dict] = []
    b = sn.web.status

    def f(sev, text):
        out.append({"sev": sev, "text": text})

    usb = sn.kind == "usb"
    if not sn.host:
        f("high", "Set sniffer_host in this app's Configuration to the bridge's address")
    elif not sn.connected:
        away = time.time() - sn.disconnected_since if sn.disconnected_since else None
        f("high", ("Can't read the USB radio" if usb else "Not connected to the bridge")
          + (f" for {report._gap_text(away)}" if away else "") + (f": {sn.last_error}" if sn.last_error else ""))
    if sn.host and sn.web.error:
        f("info", f"The bridge's status page doesn't answer ({sn.web.error}), so firmware and buffer details are missing")
    if usb and b.get("radio_link") is False:
        f("high", "The USB port is open but the radio sends nothing: is it running USB sniffer firmware "
                  "(radio 0.3+ built with CONFIG_SNIFF_LINK_USB)? Unplug it and plug it back in")
    elif b.get("radio_link") is False or sn.bridge.get("radio_link_ok") is False:
        f("high", "The bridge isn't hearing the radio board: check the UART wires between them")
    for board in ("radio", "bridge"):
        state = b.get(f"{board}_firmware")
        if state == "rolled_back":
            f("warn", f"The {board} rolled back: a newer image failed its trial, so it runs {b.get(board)}")
        elif state == "trial":
            f("info", f"The {board} is on trial with {b.get(board)}: it keeps the image only if its check passes")
    rssi = b.get("wifi_rssi") or sn.bridge.get("wifi_rssi")
    if rssi and rssi < -75:
        f("warn", f"Weak Wi-Fi at the bridge: {rssi} dBm (below about -75 dBm the link drops)")
    if totals["disconnects"] >= 3:
        buffered = isinstance(sn.hello.get("bridge_us"), int)
        f("warn", f"The bridge's connection dropped {totals['disconnects']} times in this range"
          + (" (frames heard meanwhile were buffered and delivered)" if buffered
             else " (frames heard meanwhile were lost; bridge firmware 0.3 buffers them)"))
    if b.get("buffer_full_drops"):
        f("warn", f"The bridge's buffer filled up and dropped {b['buffer_full_drops']} frames since it started")
    reboots = sum(1 for e in events if e["kind"] in ("bridge_reboot", "radio_reboot"))
    if reboots:
        f("warn" if reboots >= 3 else "info", f"{reboots} board restart{'s' if reboots > 1 else ''} in this range")
    if totals["crc"] >= 10:
        # a bridge writing its flash (an update, the boot after it) stops reading the UART for a moment
        upd = [e["ts"] for e in events if e["kind"] in ("firmware_update", "bridge_reboot")]
        during = sum(n for m, n in (crc_minutes or []) if any(t - 300 <= m <= t + 60 for t in upd))
        rest = totals["crc"] - during
        if rest >= 10:
            f("info", f"{rest} damaged messages on the USB cable in this range" if usb
                      else f"{rest} damaged messages on the UART between the boards in this range")
        if during >= 10:
            f("info", f"{during} damaged UART messages around the bridge's update or restart (expected: it stops "
                      "reading the UART while it writes its flash)")
    if usb:
        pass  # updates go over the cable: no token, no Wi-Fi
    elif b and b.get("updates") is False:
        f("info", "Firmware updates over Wi-Fi are off on this bridge (it was built without an update token)")
    elif not UPDATE_TOKEN:
        f("info", "To update firmware from here, set update_token in this app's Configuration "
                  "(the bridge's CONFIG_BRIDGE_UPDATE_TOKEN)")
    if S.channel != CHANNEL:
        f("info", f"Listening on channel {S.channel}, not the configured {CHANNEL} (changed on this page)")
    if PUBLISH_HA and HA.error:
        f("info", f"Home Assistant entities and events: {HA.error}")
    out.sort(key=lambda x: -report.SEV[x["sev"]])
    return out


async def api_sniffer_moved(request: web.Request) -> web.Response:
    """The sniffer was moved: what it hears now is its new normal. Its normals start again from now
    (they need SNIFFER_NORMAL_HOURS), and the move is marked on every device's charts."""
    sn = sniffer_of(request)
    REPORT.sniffer_moves[sn.id] = time.time()
    try:
        MOVES_FILE.write_text(json.dumps(REPORT.sniffer_moves))
    except OSError as e:
        raise web.HTTPInternalServerError(text=f"can't remember it: {e}") from e
    REPORT.forget_baselines()
    sn.event("sniffer_moved", "moved: its signal normals start again from here")
    return web.json_response({"ok": True, "moved_at": REPORT.sniffer_moves[sn.id]})


async def moved_hint(sn: Sniffer) -> dict | None:
    """Most devices sound louder or quieter at one sniffer at once: it was most likely moved (or its
    antenna). Said on its Sniffer page, with the button that starts its normals again."""
    if len(SNIFFERS) < 2:
        return None
    devs = await REPORT.devices("1h")
    ch = [abs(x["change"]) for d in devs["devices"] for x in d.get("signal") or []
          if x["sniffer"] == sn.id and x.get("change") is not None]
    if len(ch) < 10:
        return None
    ch.sort()
    med, share = ch[len(ch) // 2], sum(1 for c in ch if c >= 8) / len(ch)
    if med >= 5 or share >= 0.3:
        return {"sev": "warn", "text": f"Most devices sound different at this sniffer than usual (half of them by "
                                       f"{med:.0f} dB or more): was it moved? If so, press \"Moved it\" so it learns its new normal"}
    return None


def coverage_of(sn: Sniffer, totals: dict, heard: list[dict]) -> dict | None:
    """What this sniffer adds to the others: the share of our transmissions it heard and that only
    it heard, the devices only it hears, and how much louder or quieter it hears the devices it
    shares with each other sniffer (its antenna and where it sits)."""
    if len(SNIFFERS) < 2:
        return None
    per: dict[str, dict[str, dict]] = {}
    for r in heard:
        if r["n"] >= 3:
            per.setdefault(r["addr"], {})[r["sniffer"]] = r
    mine = [a for a, v in per.items() if sn.id in v]
    solo = sorted((a for a in mine if len(per[a]) == 1), key=lambda a: (NAMES.name(a) or a).lower())
    vs = []
    for other in SNIFFERS:
        if other.id == sn.id:
            continue
        diffs = sorted(per[a][sn.id]["rssi_avg"] - per[a][other.id]["rssi_avg"] for a in mine if other.id in per[a])
        vs.append({"id": other.id, "name": other.name, "devices": len(diffs),
                   "median_db": round(diffs[len(diffs) // 2], 1) if diffs else None})
    total = totals.get("total") or 0
    return {"total": total, "heard_pct": round(min(100.0, 100 * totals.get("heard", 0) / total), 1) if total else None,
            "solo_pct": round(max(0.0, 100 * totals.get("solo", 0) / total), 1) if total else None,
            "devices": len(mine), "solo_devices": [{"addr": a, "name": NAMES.name(a) or ""} for a in solo[:40]],
            "solo_devices_n": len(solo), "vs": vs}


async def api_sniffer(request: web.Request) -> web.Response:
    sn = sniffer_of(request)
    rng = range_of(request)
    span, bucket = report.RANGES[rng]
    now = time.time()
    since = now - span
    series = await asyncio.to_thread(STORE.sniffer_series, sn.id, since, bucket)
    totals = await asyncio.to_thread(STORE.sniffer_totals, sn.id, since)
    net = await asyncio.to_thread(STORE.net_series, since, bucket)
    events = await asyncio.to_thread(STORE.events, since, None, 300, sn.id)
    heard = await asyncio.to_thread(STORE.device_sniffers, since)
    marks = await asyncio.to_thread(REPORT.marks, since, None, sn.id)
    crc_min = await asyncio.to_thread(STORE.crc_minutes, sn.id, since)
    b = sn.web.status
    match = MERGER.match_stats()
    sniffers = [{**s.summary(), "skew_ms": MERGER.skew_ms(s.id), "match": match["by_sniffer"].get(s.id)} for s in SNIFFERS]
    return web.json_response({
        "range": rng, "span": span, "bucket": bucket, "now": now, "series": series, "totals": totals, "marks": marks,
        "drops": [[r[0], r[11]] for r in net], "events": events,
        "findings": [h for h in [await moved_hint(sn)] if h] + sniffer_findings(sn, totals, events, crc_min),
        "id": sn.id, "name": sn.name, "sniffers": sniffers, "coverage": coverage_of(sn, totals, heard),
        "merge": {"window_ms": match["window_ms"], **MERGER.status()},
        "normals": {"moved_at": REPORT.sniffer_moves.get(sn.id), "needed": report.SNIFFER_NORMAL_HOURS,
                    "hours": (await asyncio.to_thread(REPORT.normal_hours, now - 3600)).get(sn.id, 0)},
        "devices_heard": sum(1 for r in heard if r["sniffer"] == sn.id),
        "bridge": b, "bridge_at": sn.web.at, "bridge_error": sn.web.error,
        "link": {"kind": sn.kind, "host": sn.host, "connected": sn.connected, "connected_since": sn.connected_since,
                 "disconnected_since": sn.disconnected_since, "last_error": sn.last_error, "fps": sn.fps(),
                 "buffered_frames": sn.buffered_frames, "backlog_bytes": sn.backlog_bytes, "radio": sn.radio,
                 "bridge": sn.bridge, "hello": sn.hello},
        "channel": {"current": S.channel, "configured": CHANNEL},
        "firmware": {"token_set": bool(UPDATE_TOKEN) or sn.kind == "usb", "updates_enabled": b.get("updates"),
                     "kind": sn.kind,
                     "updating": sn.web.updating, "last_result": sn.web.last_result,
                     "last_update": b.get("last_update"), "files": await asyncio.to_thread(firmware_files),
                     "folder": str(FIRMWARE_DIR)},
        "ha": {"enabled": HA.enabled, "connected": HA.connected, "error": HA.error, "device_sensors": DEVICE_SENSORS},
    })


async def firmware_bytes(request: web.Request) -> bytes:
    name = request.query.get("file")
    if name:
        path = FIRMWARE_DIR / Path(name).name
        if path.suffix != ".bin" or not path.is_file():
            raise web.HTTPNotFound(text="no such firmware file")
        return await asyncio.to_thread(path.read_bytes)
    data = await request.read()
    if not data:
        raise web.HTTPBadRequest(text="no image sent")
    return data


async def api_firmware_inspect(request: web.Request) -> web.Response:
    """What an image is, and whether it fits that sniffer's radio or bridge."""
    sn = sniffer_of(request)
    data = await firmware_bytes(request)
    try:
        info = bridge_mod.image_info(data)
    except ValueError as e:
        raise web.HTTPBadRequest(text=str(e)) from e
    target = info["target"]
    problems = (bridge_mod.check_image(info, target, sn.web.status) if target
                else ["not sniffer firmware (neither zigbee_sniffer_radio nor zigbee_sniffer_bridge)"])
    if sn.kind == "usb" and target == "bridge":
        problems = ["a USB sniffer has no bridge: only radio images go to it"]
    return web.json_response({"info": info, "target": target, "problems": problems,
                              "running": sn.web.status.get(target) if target else None})


async def api_firmware_flash(request: web.Request) -> web.Response:
    """Send an image to a sniffer's bridge (radio images are relayed to its radio over the UART)."""
    sn = sniffer_of(request)
    target = request.match_info["target"]
    if target not in bridge_mod.PROJECTS:
        raise web.HTTPNotFound()
    if sn.kind == "usb" and target != "radio":
        raise web.HTTPBadRequest(text="A USB sniffer has no bridge: only radio images go to it")
    if sn.kind != "usb" and not UPDATE_TOKEN:
        raise web.HTTPConflict(text="Set update_token in this app's Configuration first (the bridge's CONFIG_BRIDGE_UPDATE_TOKEN)")
    if sn.web.updating:
        raise web.HTTPConflict(text=f"An update of the {sn.web.updating['target']} is already running")
    # taken before the image is even read, so a second click can't start a second upload meanwhile
    sn.web.updating = {"target": target, "version": "?", "size": 0, "started": time.time(), "state": "checking"}
    try:
        data = await firmware_bytes(request)
        try:
            info = bridge_mod.image_info(data)
        except ValueError as e:
            raise web.HTTPBadRequest(text=str(e)) from e
        if not sn.web.status:  # (a USB radio's status is always there)
            await sn.web.poll()
        problems = bridge_mod.check_image(info, target, sn.web.status)
        if problems:
            raise web.HTTPBadRequest(text="; ".join(problems))
    except BaseException:
        sn.web.updating = None
        raise
    sn.web.updating = {"target": target, "version": info["version"], "size": len(data), "started": time.time()}
    sn.event("firmware_update", f"{target}: sending {info['version']} ({len(data) // 1024} KB) from the Sniffer page")

    async def run() -> None:
        result = await sn.web.update(target, data, UPDATE_TOKEN)
        sn.event("firmware_update", f"{target} {info['version']}: {result['message']}")

    asyncio.create_task(run())
    return web.json_response({"started": True, "target": target, "version": info["version"]}, status=202)


# ---------------------------------------------------------------- web: ping and trace

async def api_ping(request: web.Request) -> web.Response:
    """Ask Zigbee2MQTT to read the device (Basic cluster), so its path can be traced on air."""
    addr = request.match_info["addr"].lower()
    name = NAMES.name(addr)
    if addr == "0x0000" or not name or name.startswith("0x"):
        raise web.HTTPBadRequest(text="not a Zigbee2MQTT device with a name")
    base = names_mod.base_topic(names_mod.load_z2m_config())
    t0 = time.time()
    # keep this device's frames for the trace (the live buffer holds only seconds when the channel is busy)
    tr = S.traces.setdefault(addr, {"until": 0, "frames": collections.deque(maxlen=5000)})
    tr["until"] = t0 + 60
    if not HA.z2m_read(base, name):
        raise web.HTTPServiceUnavailable(text=f"MQTT isn't connected ({HA.error or 'starting'}), so Zigbee2MQTT can't be asked")
    return web.json_response({"t0": t0, "device": name, "topic": f"{base}/{name}/set"})


async def api_trace(request: web.Request) -> web.Response:
    """The frames between the coordinator and a device since `since`, grouped into messages, each
    with the hops it took: who handed it to whom, at what signal, resent or not, ACK heard or not."""
    addr = request.match_info["addr"].lower()
    since = float(request.query.get("since", 0))
    tr = S.traces.get(addr)
    source = tr["frames"] if tr else S.live
    live = [f for f in source if f["ts"] >= since - 0.2]
    msgs: dict[tuple, dict] = {}
    polls = []
    for i, f in enumerate(live):
        m = f["mac"]
        nwk = m.get("nwk") or {}
        ns, nd = nwk.get("src"), nwk.get("dst")
        if m.get("type") == "command" and m.get("cmd") == 4 and m.get("src") == addr:
            polls.append(round((f["ts"] - since) * 1000))
            continue
        if not ns or {ns, nd} != {"0x0000", addr}:
            continue
        nxt = live[i + 1] if i + 1 < len(live) else None
        acked = bool(nxt and nxt["mac"].get("type") == "ack" and nxt.get("ack_of") == (m.get("dst"), m.get("src")))
        key = (ns, nd, nwk.get("seq"))
        msg = msgs.setdefault(key, {"dir": "request" if ns == "0x0000" else "response", "hops": [], "frames": []})
        msg["hops"].append({"from": m.get("src"), "from_name": NAMES.name(m.get("src")), "to": m.get("dst"),
                            "to_name": NAMES.name(m.get("dst")), "rssi": f["rssi"], "retry": f["retry"],
                            "acked": acked, "ms": round((f["ts"] - since) * 1000), "live": f["id"]})
        msg["frames"].append(f)
    if msgs and TSHARK.enabled:
        await decode_live([m["frames"][0] for m in msgs.values()])
    out = []
    for (ns, nd, seq), msg in msgs.items():
        dec = msg["frames"][0].get("dec") or ("", "")
        out.append({"dir": msg["dir"], "seq": seq, "info": dec[1], "proto": dec[0], "hops": msg["hops"],
                    "start_ms": msg["hops"][0]["ms"], "end_ms": msg["hops"][-1]["ms"]})
    out.sort(key=lambda x: x["start_ms"])
    req = next((x for x in out if x["dir"] == "request"), None)
    resp = next((x for x in out if x["dir"] == "response" and "Response" in (x["info"] or "")), None)
    return web.json_response({
        "since": since, "messages": out, "polls": polls, "request_seen": bool(req), "response_seen": bool(resp),
        "rtt_ms": resp["end_ms"] - req["start_ms"] if req and resp else None,
    })


# ---------------------------------------------------------------- web: maps and coverage

def map_key(d: dict) -> str:
    return d["ieee"] or f"addr:{d['addr']}"


async def api_map(request: web.Request) -> web.Response:
    """Floors, positions, and everything that can be placed (devices and sniffers)."""
    devs = await REPORT.devices("24h")
    items = [{"key": map_key(d), "kind": "device", "addr": d["addr"], "name": d["name"] or d["addr"],
              "type": d["type"], "model": d["model"]} for d in devs["devices"] if d["known"] or d["tx"]]
    items += [{"key": f"sniffer:{s.id}", "kind": "sniffer", "name": f"Sniffer: {s.name}",
               "type": "Sniffer"} for s in SNIFFERS]
    floors = [{**f, "size_m": MAPS.size_m(f)} for f in MAPS.floors]
    return web.json_response({"floors": floors, "positions": MAPS.data["positions"], "items": items,
                              "floor_height_m": MAPS.data["floor_height_m"]})


async def api_map_floor_add(request: web.Request) -> web.Response:
    body = await request.json()
    f = MAPS.add_floor(str(body.get("name") or "Floor")[:60], int(body.get("level") or 0),
                       body.get("width_m"), body.get("height_m"))
    return web.json_response(f)


async def api_map_floor_update(request: web.Request) -> web.Response:
    body = await request.json()
    if "floor_height_m" in body:
        MAPS.data["floor_height_m"] = max(1.5, min(10.0, float(body.pop("floor_height_m"))))
        MAPS.save()
    return web.json_response(MAPS.update_floor(request.match_info["fid"], body))


async def api_map_floor_delete(request: web.Request) -> web.Response:
    MAPS.delete_floor(request.match_info["fid"])
    return web.json_response({"ok": True})


async def api_map_image_put(request: web.Request) -> web.Response:
    data = await request.read()
    if not data:
        raise web.HTTPBadRequest(text="no image sent")
    f = MAPS.set_image(request.match_info["fid"], data, request.content_type,
                       int(request.query["w"]), int(request.query["h"]))
    return web.json_response(f)


async def api_map_image(request: web.Request) -> web.StreamResponse:
    path = MAPS.image_path(request.match_info["fid"])
    if not path or not path.is_file():
        raise web.HTTPNotFound()
    # An uploaded plan (an SVG can hold script) is served on Home Assistant's origin: opened on its own
    # it must not run anything.
    return web.FileResponse(path, headers={
        "Cache-Control": "max-age=86400", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"})


async def api_map_positions(request: web.Request) -> web.Response:
    body = await request.json()
    MAPS.set_positions(body.get("set") or {}, body.get("clear") or [])
    return web.json_response({"ok": True, "positions": MAPS.data["positions"]})


async def api_map_coverage(request: web.Request) -> web.Response:
    """What the coverage map needs: each placed device's signal at each placed sniffer, the fitted
    path-loss model, each placed router's strength, and the mesh links between placed routers."""
    rng = range_of(request)
    since = time.time() - report.RANGES[rng][0]
    devs = await REPORT.devices(rng)
    heard = await asyncio.to_thread(STORE.device_sniffers, since)
    mesh = await REPORT.mesh(rng)
    pos = MAPS.data["positions"]
    by_addr = {d["addr"]: d for d in devs["devices"]}
    signal: dict[str, dict[str, dict]] = {}
    for r in heard:
        if r["n"] >= 3:
            signal.setdefault(r["addr"], {})[r["sniffer"]] = r
    # measurements for the model: placed sniffer x placed device, both on scaled floors
    samples = []
    for s in SNIFFERS:
        sp = pos.get(f"sniffer:{s.id}")
        spm = MAPS.point_m(sp) if sp else None
        if not spm:
            continue
        for addr, per in signal.items():
            d = by_addr.get(addr)
            r = per.get(s.id)
            dp = pos.get(map_key(d)) if d and r else None
            dpm = MAPS.point_m(dp) if dp else None
            if dpm:
                dist, floors = MAPS.distance(dpm, spm)
                samples.append({"device": map_key(d), "sniffer": s.id, "d": dist, "floors": floors,
                                "rssi": r["rssi_avg"], "n": r["n"]})
    model = mapping.fit(samples, ref=SNIFFERS[0].id)
    for g in model.get("gains") or []:
        g["name"] = sniffer_name(g["sniffer"])
    offsets = model.pop("offsets", {}) if model.get("ok") else {}
    # a router never measured gets the strength of others of its model, else the house's
    by_model: dict[str, list[float]] = {}
    for d in devs["devices"]:
        if map_key(d) in offsets and d["model"]:
            by_model.setdefault(d["model"], []).append(offsets[map_key(d)])
    items = []
    for d in devs["devices"]:
        key = map_key(d)
        p = pos.get(key)
        if not p:
            continue
        per = signal.get(d["addr"], {})
        strength = None
        if model.get("ok"):
            if key in offsets:
                strength, src = model["a0"] + offsets[key], "measured"
            elif by_model.get(d["model"]):
                strength, src = model["a0"] + sum(by_model[d["model"]]) / len(by_model[d["model"]]), "model"
            else:
                strength, src = model["a0"], "house"
        items.append({"key": key, "kind": "device", "addr": d["addr"], "name": d["name"] or d["addr"],
                      "type": d["type"], "model": d["model"], "sev": d["sev"], **p,
                      "flags": [f["text"] for f in d["flags"][:3]], "mesh": d["mesh"],
                      "signal": {sid: {"rssi": r["rssi_avg"], "n": r["n"]} for sid, r in per.items()},
                      "best_rssi": max((r["rssi_avg"] for r in per.values()), default=None),
                      "strength": round(strength, 1) if strength is not None else None,
                      "strength_from": src if strength is not None else None})
    for s in SNIFFERS:
        p = pos.get(f"sniffer:{s.id}")
        if p:
            items.append({"key": f"sniffer:{s.id}", "kind": "sniffer", "id": s.id, "name": s.name,
                          "connected": s.connected, **p})
    placed = {i["addr"] for i in items if i["kind"] == "device"}
    links = [{"a": e["a"], "b": e["b"], "cost": report.link_cost(e["ab"], e["ba"])}
             for e in mesh["edges"] if e["a"] in placed and e["b"] in placed]
    floors = [{**f, "size_m": MAPS.size_m(f)} for f in MAPS.floors]
    return web.json_response({"range": rng, "model": model, "items": items, "links": links, "floors": floors,
                              "sniffers": [{"id": s.id, "name": s.name} for s in SNIFFERS],
                              "floor_height_m": MAPS.data["floor_height_m"]})


@web.middleware
async def ingress_only(request: web.Request, handler):
    """Only Home Assistant's ingress proxy (which has checked the user's login) gets an answer. The
    port is reachable from every container on HA's internal network, and the page can change the
    channel, start firmware updates and show decrypted frames. Zigbee Studio may also GET a few
    read-only answers and set up the floor maps, with its key (studio.py)."""
    if request.remote not in ALLOW:
        if studio.allowed(request.method, request.path, request.headers.get(studio.HEADER), STUDIO_KEY):
            return await handler(request)
        log.warning("Refused a request from %s (only Home Assistant's ingress may use this page)", request.remote)
        raise web.HTTPForbidden(text="Open the Zigbee Sniffer from Home Assistant's sidebar.")
    return await handler(request)


@web.middleware
async def errors(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except (ValueError, KeyError) as e:
        raise web.HTTPBadRequest(text=str(e)) from e


async def main() -> None:
    if TIME_ZONE and not Path("/usr/share/zoneinfo", TIME_ZONE).exists() and os.name != "nt":
        log.warning("No time-zone data for %s: capture files are named in UTC", TIME_ZONE)
    log.info("Time zone %s; our network: PAN %s; sniffers: %s", TIME_ZONE or "UTC",
             decode.pan_text(our_pan()) or "unknown (showing every network)",
             ", ".join(f"{s.name} ({s.host or 'no host'})" for s in SNIFFERS))
    if STORE.recovered:
        log.warning(STORE.recovered)
    for old, new, appended_at in await asyncio.to_thread(pcap.rename_to_local_time, CAPTURE_DIR):
        log.info("Renamed %s -> %s (local hour)", old, new)
        if appended_at is None:
            await asyncio.to_thread(STORE.rename_file, old, new)  # its counted offsets go with it
        elif (STORE.file(old) or {}).get("offset"):
            # appended to an existing hour, and already counted under its old name: not again
            frames, end = await asyncio.to_thread(pcap.scan, CAPTURE_DIR / new)
            await asyncio.to_thread(STORE.set_file, new, offset=end, frames=frames)
    NAMES.reload()
    ANALYZER.our_ieee = set(NAMES.by_ieee)
    cfg = names_mod.load_z2m_config()
    HA.z2m_base = names_mod.base_topic(cfg)
    S.key_loaded = names_mod.write_tshark_keys(TSHARK_HOME, names_mod.network_key(cfg))
    pairs = STORE.address_pairs()
    ANALYZER.seed_addresses(pairs)
    learn_addresses(pairs)
    S.seen = STORE.seen()
    S.msg_seen = STORE.msg_seen()
    S.channel = load_channel()
    global STUDIO_KEY
    try:
        STUDIO_KEY = studio.ensure_key(studio.KEY_FILE, ZIGBEE_STUDIO)
    except OSError as e:
        log.warning("Could not keep Zigbee Studio's key in %s: %s", studio.KEY_FILE, e)
    if STUDIO_KEY:
        log.info("Zigbee Studio may read devices, health and live frames and set up the floor maps (key in %s)",
                 studio.KEY_FILE)
    app = web.Application(middlewares=[ingress_only, errors], client_max_size=24 * 1024 * 1024)  # firmware, floor plans
    app.add_routes([
        web.get("/", page),
        web.get("/static/{name}", static_file),
        web.get("/api/status", api_status),
        web.get("/api/overview", api_overview),
        web.get("/api/devices", api_devices),
        web.get("/api/device/{addr}", api_device),
        web.get("/api/device/{addr}/hours", api_device_hours),
        web.get("/api/mesh", api_mesh),
        web.get("/api/networks", api_networks),
        web.get("/api/live", api_live),
        web.get("/api/captures", api_captures),
        web.get("/api/decode", api_decode),
        web.get("/api/frame", api_frame),
        web.post("/api/channel", api_channel),
        web.get("/api/sniffer", api_sniffer),
        web.post("/api/sniffer/moved", api_sniffer_moved),
        web.post("/api/firmware/inspect", api_firmware_inspect),
        web.post("/api/firmware/{target}", api_firmware_flash),
        web.post("/api/ping/{addr}", api_ping),
        web.get("/api/trace/{addr}", api_trace),
        web.get("/api/map", api_map),
        web.post("/api/map/floors", api_map_floor_add),
        web.post("/api/map/floors/{fid}", api_map_floor_update),
        web.delete("/api/map/floors/{fid}", api_map_floor_delete),
        web.post("/api/map/floors/{fid}/image", api_map_image_put),
        web.get("/api/map/floors/{fid}/image", api_map_image),
        web.post("/api/map/positions", api_map_positions),
        web.get("/api/map/coverage", api_map_coverage),
        web.get("/download/{rel:.+}", download),
        web.get("/decoded/{rel:.+}", download_decoded),
    ])
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, BIND, WEB_PORT).start()
    live = await asyncio.start_server(live_pcap_client, BIND, LIVE_PORT)
    log.info("Web page on :%d (ingress), live Wireshark stream on :%d, captures in %s, history in %s",
             WEB_PORT, LIVE_PORT, CAPTURE_DIR, DATA_DIR / "history.db")
    tasks = [("catch-up", catch_up, False), ("history", flusher, True), ("decoder", decoder, True),
             ("housekeeping", housekeeping, True), ("ticker", ticker, True), ("Home Assistant", ha_publisher, True),
             ("HA events", HA.run_events, True), ("Wireshark stream", live.serve_forever, True)]
    for sn in SNIFFERS:
        tasks += [(f"sniffer {sn.name}", lambda sn=sn: sn.run(S.ready, PCAP.flush), True),
                  (f"bridge status {sn.name}", sn.web.run, True)]
    await asyncio.gather(*(supervise(name, fn, again) for name, fn, again in tasks))


async def supervise(name: str, fn, again: bool) -> None:
    """Run one of the app's tasks; if it ever fails, log it and start it again (one task's bug must
    not end the app, or leave it running without that part)."""
    delay = 2
    while True:
        try:
            await fn()
            if not again:
                return
            log.warning("The %s task ended; starting it again", name)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("The %s task failed; starting it again in %d s", name, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 60)


if __name__ == "__main__":
    asyncio.run(main())
