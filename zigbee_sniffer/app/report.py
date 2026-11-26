"""What the history says: the device table with its findings, the overview, one device's
story (signal, traffic, who it talks to, its mesh links, its events) and the mesh map.

A word on RSSI: the sniffer's RSSI is how well the *sniffer* hears a device, which depends on
where the sniffer sits and on its antenna. With several sniffers a device's signal is the one
sniffer that hears it best (named), its chart has a line per sniffer, and "weaker than usual"
compares each sniffer with its own normal: sniffers differ by many dB (antennas), so a mix of them
would jump whenever one comes, goes or moves. How well devices hear each other is in the routers' Link Status costs
(1 = excellent ... 7 = barely usable), and delivery trouble shows as retries, missing ACKs,
route errors, leaves and rejoins. The findings weigh those first.

Findings are judged in context:

- **Incidents.** When the whole mesh is in trouble at once (traffic many times its normal, route
  failures on many routers in the same minutes, firmware updates flooding the channel), that is
  one incident with a start, an end and a likely cause, not dozens of per-device warnings: a
  device's findings that fall inside an incident are marked so and count one level lower.
- **Baselines.** Each device is compared with its own previous 7 days (traffic, resends, signal,
  relaying) as well as with fixed limits, and resends with the network's rate at the same time.
- **Firmware updates.** A device downloading firmware (OTA image blocks, read by the tshark pass)
  is shown with its progress, and its findings during the download are marked.
"""

import asyncio
import re
import statistics
import time
from collections import Counter

import names as names_mod
from analysis import BROADCAST, unicast

RANGES = {"1h": (3600, 60), "6h": (21600, 300), "24h": (86400, 900), "7d": (604800, 3600)}
SPARK_POINTS = 24
SEV = {"high": 3, "warn": 2, "info": 1}
DEMOTE = {"high": "warn", "warn": "info", "info": "info"}
EVENT_WORDS = {
    "leave": "left the network", "rejoin": "rejoin request", "rejoin_response": "rejoined",
    "announce": "announced itself", "network_status": "route error", "orphan": "orphan notification",
    "route_failure_up": "couldn't forward toward the coordinator", "address_conflict": "address conflict",
    "bad_frame_counter": "stale frame counter",
    "address_change": "short address changed", "address_reused": "short address reused",
    "association": "join request", "association_response": "joined", "ed_timeout": "attached to a parent",
    "network_report": "network report", "network_update": "network update",
    "ota_start": "firmware download started", "ota_offer": "firmware offered", "ota_done": "firmware downloaded",
    "ota_failed": "firmware download failed",
    "z2m_online": "Zigbee2MQTT online", "z2m_offline": "Zigbee2MQTT offline", "z2m_restart": "Zigbee2MQTT restarted",
    "sniffer_added": "sniffer added", "sniffer_offline": "sniffer offline", "sniffer_back": "sniffer back",
    "sniffer_moved": "sniffer moved",
    "device_joined": "joined (Zigbee2MQTT)", "device_interview": "interview (Zigbee2MQTT)",
    "device_leave": "left (Zigbee2MQTT)", "device_announce": "announced (Zigbee2MQTT)",
}
ROUTE_FINDING_KINDS = ("route_failure_up", "network_status")
SUM_FIELDS = ("tx", "rssi_sum", "lqi_sum", "uni", "retry", "relay", "poll", "msgs", "rx", "noack", "air", "minutes")
BASELINE_DAYS = 7
SNIFFER_NORMAL_HOURS = 12  # a sniffer needs this much history (since it was placed) before its normals count
STALE_S = 90  # a cached answer is kept until the history changes, but never longer than this
OTA_GAP_S = 600  # image blocks this far apart belong to two downloads
OTA_LOOKBACK_S = 3 * 3600  # a download that began before the range is still shown whole


def fw_version(v) -> str:
    """A Zigbee OTA file version (32 bits: application release, build, stack release, build) as
    "1.0.43.0"; "" when unknown."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    return ".".join(str((v >> sh) & 0xFF) for sh in (24, 16, 8, 0)) if v > 0 else ""


def _pct(a: int, b: int) -> float | None:
    return round(100 * a / b, 1) if b else None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _gap_text(s: float) -> str:
    if s < 90:
        return f"{round(s)} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} days"


def _clock(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def link_cost(a: int | None, b: int | None) -> int | None:
    """A link's cost: the worse of its two directions. 0 means not known yet, so it doesn't count."""
    known = [c for c in (a, b) if c]
    return max(known) if known else None


def latest_tables(links: list[dict]) -> dict[str, list[dict]]:
    """Each router's most recent Link Status table (all entries from its last report cycle)."""
    by_router: dict[str, list[dict]] = {}
    for link in links:
        if link["last_in"] is not None:
            by_router.setdefault(link["router"], []).append(link)
    out = {}
    for router, rows in by_router.items():
        newest = max(r["last_ts"] or 0 for r in rows)
        out[router] = [r for r in rows if (r["last_ts"] or 0) >= newest - 60]
    return out


def find_path(hops: dict[tuple[str, str], int], start: str, end: str) -> list[str | None]:
    """The usual chain of MAC hops from start to end (None marks hops the sniffer didn't hear)."""
    fwd, cur, used = [start], start, {start}
    for _ in range(10):
        if cur == end:
            return fwd
        nxt = max(((d, n) for (s, d), n in hops.items() if s == cur and d not in used), key=lambda x: x[1], default=None)
        if not nxt:
            break
        cur = nxt[0]
        fwd.append(cur)
        used.add(cur)
    if cur == end:
        return fwd
    back, cur = [end], end
    for _ in range(10):
        prv = max(((s, n) for (s, d), n in hops.items() if d == cur and s not in back), key=lambda x: x[1], default=None)
        if not prv:
            break
        cur = prv[0]
        if cur in used:
            return fwd[: fwd.index(cur) + 1] + back
        back.insert(0, cur)
    return fwd + [None] + back


def _split_noack(row: dict, resent: int) -> None:
    """Split the frames sent to a device with no ACK heard into real losses (its neighbours sent the
    frame again: a MAC retry follows only a missing ACK) and ACKs the sniffers missed (the sender
    carried on, so it got one). `resent` = MAC retries of frames to it (link_tx), counted per hour,
    so it is capped at the missing ACKs counted per minute."""
    lost = min(resent, row["noack"])
    row["rx_lost"] = lost
    row["rx_lost_pct"] = _pct(lost, row["rx"])
    row["noack_missed"] = row["noack"] - lost


def _merge_totals(a: dict, b: dict) -> dict:
    """Two devices' totals as one (a device heard under an old and a new short address)."""
    out = dict(a)
    for f in SUM_FIELDS:
        out[f] = (a.get(f) or 0) + (b.get(f) or 0)
    for f, pick in (("rssi_min", min), ("rssi_max", max), ("last_minute", max), ("first_minute", min)):
        vals = [v for v in (a.get(f), b.get(f)) if v is not None]
        out[f] = pick(vals) if vals else None
    return out


def _merge_counts(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return out


class Report:
    def __init__(self, store, names, state) -> None:
        self.store, self.names, self.S = store, names, state
        self._cache: dict = {}  # key -> (computed at, history generation, value)
        self.gen = 0  # bumped whenever the history is written
        self.sniffer_names: dict[str, str] = {}  # sniffer id -> name (set by the app)
        self.sniffer_moves: dict[str, float] = {}  # sniffer id -> when it was moved (its normals start again)
        self.sniffer_hours: dict[str, int] = {}  # sniffer id -> hours of history its normals have (last baseline)
        self._normal_hours: dict[int, dict[str, int]] = {}  # the same, per baseline window

    @property
    def several(self) -> bool:
        return len(self.sniffer_names) > 1

    def _sniffer_name(self, sid: str) -> str:
        return self.sniffer_names.get(sid, sid)

    def invalidate(self) -> None:
        """New decoded data: drop what depends on it (the baselines are about earlier days)."""
        for k in list(self._cache):  # list(): worker threads add entries meanwhile
            if k[0] != "baselines":
                self._cache.pop(k, None)

    def history_written(self) -> None:
        """The history got new rows (every FLUSH_S): answers computed before are out of date. Until
        then they stay good: the pages poll every few seconds, and the 7-day overview takes a second."""
        self.gen += 1

    def _hit(self, key, ttl: float):
        hit = self._cache.get(key)
        if hit:
            age = time.time() - hit[0]
            if age < ttl or (hit[1] == self.gen and age < STALE_S):
                return hit
        return None

    async def _cached(self, key, ttl: float, fn, *args):
        """fn(*args), kept for `ttl` seconds, or until the history is next written (at most STALE_S)."""
        hit = self._hit(key, ttl)
        if hit:
            return hit[2]
        gen = self.gen
        val = await asyncio.to_thread(fn, *args)
        self._cache[key] = (time.time(), gen, val)
        return val

    def _cached_sync(self, key, ttl: float, fn, *args):
        """The same, from inside a worker thread."""
        hit = self._hit(key, ttl)
        if hit:
            return hit[2]
        gen = self.gen
        val = fn(*args)
        self._cache[key] = (time.time(), gen, val)
        if len(self._cache) > 200:  # time-keyed entries pile up: keep the newest
            for k, _ in sorted(list(self._cache.items()), key=lambda kv: kv[1][0])[:100]:
                self._cache.pop(k, None)
        return val

    def _name(self, addr: str | None) -> str:
        if not addr:
            return ""
        if addr in BROADCAST:
            return "broadcast"
        return self.names.name(addr) or ""

    def _label_events(self, events: list[dict]) -> list[dict]:
        """Names for the addresses in events (and in their text)."""
        for e in events:
            e["name"] = self._name(e["addr"]) or (self.names.name(e["ieee"]) if e["ieee"] else "") or ""
            e["other_name"] = self._name(e["other"])
            e["what"] = EVENT_WORDS.get(e["kind"], e["kind"])
            e["detail"] = re.sub(r"(?<!address )(?<!was )0x[0-9a-f]{4}(?![0-9a-f])", lambda m: self._name(m.group(0)) or m.group(0), e["detail"] or "")
        return events

    def _seen(self) -> dict[str, tuple]:
        seen = self.store.seen()
        for a, v in self.S.seen.copy().items():  # a copy: the frame path adds devices meanwhile
            if a not in seen or seen[a][0] < v[0]:
                seen[a] = v
        return seen

    def _msg_seen(self) -> dict[str, float]:
        out = self.store.msg_seen()
        for a, ts in self.S.msg_seen.copy().items():
            if ts > out.get(a, 0):
                out[a] = ts
        return out

    def _listening(self) -> tuple[bool, float]:
        """(is any sniffer connected, when the last frame of our network was heard)."""
        return bool(self.S.listening), self.S.last_frame_ts or 0.0

    def marks(self, since: float, addr: str | None = None, sniffer: str | None = None) -> list[dict]:
        rows = self.store.marks(since, addr, sniffer)
        out = []
        for r in rows:
            who = self._name(r["addr"]) if r["addr"] not in ("z2m", "sniffer", "") else ""
            detail = re.sub(r"0x[0-9a-f]{4}(?![0-9a-f])", lambda m: self._name(m.group(0)) or m.group(0), r["detail"] or "")
            text = f"{who}: {detail}" if who and detail else (detail or who or EVENT_WORDS.get(r["kind"], r["kind"]))
            out.append({"ts": r["ts"], "kind": r["kind"], "text": text,
                        "addr": r["addr"] if r["addr"] not in ("z2m", "sniffer") else None})
        return out

    # ------------------------------------------------------------ baselines

    def _baselines(self, since: float) -> dict[str, dict]:
        """Each device's normal over the BASELINE_DAYS before `since` (hourly rates; None when there
        isn't half a day of history)."""
        # Each sniffer's own normal for the device's signal: only from where it is now (since it was last
        # moved), and only once it has half a day of that (two hours at a desk is no normal)
        per: dict[str, dict[str, list]] = {}
        s_hours: dict[str, set] = {}
        for r in self.store.device_sniffer_hourly(since - BASELINE_DAYS * 86400, since):
            moved = self.sniffer_moves.get(r["sniffer"])
            if moved and r["h"] < moved:
                continue
            s_hours.setdefault(r["sniffer"], set()).add(r["h"])
            a = per.setdefault(r["addr"], {}).setdefault(r["sniffer"], [0, 0])
            a[0] += r["n"] or 0
            a[1] += r["rs"] or 0
        self.sniffer_hours = {sid: len(hs) for sid, hs in s_hours.items()}
        self._normal_hours[int(since // 1800)] = self.sniffer_hours
        while len(self._normal_hours) > 20:
            self._normal_hours.pop(next(iter(self._normal_hours)))
        settled = {sid for sid, hs in s_hours.items() if len(hs) >= SNIFFER_NORMAL_HOURS}
        rows = self.store.device_hourly(since - BASELINE_DAYS * 86400, since)
        hours = len({r["h"] for r in rows})
        if hours < 12:
            return {}
        acc: dict[str, dict] = {}
        for r in rows:
            a = acc.setdefault(r["addr"], {"tx": 0, "rs": 0, "uni": 0, "retry": 0, "relay": 0, "msgs": 0})
            for k in a:
                a[k] += r[k] or 0
        out = {}
        for addr, a in acc.items():
            out[addr] = {
                "tx_per_h": round(a["tx"] / hours, 1), "relay_per_h": round(a["relay"] / hours, 1),
                "msgs_per_h": round(a["msgs"] / hours, 1),
                "retry_pct": round(100 * a["retry"] / a["uni"], 1) if a["uni"] >= 50 else None,
                "rssi_avg": round(a["rs"] / a["tx"], 1) if a["tx"] >= 20 else None, "days": round(hours / 24, 1),
                "rssi_by_sniffer": {sid: round(rs / n, 1) for sid, (n, rs) in per.get(addr, {}).items()
                                    if n >= 20 and sid in settled},
            }
        return out

    def baselines(self, since: float) -> dict[str, dict]:
        return self._cached_sync(("baselines", int(since // 1800)), 1800, self._baselines, since)

    def normal_hours(self, since: float) -> dict[str, int]:
        """Hours of history each sniffer's normals rest on, for the baseline before `since`."""
        self.baselines(since)
        return self._normal_hours.get(int(since // 1800), self.sniffer_hours)

    def forget_baselines(self) -> None:
        """A sniffer was moved: work the normals out again (and everything built on them)."""
        self._cache.clear()

    # ------------------------------------------------------------ incidents

    def incidents(self, since: float, now: float) -> list[dict]:
        return self._cached_sync(("incidents", int(since // 60)), 20, self._incidents, since, now)

    def _incidents(self, since: float, now: float) -> list[dict]:
        """Stretches where the whole mesh was in trouble at once, with the evidence and a likely cause."""
        st = self.store
        net = {r[0]: r for r in st.net_series(since, 60)}  # minute -> [m, ours, others, unnamed, air_ours, air_all, uni, retry, noack, ...]
        if not net:
            return []
        ours = sorted(r[1] for r in net.values())
        base = statistics.median(ours) if ours else 0
        if since > now - 86400:  # a short range: take the normal from the day before as well
            prev = [r[1] for r in st.net_series(now - 86400, 60)]
            if len(prev) >= 120:
                base = statistics.median(prev)
        base = max(base, 20)
        route = st.event_minutes(since, ROUTE_FINDING_KINDS)
        route_by_min: dict[int, set] = {}
        for m, addr, _kind in route:
            route_by_min.setdefault(m, set()).add(addr)
        ota_by_min: dict[int, set] = {}
        for m, addr in st.ota_minutes(since):
            ota_by_min.setdefault(m, set()).add(addr)
        minutes = sorted(set(net) | set(route_by_min) | set(ota_by_min))
        bad = []
        for m in minutes:
            r = net.get(m)
            window_routers = set()
            for k in range(m - 240, m + 60, 60):
                window_routers |= route_by_min.get(k, set())
            traffic_x = (r[1] / base) if r else 0
            retry_pct = (100 * r[7] / r[6]) if r and r[6] >= 100 else 0
            # (a minute counts for route failures only if it has some itself, so an incident ends with them)
            if (traffic_x >= 3 and r[1] >= 200) or (len(window_routers) >= 5 and route_by_min.get(m)) \
                    or len(ota_by_min.get(m, ())) >= 3 or retry_pct >= 10:
                bad.append(m)
        # group bad minutes into stretches, bridging gaps of up to 5 minutes
        spans: list[list[int]] = []
        for m in bad:
            if spans and m - spans[-1][1] <= 360:
                spans[-1][1] = m
            else:
                spans.append([m, m])
        marks = st.marks(since - 600)
        out = []
        for start, end in spans:
            mins = [m for m in minutes if start <= m <= end]
            rows = [net[m] for m in mins if m in net]
            routers = set().union(*(route_by_min.get(m, set()) for m in mins)) if mins else set()
            ota_devs = set().union(*(ota_by_min.get(m, set()) for m in mins)) if mins else set()
            if end - start < 120 and len(routers) < 8 and not ota_devs:
                continue
            peak = max((r[1] for r in rows), default=0)
            uni = sum(r[6] for r in rows)
            retry = sum(r[7] for r in rows)
            busy = max((r[5] / 60e6 * 100 for r in rows), default=0)
            route_n = sum(len(route_by_min.get(m, ())) for m in mins)
            ongoing = end >= now - 240
            z2m = [mk for mk in marks if start - 600 <= mk["ts"] <= end + 120
                   and mk["kind"] in ("z2m_restart", "z2m_offline", "z2m_online")]
            failed = {mk["addr"] for mk in marks if start <= mk["ts"] <= end + 300 and mk["kind"] == "ota_failed"}
            causes = []  # (the firmware updates are the title when there are any: not said again here)
            if z2m:
                restart = next((mk for mk in z2m if mk["kind"] in ("z2m_restart", "z2m_offline")), z2m[0])
                causes.append(f"Zigbee2MQTT {'restarted' if restart['kind'] != 'z2m_online' else 'came back'} at {_clock(restart['ts'])}")
            traffic_x = round(peak / base, 1) if base else None
            if ota_devs:
                title = f"Firmware updates of {_plural(len(ota_devs), 'device')}"
            elif traffic_x and traffic_x >= 3:
                title = f"Traffic surge (×{traffic_x:g})"
            elif len(routers) >= 5:
                title = f"Route failures on {_plural(len(routers), 'router')}"
            else:
                title = "Delivery trouble across the network"
            detail = []
            if ota_devs:
                fw = self.ota(since, now)
                states = Counter(fw.get(a, {}).get("state") for a in ota_devs)
                detail.append(", ".join(f"{n} {w}" for w, n in (("done", states["done"]), ("updating", states["updating"]),
                                                                ("failed", max(states["failed"], len(failed))),
                                                                ("stalled", states["stalled"])) if n) or "firmware downloads")
                if ongoing and not states["updating"] and end < now - 120:
                    ongoing = False  # the downloads are over: so is the incident, whatever the last 4 minutes held
            if traffic_x and traffic_x >= 2:
                detail.append(f"traffic up to {traffic_x:g}× normal")
            if busy >= 10:
                detail.append(f"channel {busy:.0f}% busy")
            if uni >= 100 and retry / uni >= 0.04:
                detail.append(f"{round(100 * retry / uni, 1)}% resent")
            if routers:
                detail.append(f"route failures from {_plural(len(routers), 'device')}")
            sev = "high" if len(routers) >= 15 or busy >= 30 else "warn"
            devices = sorted(routers | ota_devs)
            out.append({
                "id": f"inc-{start}", "start": start, "end": None if ongoing else end + 60, "sev": sev,
                "title": title, "detail": ", ".join(detail), "cause": "; ".join(causes) or None,
                "devices": [{"addr": a, "name": self._name(a) or a} for a in devices],
                "evidence": {"traffic_x": traffic_x, "busy_pct": round(busy, 1),
                             "retry_pct": round(100 * retry / uni, 1) if uni else None, "route_failures": route_n,
                             "devices_n": len(devices), "ota_n": len(ota_devs)},
            })
        return out

    # ------------------------------------------------------------ firmware updates

    def ota(self, since: float, now: float) -> dict[str, dict]:
        return self._cached_sync(("ota", int(since // 60)), 20, self._ota, since, now)

    def _ota(self, since: float, now: float) -> dict[str, dict]:
        """Each device's firmware downloads in the range, read from the image blocks on air: when
        each began and ended, where it began (a download that was cut off picks up where it
        stopped), how far it got, how fast, how it ended (the device's Upgrade End, or Zigbee2MQTT's
        result with the versions) and whether the device restarted with it afterwards. The latest
        download stands for the device, with its earlier ones under `sessions`."""
        rows = self.store.ota_rows(since - OTA_LOOKBACK_S)
        if not rows:
            return {}
        marks = self.store.marks(since - OTA_LOOKBACK_S)
        ends: dict[str, list] = {}
        restarts: dict[str, list[float]] = {}
        for mk in marks:
            if not mk["addr"]:
                continue
            if mk["kind"] in ("ota_done", "ota_failed"):
                ends.setdefault(mk["addr"], []).append(mk)
            elif mk["kind"] in ("device_announce", "device_interview", "device_joined"):
                restarts.setdefault(mk["addr"], []).append(mk["ts"])
        by: dict[str, list] = {}
        for m, addr, blocks, lo, hi, size in rows:
            by.setdefault(addr, []).append((m, blocks or 0, lo, hi or 0, size or 0))
        out = {}
        for addr, rs in by.items():
            sessions, cur, size_seen = [], None, 0
            for m, blocks, lo, hi, size in rs:
                size_seen = size or size_seen
                if not blocks:  # an offer (the image's size) without blocks this minute
                    continue
                if cur is None or m - cur["last"] > OTA_GAP_S:
                    cur = {"start": m, "last": m, "blocks": 0, "lo": lo, "hi": 0, "size": size_seen}
                    sessions.append(cur)
                cur["last"], cur["blocks"] = m, cur["blocks"] + blocks
                cur["hi"] = max(cur["hi"], hi)
                if lo is not None:
                    cur["lo"] = lo if cur["lo"] is None else min(cur["lo"], lo)
                cur["size"] = size or cur["size"] or size_seen
            done = []
            for i, ss in enumerate(sessions):
                end_ts = ss["last"] + 60
                if end_ts < since:
                    continue
                nxt = sessions[i + 1]["start"] if i + 1 < len(sessions) else now + 1
                result = None
                for mk in ends.get(addr, []):  # how it ended: a result after it began (Zigbee2MQTT's, with the versions, wins)
                    if ss["start"] <= mk["ts"] <= min(nxt, end_ts + 900):
                        if result is None or ("updated from" in (mk["detail"] or "") and "updated from" not in (result["detail"] or "")):
                            result = mk
                size, hi, lo = ss["size"], ss["hi"], ss["lo"]
                dur = max(60, end_ts - ss["start"])
                # (lo is None for minutes stored before 0.5.4: where it began isn't known, nor how much came)
                got = max(0, hi - lo) if lo is not None else None
                state = ("done" if result["kind"] == "ota_done" else "failed") if result else \
                    "updating" if now - end_ts <= 180 else "stalled"
                rate = got / dur if got else None
                restarted = next((t for t in sorted(restarts.get(addr, [])) if result and result["ts"] - 30 <= t <= result["ts"] + 900), None)
                done.append({
                    "started": ss["start"], "last_ts": end_ts, "duration": dur, "state": state, "blocks": ss["blocks"],
                    "size": size or None, "progress": round(min(1.0, hi / size), 3) if size else None,
                    "from": round(min(1.0, lo / size), 3) if size and lo is not None else None,
                    "bytes": got, "rate": round(rate) if rate else None,
                    "eta": round((size - hi) / rate) if state == "updating" and rate and size and hi < size else None,
                    "result": result["detail"] if result else None, "result_ts": result["ts"] if result else None,
                    "restarted": restarted,
                })
            if not done:
                continue
            latest = done[-1]
            out[addr] = {"addr": addr, "name": self._name(addr) or addr, **latest, "sessions": done}
        return out

    def firmware(self, since: float, now: float) -> dict:
        """Firmware for the Overview: the downloads in the range, and what Zigbee2MQTT says about every
        device's firmware (installed and latest version, update available)."""
        ota = self.ota(since, now)
        z2m = names_mod.load_z2m_updates()
        rows, available = [], []
        for addr, o in ota.items():
            rows.append({**o, "z2m": self._z2m_fw(z2m, addr)})
        for ieee, u in z2m.items():
            if u.get("state") in ("available", "updating", "scheduled"):
                addr = self.names.current_short(ieee) or ieee
                available.append({"addr": addr, "name": self.names.name(addr) or self.names.by_ieee.get(ieee) or ieee,
                                  **self._z2m_fw(z2m, addr, ieee)})
        rows.sort(key=lambda r: (r["state"] != "updating", -(r["last_ts"] or 0)))
        available.sort(key=lambda r: r["name"].lower())
        return {"active": sum(1 for r in rows if r["state"] == "updating"), "devices": rows, "available": available,
                "known": len(z2m)}

    def _z2m_fw(self, z2m: dict, addr: str, ieee: str | None = None) -> dict | None:
        u = z2m.get((ieee or self.names.ieee(addr) or "").lower())
        if not u:
            return None
        return {"state": u["state"], "installed": fw_version(u["installed"]), "latest": fw_version(u["latest"]),
                "notes": u["notes"]}

    # ------------------------------------------------------------ devices

    async def devices(self, rng: str) -> dict:
        return await self._cached(("devices", rng), 8, self._devices, rng)

    def _devices(self, rng: str) -> dict:
        span, _ = RANGES[rng]
        now = time.time()
        since = now - span
        st = self.store
        spark_bucket = max(60, (span // SPARK_POINTS) // 60 * 60)
        totals = st.devices(since)
        sparks = st.device_sparks(since, spark_bucket)
        sig, ssparks = st.device_sniffer_buckets(since, spark_bucket)
        cmds = st.cmd_totals(since)
        events = st.event_counts(since)
        hops = st.hops(since)
        tables = latest_tables(st.links(since))
        seen = self._seen()
        msg_seen = self._msg_seen()
        links = st.link_tx(since)
        baselines = self.baselines(since)
        incidents = self.incidents(since, now)
        ota = self.ota(since, now)
        z2m_fw = names_mod.load_z2m_updates()
        net = st.net_totals(since)

        # one row per device: fold a device's old short addresses into its current one (the history's
        # pairs know the old ones; the names only keep the current pair)
        hist = dict(st.address_pairs())
        by_ieee: dict[str, list[str]] = {}
        for addr in totals:
            ieee = self.names.ieee(addr) or hist.get(addr)
            if ieee:
                by_ieee.setdefault(ieee, []).append(addr)
        for ieee, addrs in by_ieee.items():
            if len(addrs) < 2:
                continue
            cur = self.names.current_short(ieee)
            keep = cur if cur in addrs else max(addrs, key=lambda a: totals[a].get("last_minute") or 0)
            for a in addrs:
                if a == keep:
                    continue
                totals[keep] = _merge_totals(totals[keep], totals.pop(a))
                for sid, v in sig.pop(a, {}).items():
                    k = sig.setdefault(keep, {}).get(sid)
                    if k is None:
                        sig[keep][sid] = dict(v)
                    else:
                        k["n"] += v["n"]
                        k["rs"] += v["rs"]
                        k["mn"] = min((x for x in (k["mn"], v["mn"]) if x is not None), default=None)
                        k["mx"] = max((x for x in (k["mx"], v["mx"]) if x is not None), default=None)
                cmds[keep] = _merge_counts(cmds.get(keep, {}), cmds.pop(a, {}))
                events[keep] = _merge_counts(events.get(keep, {}), events.pop(a, {}))
                if a in seen and (keep not in seen or seen[a][0] > seen[keep][0]):
                    seen[keep] = seen[a]
                msg_seen[keep] = max(msg_seen.get(keep, 0), msg_seen.get(a, 0))

        next_hop: dict[str, Counter] = {}
        relayers: dict[str, Counter] = {}
        parents: dict[str, Counter] = {}
        for h in hops:
            ms, md, ns = h["mac_src"], h["mac_dst"], h["nwk_src"]
            if unicast(md) and (not ns or ns == ms):
                next_hop.setdefault(ms, Counter())[md] += h["n"]
                parents.setdefault(ms, Counter())[md] += h["n"]
            if ns and ns != ms:
                relayers.setdefault(ns, Counter())[ms] += h["n"]
        reported: dict[str, list[dict]] = {}  # device -> routers' entries about it
        for router, rows in tables.items():
            for r in rows:
                reported.setdefault(r["neighbor"], []).append(r)
        resend_to: dict[str, list] = {}
        resent_into: Counter = Counter()  # device -> frames its neighbours had to send it again
        for lk in links:
            resend_to.setdefault(lk["src"], []).append(lk)
            resent_into[lk["dst"]] += lk["retry"] or 0
        # route-error minutes inside incidents, to tell a device's own trouble from the network's
        windows = [(i["start"], i["end"] or now + 60, {d["addr"] for d in i["devices"]}) for i in incidents]
        route_in: Counter = Counter()
        for m, addr, kind in st.event_minutes(since, ROUTE_FINDING_KINDS):
            if any(s <= m < e for s, e, _ in windows):
                route_in[(addr, kind)] += 1

        ctx = {"span": span, "now": now, "net_retry_pct": _pct(net["retry"], net["uni"]) if net["uni"] >= 200 else None,
               "listening": self._listening(), "incidents": windows, "route_in": route_in}
        rows, heard_ieee, used_addrs = [], set(), set()
        for addr, t in totals.items():
            if addr in BROADCAST or addr == "0xfffe":
                continue
            row = self._row(addr, t, seen.get(addr), sparks.get(addr, []), cmds.get(addr, {}), events.get(addr, {}),
                            next_hop.get(addr), relayers.get(addr), tables.get(addr), reported.get(addr),
                            sig=sig.get(addr), ssparks=ssparks.get(addr))
            row["last_msg"] = msg_seen.get(addr)
            row["parents"] = parents.get(addr)
            row["resend_to"] = resend_to.get(addr, [])
            _split_noack(row, resent_into.get(addr, 0))
            if row["ieee"]:
                heard_ieee.add(row["ieee"])
            used_addrs.add(addr)
            rows.append(row)
        # Zigbee2MQTT's devices the sniffer didn't hear at all in this range
        for ieee, meta in self.names.devices.copy().items():
            if ieee in heard_ieee or (meta.get("type") == "Coordinator" and "0x0000" in totals):
                continue
            if meta.get("type") == "Coordinator":
                addr = "0x0000"
            else:
                addr = self.names.current_short(ieee) or meta.get("nwk") or ieee
                if addr in used_addrs:  # that short address belongs to another device now
                    addr = ieee
            row = self._row(addr, {}, seen.get(addr), [], cmds.get(addr, {}), events.get(addr, {}),
                            None, None, tables.get(addr), reported.get(addr), meta=meta, ieee=ieee)
            row["last_msg"] = msg_seen.get(addr)
            row["parents"], row["resend_to"] = None, []
            _split_noack(row, 0)
            used_addrs.add(addr)
            rows.append(row)
        for r in rows:
            base = baselines.get(r["addr"])
            by = (base or {}).get("rssi_by_sniffer") or {}
            for x in r["signal"]:  # each sniffer against its own normal (None: no 7-day normal there yet)
                x["normal"] = by.get(x["sniffer"])
                x["change"] = round(x["rssi_avg"] - x["normal"], 1) if x["normal"] is not None and x["n"] >= 5 else None
            if base and r["signal"]:  # the normal signal at the sniffer shown (None if it is new there)
                base = {**base, "rssi_avg": by.get(r["rssi_sniffer"])}
            r["baseline"] = base
            r["ota"] = ota.get(r["addr"])
            r["fw_update"] = (z2m_fw.get((r["ieee"] or "").lower()) or {}).get("state")
            r["flags"] = self._flags(r, ctx)
            r["sev"] = max((SEV[f["sev"]] for f in r["flags"]), default=0)
            r.pop("resend_to", None)
            r["parents"] = len(r["parents"]) if r.get("parents") else None
        rows.sort(key=lambda r: (-r["sev"], r["name"].lower() or r["addr"]))
        return {"range": rng, "span": span, "spark_bucket": spark_bucket, "now": now, "devices": rows,
                "sniffers": [{"id": sid, "name": name} for sid, name in self.sniffer_names.items()]}

    def _row(self, addr, t, seen, spark, cmds, events, next_hop, relayers, own_links, reported,
             meta: dict | None = None, ieee: str | None = None, sig: dict | None = None,
             ssparks: dict | None = None) -> dict:
        meta = meta if meta is not None else self.names.meta(addr)
        tx, uni, rx = t.get("tx", 0), t.get("uni", 0), t.get("rx", 0)
        row = {
            "addr": addr, "name": (meta.get("name") if ieee else None) or self._name(addr) or meta.get("name", ""),
            "ieee": ieee or self.names.ieee(addr) or "",
            "type": meta.get("type", ""), "model": meta.get("model", ""), "vendor": meta.get("vendor", ""),
            "power": meta.get("power", ""), "known": bool(meta),
            "tx": tx, "rssi_avg": round(t["rssi_sum"] / tx, 1) if tx else None,
            "rssi_min": t.get("rssi_min"), "rssi_max": t.get("rssi_max"),
            "lqi_avg": round(t["lqi_sum"] / tx) if tx else None,
            "uni": uni, "retry": t.get("retry", 0), "retry_pct": _pct(t.get("retry", 0), uni),
            "relay": t.get("relay", 0), "poll": t.get("poll", 0), "msgs": t.get("msgs", 0),
            "rx": rx, "noack": t.get("noack", 0), "noack_pct": _pct(t.get("noack", 0), rx), "air": t.get("air", 0),
            "first_minute": t.get("first_minute"),
            "last_seen": seen[0] if seen else None, "last_rssi": seen[1] if seen else None,
            "cmds": cmds, "events": events, "spark": spark,
            "via": None, "heard_via": None, "mesh": None, "lopsided": [],
        }
        # the signal: per sniffer, and the one that hears it best stands for it (a mix of sniffers
        # would jump by their antennas' difference whenever one comes or goes)
        signal = sorted(({"sniffer": sid, "name": self._sniffer_name(sid), "n": v["n"],
                          "rssi_avg": round(v["rs"] / v["n"], 1), "rssi_min": v["mn"], "rssi_max": v["mx"]}
                         for sid, v in (sig or {}).items() if v["n"]), key=lambda x: -x["rssi_avg"])
        row["signal"], row["rssi_sniffer"], row["rssi_sniffer_name"] = signal, None, None
        if signal:
            most = max(x["n"] for x in signal)
            best = next((x for x in signal if x["n"] >= max(3, 0.02 * most)), signal[0])
            row["rssi_avg"], row["rssi_min"], row["rssi_max"] = best["rssi_avg"], best["rssi_min"], best["rssi_max"]
            row["rssi_sniffer"], row["rssi_sniffer_name"] = best["sniffer"], best["name"]
            sp = (ssparks or {}).get(best["sniffer"], {})
            row["spark"] = [[p[0], sp.get(p[0]), *p[2:]] for p in spark]
        if next_hop:
            dst, n = next_hop.most_common(1)[0]
            row["via"] = {"addr": dst, "name": self._name(dst), "n": n, "share": round(100 * n / sum(next_hop.values()))}
        if relayers and not tx:
            src, n = relayers.most_common(1)[0]
            row["heard_via"] = {"addr": src, "name": self._name(src), "n": n}
        # Link Status: the costs it reports for its neighbours, else what routers report about it
        costs = []
        if own_links:
            costs = [link_cost(r["last_in"], r["last_out"]) for r in own_links]
            for r in own_links:
                a, b = r["last_in"], r["last_out"]
                if a and b and ((a <= 3 and b >= 5) or (a >= 5 and b <= 3)):
                    row["lopsided"].append({"addr": r["neighbor"], "name": self._name(r["neighbor"]), "in": a, "out": b})
        elif reported:
            costs = [link_cost(r["last_in"], r["last_out"]) for r in reported]
        costs = [c for c in costs if c is not None]
        if costs:
            row["mesh"] = {"n": len(costs), "best": min(costs), "worst": max(costs),
                           "good": sum(c <= 3 for c in costs), "own": bool(own_links)}
        return row

    def _flags(self, r: dict, ctx: dict) -> list[dict]:
        flags: list[dict] = []
        span, now = ctx["span"], ctx["now"]
        listening, last_frame = ctx["listening"]
        in_incident = any(r["addr"] in devs for _, _, devs in ctx["incidents"])
        ota = r.get("ota")

        def flag(sev, code, text, context=None, detail=None):
            if context and sev != "info" and code not in ("leave", "silent", "not_heard", "unreachable", "ota"):
                sev = DEMOTE[sev]
            flags.append({"sev": sev, "code": code, "text": text, "context": context, "detail": detail})

        router = r["type"] in ("Router", "Coordinator")
        active = max(r["tx"], r["msgs"])
        ev, cmds = r["events"], r["cmds"]
        hours = max(1.0, span / 3600)
        context = "ota" if ota else "incident" if in_incident else None

        # silence: measured from the last time it was heard at all (directly or through relays),
        # up to the last time any sniffer heard anything - an outage of the sniffers isn't the device's
        if r["type"] != "Coordinator" and r["known"] and listening:
            last = max(r["last_seen"] or 0, r.get("last_msg") or 0) or None
            ref = max(last_frame, last or 0) if last_frame else now
            if not active and (last is None or ref - last > span):
                if router and last:
                    flag("high", "not_heard", f"Not heard for {_gap_text(ref - last)} (a router that stays away is down)")
                else:
                    flag("warn" if router else "info", "not_heard",
                         "Not heard in this time range" + (f" (last heard {_gap_text(ref - last)} ago)" if last else ""))
            elif last:
                gap = ref - last
                first = max(now - span, r["first_minute"] or now - span)
                usual = max(1.0, (ref - first)) / max(1, active)
                limit = max(6 * usual, 300 if router else 900)
                if gap > limit:
                    flag("high" if router else "warn", "silent",
                         f"Silent for {_gap_text(gap)} (it usually sends every {_gap_text(usual)})")
        # unreachable: frames go to it, nothing comes back, and it sends nothing itself
        if not r["tx"] and not r["msgs"] and r["rx"] >= 20 and r["noack_pct"] == 100:
            flag("high", "unreachable", f"Unreachable: {r['rx']} frames sent to it, none acknowledged, and it sent nothing")
        # delivery trouble: MAC retries of a few percent are normal in a busy mesh; a link in trouble
        # resends far more. Judged against the network's rate and the device's own normal, on enough frames.
        pct, uni = r["retry_pct"], r["uni"]
        base = r.get("baseline") or {}
        limit = max(8.0, 2 * (ctx["net_retry_pct"] or 0), 2 * (base.get("retry_pct") or 0))
        if uni >= 20 and pct is not None and pct >= limit:
            sev = "high" if pct >= max(30, limit + 15) and uni >= 100 else "warn" if pct >= max(15, limit + 5) and uni >= 40 else "info"
            notes = []
            if ctx["net_retry_pct"] is not None:
                notes.append(f"network-wide {ctx['net_retry_pct']}%")
            if base.get("retry_pct") is not None:
                notes.append(f"its normal {base['retry_pct']}%")
            worst = max((lk for lk in r.get("resend_to", []) if lk["uni"] >= 10), key=lambda lk: lk["retry"], default=None)
            if worst and worst["retry"] and r["retry"]:
                share = round(100 * worst["retry"] / r["retry"])
                notes.append(f"{share}% of the resends go to {self._name(worst['dst']) or worst['dst']} "
                             f"({_pct(worst['retry'], worst['uni'])}% of what it sends there)")
            flag(sev, "retries", f"{pct}% of its frames had to be resent ({r['retry']} of {uni})",
                 context, "; ".join(notes) or None)
        # A missing ACK is either a real loss - the sender then sends the frame again - or an ACK the
        # sniffers didn't catch (ACKs are short), after which the sender carries on. The resends tell
        # them apart, so the finding is judged on the real losses and names the missed ACKs apart.
        if r["rx"] >= 20 and r["noack_pct"] is not None and r["noack_pct"] >= 20 and r["tx"]:
            lost, missed, lost_pct = r["rx_lost"], r["noack_missed"], r["rx_lost_pct"] or 0
            detail = (f"no ACK heard for {r['noack']} of {r['rx']} frames sent to it: {lost} sent again "
                      f"(real losses), {missed} carried on (ACKs the sniffers missed)")
            if lost_pct >= 10:
                sev = "warn" if lost_pct >= 30 and r["rx"] >= 40 else "info"
                flag(sev, "no_ack", f"Lost {lost_pct}% of the frames sent to it ({lost} of {r['rx']} had to be "
                                    "sent again)", context, detail)
            elif missed >= 0.8 * r["noack"]:
                pass  # nearly all of it is ACKs the sniffers missed: nothing wrong with the device
            else:
                flag("info", "no_ack", f"No ACK heard for {r['noack_pct']}% of frames sent to it "
                                       f"({r['noack']} of {r['rx']}; {lost} of them sent again)", context, detail)
        # events
        if ev.get("leave"):
            flag("high", "leave", f"Left the network {_plural(ev['leave'], 'time')}")
        rejoins = max(ev.get("rejoin", 0), ev.get("rejoin_response", 0))
        if rejoins:
            flag("warn", "rejoin", f"Rejoined {_plural(rejoins, 'time')}", context)
        if ev.get("orphan"):
            flag("warn", "orphan", f"Lost its parent {_plural(ev['orphan'], 'time')} (orphan notification)", context)
        if ev.get("announce", 0) >= 2:
            flag("warn", "announce", f"Announced itself {ev['announce']} times (rebooting or rejoining)",
                 "ota" if ota else context)
        elif ev.get("announce") and r["type"] != "Coordinator":
            flag("info", "announce", "Announced itself once (joined, rejoined or power-cycled)")
        if ev.get("address_change") or ev.get("address_reused"):
            flag("warn", "address", "Its short address changed (it rejoined, or an address conflict)")
        if ev.get("address_conflict"):
            flag("warn", "address_conflict", f"Address conflict reported {_plural(ev['address_conflict'], 'time')} "
                 "(two devices claim its short address)")
        if ev.get("bad_frame_counter"):
            flag("warn", "frame_counter", f"Sent frames with a stale security frame counter "
                 f"({_plural(ev['bad_frame_counter'], 'report')}): after a reset or restore it may need re-pairing")
        # route errors, in distinct minutes and per hour of the range; the minutes inside a network-wide
        # incident are the network's trouble, not this device's
        for kind, code, word in (("route_failure_up", "uplink_errors",
                                  "Couldn't forward traffic toward the coordinator in {n} (its route up the mesh breaks)"),
                                 ("network_status_reported", "route_errors", "Reported route errors in {n} (it couldn't forward frames)"),
                                 ("network_status", "route_errors_to", "Routers couldn't reach it in {n}")):
            n = ev.get(kind, 0)
            if kind == "network_status" and r["type"] == "Coordinator":
                continue
            if n >= 3 and n / hours >= 0.25:
                inside = ctx["route_in"].get((r["addr"], "route_failure_up" if kind == "route_failure_up" else "network_status"), 0)
                text = word.format(n=_plural(n, "minute"))
                if n - inside < 3 or (n - inside) / hours < 0.25:
                    flag("info", code, text, "incident",
                         f"{inside} of those minutes during a network-wide incident" if inside else None)
                else:
                    flag("warn", code, text, None, f"{inside} of those during a network-wide incident" if inside else None)
        rreq = cmds.get("route_request", 0)
        if rreq >= 6 and rreq / hours >= 3 and r["type"] != "Coordinator":
            flag("warn", "route_discovery", f"Looked for routes {rreq} times (its routes keep breaking)", context)
        # mesh links
        mesh = r["mesh"]
        if mesh and mesh["own"]:
            if mesh["best"] >= 5:
                flag("warn", "weak_mesh", f"Weak mesh links: its best neighbour link costs {mesh['best']} (1 best, 7 worst)")
            elif mesh["n"] <= 2:
                flag("info", "few_neighbors", f"Only {_plural(mesh['n'], 'mesh neighbour')}")
        elif mesh and router and mesh["best"] >= 5:
            flag("warn", "weak_mesh", f"Routers report weak links to it (best cost {mesh['best']})")
        if r["lopsided"]:
            worst = r["lopsided"][0]
            flag("info", "lopsided", f"Lopsided link{'s' if len(r['lopsided']) > 1 else ''}: it hears "
                 f"{worst['name'] or worst['addr']} at cost {worst['in']} but is heard at cost {worst['out']}"
                 + (f" (and {len(r['lopsided']) - 1} more)" if len(r["lopsided"]) > 1 else ""),
                 None, "One direction works and the other doesn't: often a transmit-power difference or interference near one side")
        # end devices that hop between parents
        parents = r.get("parents")
        if r["type"] == "EndDevice" and parents:
            total = sum(parents.values())
            real = [(p, n) for p, n in parents.most_common() if n >= max(3, total * 0.1)]
            if len(real) >= 2:
                flag("warn", "parent_changes", f"Switched between {len(real)} parents in this range ("
                     + ", ".join(self._name(p) or p for p, _ in real[:3]) + ")", context,
                     "An end device changes parent when it loses the old one: a weak or overloaded parent")
        # compared with its own normal
        if base and r["tx"]:
            first = max(now - span, r["first_minute"] or now - span)
            h_active = max(1 / 6, (now - first) / 3600)
            tx_h = r["tx"] / h_active
            if base.get("tx_per_h") and tx_h >= 4 * base["tx_per_h"] and tx_h >= 120 and not ota:
                flag("info", "unusual_traffic", f"Sends {tx_h / base['tx_per_h']:.0f}× its normal traffic "
                     f"({tx_h:.0f}/h, normally {base['tx_per_h']:.0f}/h)", context)
            by = base.get("rssi_by_sniffer") or {}
            if r.get("signal"):
                # each sniffer against its own normal; weaker only if every one that can tell agrees
                cmp = [(x, by[x["sniffer"]]) for x in r["signal"] if x["n"] >= 20 and by.get(x["sniffer"]) is not None]
                if cmp and all(b - x["rssi_avg"] >= 8 for x, b in cmp):
                    if len(cmp) == 1:
                        x, b = cmp[0]
                        where = f"at {x['name']}" if self.several else "at the sniffer"
                        text = f"Heard {b - x['rssi_avg']:.0f} dB weaker than usual {where} ({x['rssi_avg']} dBm, normally {b})"
                    else:
                        text = "Heard weaker than usual at every sniffer that hears it (" + ", ".join(
                            f"{x['name']} {b - x['rssi_avg']:.0f} dB" for x, b in cmp) + ")"
                    flag("info", "weaker", text, None, "Moved, or something new in the way")
            elif base.get("rssi_avg") is not None and r["rssi_avg"] is not None and r["tx"] >= 20 \
                    and r["rssi_avg"] <= base["rssi_avg"] - 8:
                flag("info", "weaker", f"Heard {base['rssi_avg'] - r['rssi_avg']:.0f} dB weaker than usual at the sniffer "
                     f"({r['rssi_avg']} dBm, normally {base['rssi_avg']})", None, "Moved, or something new in the way")
            if base.get("relay_per_h", 0) >= 60 and r["relay"] / h_active < 0.2 * base["relay_per_h"] and router:
                flag("info", "relays_less", f"Relays much less than usual ({r['relay'] / h_active:.0f}/h, normally "
                     f"{base['relay_per_h']:.0f}/h): routes moved away from it")
        # what the sniffer saw
        if r["tx"] >= 5 and r["rssi_avg"] is not None and r["rssi_avg"] <= -88:
            if self.several and r.get("rssi_sniffer_name"):
                flag("info", "faint", f"Faint at every sniffer: {r['rssi_avg']} dBm on average at the best one "
                     f"({r['rssi_sniffer_name']}; only says how far it is from the sniffers)")
            else:
                flag("info", "faint", f"Faint at the sniffer: {r['rssi_avg']} dBm on average (only says how far it is from the sniffer)")
        if not r["tx"] and r["msgs"] and r["heard_via"]:
            flag("info", "relayed_only", f"Not heard directly; its messages arrive through {r['heard_via']['name'] or r['heard_via']['addr']}")
        if ota:
            pct = (lambda v: f"{round(100 * v)}%") if True else None
            picked = f" (picked up at {pct(ota['from'])})" if ota.get("from") else ""
            st = ota["state"]
            if st == "updating":
                text = "Downloading firmware" + (f": {pct(ota['progress'])}" if ota.get("progress") is not None else "") \
                    + (f", about {_gap_text(ota['eta'])} left" if ota.get("eta") else "") + picked
            elif st == "stalled":
                text = "Firmware download stalled" + (f" at {pct(ota['progress'])}" if ota.get("progress") is not None else "") \
                    + f" (last block {_clock(ota['last_ts'])})"
            elif st == "done":
                text = "Firmware downloaded" + picked + (f"; it restarted at {_clock(ota['restarted'])}" if ota.get("restarted") else "")
            else:
                text = "Firmware download failed" + (f": {ota['result']}" if ota.get("result") else "")
            flag("warn" if st in ("stalled", "failed") else "info", "ota", text, "ota",
                 ota.get("result") if st == "done" and ota.get("result") else None)
        flags.sort(key=lambda f: -SEV[f["sev"]])
        return flags

    # ------------------------------------------------------------ overview

    async def overview(self, rng: str, networks: list[dict]) -> dict:
        devs = await self.devices(rng)
        data = await self._cached(("overview", rng), 8, self._overview, rng, devs)
        return {**data, "networks": networks}

    def _overview(self, rng: str, devs: dict) -> dict:
        span, bucket = RANGES[rng]
        now = time.time()
        since = now - span
        st = self.store
        totals = st.net_totals(since)
        rows = devs["devices"]
        attention = []
        heard = sum(1 for d in rows if d["tx"] or d["msgs"])
        frames = totals["ours"] + totals["others"] + totals["unnamed"]
        listening, _ = self._listening()
        incidents = self.incidents(since, now)
        for inc in incidents:
            when = f"since {_clock(inc['start'])}" if inc["end"] is None else f"{_clock(inc['start'])}-{_clock(inc['end'])}"
            attention.append({"sev": inc["sev"], "code": "incident", "addr": "", "name": "Network",
                              "text": f"{inc['title']} ({when})" + (f": {inc['cause']}" if inc["cause"] else ""),
                              "detail": inc["detail"] or None, "context": None})
        if not listening:
            attention.append({"sev": "warn", "code": "not_listening", "addr": "", "name": "Sniffer",
                              "text": "No sniffer is connected: devices aren't judged silent meanwhile"})
        if frames + totals["dropped"] and totals["dropped"] / (frames + totals["dropped"]) >= 0.01:
            pct = round(100 * totals["dropped"] / (frames + totals["dropped"]), 1)
            attention.append({"sev": "warn" if pct >= 5 else "info", "code": "sniffer_drops", "addr": "", "name": "Sniffer",
                              "text": f"The sniffer dropped {pct}% of frames (bridge queue or Wi-Fi), so counts here run a little low"})
        minutes = max(1, totals["minutes"])
        busy = totals["air_all"] / (minutes * 60e6) * 100
        if busy >= 25:
            attention.append({"sev": "warn", "code": "busy", "addr": "", "name": "Channel",
                              "text": f"The channel is busy {busy:.0f}% of the time (Zigbee slows down past about 30%)"})
        if frames and totals["others"] / frames >= 0.3:
            attention.append({"sev": "info", "code": "neighbours", "addr": "", "name": "Channel",
                              "text": f"Other networks use {round(100 * totals['others'] / frames)}% of the frames on this channel"})
        if totals["uni"] >= 100 and totals["retry"] / totals["uni"] >= 0.05:
            attention.append({"sev": "warn", "code": "net_retries", "addr": "", "name": "Network",
                              "text": f"{round(100 * totals['retry'] / totals['uni'], 1)}% of unicast frames network-wide were resent"})
        if totals["scans"] >= 20:
            attention.append({"sev": "info", "code": "scans", "addr": "", "name": "Channel",
                              "text": f"{totals['scans']} beacon requests: devices (ours or a neighbour's) searching for a network"})
        counts = Counter()
        for d in rows:
            for k in ("network_report", "network_update"):
                counts[k] += (d["events"] or {}).get(k, 0)
        if counts["network_report"]:
            attention.append({"sev": "warn", "code": "pan_conflict", "addr": "", "name": "Network",
                              "text": f"Routers sent {_plural(counts['network_report'], 'network report')} "
                                      "(a PAN ID conflict: another network uses our PAN ID nearby)"})
        if counts["network_update"]:
            attention.append({"sev": "warn", "code": "network_update", "addr": "", "name": "Network",
                              "text": f"The network announced {_plural(counts['network_update'], 'update')} "
                                      "(PAN ID or channel change)"})
        if not self.S.key_loaded:
            attention.append({"sev": "info", "code": "no_key", "addr": "", "name": "Decryption",
                              "text": "No network key: leaves, rejoins, route errors and mesh links can't be read"})
        for d in rows:
            for f in d["flags"]:
                if f["code"] in ("faint", "relayed_only", "few_neighbors"):
                    continue
                attention.append({**f, "addr": d["addr"], "name": d["name"] or d["addr"], "type": d["type"]})
        attention.sort(key=lambda a: (-SEV[a["sev"]], a.get("context") is not None))
        events = self._label_events(st.events(since, limit=60))
        return {
            "range": rng, "span": span, "bucket": bucket, "now": now,
            "net": st.net_series(since, bucket), "totals": totals, "cmds": st.cmd_series(since, bucket),
            "counts": {
                "heard": heard, "known": len(self.names.devices),
                "routers": sum(1 for d in rows if d["type"] == "Router" and (d["tx"] or d["msgs"])),
                "end_devices": sum(1 for d in rows if d["type"] == "EndDevice" and (d["tx"] or d["msgs"])),
                "not_heard": sum(1 for d in rows if d["known"] and not (d["tx"] or d["msgs"])),
                "problems": sum(1 for d in rows if d["sev"] >= 2),
            },
            "attention": attention[:80], "events": events, "incidents": incidents,
            "ota": self.firmware(since, now),
            "marks": self.marks(since),
        }

    # ------------------------------------------------------------ one device

    async def device(self, addr: str, rng: str) -> dict:
        devs = await self.devices(rng)
        row = next((d for d in devs["devices"] if d["addr"] == addr), None)
        return await asyncio.to_thread(self._device, addr, rng, row)

    def _device(self, addr: str, rng: str, row: dict | None) -> dict:
        span, bucket = RANGES[rng]
        now = time.time()
        since = now - span
        st = self.store
        if row is None:
            row = self._row(addr, {}, self._seen().get(addr), [], {}, {}, None, None, None, None)
            _split_noack(row, 0)
            row["last_msg"] = self._msg_seen().get(addr)
            row["baseline"], row["ota"], row["parents"] = None, None, None
            row["flags"], row["sev"] = [], 0
        hops = st.hops(since, addr)

        def group(rows, key, rssi=False):
            acc: dict[str, list] = {}
            for h in rows:
                a = acc.setdefault(h[key], [0, 0])
                a[0] += h["n"]
                a[1] += h["rssi_sum"]
            out = [{"addr": k, "name": self._name(k), "n": n, "rssi_avg": round(s / n, 1) if rssi and n else None}
                   for k, (n, s) in acc.items()]
            return sorted(out, key=lambda x: -x["n"])

        sends_to = group([h for h in hops if h["mac_src"] == addr and h["mac_dst"]], "mac_dst")
        hears_from = group([h for h in hops if h["mac_dst"] == addr], "mac_src", rssi=True)
        relays_for = group([h for h in hops if h["mac_src"] == addr and h["nwk_src"] and h["nwk_src"] != addr], "nwk_src")
        relayed_by = group([h for h in hops if h["nwk_src"] == addr and h["mac_src"] != addr], "mac_src", rssi=True)

        def routes(direction: str) -> list[dict]:
            flows: dict[str, dict[tuple[str, str], int]] = {}
            totals: Counter = Counter()
            for h in hops:
                if direction == "out" and h["nwk_src"] == addr and unicast(h["nwk_dst"]) and h["nwk_dst"] != addr:
                    other = h["nwk_dst"]
                elif direction == "in" and h["nwk_dst"] == addr and h["nwk_src"] and h["nwk_src"] != addr:
                    other = h["nwk_src"]
                else:
                    continue
                f = flows.setdefault(other, {})
                f[(h["mac_src"], h["mac_dst"])] = f.get((h["mac_src"], h["mac_dst"]), 0) + h["n"]
                totals[other] += h["n"]
            out = []
            for other, n in totals.most_common(6):
                start, end = (addr, other) if direction == "out" else (other, addr)
                path = find_path(flows[other], start, end)
                out.append({"addr": other, "name": self._name(other), "n": n,
                            "path": [{"addr": p, "name": self._name(p)} if p else None for p in path]})
            return out

        tables = latest_tables(st.links(since, addr))
        neighbours: dict[str, dict] = {}
        for r in tables.get(addr, []):  # its own table: in = how well it hears them, out = how well they hear it
            neighbours[r["neighbor"]] = {"addr": r["neighbor"], "in": r["last_in"], "out": r["last_out"],
                                         "in_avg": r["in_avg"], "out_avg": r["out_avg"], "ts": r["last_ts"], "own": True}
        for router, rows in tables.items():
            for r in rows:
                if r["neighbor"] != addr or router == addr:
                    continue
                n = neighbours.setdefault(router, {"addr": router, "in": r["last_out"], "out": r["last_in"],
                                                   "in_avg": r["out_avg"], "out_avg": r["in_avg"], "ts": r["last_ts"],
                                                   "own": False})
                n["reported"] = True
        for n in neighbours.values():
            n["name"] = self._name(n["addr"])
            n["cost"] = link_cost(n["in"], n["out"])
        link_hist = {}
        for r in st.link_series(addr, since):
            link_hist.setdefault(r["neighbor"], []).append([r["hour"], round(r["in_sum"] / r["n"], 1), round(r["out_sum"] / r["n"], 1)])
        next_hops = [{"addr": lk["dst"], "name": self._name(lk["dst"]), "uni": lk["uni"], "retry": lk["retry"],
                      "noack": lk["noack"], "pct": _pct(lk["retry"], lk["uni"])}
                     for lk in st.link_tx(since, addr) if lk["uni"]]
        next_hops.sort(key=lambda x: (-x["retry"], -x["uni"]))
        incidents = [i for i in self.incidents(since, now) if any(d["addr"] == addr for d in i["devices"])]
        events = self._label_events(st.events(since, addr, 300))
        return {
            "range": rng, "span": span, "bucket": bucket, "now": now, "device": row,
            "series": st.device_series(addr, since, bucket), "cmds": st.cmd_series(since, bucket, addr),
            "signal_series": self._signal_series(row, st.device_sniffer_series(addr, since, bucket)),
            "sends_to": sends_to[:12], "hears_from": hears_from[:12], "relays_for": relays_for[:12],
            "relayed_by": relayed_by[:12], "routes_out": routes("out"), "routes_in": routes("in"),
            "neighbours": sorted(neighbours.values(), key=lambda n: (n["cost"] or 9, n["name"])),
            "link_history": link_hist, "events": events, "next_hops": next_hops[:12],
            "baseline": row.get("baseline"), "ota": row.get("ota"), "incidents": incidents,
            "firmware": self._z2m_fw(names_mod.load_z2m_updates(), addr, row.get("ieee") or None),
            "marks": self.marks(since, addr),
        }

    def _signal_series(self, row: dict, series: dict[str, list]) -> list[dict]:
        """A device's signal per sniffer over the range, each with what it is compared with: the
        sniffer's 7-day normal for this device, else (a new sniffer) its average over the range."""
        normals = {x["sniffer"]: x.get("normal") for x in row.get("signal") or []}
        order = list(self.sniffer_names)
        out = []
        for sid, data in sorted(series.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99):
            ref, ref_kind = normals.get(sid), "normal"
            if ref is None:
                n = sum(d[4] for d in data)
                ref, ref_kind = (round(sum(d[1] * d[4] for d in data) / n, 1), "range") if n else (None, None)
            out.append({"sniffer": sid, "name": self._sniffer_name(sid), "data": data, "ref": ref, "ref_kind": ref_kind})
        return out

    # ------------------------------------------------------------ the mesh

    async def mesh(self, rng: str) -> dict:
        devs = await self.devices(rng)
        return await self._cached(("mesh", rng), 15, self._mesh, rng, devs)

    def _mesh(self, rng: str, devs: dict) -> dict:
        span, _ = RANGES[rng]
        since = time.time() - span
        st = self.store
        tables = latest_tables(st.links(since))
        edges: dict[tuple[str, str], dict] = {}
        for router, rows in tables.items():
            for r in rows:
                a, b = sorted((router, r["neighbor"]))
                e = edges.setdefault((a, b), {"a": a, "b": b, "ab": None, "ba": None, "ab_own": False, "ba_own": False, "ts": 0})
                e["ts"] = max(e["ts"], r["last_ts"] or 0)
                # the router measured neighbour->router itself; router->neighbour is the neighbour's figure, relayed
                into_router, out_of_router = ("ba", "ab") if router == a else ("ab", "ba")
                e[into_router], e[into_router + "_own"] = r["last_in"], True
                if not e[out_of_router + "_own"]:
                    e[out_of_router] = r["last_out"]
        by_addr = {d["addr"]: d for d in devs["devices"]}
        hops = st.hops(since)
        parent: dict[str, Counter] = {}
        traffic: Counter = Counter()
        for h in hops:
            if not unicast(h["mac_dst"]):
                continue
            traffic[tuple(sorted((h["mac_src"], h["mac_dst"])))] += h["n"]
            d = by_addr.get(h["mac_src"])
            if d and d["type"] == "EndDevice":
                parent.setdefault(h["mac_src"], Counter())[h["mac_dst"]] += h["n"]
        children = [{"child": c, "parent": p.most_common(1)[0][0], "n": p.most_common(1)[0][1]} for c, p in parent.items()]
        addrs = {e["a"] for e in edges.values()} | {e["b"] for e in edges.values()} | {"0x0000"}
        addrs |= {c["child"] for c in children} | {c["parent"] for c in children}
        nodes = []
        for a in sorted(addrs):
            d = by_addr.get(a) or {}
            nodes.append({"addr": a, "name": d.get("name") or self._name(a) or a, "type": d.get("type") or self.names.meta(a).get("type", ""),
                          "rssi_avg": d.get("rssi_avg"), "sev": d.get("sev", 0), "last_seen": d.get("last_seen"),
                          "tx": d.get("tx", 0), "mesh": d.get("mesh")})
        return {"range": rng, "nodes": nodes, "edges": list(edges.values()), "children": children,
                "traffic": [{"a": a, "b": b, "n": n} for (a, b), n in traffic.most_common(400)]}
