"""The history: per-minute counters, hops, events and mesh links in SQLite (/data/history.db).

Every row is additive, so a minute can be written in parts (live every few seconds, or a
capture replayed after a restart) and still add up. `files` remembers how far each capture
file has been counted (and decoded for events), so nothing is counted twice and frames
written while the app was down are counted from the capture when it starts again.
"""

import logging
import sqlite3
import threading
import time
from pathlib import Path

from analysis import DEV_FIELDS, NET_FIELDS, Batch

log = logging.getLogger("store")

SNIFFER_FIELDS = ("up_s", "disconnects", "rssi_sum", "rssi_n", "rssi_min", "rssi_max", "buffered", "backlog_max", "crc",
                  "heard", "solo", "total")

SCHEMA = """
CREATE TABLE IF NOT EXISTS dev_min (
  minute INTEGER NOT NULL, addr TEXT NOT NULL,
  tx INTEGER NOT NULL DEFAULT 0, rssi_sum INTEGER NOT NULL DEFAULT 0, rssi_min INTEGER, rssi_max INTEGER,
  lqi_sum INTEGER NOT NULL DEFAULT 0, uni INTEGER NOT NULL DEFAULT 0, retry INTEGER NOT NULL DEFAULT 0,
  relay INTEGER NOT NULL DEFAULT 0, poll INTEGER NOT NULL DEFAULT 0, msgs INTEGER NOT NULL DEFAULT 0,
  rx INTEGER NOT NULL DEFAULT 0, noack INTEGER NOT NULL DEFAULT 0, air INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (addr, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dev_min_minute ON dev_min (minute);
CREATE TABLE IF NOT EXISTS net_min (
  minute INTEGER PRIMARY KEY, ours INTEGER NOT NULL DEFAULT 0, others INTEGER NOT NULL DEFAULT 0,
  unnamed INTEGER NOT NULL DEFAULT 0, air_ours INTEGER NOT NULL DEFAULT 0, air_all INTEGER NOT NULL DEFAULT 0,
  uni INTEGER NOT NULL DEFAULT 0, retry INTEGER NOT NULL DEFAULT 0, noack INTEGER NOT NULL DEFAULT 0,
  bcast INTEGER NOT NULL DEFAULT 0, scans INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS hops (
  hour INTEGER NOT NULL, mac_src TEXT NOT NULL, mac_dst TEXT NOT NULL, nwk_src TEXT NOT NULL, nwk_dst TEXT NOT NULL,
  n INTEGER NOT NULL, rssi_sum INTEGER NOT NULL,
  PRIMARY KEY (hour, mac_src, mac_dst, nwk_src, nwk_dst)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS seen (addr TEXT PRIMARY KEY, ts REAL, rssi INTEGER, lqi INTEGER);
CREATE TABLE IF NOT EXISTS ieee (addr TEXT NOT NULL, ieee TEXT NOT NULL, first REAL, last REAL,
  PRIMARY KEY (addr, ieee)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, addr TEXT, other TEXT, ieee TEXT,
  detail TEXT, file TEXT, n INTEGER);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_addr ON events (addr, ts);
CREATE TABLE IF NOT EXISTS cmd_min (minute INTEGER NOT NULL, addr TEXT NOT NULL, cmd TEXT NOT NULL,
  n INTEGER NOT NULL, PRIMARY KEY (addr, cmd, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cmd_min_minute ON cmd_min (minute);
CREATE TABLE IF NOT EXISTS links (
  hour INTEGER NOT NULL, router TEXT NOT NULL, neighbor TEXT NOT NULL, n INTEGER NOT NULL,
  in_sum INTEGER NOT NULL, out_sum INTEGER NOT NULL, last_ts REAL, last_in INTEGER, last_out INTEGER,
  PRIMARY KEY (router, neighbor, hour)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS links_hour ON links (hour);
DROP TABLE IF EXISTS sniffer_min;
CREATE TABLE IF NOT EXISTS sniffer_health (
  sniffer TEXT NOT NULL, minute INTEGER NOT NULL, up_s INTEGER NOT NULL DEFAULT 0,
  disconnects INTEGER NOT NULL DEFAULT 0, rssi_sum INTEGER NOT NULL DEFAULT 0, rssi_n INTEGER NOT NULL DEFAULT 0,
  rssi_min INTEGER, rssi_max INTEGER, buffered INTEGER NOT NULL DEFAULT 0, backlog_max INTEGER NOT NULL DEFAULT 0,
  crc INTEGER NOT NULL DEFAULT 0, heard INTEGER NOT NULL DEFAULT 0, solo INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (sniffer, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS sniffer_health_minute ON sniffer_health (minute);
CREATE TABLE IF NOT EXISTS dev_sniffer_min (
  minute INTEGER NOT NULL, addr TEXT NOT NULL, sniffer TEXT NOT NULL, n INTEGER NOT NULL,
  rssi_sum INTEGER NOT NULL, rssi_min INTEGER, rssi_max INTEGER,
  PRIMARY KEY (addr, sniffer, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dev_sniffer_min_minute ON dev_sniffer_min (minute);
CREATE TABLE IF NOT EXISTS files (rel TEXT PRIMARY KEY, offset INTEGER NOT NULL DEFAULT 0,
  frames INTEGER NOT NULL DEFAULT 0, ev_offset INTEGER NOT NULL DEFAULT 0, ev_frames INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS link_tx (
  hour INTEGER NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, uni INTEGER NOT NULL DEFAULT 0,
  retry INTEGER NOT NULL DEFAULT 0, noack INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, src, dst)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ota_min (
  minute INTEGER NOT NULL, addr TEXT NOT NULL, blocks INTEGER NOT NULL DEFAULT 0,
  offset_max INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, addr)) WITHOUT ROWID;
"""
# Events that go on the charts as markers (and not into a device's findings).
MARK_KINDS = ("z2m_online", "z2m_offline", "z2m_restart", "device_joined", "device_interview", "device_leave",
              "device_announce", "ota_start", "ota_done", "ota_failed", "channel", "sniffer_disconnected",
              "sniffer_back", "sniffer_offline", "sniffer_added", "sniffer_moved")
# The sniffer events that also go on every device's charts: a change in who is listening changes
# what is heard of a device (its traffic, its signal)
DEVICE_SNIFFER_MARKS = ("sniffer_added", "sniffer_offline", "sniffer_back", "sniffer_moved")
ROUTE_KINDS = ("network_status", "route_failure_up")  # counted in distinct minutes: one failure resends its status

_DEV_COLS = ", ".join(DEV_FIELDS)
_DEV_UPSERT = (
    f"INSERT INTO dev_min (minute, addr, {_DEV_COLS}) VALUES (?, ?, {', '.join('?' * len(DEV_FIELDS))}) "
    "ON CONFLICT (addr, minute) DO UPDATE SET "
    + ", ".join(
        f"{f} = coalesce({'min' if f == 'rssi_min' else 'max'}({f}, excluded.{f}), {f}, excluded.{f})"
        if f in ("rssi_min", "rssi_max") else f"{f} = {f} + excluded.{f}"
        for f in DEV_FIELDS
    )
)
_NET_UPSERT = (
    f"INSERT INTO net_min (minute, {', '.join(NET_FIELDS)}) VALUES (?, {', '.join('?' * len(NET_FIELDS))}) "
    "ON CONFLICT (minute) DO UPDATE SET " + ", ".join(f"{f} = {f} + excluded.{f}" for f in NET_FIELDS)
)


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.recovered = ""  # set when a damaged database was moved aside and the history started over
        try:
            self._open()
        except sqlite3.DatabaseError as e:
            # A damaged file (a hard reset mid-write) must not keep the app from starting: move it aside;
            # the empty `files` table makes the app count the captures into a fresh history.
            for conn in (getattr(self, "db", None), getattr(self, "rdb", None)):
                try:
                    if conn is not None:
                        conn.close()
                except sqlite3.Error:
                    pass
            for p in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
                if p.exists():
                    p.replace(p.with_name(p.name + f".damaged-{int(time.time())}"))
            self.recovered = f"the history database was damaged ({e}); it was moved aside and rebuilt from the captures"
            log.warning(self.recovered)
            self._open()

    def _open(self) -> None:
        self.db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            cols = {r[1] for r in self.db.execute("PRAGMA table_info(seen)")}
            if "msg_ts" not in cols:
                self.db.execute("ALTER TABLE seen ADD COLUMN msg_ts REAL")
            if "offset_min" not in {r[1] for r in self.db.execute("PRAGMA table_info(ota_min)")}:  # 0.5.4
                self.db.execute("ALTER TABLE ota_min ADD COLUMN offset_min INTEGER")
            cols = {r[1] for r in self.db.execute("PRAGMA table_info(sniffer_health)")}
            for c in ("heard", "solo", "total"):  # 0.5.3
                if c not in cols:
                    self.db.execute(f"ALTER TABLE sniffer_health ADD COLUMN {c} INTEGER NOT NULL DEFAULT 0")
            self._migrate_route_events()
            self.db.execute("SELECT count(*) FROM files").fetchone()
        # Pages read through their own connection (WAL lets readers run beside the writer), so a long
        # 7-day query never holds up the history being written, and the reverse.
        self.rdb = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.rdb.row_factory = sqlite3.Row
        self.rlock = threading.Lock()

    def _migrate_route_events(self) -> None:
        """Before 0.5.1 every Network Status was stored as `network_status` on the address it named.
        Their text says which status it was, so re-file them as 0.5.1 does: a many-to-one route
        failure on the router that reported it, address conflicts and stale frame counters as
        their own kinds. Runs once (afterwards no such rows are left)."""
        db = self.db
        rows = db.execute("SELECT id, addr, other, detail FROM events WHERE kind = 'network_status' AND "
                          "(detail LIKE 'many-to-one route failure (reported by %' OR detail LIKE 'address conflict (reported by %' "
                          "OR detail LIKE 'bad frame counter (reported by %')").fetchall()
        if not rows:
            return
        db.execute("BEGIN")
        try:
            for r in rows:
                d = r["detail"]
                if d.startswith("many-to-one"):
                    db.execute("UPDATE events SET kind = 'route_failure_up', addr = ?, other = ?, detail = ? WHERE id = ?",
                               (r["other"], r["addr"], f"couldn't forward {r['addr'] or 'a device'}'s traffic toward the "
                                "coordinator (many-to-one route failure)", r["id"]))
                elif d.startswith("address conflict"):
                    db.execute("UPDATE events SET kind = 'address_conflict' WHERE id = ?", (r["id"],))
                else:
                    db.execute("UPDATE events SET kind = 'bad_frame_counter', detail = ? WHERE id = ?",
                               (f"sent a frame with a stale security frame counter (reported by {r['other']})", r["id"]))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
        log.info("Re-filed %d route errors stored before 0.5.1", len(rows))

    # ------------------------------------------------------------ writing

    def write(self, b: Batch) -> None:
        with self.lock:
            db = self.db
            db.execute("BEGIN")
            try:
                db.executemany(_DEV_UPSERT, [(m, a, *r) for (m, a), r in b.dev.items()])
                db.executemany(_NET_UPSERT, [(m, *r) for m, r in b.net.items()])
                db.executemany(
                    "INSERT INTO hops VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "n = n + excluded.n, rssi_sum = rssi_sum + excluded.rssi_sum",
                    [(*k, n, s) for k, (n, s) in b.hops.items()])
                db.executemany(
                    "INSERT INTO seen (addr, ts, rssi, lqi) VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "ts = excluded.ts, rssi = excluded.rssi, lqi = excluded.lqi WHERE excluded.ts > coalesce(seen.ts, 0)",
                    [(a, *v) for a, v in b.seen.items()])
                db.executemany(
                    "INSERT INTO seen (addr, msg_ts) VALUES (?, ?) ON CONFLICT DO UPDATE SET "
                    "msg_ts = max(coalesce(msg_ts, 0), excluded.msg_ts)",
                    list(b.msg_seen.items()))
                db.executemany(
                    "INSERT INTO link_tx VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "uni = uni + excluded.uni, retry = retry + excluded.retry, noack = noack + excluded.noack",
                    [(*k, *v) for k, v in b.link.items()])
                db.executemany(
                    "INSERT INTO ieee VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "first = min(first, excluded.first), last = max(last, excluded.last)",
                    [(*k, f, la) for k, (f, la) in b.ieee.items()])
                self._insert_events(b.events)
                db.executemany(
                    "INSERT INTO dev_sniffer_min VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "n = n + excluded.n, rssi_sum = rssi_sum + excluded.rssi_sum, "
                    "rssi_min = min(rssi_min, excluded.rssi_min), rssi_max = max(rssi_max, excluded.rssi_max)",
                    [(*k, *v) for k, v in b.sniff.items()])
                for rel, (offset, frames) in b.files.items():
                    db.execute(
                        "INSERT INTO files (rel, offset, frames) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET "
                        "offset = max(offset, excluded.offset), frames = max(frames, excluded.frames)",
                        (rel, offset, frames))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def _insert_events(self, events: list[dict]) -> None:
        self.db.executemany(
            "INSERT INTO events (ts, kind, addr, other, ieee, detail, file, n) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(e["ts"], e["kind"], e["addr"], e["other"], e["ieee"], e["detail"], e["file"], e["n"]) for e in events])

    def write_decoded(self, rel: str, offset: int, frames: int, events: list[dict], cmds: dict, links: dict,
                      ota: dict | None = None) -> None:
        """What the tshark pass found in one stretch of a capture file."""
        with self.lock:
            db = self.db
            db.execute("BEGIN")
            try:
                self._insert_events(events)
                db.executemany(
                    "INSERT INTO ota_min (minute, addr, blocks, offset_max, size, offset_min) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT DO UPDATE SET blocks = blocks + excluded.blocks, "
                    "offset_max = max(offset_max, excluded.offset_max), size = max(size, excluded.size), "
                    "offset_min = CASE WHEN offset_min IS NULL THEN excluded.offset_min "
                    "WHEN excluded.offset_min IS NULL THEN offset_min ELSE min(offset_min, excluded.offset_min) END",
                    [(*k, *(list(v) + [None])[:4]) for k, v in (ota or {}).items()])
                db.executemany(
                    "INSERT INTO cmd_min VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET n = n + excluded.n",
                    [(*k, n) for k, n in cmds.items()])
                db.executemany(
                    "INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "n = n + excluded.n, in_sum = in_sum + excluded.in_sum, out_sum = out_sum + excluded.out_sum, "
                    "last_in = CASE WHEN excluded.last_ts >= last_ts THEN excluded.last_in ELSE last_in END, "
                    "last_out = CASE WHEN excluded.last_ts >= last_ts THEN excluded.last_out ELSE last_out END, "
                    "last_ts = max(last_ts, excluded.last_ts)",
                    [(*k, *v) for k, v in links.items()])
                db.execute(
                    "INSERT INTO files (rel, ev_offset, ev_frames) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET "
                    "ev_offset = excluded.ev_offset, ev_frames = excluded.ev_frames", (rel, offset, frames))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def write_sniffer(self, rows: dict[tuple[str, int], list], events: list[dict]) -> None:
        """Each sniffer's own health per minute ((sniffer, minute) -> SNIFFER_FIELDS) and its events."""
        with self.lock:
            db = self.db
            db.execute("BEGIN")
            try:
                db.executemany(
                    f"INSERT INTO sniffer_health (sniffer, minute, {', '.join(SNIFFER_FIELDS)}) "
                    f"VALUES (?, ?, {', '.join('?' * len(SNIFFER_FIELDS))}) "
                    "ON CONFLICT (sniffer, minute) DO UPDATE SET up_s = up_s + excluded.up_s, "
                    "disconnects = disconnects + excluded.disconnects, rssi_sum = rssi_sum + excluded.rssi_sum, "
                    "rssi_n = rssi_n + excluded.rssi_n, "
                    "rssi_min = coalesce(min(rssi_min, excluded.rssi_min), rssi_min, excluded.rssi_min), "
                    "rssi_max = coalesce(max(rssi_max, excluded.rssi_max), rssi_max, excluded.rssi_max), "
                    "buffered = buffered + excluded.buffered, backlog_max = max(backlog_max, excluded.backlog_max), "
                    "crc = crc + excluded.crc, heard = heard + excluded.heard, solo = solo + excluded.solo, "
                    "total = total + excluded.total",
                    [(sid, m, *r) for (sid, m), r in rows.items()])
                self._insert_events(events)
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def forget(self, files: list[tuple[str, float]]) -> None:
        """Take what capture files put in the history back out, to count them again from scratch
        (recount.py): for each (file, start of its hour), that hour's counters, hops and links, the
        file's events and bookkeeping, and who heard what (each sniffer's heard/solo/total). What
        didn't come from the captures stays: the sniffers' own health, frames the bridges dropped,
        Zigbee2MQTT's and the sniffers' events."""
        net = ", ".join(f"{f} = 0" for f in NET_FIELDS if f != "dropped")
        with self.lock:
            db = self.db
            db.execute("BEGIN")
            try:
                for rel, start in files:
                    m0 = int(start // 60) * 60
                    span = (m0, m0 + 3600)
                    for table in ("dev_min", "dev_sniffer_min", "cmd_min", "ota_min"):
                        db.execute(f"DELETE FROM {table} WHERE minute >= ? AND minute < ?", span)
                    db.execute(f"UPDATE net_min SET {net} WHERE minute >= ? AND minute < ?", span)
                    db.execute("DELETE FROM net_min WHERE minute >= ? AND minute < ? AND dropped = 0", span)
                    db.execute("UPDATE sniffer_health SET heard = 0, solo = 0, total = 0 "
                               "WHERE minute >= ? AND minute < ?", span)
                    for table in ("hops", "links", "link_tx"):
                        db.execute(f"DELETE FROM {table} WHERE hour = ?", (int(start // 3600) * 3600,))
                    db.execute("DELETE FROM events WHERE file = ?", (rel,))
                    db.execute("DELETE FROM files WHERE rel = ?", (rel,))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def connected_minutes(self, start: float, end: float) -> dict[int, set[str]]:
        """Minute -> the sniffers connected some of it."""
        out: dict[int, set[str]] = {}
        for r in self._all("SELECT sniffer, minute FROM sniffer_health WHERE up_s > 0 AND minute >= ? AND minute < ?",
                           (start, end)):
            out.setdefault(r["minute"], set()).add(r["sniffer"])
        return out

    def sniffer_series(self, sniffer: str, since: float, bucket: int) -> list[list]:
        """[bucket, connected seconds, disconnects, avg Wi-Fi RSSI, min, max, buffered frames, peak backlog, UART CRC errors,
        our transmissions it heard, only it heard, all of them while it was connected]"""
        rows = self._all(
            "SELECT (minute / ?) * ? b, sum(up_s) up, sum(disconnects) dis, sum(rssi_sum) rs, sum(rssi_n) rn, "
            "min(rssi_min) mn, max(rssi_max) mx, sum(buffered) buf, max(backlog_max) bl, sum(crc) crc, "
            "sum(heard) heard, sum(solo) solo, sum(total) total "
            "FROM sniffer_health WHERE sniffer = ? AND minute >= ? GROUP BY b ORDER BY b",
            (bucket, bucket, sniffer, int(since // 60) * 60))
        return [[r["b"], r["up"], r["dis"], round(r["rs"] / r["rn"], 1) if r["rn"] else None, r["mn"], r["mx"],
                 r["buf"], r["bl"], r["crc"], r["heard"], r["solo"], r["total"]] for r in rows]

    def sniffer_totals(self, sniffer: str, since: float) -> dict:
        r = self._all("SELECT coalesce(sum(up_s), 0) up_s, coalesce(sum(disconnects), 0) disconnects, "
                      "coalesce(sum(buffered), 0) buffered, coalesce(max(backlog_max), 0) backlog_max, "
                      "coalesce(sum(crc), 0) crc, min(rssi_min) rssi_min, count(*) minutes, "
                      "coalesce(sum(heard), 0) heard, coalesce(sum(solo), 0) solo, coalesce(sum(total), 0) total "
                      "FROM sniffer_health WHERE sniffer = ? AND minute >= ?", (sniffer, int(since // 60) * 60))[0]
        return dict(r)

    def device_sniffers(self, since: float, addr: str | None = None) -> list[dict]:
        """How each sniffer heard each device since `since`: frames and RSSI average, min, max."""
        where, args = "minute >= ?", [int(since // 60) * 60]
        if addr:
            where += " AND addr = ?"
            args.append(addr)
        return [{"addr": r["addr"], "sniffer": r["sniffer"], "n": r["n"], "rssi_avg": round(r["rs"] / r["n"], 1),
                 "rssi_min": r["mn"], "rssi_max": r["mx"]} for r in self._all(
            "SELECT addr, sniffer, sum(n) n, sum(rssi_sum) rs, min(rssi_min) mn, max(rssi_max) mx "
            f"FROM dev_sniffer_min WHERE {where} GROUP BY addr, sniffer", args)]

    def device_sniffer_hourly(self, start: float, end: float) -> list[dict]:
        """Per device, sniffer and hour between `start` and `end`: frames and RSSI sum (for baselines)."""
        return [dict(r) for r in self._all(
            "SELECT addr, sniffer, (minute / 3600) * 3600 h, sum(n) n, sum(rssi_sum) rs FROM dev_sniffer_min "
            "WHERE minute >= ? AND minute < ? GROUP BY addr, sniffer, h", (int(start // 60) * 60, int(end // 60) * 60))]

    def device_sniffer_series(self, addr: str, since: float, bucket: int) -> dict[str, list[list]]:
        """sniffer -> [[bucket, avg RSSI, min, max, frames]] for one device."""
        out: dict[str, list[list]] = {}
        for r in self._all(
                "SELECT sniffer, (minute / ?) * ? b, sum(n) n, sum(rssi_sum) rs, min(rssi_min) mn, max(rssi_max) mx "
                "FROM dev_sniffer_min WHERE addr = ? AND minute >= ? GROUP BY sniffer, b ORDER BY b",
                (bucket, bucket, addr, int(since // 60) * 60)):
            out.setdefault(r["sniffer"], []).append([r["b"], round(r["rs"] / r["n"], 1), r["mn"], r["mx"], r["n"]])
        return out

    def device_sniffer_buckets(self, since: float, bucket: int) -> tuple[dict, dict]:
        """One pass over dev_sniffer_min for the device table: (addr -> sniffer -> {"n", "rs", "mn",
        "mx"} over the range, addr -> sniffer -> {bucket: avg RSSI})."""
        totals: dict[str, dict[str, dict]] = {}
        sparks: dict[str, dict[str, dict[int, float]]] = {}
        for r in self._all(
                "SELECT addr, sniffer, (minute / ?) * ? b, sum(n) n, sum(rssi_sum) rs, min(rssi_min) mn, max(rssi_max) mx "
                "FROM dev_sniffer_min WHERE minute >= ? GROUP BY addr, sniffer, b", (bucket, bucket, int(since // 60) * 60)):
            t = totals.setdefault(r["addr"], {}).get(r["sniffer"])
            if t is None:
                totals[r["addr"]][r["sniffer"]] = {"n": r["n"], "rs": r["rs"], "mn": r["mn"], "mx": r["mx"]}
            else:
                t["n"] += r["n"]
                t["rs"] += r["rs"]
                t["mn"] = min((x for x in (t["mn"], r["mn"]) if x is not None), default=None)
                t["mx"] = max((x for x in (t["mx"], r["mx"]) if x is not None), default=None)
            sparks.setdefault(r["addr"], {}).setdefault(r["sniffer"], {})[r["b"]] = round(r["rs"] / r["n"], 1)
        return totals, sparks

    def crc_minutes(self, sniffer: str, since: float) -> list[tuple[int, int]]:
        """(minute, damaged UART messages) for the minutes that had any."""
        return [(r["minute"], r["crc"]) for r in self._all(
            "SELECT minute, crc FROM sniffer_health WHERE sniffer = ? AND minute >= ? AND crc > 0 ORDER BY minute",
            (sniffer, int(since // 60) * 60))]

    def sniffer_ids(self) -> set[str]:
        """Every sniffer the history knows of."""
        return {r["sniffer"] for r in self._all("SELECT DISTINCT sniffer FROM sniffer_health")}

    def prune(self, cutoff: float, existing_files: set[str]) -> None:
        minute, hour = int(cutoff // 60) * 60, int(cutoff // 3600) * 3600
        with self.lock:
            db = self.db
            db.execute("DELETE FROM dev_min WHERE minute < ?", (minute,))
            db.execute("DELETE FROM net_min WHERE minute < ?", (minute,))
            db.execute("DELETE FROM cmd_min WHERE minute < ?", (minute,))
            db.execute("DELETE FROM sniffer_health WHERE minute < ?", (minute,))
            db.execute("DELETE FROM dev_sniffer_min WHERE minute < ?", (minute,))
            db.execute("DELETE FROM hops WHERE hour < ?", (hour,))
            db.execute("DELETE FROM links WHERE hour < ?", (hour,))
            db.execute("DELETE FROM link_tx WHERE hour < ?", (hour,))
            db.execute("DELETE FROM ota_min WHERE minute < ?", (minute,))
            db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            db.execute("DELETE FROM ieee WHERE last < ?", (cutoff,))
            db.execute("DELETE FROM seen WHERE coalesce(ts, 0) < ? AND coalesce(msg_ts, 0) < ?", (cutoff, cutoff))
            for (rel,) in db.execute("SELECT rel FROM files").fetchall():
                if rel not in existing_files:
                    db.execute("DELETE FROM files WHERE rel = ?", (rel,))

    # ------------------------------------------------------------ reading

    def _all(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self.rlock:
            return self.rdb.execute(sql, args).fetchall()

    def files(self) -> dict[str, dict]:
        return {r["rel"]: dict(r) for r in self._all("SELECT * FROM files")}

    def file(self, rel: str) -> dict | None:
        rows = self._all("SELECT * FROM files WHERE rel = ?", (rel,))
        return dict(rows[0]) if rows else None

    def set_file(self, rel: str, **cols) -> None:
        """Correct one capture file's bookkeeping (offsets past a file cut short by a hard reset)."""
        with self.lock:
            self.db.execute("INSERT INTO files (rel) VALUES (?) ON CONFLICT DO NOTHING", (rel,))
            for k, v in cols.items():
                if k in ("offset", "frames", "ev_offset", "ev_frames"):
                    self.db.execute(f"UPDATE files SET {k} = ? WHERE rel = ?", (v, rel))

    def rename_file(self, old: str, new: str) -> None:
        """A capture file was renamed (to its local hour): its counted offsets go with it."""
        with self.lock:
            row = self.db.execute("SELECT * FROM files WHERE rel = ?", (old,)).fetchone()
            if row is None:
                return
            self.db.execute("DELETE FROM files WHERE rel = ?", (old,))
            self.db.execute("INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
                            (new, row["offset"], row["frames"], row["ev_offset"], row["ev_frames"]))
            self.db.execute("UPDATE events SET file = ? WHERE file = ?", (new, old))

    def seen(self) -> dict[str, tuple]:
        return {r["addr"]: (r["ts"], r["rssi"], r["lqi"]) for r in self._all("SELECT * FROM seen WHERE ts IS NOT NULL")}

    def msg_seen(self) -> dict[str, float]:
        """addr -> when its last own NWK message was heard (at any hop, relayed or not)."""
        return {r["addr"]: r["msg_ts"] for r in self._all("SELECT addr, msg_ts FROM seen WHERE msg_ts IS NOT NULL")}

    def address_pairs(self) -> list[tuple[str, str]]:
        """The latest IEEE heard for each short address, oldest first."""
        return [(r["addr"], r["ieee"]) for r in self._all("SELECT addr, ieee FROM ieee ORDER BY last")]

    def ieee_map(self) -> dict[str, str]:
        return dict(self.address_pairs())

    def devices(self, since: float) -> dict[str, dict]:
        """Totals per device since `since`."""
        rows = self._all(
            "SELECT addr, sum(tx) tx, sum(rssi_sum) rssi_sum, min(rssi_min) rssi_min, max(rssi_max) rssi_max, "
            "sum(lqi_sum) lqi_sum, sum(uni) uni, sum(retry) retry, sum(relay) relay, sum(poll) poll, "
            "sum(msgs) msgs, sum(rx) rx, sum(noack) noack, sum(air) air, count(*) minutes, max(minute) last_minute, "
            "min(CASE WHEN tx > 0 OR msgs > 0 THEN minute END) first_minute "
            "FROM dev_min WHERE minute >= ? GROUP BY addr", (int(since // 60) * 60,))
        return {r["addr"]: dict(r) for r in rows}

    def device_sparks(self, since: float, bucket: int) -> dict[str, list]:
        """Per device and bucket: [bucket start, avg RSSI or None, frames sent, messages]."""
        rows = self._all(
            "SELECT addr, (minute / ?) * ? b, sum(tx) tx, sum(rssi_sum) rs, sum(msgs) msgs FROM dev_min "
            "WHERE minute >= ? GROUP BY addr, b ORDER BY b", (bucket, bucket, int(since // 60) * 60))
        out: dict[str, list] = {}
        for r in rows:
            out.setdefault(r["addr"], []).append(
                [r["b"], round(r["rs"] / r["tx"], 1) if r["tx"] else None, r["tx"], r["msgs"]])
        return out

    def device_series(self, addr: str, since: float, bucket: int) -> list[list]:
        rows = self._all(
            "SELECT (minute / ?) * ? b, sum(tx) tx, sum(rssi_sum) rs, min(rssi_min) mn, max(rssi_max) mx, "
            "sum(lqi_sum) ls, sum(uni) uni, sum(retry) retry, sum(relay) relay, sum(poll) poll, sum(msgs) msgs, "
            "sum(rx) rx, sum(noack) noack, sum(air) air FROM dev_min WHERE addr = ? AND minute >= ? "
            "GROUP BY b ORDER BY b", (bucket, bucket, addr, int(since // 60) * 60))
        return [[r["b"], r["tx"], round(r["rs"] / r["tx"], 1) if r["tx"] else None, r["mn"], r["mx"],
                 round(r["ls"] / r["tx"]) if r["tx"] else None, r["uni"], r["retry"], r["relay"], r["poll"],
                 r["msgs"], r["rx"], r["noack"], r["air"]] for r in rows]

    def net_series(self, since: float, bucket: int) -> list[list]:
        rows = self._all(
            f"SELECT (minute / ?) * ? b, {', '.join(f'sum({f}) {f}' for f in NET_FIELDS)} FROM net_min "
            "WHERE minute >= ? GROUP BY b ORDER BY b", (bucket, bucket, int(since // 60) * 60))
        return [[r["b"], *(r[f] for f in NET_FIELDS)] for r in rows]

    def net_totals(self, since: float) -> dict:
        r = self._all(f"SELECT {', '.join(f'coalesce(sum({f}), 0) {f}' for f in NET_FIELDS)}, count(*) minutes "
                      "FROM net_min WHERE minute >= ?", (int(since // 60) * 60,))[0]
        return dict(r)

    def cmd_series(self, since: float, bucket: int, addr: str | None = None) -> list[list]:
        where, args = "minute >= ?", [bucket, bucket, int(since // 60) * 60]
        if addr:
            where += " AND addr = ?"
            args.append(addr)
        rows = self._all(f"SELECT (minute / ?) * ? b, cmd, sum(n) n FROM cmd_min WHERE {where} GROUP BY b, cmd ORDER BY b",
                         args)
        return [[r["b"], r["cmd"], r["n"]] for r in rows]

    def cmd_totals(self, since: float) -> dict[str, dict[str, int]]:
        """addr -> {command: count}"""
        out: dict[str, dict[str, int]] = {}
        for r in self._all("SELECT addr, cmd, sum(n) n FROM cmd_min WHERE minute >= ? GROUP BY addr, cmd",
                           (int(since // 60) * 60,)):
            out.setdefault(r["addr"], {})[r["cmd"]] = r["n"]
        return out

    def hops(self, since: float, addr: str | None = None) -> list[dict]:
        where, args = "hour >= ?", [int(since // 3600) * 3600]
        if addr:
            where += " AND ? IN (mac_src, mac_dst, nwk_src, nwk_dst)"
            args.append(addr)
        return [dict(r) for r in self._all(
            f"SELECT mac_src, mac_dst, nwk_src, nwk_dst, sum(n) n, sum(rssi_sum) rssi_sum FROM hops WHERE {where} "
            "GROUP BY mac_src, mac_dst, nwk_src, nwk_dst", args)]

    def links(self, since: float, addr: str | None = None) -> list[dict]:
        """Link Status costs per (router, neighbour): latest and average since `since`."""
        where, args = "hour >= ?", [int(since // 3600) * 3600]
        if addr:
            where += " AND ? IN (router, neighbor)"
            args.append(addr)
        rows = self._all(
            "SELECT router, neighbor, sum(n) n, sum(in_sum) in_sum, sum(out_sum) out_sum, max(last_ts) last_ts "
            f"FROM links WHERE {where} GROUP BY router, neighbor", args)
        latest = {(r["router"], r["neighbor"]): (r["last_in"], r["last_out"]) for r in self._all(
            f"SELECT router, neighbor, last_in, last_out, max(last_ts) FROM links WHERE {where} "
            "GROUP BY router, neighbor", args)}
        out = []
        for r in rows:
            last_in, last_out = latest.get((r["router"], r["neighbor"]), (None, None))
            out.append({"router": r["router"], "neighbor": r["neighbor"], "n": r["n"],
                        "in_avg": round(r["in_sum"] / r["n"], 1), "out_avg": round(r["out_sum"] / r["n"], 1),
                        "last_in": last_in, "last_out": last_out, "last_ts": r["last_ts"]})
        return out

    def link_series(self, router: str, since: float) -> list[dict]:
        return [dict(r) for r in self._all(
            "SELECT hour, neighbor, n, in_sum, out_sum FROM links WHERE router = ? AND hour >= ? ORDER BY hour",
            (router, int(since // 3600) * 3600))]

    def events(self, since: float, addr: str | None = None, limit: int = 200, sniffer: str | None = None) -> list[dict]:
        """Events since `since`: one device's, one sniffer's (`sniffer`, with the app's own such as
        channel changes), else every device's (not the sniffers' or Zigbee2MQTT's own)."""
        where, args = "ts >= ?", [since]
        if sniffer:
            where += " AND addr = 'sniffer' AND (other = ? OR other = 'app')"
            args.append(sniffer)
        elif addr:
            where += " AND (addr = ? OR other = ?)"
            args += [addr, addr]
        else:
            where += " AND addr NOT IN ('sniffer', 'z2m')"
        return [dict(r) for r in self._all(
            f"SELECT ts, kind, addr, other, ieee, detail, file, n FROM events WHERE {where} ORDER BY ts DESC LIMIT ?",
            (*args, limit))]

    def event_counts(self, since: float) -> dict[str, dict[str, int]]:
        """addr -> {kind: count}; route errors count distinct minutes (a router resends its Network
        Status for every frame and every retry of one failed message)."""
        out: dict[str, dict[str, int]] = {}
        kinds = ", ".join(f"'{k}'" for k in ROUTE_KINDS)
        for r in self._all(
                "SELECT addr, kind, CASE WHEN kind IN (" + kinds + ") THEN count(DISTINCT CAST(ts / 60 AS INTEGER)) "
                "ELSE count(*) END n FROM events WHERE ts >= ? AND addr NOT IN ('sniffer', 'z2m') GROUP BY addr, kind",
                (since,)):
            out.setdefault(r["addr"], {})[r["kind"]] = r["n"]
        # route errors also count against the router that reported them (its forwarding failed)
        for r in self._all("SELECT other, count(DISTINCT CAST(ts / 60 AS INTEGER)) n FROM events WHERE ts >= ? "
                           "AND kind = 'network_status' AND other != '' GROUP BY other", (since,)):
            out.setdefault(r["other"], {})["network_status_reported"] = r["n"]
        return out

    def event_minutes(self, since: float, kinds: tuple[str, ...]) -> list[tuple[int, str, str]]:
        """(minute, addr, kind) once per minute, for spotting network-wide trouble."""
        marks = ", ".join("?" * len(kinds))
        return [(r["m"], r["addr"], r["kind"]) for r in self._all(
            f"SELECT DISTINCT CAST(ts / 60 AS INTEGER) * 60 m, addr, kind FROM events WHERE ts >= ? AND kind IN ({marks})",
            (since, *kinds))]

    def marks(self, since: float, addr: str | None = None, sniffer: str | None = None) -> list[dict]:
        """What goes on the charts as a marker: Zigbee2MQTT's restarts and device events, firmware
        updates, channel changes, sniffer disconnects. One device's, one sniffer's, or the network's."""
        kinds = ", ".join("?" * len(MARK_KINDS))
        where, args = f"ts >= ? AND kind IN ({kinds})", [since, *MARK_KINDS]
        sk = ", ".join(f"'{k}'" for k in DEVICE_SNIFFER_MARKS)
        if addr:
            where += (" AND (addr = ? OR (addr = 'z2m' AND kind IN ('z2m_online', 'z2m_offline', 'z2m_restart'))"
                      f" OR (addr = 'sniffer' AND kind IN ({sk})))")
            args.append(addr)
        elif sniffer:
            where += " AND ((addr = 'sniffer' AND other IN (?, 'app')) OR addr = 'z2m')"
            args.append(sniffer)
        else:
            where += f" AND (addr != 'sniffer' OR other = 'app' OR kind IN ('sniffer_disconnected', {sk}))"
        rows = self._all(f"SELECT ts, kind, addr, other, detail FROM events WHERE {where} ORDER BY ts LIMIT 500", args)
        return [dict(r) for r in rows]

    def link_tx(self, since: float, src: str | None = None) -> list[dict]:
        """Unicast frames, resends and missing ACKs per link (MAC sender -> receiver)."""
        where, args = "hour >= ?", [int(since // 3600) * 3600]
        if src:
            where += " AND src = ?"
            args.append(src)
        return [dict(r) for r in self._all(
            f"SELECT src, dst, sum(uni) uni, sum(retry) retry, sum(noack) noack FROM link_tx WHERE {where} "
            "GROUP BY src, dst", args)]

    def ota(self, since: float) -> dict[str, dict]:
        """Firmware-update blocks per device: total, first and last minute, highest offset, image size."""
        out = {}
        for r in self._all("SELECT addr, sum(blocks) blocks, min(minute) first, max(minute) last, "
                           "max(offset_max) offset_max, max(size) size FROM ota_min WHERE minute >= ? GROUP BY addr",
                           (int(since // 60) * 60,)):
            out[r["addr"]] = dict(r)
        return out

    def ota_rows(self, since: float) -> list[tuple]:
        """(minute, device, blocks, lowest block offset, highest offset, image size), oldest first: the
        firmware downloads minute by minute."""
        return [(r["minute"], r["addr"], r["blocks"], r["offset_min"], r["offset_max"], r["size"]) for r in self._all(
            "SELECT minute, addr, blocks, offset_min, offset_max, size FROM ota_min WHERE minute >= ? ORDER BY minute",
            (int(since // 60) * 60,))]

    def ota_minutes(self, since: float) -> list[tuple[int, str]]:
        return [(r["minute"], r["addr"]) for r in self._all(
            "SELECT minute, addr FROM ota_min WHERE minute >= ? AND blocks > 0", (int(since // 60) * 60,))]

    def device_hourly(self, start: float, end: float) -> list[dict]:
        """Per device and hour between `start` and `end`: the counters a baseline is made of."""
        return [dict(r) for r in self._all(
            "SELECT addr, (minute / 3600) * 3600 h, sum(tx) tx, sum(rssi_sum) rs, sum(uni) uni, sum(retry) retry, "
            "sum(relay) relay, sum(msgs) msgs, count(*) minutes FROM dev_min WHERE minute >= ? AND minute < ? "
            "GROUP BY addr, h", (int(start // 60) * 60, int(end // 60) * 60))]

    def device_hours(self, addr: str, since: float) -> list[tuple[int, int]]:
        """(hour, frames to or from the device) for each hour it was heard in."""
        return [(r["h"], r["n"]) for r in self._all(
            "SELECT (minute / 3600) * 3600 h, sum(tx) + sum(rx) n FROM dev_min WHERE addr = ? AND minute >= ? "
            "GROUP BY h ORDER BY h DESC", (addr, int(since // 60) * 60))]

    def last_frame_minute(self) -> int | None:
        r = self._all("SELECT max(minute) m FROM net_min WHERE ours > 0")[0]
        return r["m"]

    def oldest(self) -> float | None:
        r = self._all("SELECT min(minute) m FROM net_min")[0]
        return r["m"]

    def size_bytes(self) -> int:
        with self.rlock:
            (pages,) = self.rdb.execute("PRAGMA page_count").fetchone()
            (size,) = self.rdb.execute("PRAGMA page_size").fetchone()
        return pages * size
