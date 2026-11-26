"""Counting capture files into the history again, from scratch (after they were repaired).

Ask for it with recount.json in the captures folder:
    {"files": ["2026-11-10/zigbee_2026-11-10_05.pcap", ...], "reason": "why"}
At the next start the app takes what those files put in the history back out (Store.forget), counts
them again like frames written while it was down, with who heard each frame from their .sniffers
files, and deletes the request once every file is done. A restart half-way carries on where it was
(the request remembers that the old counts are already out).
"""

import json
import logging
import re
import time
from pathlib import Path

from sniffers import H_HEARD, H_SOLO, H_TOTAL, HEALTH_FIELDS

log = logging.getLogger("sniffer")

REQUEST = "recount.json"
_NAME = re.compile(r"zigbee_(\d{4}-\d{2}-\d{2}_\d{2})\.pcap$")


def hour_of(rel: str) -> float | None:
    """When the local hour a capture file holds starts (None for a name that isn't one of ours)."""
    m = _NAME.search(rel)
    return time.mktime(time.strptime(m.group(1), "%Y-%m-%d_%H")) if m else None


def start(base: Path, store) -> dict[str, float]:
    """The files asked for (file -> start of its hour), their old counts taken out of the history."""
    path = base / REQUEST
    try:
        req = json.loads(path.read_text())
        files = [str(f) for f in req["files"]]
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, KeyError) as e:
        log.warning("Ignoring %s: %s", REQUEST, e)
        return {}
    hours = {rel: hour_of(rel) for rel in files if (base / rel).is_file()}
    left = [rel for rel in files if hours.get(rel) is None]
    if left:
        log.warning("%s: %d files aren't captures here, left alone (%s)", REQUEST, len(left), ", ".join(left[:3]))
    hours = {rel: h for rel, h in hours.items() if h is not None}
    if not req.get("forgotten"):
        store.forget(sorted(hours.items()))
        req["forgotten"] = True
        path.write_text(json.dumps(req))  # a restart half-way mustn't take the new counts out again
        log.info("Counting %d capture files into the history again%s", len(hours),
                 f" ({req['reason']})" if req.get("reason") else "")
    return hours


def finish(base: Path) -> None:
    (base / REQUEST).unlink(missing_ok=True)


class Coverage:
    """Each sniffer's heard / solo / total, counted again from a capture's .sniffers file (live,
    main.count_coverage counts them as frames come): of our transmissions while a sniffer was
    connected, how many it heard and how many only it heard."""

    def __init__(self, connected: dict[int, set[str]]) -> None:
        self.connected = connected  # minute -> the sniffers connected some of it
        self.rows: dict[tuple[str, int], list] = {}

    def add(self, ts: float, info: dict, copies) -> None:
        m = info["m"]
        if not (copies and info["ours"] and m.get("src") and m.get("type") != "ack"):
            return
        minute = int(ts // 60) * 60
        heard = {c[0] for c in copies}
        for sid in self.connected.get(minute, set()) | heard:
            r = self.rows.get((sid, minute))
            if r is None:
                r = self.rows[(sid, minute)] = [None if f in ("rssi_min", "rssi_max") else 0 for f in HEALTH_FIELDS]
            r[H_TOTAL] += 1
            if sid in heard:
                r[H_HEARD] += 1
                if len(heard) == 1:
                    r[H_SOLO] += 1

    def take(self) -> dict[tuple[str, int], list]:
        rows, self.rows = self.rows, {}
        return rows
