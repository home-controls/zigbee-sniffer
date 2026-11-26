"""What Zigbee Studio (a Zigbee2MQTT web UI, an add-on of its own) may ask for.

The web port answers only Home Assistant's ingress proxy. Zigbee Studio shows the Sniffer's
findings on its device, health, traffic and map pages, so it may also GET a short list of
read-only answers, and set up the floor maps (floors, plans, scale, where devices and sniffers
are), with a key the Sniffer keeps in /share/zigbee_sniffer/studio.key (Studio maps /share
read-only). Nothing else that changes anything (channel, firmware, pings, the sniffers' own
settings), decodes stored captures, downloads them or traces a device is on the list. The
add-on option `zigbee_studio: false` removes the key, and then only ingress gets an answer again.
"""

import hmac
import os
import re
import secrets
from pathlib import Path

HEADER = "X-Zigbee-Studio-Key"
KEY_FILE = Path(os.environ.get("SNIFFER_STUDIO_KEY", "/share/zigbee_sniffer/studio.key"))
FLOOR = r"floors/[A-Za-z0-9_-]{1,64}"
# GET: only these
PATHS = re.compile(r"/api/(?:status|overview|devices|mesh|live|map|map/coverage"
                   rf"|device/0x[0-9a-fA-F]{{4}}|map/{FLOOR}/image)")
# changes: the floor maps only (0.5.13)
WRITES = {
    "POST": re.compile(rf"/api/map/(?:floors|{FLOOR}|{FLOOR}/image|positions)"),
    "DELETE": re.compile(rf"/api/map/{FLOOR}"),
}


def ensure_key(path: Path, enabled: bool) -> str:
    """The key Studio must send ("" = Studio gets nothing). Made once and kept, so Studio keeps
    working across restarts; removed when the option is off."""
    if not enabled:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return ""
    try:
        key = path.read_text().strip()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    key = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(key + "\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    return key


def allowed(method: str, path: str, given: str | None, key: str) -> bool:
    """May a request from outside ingress have this answer?"""
    if not key or not given:
        return False
    rx = PATHS if method == "GET" else WRITES.get(method)
    if rx is None or rx.fullmatch(path) is None:
        return False
    return hmac.compare_digest(given.encode(), key.encode())
