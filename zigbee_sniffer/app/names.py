"""Device names and the network key, read from Zigbee2MQTT's files on this HA host.

The key is only used to write tshark's key table inside this app's private /data folder; it is
never logged, shown, or sent anywhere.
"""

import json
import os
import logging
import time
from pathlib import Path

import yaml

log = logging.getLogger("names")

Z2M_DIR = Path(os.environ.get("Z2M_DIR", "/homeassistant/zigbee2mqtt"))
ZIGBEE_ALLIANCE_09 = "5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39"


class _Z2MLoader(yaml.SafeLoader):
    """Resolves Z2M's `!secret name` references from secret.yaml next to the config."""


def _secret(loader: _Z2MLoader, node: yaml.Node):
    name = loader.construct_scalar(node)
    try:
        secrets = yaml.load((Z2M_DIR / "secret.yaml").read_text(), Loader=yaml.SafeLoader) or {}
        return secrets.get(name)
    except OSError:
        return None


_Z2MLoader.add_constructor("!secret", _secret)


def _section(cfg: dict, name: str) -> dict:
    """A config section that can also live in its own file (`devices: devices.yaml`, Z2M's split
    configuration), or be a list of such files."""
    val = cfg.get(name)
    files = [val] if isinstance(val, str) else val if isinstance(val, list) and all(isinstance(v, str) for v in val) else None
    if files is None:
        return val if isinstance(val, dict) else {}
    out: dict = {}
    for f in files:
        try:
            part = yaml.load((Z2M_DIR / f).read_text(), Loader=_Z2MLoader) or {}
        except (OSError, yaml.YAMLError) as e:
            log.warning("Can't read Zigbee2MQTT %s: %s", f, e)
            continue
        if isinstance(part, dict):
            out.update(part)
    return out


_updates: dict = {"mtime": None, "data": {}}


def load_z2m_updates() -> dict[str, dict]:
    """Zigbee2MQTT's firmware status per device (IEEE -> {state: idle/available/updating/scheduled,
    installed, latest, notes}), from the device state it keeps in state.json (rewritten every few
    minutes). Read again only when the file changed."""
    path = Z2M_DIR / "state.json"
    try:
        mtime = path.stat().st_mtime
        if mtime != _updates["mtime"]:
            raw = json.loads(path.read_text())
            out = {}
            for ieee, st in raw.items():
                u = st.get("update") if isinstance(st, dict) else None
                if isinstance(u, dict) and (u.get("installed_version") is not None or u.get("state")):
                    out[ieee.lower()] = {"state": u.get("state"), "installed": u.get("installed_version"),
                                         "latest": u.get("latest_version"),
                                         "notes": str(u.get("latest_release_notes") or "")[:120] or None}
            _updates.update(mtime=mtime, data=out)
    except (OSError, ValueError, AttributeError) as e:
        log.debug("Can't read Zigbee2MQTT state.json: %s", e)
    return _updates["data"]


def load_z2m_config() -> dict:
    try:
        cfg = yaml.load((Z2M_DIR / "configuration.yaml").read_text(), Loader=_Z2MLoader) or {}
    except (OSError, yaml.YAMLError) as e:
        log.warning("Can't read Zigbee2MQTT configuration.yaml: %s", e)
        return {}
    if not isinstance(cfg, dict):
        return {}
    for name in ("devices", "groups"):
        if name in cfg:
            cfg[name] = _section(cfg, name)
    return cfg


def base_topic(cfg: dict) -> str:
    return ((cfg.get("mqtt") or {}).get("base_topic") or "zigbee2mqtt") if isinstance(cfg.get("mqtt"), dict) else "zigbee2mqtt"


def network_key(cfg: dict) -> str | None:
    key = (cfg.get("advanced") or {}).get("network_key")
    if isinstance(key, list) and len(key) == 16 and all(isinstance(b, int) for b in key):
        return ":".join(f"{b:02X}" for b in key)
    return None


def our_pan(cfg: dict) -> int | None:
    """Zigbee2MQTT's PAN ID: `advanced.pan_id` in configuration.yaml, else the coordinator backup."""
    pan = (cfg.get("advanced") or {}).get("pan_id")
    if isinstance(pan, str):
        try:
            pan = int(pan, 0)  # "0x852c" or "34092"; "GENERATE" is no value yet
        except ValueError:
            pan = None
    if not isinstance(pan, int):
        try:
            raw = json.loads((Z2M_DIR / "coordinator_backup.json").read_text())["pan_id"]
            pan = raw if isinstance(raw, int) else int(str(raw), 16)
        except (OSError, ValueError, KeyError, TypeError):
            return None
    return pan if 0 <= pan < 0xFFFF else None


def write_tshark_keys(home: Path, key: str | None) -> bool:
    """tshark reads ~/.config/wireshark/zigbee_pc_keys; HOME points at a folder in /data."""
    conf = home / ".config" / "wireshark"
    conf.mkdir(parents=True, exist_ok=True)
    lines = [f'"{ZIGBEE_ALLIANCE_09}","Normal","Trust Center link key (ZigBeeAlliance09)"']
    if key:
        lines.append(f'"{key}","Normal","Zigbee2MQTT network key"')
    path = conf / "zigbee_pc_keys"
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
    return key is not None


class Names:
    """Short (NWK) address and IEEE address -> Zigbee2MQTT friendly name, plus what Zigbee2MQTT
    knows about each device (router or end device, model, vendor, power source).

    Only for frames of our network: other networks reuse the same short addresses (each has
    its own coordinator at 0x0000)."""

    def __init__(self) -> None:
        self.by_nwk: dict[int, str] = {0: "Coordinator"}
        self.by_ieee: dict[str, str] = {}
        self.devices: dict[str, dict] = {}  # IEEE -> {name, type, model, vendor, power, nwk}
        self.nwk_ieee: dict[int, str] = {}  # short address -> IEEE
        self.learned: dict[str, str] = {}  # short address -> IEEE, as heard on air (newer than Z2M's database)
        self.loaded_at = 0.0

    def reload(self) -> None:
        cfg = load_z2m_config()
        friendly = {str(k).lower(): (v if isinstance(v, dict) else {}).get("friendly_name", k)
                    for k, v in (cfg.get("devices") or {}).items()}
        by_nwk: dict[int, str] = {0: "Coordinator"}
        by_ieee: dict[str, str] = {}
        devices: dict[str, dict] = {}
        nwk_ieee: dict[int, str] = {}
        try:
            for line in (Z2M_DIR / "database.db").read_text().splitlines():
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ieee = str(d.get("ieeeAddr", "")).lower()
                if not ieee:
                    continue
                kind = d.get("type") or ""
                name = "Coordinator" if kind == "Coordinator" else friendly.get(ieee, ieee)
                by_ieee[ieee] = name
                nwk = d.get("nwkAddr")
                if isinstance(nwk, int):
                    by_nwk[nwk] = name
                    nwk_ieee[nwk] = ieee
                devices[ieee] = {
                    "name": name, "ieee": ieee, "type": kind, "model": d.get("modelId") or "",
                    "vendor": d.get("manufName") or "", "power": d.get("powerSource") or "",
                    "nwk": f"0x{nwk:04x}" if isinstance(nwk, int) else "",
                }
        except OSError as e:
            log.warning("Can't read Zigbee2MQTT database.db: %s", e)
        old, first = self.by_ieee, not self.loaded_at
        self.by_nwk, self.by_ieee, self.devices, self.nwk_ieee = by_nwk, by_ieee, devices, nwk_ieee
        self.loaded_at = time.time()
        # Reloaded every 10 minutes: say so only when something changed.
        if first:
            log.info("Loaded %d device names", len(by_ieee))
        elif by_ieee != old:
            added = sorted(by_ieee[i] for i in by_ieee.keys() - old.keys())
            removed = sorted(old[i] for i in old.keys() - by_ieee.keys())
            renamed = sorted(f"{old[i]} -> {by_ieee[i]}" for i in by_ieee.keys() & old.keys() if old[i] != by_ieee[i])
            parts = [f"{label}: {', '.join(names)}" for label, names in
                     (("added", added), ("removed", removed), ("renamed", renamed)) if names]
            log.info("Device names changed (%d now); %s", len(by_ieee), "; ".join(parts))

    def learn(self, short: str, ieee: str) -> None:
        """A (short, IEEE) pair heard on air. A device has one short address: drop the older pairs of
        the same IEEE, so its old address doesn't keep showing up as a second, "silent" device."""
        for old in [s for s, i in self.learned.items() if i == ieee and s != short]:
            del self.learned[old]
        self.learned[short] = ieee

    def ieee(self, addr: str | None) -> str | None:
        """The IEEE address behind a short address (as heard on air, else Zigbee2MQTT's database)."""
        if not addr:
            return None
        if len(addr) == 18:
            return addr.lower()
        try:
            return self.learned.get(addr) or self.nwk_ieee.get(int(addr, 16))
        except ValueError:
            return None

    def current_short(self, ieee: str) -> str | None:
        """The short address a device uses now: as heard on air, else Zigbee2MQTT's database."""
        for s, i in self.learned.items():
            if i == ieee:
                return s
        nwk = (self.devices.get(ieee) or {}).get("nwk")
        if nwk:
            learned_there = self.learned.get(nwk)
            return nwk if not learned_there or learned_there == ieee else None
        return None

    def name(self, addr: str | None) -> str | None:
        if not addr:
            return None
        if len(addr) == 6:  # 0x1234
            try:
                if int(addr, 16) == 0:
                    return "Coordinator"
            except ValueError:
                return None
        ieee = self.ieee(addr)
        if ieee and ieee in self.by_ieee:
            return self.by_ieee[ieee]
        if len(addr) == 6:
            learned = self.learned.get(addr)
            z2m = self.nwk_ieee.get(int(addr, 16))
            if learned and z2m and learned != z2m:
                return None  # the address now belongs to a device Zigbee2MQTT doesn't know: not its old owner's name
            return self.by_nwk.get(int(addr, 16))
        return None

    def meta(self, addr: str | None) -> dict:
        """Zigbee2MQTT's facts about the device at an address ({} if it isn't one of its devices)."""
        if addr == "0x0000":
            for d in self.devices.values():
                if d["type"] == "Coordinator":
                    return d
            return {"name": "Coordinator", "type": "Coordinator"}
        ieee = self.ieee(addr)
        return self.devices.get(ieee, {}) if ieee else {}
