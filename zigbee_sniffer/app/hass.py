"""Home Assistant integration: entities over MQTT discovery, events on HA's event bus, and
Zigbee2MQTT requests (the device page's Ping).

- The sniffer gets an HA device with sensors (connected, Wi-Fi signal, frames per minute,
  channel busy, resent, devices with problems, firmware of both boards, ...).
- Each Zigbee2MQTT device gets one "Zigbee health" sensor (ok / note / warning / problem /
  not heard, with the findings and numbers as attributes), attached to the device Zigbee2MQTT
  already created in HA, so it shows on that device's page.
- Leaves, rejoins, announcements, route errors, orphans, address changes and sniffer
  disconnects are fired as `zigbee_sniffer_event` on HA's event bus, for automations.

MQTT credentials come from the Supervisor (the Mosquitto add-on); events go through the
Supervisor's proxy to Core. Outside an add-on (no SUPERVISOR_TOKEN) all of this stays off.

The same MQTT connection listens to Zigbee2MQTT's bridge topics (its online/offline state, device
joins, interviews, leaves and announcements, OTA update results), which the app puts on its
charts as markers: most "why did this happen" questions are answered by what Zigbee2MQTT did a
minute before.
"""

import asyncio
import collections
import json
import logging
import os
import time
from pathlib import Path

import aiohttp

try:
    import paho.mqtt.client as mqtt
except ImportError:  # local runs without paho
    mqtt = None

log = logging.getLogger("hass")

BASE = "zigbee_sniffer"
EVENT_TYPE = "zigbee_sniffer_event"
EVENT_KINDS = {"leave", "rejoin", "rejoin_response", "announce", "network_status", "orphan", "address_change",
               "address_reused", "association", "association_response", "sniffer_offline", "sniffer_back", "sniffer_added",
               "bridge_reboot", "radio_reboot", "firmware_update", "incident", "ota_done", "ota_failed",
               "address_conflict", "bad_frame_counter"}
Z2M_EVENTS = {"device_joined", "device_interview", "device_leave", "device_announce"}
EVENT_MAX_AGE_S = 600  # events older than this (counted from stored captures after a restart) aren't fired
HEALTH = {3: "problem", 2: "warning", 1: "note", 0: "ok"}


def supervisor_token() -> str:
    """The add-on's Supervisor token. The base image's init (s6) starts the app with a clean
    environment, so it is read from s6's copy of the container environment when it isn't set."""
    tok = os.environ.get("SUPERVISOR_TOKEN") or os.environ.get("HASSIO_TOKEN") or ""
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        if tok:
            break
        try:
            with open(f"/run/s6/container_environment/{name}") as f:
                tok = f.read().strip()
        except OSError:
            pass
    return tok


class HomeAssistant:
    def __init__(self, enabled: bool, device_sensors: bool, version: str, data_dir: Path | None = None) -> None:
        self.token = supervisor_token()
        self.z2m_base = "zigbee2mqtt"  # Zigbee2MQTT's base topic (main sets it from its configuration)
        self.z2m_events: collections.deque = collections.deque(maxlen=1000)  # filled by MQTT's thread, drained by the app
        self._z2m_state: tuple[str, float] | None = None  # (last bridge state, since)
        self._published_file = (data_dir / "ha_devices.json") if data_dir else None
        self._published: set[str] = set()
        if self._published_file and self._published_file.exists():
            try:
                self._published = set(json.loads(self._published_file.read_text()))
            except (OSError, ValueError):
                pass
        self._event_q: asyncio.Queue | None = None
        self.enabled = enabled and bool(self.token) and mqtt is not None
        self.events_on = enabled and bool(self.token)  # events go through Core's API, no MQTT needed
        self.device_sensors = device_sensors
        self.version = version
        self.client = None
        self.connected = False
        self.error = "" if self.enabled else ("off in the app's options" if not enabled else
                                              "not running as a Home Assistant add-on" if not self.token else
                                              "paho-mqtt missing")
        self._announced: set[str] = set()  # discovery topics published since the last connect
        self._last: dict[str, str] = {}  # state topic -> last payload (publish changes only)
        self._recent_events: dict[tuple, float] = {}
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------ plumbing

    def _http(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers={"Authorization": f"Bearer {self.token}"})
        return self._session

    async def start(self) -> None:
        if not self.enabled:
            log.info("Home Assistant entities and events: %s", self.error)
            return
        try:
            async with self._http().get("http://supervisor/services/mqtt", timeout=aiohttp.ClientTimeout(total=10)) as r:
                cfg = (await r.json()).get("data") or {}
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            self.error = f"no MQTT broker from the Supervisor: {e}"
            log.warning(self.error)
            return
        if not cfg.get("host"):
            self.error = "no MQTT broker (install the Mosquitto add-on)"
            log.warning(self.error)
            return
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="zigbee_sniffer")
        if cfg.get("username"):
            c.username_pw_set(cfg["username"], cfg.get("password"))
        c.will_set(f"{BASE}/status", "offline", qos=1, retain=True)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        c.reconnect_delay_set(2, 60)
        c.connect_async(cfg["host"], int(cfg.get("port", 1883)), keepalive=60)
        c.loop_start()
        self.client = c
        log.info("MQTT: connecting to %s:%s", cfg["host"], cfg.get("port", 1883))

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        self.connected = not reason_code.is_failure
        if self.connected:
            self.error = ""
            self._announced.clear()
            self._last.clear()  # republish every state after a reconnect
            client.publish(f"{BASE}/status", "online", qos=1, retain=True)
            self._announce_sniffer()
            base = self.z2m_base
            for t in ("bridge/state", "bridge/event", "bridge/response/device/ota_update/update"):
                client.subscribe(f"{base}/{t}", qos=0)
            log.info("MQTT connected: Home Assistant entities are published; listening to %s/bridge", base)
        else:
            self.error = f"MQTT refused the connection: {reason_code}"
            log.warning(self.error)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None) -> None:
        self.connected = False
        if reason_code and reason_code.is_failure:
            self.error = f"MQTT connection lost: {reason_code}"

    def _on_message(self, client, userdata, msg) -> None:
        """Zigbee2MQTT's bridge topics (MQTT's thread): queue what happened for the app's timeline."""
        try:
            self._z2m_message(msg.topic, msg.payload.decode("utf-8", "replace"), bool(msg.retain))
        except Exception:  # noqa: BLE001 - a message we can't read must not stop MQTT's loop
            log.exception("Couldn't read Zigbee2MQTT's %s", msg.topic)

    def _z2m_message(self, topic: str, text: str, retained: bool) -> None:
        now = time.time()
        sub = topic[len(self.z2m_base) + 1:]
        try:
            data = json.loads(text)
        except ValueError:
            data = text
        if sub == "bridge/state":
            state = (data.get("state") if isinstance(data, dict) else str(data)).strip().lower()
            prev = self._z2m_state
            self._z2m_state = (state, now)
            if retained or prev is None or prev[0] == state:
                return  # the retained state on subscribing is old news
            if state == "online":
                away = now - prev[1]
                kind = "z2m_restart" if away < 600 else "z2m_online"
                self.z2m_events.append({"ts": now, "kind": kind, "ieee": "", "name": "",
                                        "detail": f"Zigbee2MQTT {'restarted' if kind == 'z2m_restart' else 'is online again'} "
                                                  f"(offline for {round(away)} s)"})
            elif state == "offline":
                self.z2m_events.append({"ts": now, "kind": "z2m_offline", "ieee": "", "name": "",
                                        "detail": "Zigbee2MQTT went offline"})
        elif sub == "bridge/event" and isinstance(data, dict) and not retained:
            kind = data.get("type")
            if kind not in Z2M_EVENTS:
                return
            d = data.get("data") or {}
            status = d.get("status")
            word = {"device_joined": "joined the network", "device_leave": "left the network (Zigbee2MQTT)",
                    "device_announce": "announced itself (Zigbee2MQTT)",
                    "device_interview": f"interview {status}" if status else "interview"}[kind]
            self.z2m_events.append({"ts": now, "kind": kind, "ieee": str(d.get("ieee_address") or "").lower(),
                                    "name": d.get("friendly_name") or "", "detail": word})
        elif sub.startswith("bridge/response/device/ota_update") and isinstance(data, dict) and not retained:
            d = data.get("data") or {}
            ok = data.get("status") == "ok"
            name = d.get("id") or d.get("friendly_name") or ""

            def version(v):
                if isinstance(v, dict):
                    return v.get("software_build_id") or v.get("date_code") or "?"
                return str(v) if v is not None else "?"

            detail = (f"firmware updated from {version(d.get('from'))} to {version(d.get('to'))} (Zigbee2MQTT)" if ok and (d.get("from") or d.get("to"))
                      else "firmware update finished (Zigbee2MQTT)" if ok
                      else f"firmware update failed (Zigbee2MQTT): {str(data.get('error') or '')[:200]}")
            self.z2m_events.append({"ts": now, "kind": "ota_done" if ok else "ota_failed", "ieee": "", "name": str(name),
                                    "detail": detail})

    def take_z2m_events(self) -> list[dict]:
        out = []
        while self.z2m_events:
            out.append(self.z2m_events.popleft())
        return out

    def _publish(self, topic: str, payload, retain: bool = True, only_changed: bool = True) -> None:
        if not (self.client and self.connected):
            return
        text = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        if only_changed and self._last.get(topic) == text:
            return
        self._last[topic] = text
        self.client.publish(topic, text, qos=1, retain=retain)

    def _announce(self, component: str, object_id: str, config: dict) -> None:
        topic = f"homeassistant/{component}/{BASE}/{object_id}/config"
        if topic in self._announced:
            return
        config.setdefault("availability_topic", f"{BASE}/status")
        self._publish(topic, config, only_changed=False)
        self._announced.add(topic)

    # ------------------------------------------------------------ the sniffer's entities

    def _sniffer_device(self) -> dict:
        return {"identifiers": [BASE], "name": "Zigbee Sniffer", "manufacturer": "Zigbee Sniffer",
                "model": "ESP32-C6 radio + ESP32-S3 bridge", "sw_version": self.version}

    def _announce_sniffer(self) -> None:
        dev, st = self._sniffer_device(), f"{BASE}/sniffer"

        def sensor(oid, name, template, **extra):
            self._announce("sensor", oid, {"name": name, "unique_id": f"{BASE}_{oid}", "state_topic": st,
                                           "value_template": template, "device": dev, **extra})

        self._announce("binary_sensor", "connected", {
            "name": "Connected", "unique_id": f"{BASE}_connected", "state_topic": st, "device": dev,
            "device_class": "connectivity", "value_template": "{{ 'ON' if value_json.connected else 'OFF' }}"})
        self._announce("binary_sensor", "radio_link", {
            "name": "Radio link problem", "unique_id": f"{BASE}_radio_link", "state_topic": st, "device": dev,
            "device_class": "problem", "entity_category": "diagnostic",
            "value_template": "{{ 'OFF' if value_json.radio_link else 'ON' }}"})
        sensor("problems", "Zigbee devices with problems", "{{ value_json.problems }}", icon="mdi:alert-outline",
               state_class="measurement", json_attributes_topic=f"{BASE}/problems")
        sensor("frames_per_minute", "Frames per minute", "{{ value_json.frames_per_minute }}",
               unit_of_measurement="frames/min", state_class="measurement", icon="mdi:access-point-network")
        sensor("channel_busy", "Channel busy", "{{ value_json.channel_busy }}", unit_of_measurement="%",
               state_class="measurement", icon="mdi:chart-bell-curve")
        sensor("resent", "Frames resent", "{{ value_json.resent }}", unit_of_measurement="%",
               state_class="measurement", icon="mdi:repeat")
        sensor("wifi_signal", "Bridge Wi-Fi signal", "{{ value_json.wifi_rssi }}", unit_of_measurement="dBm",
               device_class="signal_strength", state_class="measurement", entity_category="diagnostic")
        sensor("disconnects", "Bridge disconnects (24 h)", "{{ value_json.disconnects_24h }}",
               state_class="measurement", icon="mdi:wifi-off", entity_category="diagnostic")
        sensor("buffered_frames", "Frames delivered late", "{{ value_json.buffered_frames }}",
               state_class="total_increasing", icon="mdi:tray-full", entity_category="diagnostic")
        sensor("radio_firmware", "Radio firmware", "{{ value_json.radio_firmware }}", icon="mdi:chip",
               entity_category="diagnostic", json_attributes_topic=st,
               json_attributes_template="{{ {'version': value_json.radio_version} | tojson }}")
        sensor("bridge_firmware", "Bridge firmware", "{{ value_json.bridge_firmware }}", icon="mdi:chip",
               entity_category="diagnostic", json_attributes_topic=st,
               json_attributes_template="{{ {'version': value_json.bridge_version, 'partition': value_json.bridge_partition} | tojson }}")
        sensor("channel", "Zigbee channel", "{{ value_json.channel }}", icon="mdi:radio-tower",
               entity_category="diagnostic")

    def publish_sniffer(self, state: dict, problems: list[dict]) -> None:
        self._publish(f"{BASE}/sniffer", state)
        self._publish(f"{BASE}/problems", {"devices": problems[:40]})

    def publish_extra_sniffer(self, sid: str, name: str, state: dict) -> None:
        """A second (third...) sniffer: its own HA device with its link and firmware."""
        if not (self.client and self.connected):
            return
        dev = {"identifiers": [f"{BASE}_{sid}"], "name": f"Zigbee Sniffer {name}", "manufacturer": "Zigbee Sniffer",
               "model": "ESP32-C6 radio + ESP32-S3 bridge", "sw_version": self.version, "via_device": BASE}
        st = f"{BASE}/sniffer/{sid}"

        def sensor(oid, label, template, **extra):
            self._announce("sensor", f"{sid}_{oid}", {"name": label, "unique_id": f"{BASE}_{sid}_{oid}",
                                                      "state_topic": st, "value_template": template, "device": dev, **extra})

        self._announce("binary_sensor", f"{sid}_connected", {
            "name": "Connected", "unique_id": f"{BASE}_{sid}_connected", "state_topic": st, "device": dev,
            "device_class": "connectivity", "value_template": "{{ 'ON' if value_json.connected else 'OFF' }}"})
        self._announce("binary_sensor", f"{sid}_radio_link", {
            "name": "Radio link problem", "unique_id": f"{BASE}_{sid}_radio_link", "state_topic": st, "device": dev,
            "device_class": "problem", "entity_category": "diagnostic",
            "value_template": "{{ 'OFF' if value_json.radio_link else 'ON' }}"})
        sensor("wifi_signal", "Bridge Wi-Fi signal", "{{ value_json.wifi_rssi }}", unit_of_measurement="dBm",
               device_class="signal_strength", state_class="measurement", entity_category="diagnostic")
        sensor("disconnects", "Bridge disconnects (24 h)", "{{ value_json.disconnects_24h }}",
               state_class="measurement", icon="mdi:wifi-off", entity_category="diagnostic")
        sensor("buffered_frames", "Frames delivered late", "{{ value_json.buffered_frames }}",
               state_class="total_increasing", icon="mdi:tray-full", entity_category="diagnostic")
        sensor("radio_firmware", "Radio firmware", "{{ value_json.radio_firmware }}", icon="mdi:chip",
               entity_category="diagnostic", json_attributes_topic=st,
               json_attributes_template="{{ {'version': value_json.radio_version} | tojson }}")
        sensor("bridge_firmware", "Bridge firmware", "{{ value_json.bridge_firmware }}", icon="mdi:chip",
               entity_category="diagnostic", json_attributes_topic=st,
               json_attributes_template="{{ {'version': value_json.bridge_version, 'partition': value_json.bridge_partition} | tojson }}")
        self._publish(st, state)

    # ------------------------------------------------------------ each Zigbee device's health

    def _remove_device(self, ieee: str) -> None:
        """Take a device's health sensor out of HA: an empty retained config removes the entity, an
        empty state clears what the broker kept."""
        self._publish(f"homeassistant/sensor/{BASE}/{ieee}_health/config", "", only_changed=False)
        self._publish(f"{BASE}/device/{ieee}", "", only_changed=False)
        self._announced.discard(f"homeassistant/sensor/{BASE}/{ieee}_health/config")

    def _save_published(self) -> None:
        if self._published_file:
            try:
                self._published_file.write_text(json.dumps(sorted(self._published)))
            except OSError as e:
                log.warning("Can't remember the published devices: %s", e)

    def publish_devices(self, rows: list[dict]) -> None:
        if not (self.client and self.connected):
            return
        if not self.device_sensors:
            if self._published:  # the option was turned off: remove what we published before
                for ieee in self._published:
                    self._remove_device(ieee)
                self._published.clear()
                self._save_published()
            return
        current = {d["ieee"] for d in rows if d.get("ieee") and d.get("known") and d.get("type") != "Coordinator"}
        gone = self._published - current
        # (only a few at a time: an unreadable Zigbee2MQTT database must not wipe every sensor)
        if gone and current and len(gone) <= max(3, len(self._published) // 2):
            for ieee in gone:  # removed from Zigbee2MQTT: don't leave a frozen sensor (or a nameless device) behind
                self._remove_device(ieee)
            self._published -= gone
            self._save_published()
        if current - self._published:
            self._published |= current
            self._save_published()
        for d in rows:
            ieee = d.get("ieee")
            if not ieee or not d.get("known") or d.get("type") == "Coordinator":
                continue
            topic = f"{BASE}/device/{ieee}"
            self._announce("sensor", f"{ieee}_health", {
                "name": "Zigbee health", "unique_id": f"{BASE}_{ieee}_health", "state_topic": topic,
                "value_template": "{{ value_json.state }}", "json_attributes_topic": topic,
                "json_attributes_template": "{{ value_json.attributes | tojson }}", "icon": "mdi:zigbee",
                "device_class": "enum", "options": ["ok", "note", "warning", "problem", "not heard"],
                "entity_category": "diagnostic", "device": {"identifiers": [f"zigbee2mqtt_{ieee}"]},
            })
            heard = bool(d["tx"] or d["msgs"])
            state = HEALTH[d["sev"]] if heard or d["sev"] >= 2 else "not heard"
            attrs = {
                "findings": [f["text"] for f in d["flags"]], "short_address": d["addr"],
                "signal_at_sniffer": d["rssi_avg"], "heard_best_by": d.get("rssi_sniffer_name"),
                "resent_pct": d["retry_pct"], "no_ack_pct": d["noack_pct"], "lost_pct": d.get("rx_lost_pct"),
                "best_link_cost": (d.get("mesh") or {}).get("best"), "mesh_neighbours": (d.get("mesh") or {}).get("n"),
                "next_hop": (d.get("via") or {}).get("name") or (d.get("via") or {}).get("addr"),
                "messages_last_hour": d["msgs"],
                "last_heard": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(d["last_seen"])) if d["last_seen"] else None,
            }
            self._publish(topic, {"state": state, "attributes": attrs})

    # ------------------------------------------------------------ events on HA's bus

    def queue_events(self, events: list[dict], name_of) -> None:
        """Hand events to the sender (run_events), so a slow Core never holds up the history."""
        if not (self.events_on and events):
            return
        if self._event_q is None:
            self._event_q = asyncio.Queue(maxsize=2000)
        for e in events:
            try:
                self._event_q.put_nowait((e, name_of))
            except asyncio.QueueFull:
                break

    async def run_events(self) -> None:
        if self._event_q is None:
            self._event_q = asyncio.Queue(maxsize=2000)
        while True:
            e, name_of = await self._event_q.get()
            try:
                await self._fire(e, name_of)
            except Exception:  # noqa: BLE001
                log.exception("Firing %s failed", EVENT_TYPE)

    async def fire_events(self, events: list[dict], name_of) -> None:
        for e in events:
            await self._fire(e, name_of)

    async def _fire(self, e: dict, name_of) -> None:
        now = time.time()
        if not self.events_on or e["kind"] not in EVENT_KINDS or now - e["ts"] > EVENT_MAX_AGE_S:
            return
        key = (e["kind"], e["addr"], e.get("other", "") if e["addr"] == "sniffer" else "")  # each sniffer its own
        if now - self._recent_events.get(key, 0) < 60:  # route errors come in bursts
            return
        self._recent_events[key] = now
        if len(self._recent_events) > 5000:
            self._recent_events = {k: t for k, t in self._recent_events.items() if now - t < 60}
        device = e.get("name") or (name_of(e["addr"]) if e["addr"] not in ("sniffer", "network") else None) or e["addr"]
        data = {"kind": e["kind"], "device": device, "address": e["addr"],
                "ieee": e.get("ieee", ""), "detail": e.get("detail", ""),
                "time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(e["ts"]))}
        try:
            async with self._http().post(f"http://supervisor/core/api/events/{EVENT_TYPE}", json=data,
                                         timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status >= 300:
                    log.warning("Firing %s failed: HTTP %s", EVENT_TYPE, r.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            log.warning("Firing %s failed: %s", EVENT_TYPE, err)

    # ------------------------------------------------------------ Zigbee2MQTT

    def z2m_read(self, base_topic: str, friendly_name: str) -> bool:
        """Ask Zigbee2MQTT to read the device's ZCL version (Basic cluster): a harmless round trip."""
        if not (self.client and self.connected):
            return False
        self.client.publish(f"{base_topic}/{friendly_name}/set",
                            json.dumps({"read": {"cluster": "genBasic", "attributes": ["zclVersion"]}}), qos=1)
        return True
