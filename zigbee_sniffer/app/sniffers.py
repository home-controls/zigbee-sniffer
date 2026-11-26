"""One sniffer: its bridge connection, clock, status, health counters and events.

The app can listen through several sniffers (`sniffer_host` is "main", `more_sniffers` adds
others). Each keeps its own TCP link to its bridge, pairs the bridge's clock with ours from that
link's HELLO, and hands every frame to the merger (merge.py) with the time it was heard.
"""

import asyncio
import json
import logging
import re
import time

import bridge as bridge_mod
import proto

log = logging.getLogger("sniffer")

LATE_S = 5.0  # a frame heard this much before it arrived came from the bridge's buffer
OFFLINE_S = 120  # away this long, a sniffer counts as offline (an event for Home Assistant)
CREEP = 50e-6  # the bridge clock's offset may grow this much per second (a bridge clock up to 50 ppm slow)
HEALTH_FIELDS = ("up_s", "disconnects", "rssi_sum", "rssi_n", "rssi_min", "rssi_max", "buffered", "backlog_max", "crc",
                 "heard", "solo", "total")
# heard / solo / total: of our network's transmissions while this sniffer was connected (with several
# sniffers), how many it heard, how many only it heard, and how many there were
H_HEARD, H_SOLO, H_TOTAL = 9, 10, 11


def why(e: BaseException, silent: str) -> str:
    """What went wrong, in words. A timeout carries no text of its own (str() is ""), so it gets
    `silent`; any other exception with no text shows its type rather than nothing."""
    text = str(e).strip()
    if text:
        return text
    return silent if isinstance(e, (asyncio.TimeoutError, TimeoutError)) else type(e).__name__


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:24]


class Sniffer:
    several = False  # set when more than one sniffer is configured: names go into event texts

    def __init__(self, sid: str, name: str, host: str, port: int, http_port: int, on_frame, on_dropped, channel) -> None:
        self.id, self.name, self.host, self.port = sid, name, host, port
        self.on_frame = on_frame  # on_frame(sniffer, ts, channel, rssi, lqi, psdu, late)
        self.on_dropped = on_dropped  # on_dropped(ts, frames)
        self.on_link = lambda up: None  # the connection opened (True) or closed (False)
        self.on_alive = lambda: None  # something arrived from the bridge (it isn't stalled)
        self.on_offset = lambda delta: None  # its clock pairing moved by delta seconds (frames' times move with it)
        self.on_clock_restart = lambda: None  # its bridge restarted: its clock started over (paired afresh)
        self.channel = channel  # callable: the channel to ask for
        self.web = bridge_mod.Bridge(host, http_port)
        self.connected = False
        self.connected_since: float | None = None
        self.disconnected_since: float | None = None
        self.offline_reported = False
        self.last_error = ""
        self.writer: asyncio.StreamWriter | None = None
        self.hello: dict = {}
        self.radio: dict = {}
        self.bridge: dict = {}
        self.base_radio_us: int | None = None  # plain T_FRAME timing
        self.base_wall = 0.0
        self.anchor: tuple[int, float] | None = None  # (bridge_us, wall time) from this link's HELLO
        self.offset: float | None = None  # wall time - bridge time, followed frame by frame (see bridge_time)
        self.offset_at = 0.0
        self.offset0: float | None = None  # the offset when the link opened, to show how far the clock drifted
        self.last_offset: float | None = None  # the latest offset, kept across connections (see bridge_time)
        self.last_bridge_us: int | None = None  # the bridge clock's latest reading, kept across connections
        self.frames = 0
        self.buffered_frames = 0
        self.backlog_bytes: int | None = None
        self.drop_base: dict[str, int] = {}
        self.crc_base: int | None = None
        self.uptime: dict[str, int] = {}
        self.versions: dict[str, str] = {}
        self.recent: list = []  # [second, frames] for this sniffer's frame rate
        self.health: dict[int, list] = {}  # minute -> HEALTH_FIELDS, since the last write
        self.events: list[dict] = []
        self.bad_messages = 0

    # ------------------------------------------------------------ bookkeeping

    def rec(self, ts: float | None = None) -> list:
        minute = int((ts or time.time()) // 60) * 60
        r = self.health.get(minute)
        if r is None:
            r = self.health[minute] = [0, 0, 0, 0, None, None, 0, 0, 0, 0, 0, 0]
        return r

    def event(self, kind: str, detail: str, ts: float | None = None) -> None:
        self.events.append({"ts": ts or time.time(), "kind": kind, "addr": "sniffer", "other": self.id, "ieee": "",
                            "detail": f"{self.name}: {detail}" if Sniffer.several else detail, "file": "", "n": 0})

    def take(self) -> tuple[dict, list]:
        rows = {(self.id, m): r for m, r in self.health.items()}
        events = self.events
        self.health, self.events = {}, []
        return rows, events

    def tick(self, dt: float) -> None:
        """Every few seconds: connected time, and a sniffer away long enough to report as offline."""
        if self.connected:
            self.rec()[0] += dt
        elif self.disconnected_since and not self.offline_reported and time.time() - self.disconnected_since > OFFLINE_S:
            self.offline_reported = True
            self.event("sniffer_offline", f"no connection to the bridge for {OFFLINE_S // 60} minutes: {self.last_error}")

    def fps(self) -> float:
        now = int(time.time())
        return round(sum(c for s, c in self.recent if now - 10 <= s < now) / 10, 1)

    def send(self, msg: bytes) -> None:
        if self.writer:
            self.writer.write(msg)

    # ------------------------------------------------------------ timing

    def wall_time(self, radio_us: int) -> float:
        """Plain T_FRAME: the radio's clock for spacing, re-anchored to arrival when they drift apart."""
        now = time.time()
        if self.base_radio_us is None or radio_us < self.base_radio_us:
            self.base_radio_us, self.base_wall = radio_us, now
            return now
        ts = self.base_wall + (radio_us - self.base_radio_us) / 1e6
        if abs(ts - now) > 1.0:
            self.base_radio_us, self.base_wall = radio_us, now
            return now
        return ts

    def bridge_time(self, bridge_us: int) -> float:
        """T_FRAME_AT (bridge 0.3+ sends every frame this way, live ones too): wall time = bridge time
        + offset. Arrival minus bridge time can only overstate the offset (delivery takes time), so
        the offset follows the smallest such value, allowed to creep up by CREEP per second for a
        bridge clock that runs slow. A single pairing at HELLO drifts by 10-20 ppm: past the 5 s
        "late" limit within days, and past the 0.25 s window that merges copies from two sniffers
        within hours."""
        now = time.time()
        b = bridge_us / 1e6
        seen = now - b
        if self.offset is None:
            if self.anchor is None:
                log.warning("%s: a buffered frame came before the bridge's HELLO: timing from arrival", self.name)
                self.offset = seen
            else:
                self.offset = self.anchor[1] - self.anchor[0] / 1e6
            self.offset0, self.offset_at = self.offset, now
            if seen < self.offset:
                self.offset = seen
            restarted = (self.anchor is not None and self.last_bridge_us is not None
                         and self.anchor[0] < self.last_bridge_us - 1_000_000)
            if restarted:
                # The bridge restarted: its clock started over, so the new pairing has nothing to do
                # with the old one (the offset leaps by the old uptime, while frames' times stay right).
                # The merger starts this sniffer's correction afresh instead of moving it by that leap
                # (0.5.3-0.5.9 did, and a bridge that restarted after 38 h had every frame filed 38 h ago).
                log.info("%s: the bridge restarted (its clock started over): timing paired afresh", self.name)
                self.on_clock_restart()
            elif self.last_offset is not None:
                # Same clock, new connection: to the merger that is one more move, the whole way from
                # where the last connection's pairing ended (the bridge's drift over a long connection),
                # else its correction would be that far off.
                self.on_offset(self.offset - self.last_offset)
            self.last_offset, self.last_bridge_us = self.offset, bridge_us
            return b + self.offset
        old = self.offset
        self.offset += CREEP * max(0.0, now - self.offset_at)
        self.offset_at = now
        if seen < self.offset:
            self.offset = seen
        if self.offset != old:  # (the merger moves its correction with it, so copies stay lined up)
            self.on_offset(self.offset - old)
        self.last_offset = self.offset
        if self.last_bridge_us is None or bridge_us > self.last_bridge_us:
            self.last_bridge_us = bridge_us
        return b + self.offset

    def prime(self, msgs: list) -> None:
        """Before timing a burst of frames that arrived together: move the offset once, to the
        burst's smallest "arrival - bridge time" (its newest frame's). Stepping frame by frame put
        every later frame of the burst at the arrival time, up to tens of ms off its real spacing.
        Not before the HELLO has paired the clocks: the first read holds the HELLO and the buffered
        frames, and pairing from a buffered frame's arrival would put every frame seconds late."""
        if self.offset is None and self.anchor is None:
            return
        newest = max((proto.FRAME_AT_TIME.unpack_from(p)[0] for t, p in msgs
                      if t == proto.T_FRAME_AT and len(p) > proto.FRAME_AT_TIME.size), default=None)
        if newest is not None:
            self.bridge_time(newest)

    def clock_drift_ms(self) -> float | None:
        """How far the bridge's clock has drifted from ours since the link opened (+ = it runs slow)."""
        if self.offset is None or self.offset0 is None:
            return None
        return round((self.offset - self.offset0) * 1000, 1)

    # ------------------------------------------------------------ messages

    def _frame(self, payload: bytes, ts: float | None) -> None:
        if len(payload) < proto.FRAME_HDR.size:
            return
        radio_us, channel, rssi, lqi, _flags = proto.FRAME_HDR.unpack_from(payload)
        arrival = time.time()
        if ts is None:
            ts = self.wall_time(radio_us)
        late = arrival - ts > LATE_S
        self.frames += 1
        if late:
            self.buffered_frames += 1
            self.rec(arrival)[6] += 1
        sec = int(arrival)
        if not self.recent or self.recent[-1][0] != sec:
            self.recent.append([sec, 0])
            del self.recent[:-64]
        self.recent[-1][1] += 1
        self.on_frame(self, ts, channel, rssi, lqi, payload[proto.FRAME_HDR.size :], late)

    def _drops(self, name: str, value: int) -> None:
        base = self.drop_base.get(name)
        self.drop_base[name] = value
        if base is not None:
            self.on_dropped(time.time(), value - base if value >= base else value)

    def _board(self, board: str, uptime: int, version: str | None) -> None:
        last = self.uptime.get(board)
        self.uptime[board] = uptime
        if last is not None and uptime + 10 < last and uptime < 600:
            self.event(f"{board}_reboot", f"the {board} restarted (up {uptime} s; it had been up {last} s)")
        if version:
            old = self.versions.get(board)
            self.versions[board] = version
            if old and old != version:
                self.event("firmware_update", f"{board} firmware {old} -> {version}")

    def handle(self, msg_type: int, payload: bytes) -> None:
        if msg_type == proto.T_FRAME_AT and len(payload) > proto.FRAME_AT_TIME.size:
            (bridge_us,) = proto.FRAME_AT_TIME.unpack_from(payload)
            self._frame(payload[proto.FRAME_AT_TIME.size :], self.bridge_time(bridge_us))
        elif msg_type == proto.T_FRAME:
            self._frame(payload, None)
        elif msg_type == proto.T_RADIO_STATUS and len(payload) >= proto.RADIO_STATUS.size:
            up, frames, dropped, ch, a, b, c = proto.RADIO_STATUS.unpack_from(payload)
            self.radio = {"uptime_s": up, "frames": frames, "dropped": dropped, "channel": ch,
                          "version": f"{a}.{b}.{c}", "at": time.time()}
            self._drops("radio", dropped)
            self._board("radio", up, f"{a}.{b}.{c}")
        elif msg_type == proto.T_BRIDGE_STATUS and len(payload) >= proto.BRIDGE_STATUS.size:
            up, uf, crc, dropped, rssi, link = proto.BRIDGE_STATUS.unpack_from(payload)
            self.bridge = {"uptime_s": up, "uart_frames": uf, "uart_crc_errors": crc, "tcp_dropped": dropped,
                           "wifi_rssi": rssi, "radio_link_ok": bool(link), "at": time.time()}
            self._drops("bridge", dropped)
            self._board("bridge", up, self.web.status.get("bridge"))
            r = self.rec()
            if rssi:
                r[2] += rssi
                r[3] += 1
                r[4] = rssi if r[4] is None else min(r[4], rssi)
                r[5] = rssi if r[5] is None else max(r[5], rssi)
            if self.crc_base is not None and crc >= self.crc_base:
                r[8] += crc - self.crc_base
            self.crc_base = crc
        elif msg_type == proto.T_HELLO:
            try:
                self.hello = json.loads(payload.decode())
            except ValueError:
                self.hello = {"raw": payload.decode(errors="replace")}
            if not isinstance(self.hello, dict):
                self.hello = {"raw": str(self.hello)[:200]}
            if isinstance(self.hello.get("bridge_us"), int):
                self.anchor = (self.hello["bridge_us"], time.time())
            self.backlog_bytes = self.hello.get("backlog_bytes")
            if self.backlog_bytes:
                log.info("%s: the bridge kept %d bytes of frames while we were away; they come first",
                         self.name, self.backlog_bytes)
                r = self.rec()
                r[7] = max(r[7], self.backlog_bytes)

    # ------------------------------------------------------------ the link

    # The link's own parts; a USB sniffer (usb.UsbSniffer) has its own.
    kind = "bridge"
    not_set = "Set sniffer_host in the app's Configuration tab (the bridge prints its IP at boot)."
    closed = "closed by the bridge"

    def where(self) -> str:
        return f"{self.host}:{self.port}"

    async def open(self):
        return await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=10)

    def open_failed(self, e: BaseException) -> str:
        return f"Can't reach {self.where()}: {why(e, 'no answer in 10 s')}"

    def greet(self, writer) -> None:
        # Bridge 0.3+ then sends what it buffered while we were away, each frame with its own
        # time (T_FRAME_AT); older bridges ignore this and send plain T_FRAME.
        writer.write(proto.encode(proto.T_CLIENT_HELLO, proto.CLIENT_HELLO.pack(proto.CLIENT_FRAME_AT)))
        writer.write(proto.encode(proto.T_SET_CHANNEL, bytes([self.channel()])))

    async def keep_up(self) -> None:
        """Runs while the link is open (cancelled when it closes)."""

    def after_read(self, dec: proto.Decoder) -> None:
        """After each read's messages are handled."""

    async def run(self, ready: asyncio.Event, on_disconnect) -> None:
        if not self.host:
            self.last_error = self.not_set
            log.warning(self.last_error)
            return
        await ready.wait()
        backoff = 2
        while True:
            try:
                reader, writer = await self.open()
            except (OSError, asyncio.TimeoutError) as e:
                self.last_error = self.open_failed(e)
                log.warning("%s: %s; retrying in %d s", self.name, self.last_error, backoff)
                if self.disconnected_since is None:
                    self.disconnected_since = time.time()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 2
            self.connected, self.connected_since, self.last_error, self.writer = True, time.time(), "", writer
            self.base_radio_us, self.anchor, self.offset, self.offset0 = None, None, None, None
            self.drop_base, self.crc_base = {}, None
            if self.disconnected_since:
                away = time.time() - self.disconnected_since
                self.event("sniffer_back" if self.offline_reported else "sniffer_connected",
                           f"connected again after {round(away)} s away")
                self.disconnected_since, self.offline_reported = None, False
            log.info("%s: connected to the sniffer at %s", self.name, self.where())
            self._hook(self.on_link, True)
            self.greet(writer)
            dec = proto.Decoder()
            beside = asyncio.create_task(self.keep_up())
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(4096), timeout=30)
                    if not data:
                        raise ConnectionError(self.closed)
                    self._hook(self.on_alive)
                    msgs = list(dec.feed(data))
                    self.prime(msgs)
                    for msg_type, payload in msgs:
                        try:
                            self.handle(msg_type, payload)
                        except Exception:  # noqa: BLE001 - one bad message must not end the link or the app
                            self.bad_messages += 1
                            if self.bad_messages <= 5 or self.bad_messages % 1000 == 0:
                                log.exception("%s: couldn't handle a message of type 0x%02x (%d so far)",
                                              self.name, msg_type, self.bad_messages)
                    self.after_read(dec)
            except (OSError, ConnectionError, asyncio.TimeoutError) as e:
                self.last_error = f"Connection lost: {why(e, 'no data for 30 s')}"
                log.warning("%s: %s", self.name, self.last_error)
            finally:
                beside.cancel()
                self.connected, self.writer = False, None
                self.disconnected_since = time.time()
                self.rec()[1] += 1
                self.event("sniffer_disconnected", self.last_error or "the connection closed")
                writer.close()
                self._hook(self.on_link, False)
                on_disconnect()
            await asyncio.sleep(2)

    def _hook(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception:  # noqa: BLE001 - the app's bookkeeping must not end the link
            log.exception("%s: a connection hook failed", self.name)

    def summary(self) -> dict:
        b = self.web.status
        return {
            "id": self.id, "name": self.name, "kind": self.kind, "host": self.host, "connected": self.connected,
            "connected_since": self.connected_since, "disconnected_since": self.disconnected_since,
            "last_error": self.last_error, "fps": self.fps(), "frames": self.frames,
            "buffered_frames": self.buffered_frames, "backlog_bytes": self.backlog_bytes,
            "wifi_rssi": b.get("wifi_rssi") or self.bridge.get("wifi_rssi"),
            "radio": b.get("radio") or self.radio.get("version"), "radio_firmware": b.get("radio_firmware"),
            "bridge": b.get("bridge") or self.hello.get("bridge"), "bridge_firmware": b.get("bridge_firmware"),
            "radio_link": b.get("radio_link", self.bridge.get("radio_link_ok")),
            "clock_offset_ms": self.clock_drift_ms(),
        }
