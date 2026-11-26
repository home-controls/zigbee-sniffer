"""A sniffer radio plugged straight into the Home Assistant box over USB (radio firmware 0.3+,
built with CONFIG_SNIFF_LINK_USB, e.g. a XIAO ESP32C5).

There is no bridge: the radio's own USB port (USB Serial/JTAG, /dev/ttyACM*) carries the radio's
side of the protocol, and this app plays the bridge's part:

- it reads plain T_FRAME / T_RADIO_STATUS / T_RADIO_BOOT / T_UPDATE_ACK;
- it sends T_SET_CHANNEL, a T_PING every second (with PING_RADIO_HEARD while radio statuses
  arrive, which is what lets a radio on trial keep a new image), and firmware updates
  (T_UPDATE_*: stop-and-wait, one ack per message) - so the radio updates over the cable without
  anyone pressing BOOT/RESET.

Timing: frames carry the radio's microsecond clock. It is followed like a bridge's clock
(Sniffer.bridge_time: the smallest "arrival - radio time", allowed to creep). While nobody has
the port open the radio keeps writing into its USB buffer, so the first frames after opening can
be a minute old (in 0.6.0-0.6.1 the first of them paired the clock, 53 s off, and the merger kept
that as the sniffer's skew, so nothing it heard merged). So the frames of the first CALIB_S are
held and the clock is paired from the freshest of them ("arrival - radio time" smallest); the old
ones then come out at their real time, as late frames. A radio that restarts (an update, a replug)
starts its clock over; that is a clock restart for the merger, as for a bridge.

Some frames carry a stale timestamp: ESP-IDF's 802.15.4 driver stamps a receive slot when a
frame's start is seen, and when the radio is busy (draining its USB backlog right after the port
opens) a frame can finish in a slot that wasn't stamped for it, so it carries the time the slot was
last used, seconds or minutes ago. The bridges' timing shrugs those off (the pairing only follows
the smallest "arrival - radio time"); here a clock going backwards is taken for a restart only when
the radio clock is fresh from a boot (< FRESH_BOOT_US), and a stale stamp is given the previous
frame's time (0.6.2-0.6.3 re-paired the clock on them a few times after each start).
"""

import asyncio
import logging
import os
import time

import bridge as bridge_mod
import proto
from sniffers import Sniffer, why

log = logging.getLogger("usb")

HEARD_S = 3.0  # a radio status this recent = the radio hears us and we hear it
PING_S = 1.0  # the bridge pings its radio every second
CALIB_S = 1.0  # after the port opens, frames are held this long and the clock is paired from the freshest
FRESH_BOOT_US = 30_000_000  # a radio clock this young that went backwards = the radio restarted
TRIAL_WAIT_S = 120.0  # after an update: time for the radio to come back and keep the image
ESP_ERRORS = {
    -1: "ESP_FAIL", 0x101: "ESP_ERR_NO_MEM", 0x102: "ESP_ERR_INVALID_ARG", 0x103: "ESP_ERR_INVALID_STATE",
    0x104: "ESP_ERR_INVALID_SIZE", 0x105: "ESP_ERR_NOT_FOUND", 0x107: "ESP_ERR_TIMEOUT",
    0x1501: "ESP_ERR_OTA_PARTITION_CONFLICT", 0x1502: "ESP_ERR_OTA_SELECT_INFO_INVALID",
    0x1503: "ESP_ERR_OTA_VALIDATE_FAILED", 0x1504: "ESP_ERR_OTA_SMALL_SEC_VER",
    0x1505: "ESP_ERR_OTA_ROLLBACK_FAILED", 0x1506: "ESP_ERR_OTA_ROLLBACK_INVALID_STATE",
}
STAGES = {proto.T_UPDATE_BEGIN: "the start", proto.T_UPDATE_DATA: "a block", proto.T_UPDATE_END: "the end"}


def err_name(err: int) -> str:
    return ESP_ERRORS.get(err, f"error 0x{err & 0xFFFFFFFF:x}")


# ---------------------------------------------------------------- the serial port

class SerialWriter:
    """The write half of a serial port, shaped like asyncio's StreamWriter (write / close)."""

    def __init__(self, loop: asyncio.AbstractEventLoop, fd: int) -> None:
        self.loop, self.fd = loop, fd
        self.pending = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        if self.closed:
            return
        self.pending += data
        self._flush()

    def _flush(self) -> None:
        while self.pending and not self.closed:
            try:
                n = os.write(self.fd, self.pending)
            except BlockingIOError:
                self.loop.add_writer(self.fd, self._writable)
                return
            except OSError as e:  # unplugged: the reader sees it too and ends the link
                log.debug("serial write failed: %s", e)
                self.pending.clear()
                return
            del self.pending[:n]

    def _writable(self) -> None:
        self.loop.remove_writer(self.fd)
        self._flush()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for remove in (self.loop.remove_reader, self.loop.remove_writer):
            try:
                remove(self.fd)
            except (OSError, ValueError):
                pass
        try:
            os.close(self.fd)
        except OSError:
            pass


ESPRESSIF_VID = "303a"  # USB vendor id of the ESP32 chips' own USB (Serial/JTAG)


class NotOurDevice(OSError):
    pass


def usb_vendor(path: str, sys_root: str = "/sys") -> str | None:
    """The USB vendor id (4 hex digits) of a serial device, from sysfs: /sys/class/tty/<name>/device
    leads to the USB interface, and the device above it has idVendor. None when it isn't a USB
    device or sysfs doesn't say."""
    name = os.path.basename(os.path.realpath(path))  # /dev/serial/by-id/... -> ttyACM0
    dev = os.path.join(sys_root, "class", "tty", name, "device")
    if not os.path.exists(dev):
        return None
    d = os.path.realpath(dev)
    top = os.path.realpath(sys_root)
    while d.startswith(top) and d != top:
        f = os.path.join(d, "idVendor")
        if os.path.isfile(f):
            try:
                with open(f) as fh:
                    return fh.read().strip().lower()
            except OSError:
                return None
        d = os.path.dirname(d)
    return None


def device_problem(path: str, sys_root: str = "/sys") -> str:
    """Why this app won't open a device ("" = fine). Only an ESP32's own USB port is ours: the
    device list also offers the Zigbee and Thread dongles, and pings sent into one of those would
    disturb Zigbee2MQTT or the Thread border router, so anything else is refused before it is opened."""
    vendor = usb_vendor(path, sys_root)
    if vendor == ESPRESSIF_VID:
        return ""
    if vendor is None and "espressif" in path.lower():
        return ""  # sysfs didn't say, but the by-id name does
    what = f"USB vendor {vendor}" if vendor else "not a USB device this app can identify"
    return (f"won't open {path}: it isn't an ESP32's own USB port ({what}, an ESP32's is {ESPRESSIF_VID}). "
            "It may be a Zigbee or Thread dongle; pick the usb-Espressif_USB_JTAG_serial_debug_unit device")


async def open_serial(path: str) -> tuple[asyncio.StreamReader, SerialWriter]:
    """Open a USB serial port raw (no echo, no line editing, no CR/LF changes: the bytes are binary
    frames), without HUPCL, so closing it never drops the control lines. USB Serial/JTAG ignores
    the baud rate. Raises OSError when the device isn't there, isn't an Espressif USB device (see
    device_problem) or another program holds it exclusively."""
    problem = device_problem(path)  # before anything touches the device
    if problem:
        raise NotOurDevice(problem)
    import fcntl  # Linux only (the add-on's container); tests use their own opener
    import termios
    import tty

    loop = asyncio.get_running_loop()
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.ioctl(fd, termios.TIOCEXCL)  # nothing else opens it while we have it
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[2] = (attrs[2] & ~termios.HUPCL) | termios.CLOCAL | termios.CREAD
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIOFLUSH)
    except BaseException:
        os.close(fd)
        raise
    reader = asyncio.StreamReader()
    writer = SerialWriter(loop, fd)

    def readable() -> None:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return
        except OSError as e:  # EIO when the device is unplugged
            loop.remove_reader(fd)
            reader.set_exception(e)
            return
        if not data:
            loop.remove_reader(fd)
            reader.feed_eof()
            return
        reader.feed_data(data)

    loop.add_reader(fd, readable)
    return reader, writer


# ---------------------------------------------------------------- the sniffer

class UpdateError(Exception):
    pass


class UsbRadio:
    """What a bridge's web side gives the app (status, firmware updates; see bridge.Bridge), for a
    radio on USB: the status comes from the radio's own messages, updates go over the cable."""

    def __init__(self, sn: "UsbSniffer") -> None:
        self.sn = sn
        self.host = sn.device
        self.at = 0.0
        self.error = ""
        self.updating: dict | None = None
        self.last_result: dict | None = None
        self.acks: asyncio.Queue | None = None
        self.last_update = "none since the app started"

    @property
    def status(self) -> dict:
        sn = self.sn
        r, b = sn.radio, sn.boot
        heard = bool(r) and time.time() - r.get("at", 0) < HEARD_S
        out = {
            "link": "usb", "device": sn.device, "updates": True, "last_update": self.last_update,
            "radio": b.get("version") or r.get("version"), "radio_firmware": b.get("state"),
            "radio_chip": b.get("chip"),  # None until the radio says (radio 0.3+): updates wait for it
            "radio_uptime_s": r.get("uptime_s"),
        }
        if sn.connected:
            out["radio_link"] = heard
        return out

    async def poll(self) -> dict:
        self.at = time.time()
        return self.status

    async def run(self, every_s: float = 30) -> None:
        while True:  # nothing to poll: the radio's messages keep the status current
            await asyncio.sleep(3600)

    def ack(self, payload: bytes) -> None:
        if len(payload) < proto.UPDATE_ACK.size or self.acks is None:
            return
        stage, offset, err = proto.UPDATE_ACK.unpack_from(payload)
        self.acks.put_nowait({"stage": stage, "offset": offset, "err": err})

    async def _step(self, msg_type: int, payload: bytes, timeout: float, tries: int = 1) -> dict:
        """Send one update message and wait for its ack; resend after a silent timeout."""
        assert self.acks is not None
        for _ in range(tries):
            while not self.acks.empty():  # a late ack from an earlier try
                self.acks.get_nowait()
            if not self.sn.writer:
                raise UpdateError("the radio went away during the update")
            self.sn.send(proto.encode(msg_type, payload))
            deadline = time.monotonic() + timeout
            while (left := deadline - time.monotonic()) > 0:
                try:
                    a = await asyncio.wait_for(self.acks.get(), left)
                except asyncio.TimeoutError:
                    break
                if a["stage"] != msg_type:
                    continue
                if a["err"]:
                    raise UpdateError(f"the radio refused {STAGES[msg_type]} of the image at byte {a['offset']}: "
                                      f"{err_name(a['err'])}")
                return a
        raise UpdateError(f"no answer from the radio to {STAGES[msg_type]} of the image within {timeout:g} s")

    async def _trial(self, version: str, old: str | None) -> dict:
        """After the image went in: the radio restarts into it on trial and keeps it once it hears
        our ping (both directions of the cable work), else it rolls back."""
        until = time.monotonic() + TRIAL_WAIT_S
        while time.monotonic() < until:
            b = self.sn.boot
            if b.get("version") == version and b.get("state") == "confirmed":
                return {"ok": True, "message": f"the radio runs {version} and kept it after its trial"}
            if b.get("state") == "rolled_back" and b.get("version") != version:
                return {"ok": False, "message": f"{version} failed its trial: the radio went back to {b.get('version')}"}
            await asyncio.sleep(0.5)
        running = self.sn.radio.get("version") if self.sn.connected else None
        if running == version:
            return {"ok": True, "message": f"the radio runs {version}, but hasn't said yet that it kept it"}
        return {"ok": False, "message": f"the image went in, but the radio hasn't come back with {version} within "
                                        f"{TRIAL_WAIT_S:g} s (it runs {running or 'nothing we can hear'}; was {old})"}

    async def update(self, target: str, data: bytes, token: str = "") -> dict:
        """Send an image to the radio over the cable; returns {"ok", "message", "seconds"} like
        bridge.Bridge.update. The token isn't needed: the cable is local."""
        started = time.time()
        version = "?"
        result: dict = {"ok": False, "message": "the update didn't start"}
        begun = False
        try:
            info = bridge_mod.image_info(data)
            version = info["version"]
            self.updating = {"target": target, "version": version, "size": len(data), "started": started, "sent": 0}
            if target != "radio":
                raise UpdateError("a USB sniffer has no bridge: only radio images go to it")
            problems = bridge_mod.check_image(info, target, self.status)
            if problems:
                raise UpdateError("; ".join(problems))
            if not self.sn.connected:
                raise UpdateError("the radio isn't connected")
            old = self.sn.boot.get("version") or self.sn.radio.get("version")
            self.acks = asyncio.Queue()
            begun = True
            await self._step(proto.T_UPDATE_BEGIN, proto.UPDATE_BEGIN.pack(len(data)), timeout=15)
            off = 0
            while off < len(data):
                chunk = data[off : off + proto.UPDATE_CHUNK]
                a = await self._step(proto.T_UPDATE_DATA, proto.UPDATE_DATA.pack(off) + chunk, timeout=5, tries=3)
                if a["offset"] != off + len(chunk):
                    raise UpdateError(f"the radio holds {a['offset']} bytes, expected {off + len(chunk)}")
                off = a["offset"]
                self.updating["sent"] = off
            self.sn.boot = {}  # what it says next is about the new image
            await self._step(proto.T_UPDATE_END, b"", timeout=30)
            begun = False
            self.updating["state"] = "trial"
            log.info("%s: radio %s written (%d KB); waiting for it to restart and keep it",
                     self.sn.name, version, len(data) // 1024)
            result = await self._trial(version, old)
        except UpdateError as e:
            result = {"ok": False, "message": str(e)}
        except Exception as e:  # noqa: BLE001 - whatever happens, the update must not stay "running"
            log.exception("Firmware update of the USB radio failed")
            result = {"ok": False, "message": f"the update failed: {type(e).__name__} {e}".strip()}
        finally:
            if begun:
                self.sn.send(proto.encode(proto.T_UPDATE_ABORT))
            self.acks = None
            result.update(target=target, version=version, seconds=round(time.time() - started), finished=time.time())
            self.last_result, self.updating = result, None
            self.last_update = f"{version}: {result['message']}"
        log.info("Firmware update of the USB radio to %s: %s", version, result["message"])
        return result


class UsbSniffer(Sniffer):
    kind = "usb"
    not_set = "Set the USB sniffer's device in the app's Configuration tab."
    closed = "the USB device went away"

    def __init__(self, sid: str, name: str, device: str, on_frame, on_dropped, channel, opener=None) -> None:
        super().__init__(sid, name, device, 0, 80, on_frame, on_dropped, channel)
        self.device = device
        self.web = UsbRadio(self)
        self.opener = opener or open_serial
        self.boot: dict = {}  # the radio's last T_RADIO_BOOT: version, state, chip
        self.crc_seen = 0
        self.calibrated = False  # this connection's clock pairing is done (see the module doc)
        self.calib: list = []  # (payload, radio_us, arrival) held until then
        self.calib_until: float | None = None
        self.bad_stamps = 0  # frames with a stale radio timestamp (see the module doc)

    def where(self) -> str:
        return self.device

    async def open(self):
        return await self.opener(self.device)

    def open_failed(self, e: BaseException) -> str:
        if isinstance(e, NotOurDevice):
            text = str(e)
            return text[:1].upper() + text[1:]
        return f"Can't open {self.device}: {why(e, 'no answer')}"

    def greet(self, writer) -> None:
        self.crc_seen = 0
        self.calibrated, self.calib, self.calib_until = False, [], None
        writer.write(proto.encode(proto.T_SET_CHANNEL, bytes([self.channel()])))

    async def keep_up(self) -> None:
        """The bridge's ping: every second, with PING_RADIO_HEARD while radio statuses arrive."""
        while True:
            if not self.calibrated and self.calib_until is not None and time.time() >= self.calib_until:
                self._calibrate()  # a quiet channel: don't wait for the next frame
            heard = bool(self.radio) and time.time() - self.radio.get("at", 0) < HEARD_S
            self.send(proto.encode(proto.T_PING, bytes([proto.PING_RADIO_HEARD if heard else 0])))
            await asyncio.sleep(PING_S)

    def after_read(self, dec: proto.Decoder) -> None:
        # damaged messages on the cable (a boot's ROM text is skipped without counting)
        if dec.crc_errors > self.crc_seen:
            self.rec()[8] += dec.crc_errors - self.crc_seen
        self.crc_seen = dec.crc_errors

    def _hold(self, payload: bytes, radio_us: int) -> None:
        now = time.time()
        if self.calib_until is None:
            self.calib_until = now + CALIB_S
        self.calib.append((payload, radio_us, now))
        if now >= self.calib_until:
            self._calibrate()

    def _calibrate(self) -> None:
        """Pair the radio clock from the freshest held frame, then let the held frames out."""
        held, self.calib, self.calib_until = self.calib, [], None
        self.calibrated = True
        if not held:
            return
        start, last = 0, held[0][1]  # the radio restarted among them: only its new clock counts
        fixed = []
        for i, (payload, us, arrival) in enumerate(held):
            if i and us < last - 1_000_000:
                if us < FRESH_BOOT_US:
                    start, fixed, last = i, [], us
                else:
                    us = self._stale_stamp(us, last)
            last = max(last, us)
            fixed.append((payload, us, arrival))
        held = fixed
        radio_us, arrival = min(((h[1], h[2]) for h in held), key=lambda x: x[1] - x[0] / 1e6)
        self.offset, self.anchor = None, (radio_us, arrival)
        self.bridge_time(radio_us)  # pairs, and tells the merger about a reconnect or a radio restart
        self.last_bridge_us = max(h[1] for h in held)
        stale = 0
        for payload, us, _ in held:
            ts = us / 1e6 + self.offset
            stale += time.time() - ts > 5.0
            self._frame(payload, ts)
        if stale or start:
            log.info("%s: %d frames the radio kept while the port was closed came first (out at their own time, "
                     "as late frames)%s", self.name, stale, f"; {start} from before a radio restart dropped" if start else "")

    def _stale_stamp(self, us: int, last: int) -> int:
        self.bad_stamps += 1
        if self.bad_stamps <= 5 or self.bad_stamps % 1000 == 0:
            log.info("%s: a frame stamped %.3f s before the one ahead of it (a stale receive-slot stamp): given that "
                     "one's time (%d so far)", self.name, (last - us) / 1e6, self.bad_stamps)
        return last

    def radio_time(self, radio_us: int) -> float:
        last = self.last_bridge_us
        if self.offset is not None and last is not None and radio_us < last - 1_000_000:
            if radio_us >= FRESH_BOOT_US:
                return self._stale_stamp(radio_us, last) / 1e6 + self.offset
            # The radio restarted without the cable dropping: its clock started over.
            self.offset, self.anchor = None, None
        if self.offset is None and self.anchor is None:
            self.anchor = (radio_us, time.time())  # paired from the first frame; bridge_time refines it
        return self.bridge_time(radio_us)

    def prime(self, msgs: list) -> None:
        if not self.calibrated:
            return
        newest = max((proto.FRAME_HDR.unpack_from(p)[0] for t, p in msgs
                      if t == proto.T_FRAME and len(p) >= proto.FRAME_HDR.size), default=None)
        if newest is not None:
            self.radio_time(newest)

    def handle(self, msg_type: int, payload: bytes) -> None:
        if msg_type == proto.T_FRAME:
            if len(payload) >= proto.FRAME_HDR.size:
                radio_us = proto.FRAME_HDR.unpack_from(payload)[0]
                if not self.calibrated:
                    self._hold(payload, radio_us)
                else:
                    self._frame(payload, self.radio_time(radio_us))
        elif msg_type == proto.T_RADIO_BOOT and len(payload) >= proto.RADIO_BOOT.size:
            a, b, c, state = proto.RADIO_BOOT.unpack_from(payload)
            chip = None
            if len(payload) >= proto.RADIO_BOOT.size + proto.RADIO_BOOT_CHIP.size:
                (chip_id,) = proto.RADIO_BOOT_CHIP.unpack_from(payload, proto.RADIO_BOOT.size)
                chip = bridge_mod.CHIPS.get(chip_id, f"chip {chip_id}")
            old = self.boot.get("state")
            self.boot = {"version": f"{a}.{b}.{c}", "state": proto.FW_STATES.get(state, str(state)), "chip": chip,
                         "at": time.time()}
            if self.boot["state"] != old:
                log.info("%s: radio %s firmware: %s", self.name, self.boot["version"], self.boot["state"])
        elif msg_type == proto.T_UPDATE_ACK:
            self.web.ack(payload)
        else:
            super().handle(msg_type, payload)

    def summary(self) -> dict:
        out = super().summary()
        out["radio_chip"] = self.boot.get("chip")
        return out
