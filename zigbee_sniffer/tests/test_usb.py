"""A sniffer radio on USB (usb.py): the app plays the bridge's part over a serial link. A fake
radio speaks the firmware's side of the protocol (statuses, boots, update acks, a restart into a
new image on trial) through an in-memory link."""

import asyncio
import os
import time

import pytest

import bridge
import proto
import sniffers
import usb
from test_bridge import app_desc, esp_image
from zbs_helpers import Clock, mac_data

ESP32_C5, ESP32_C6 = 23, 13
TRIAL, CONFIRMED, ROLLED_BACK = 1, 2, 3


def radio_image(version: str, chip: int = ESP32_C5, project: str = "zigbee_sniffer_radio") -> bytes:
    # several update blocks long, with an odd tail
    return esp_image([app_desc(version, project) + b"\x11" * 900, bytes(range(256)) * 9 + b"\x07" * 5], chip=chip)


class FakeWriter:
    def __init__(self, radio: "FakeRadio") -> None:
        self.radio = radio

    def write(self, data: bytes) -> None:
        self.radio.from_app(data)

    def close(self) -> None:
        pass


class FakeRadio:
    """The radio firmware's side of the link (c6-radio/main/main.c built with CONFIG_SNIFF_LINK_USB)."""

    def __init__(self, version="0.3.0", chip: int | None = ESP32_C5, state=0) -> None:
        self.version, self.chip, self.state = version, chip, state
        self.channel = None
        self.pings: list[int] = []
        self.opens = 0
        self.aborts = 0
        self.reader: asyncio.StreamReader | None = None
        self.task: asyncio.Task | None = None
        self.dec = proto.Decoder()
        self.flash = bytearray()
        self.size = 0
        self.fail_trial = False  # the new image never passes (it rolls back)
        self.refuse_at: int | None = None  # answer this byte offset with ESP_ERR_INVALID_STATE
        self.missing = False  # the device isn't there

    async def opener(self, path: str):
        if self.missing:
            raise FileNotFoundError(2, "No such file or directory")
        self.opens += 1
        self.reader = asyncio.StreamReader()
        self.reader.feed_data(b"ESP-ROM:esp32c5-eco2-20250121\r\nrst:0xc (SW_CPU),boot:0x1f\r\n")  # boot noise
        self.task = asyncio.create_task(self.statuses())
        self.boot()
        return self.reader, FakeWriter(self)

    def emit(self, msg_type: int, payload: bytes) -> None:
        if self.reader is not None:
            self.reader.feed_data(proto.encode(msg_type, payload))

    def boot(self) -> None:
        a, b, c = (int(x) for x in self.version.split("."))
        payload = proto.RADIO_BOOT.pack(a, b, c, self.state)
        if self.chip is not None:
            payload += proto.RADIO_BOOT_CHIP.pack(self.chip)
        self.emit(proto.T_RADIO_BOOT, payload)

    async def statuses(self) -> None:
        t0 = time.monotonic()
        while True:
            a, b, c = (int(x) for x in self.version.split("."))
            self.emit(proto.T_RADIO_STATUS, proto.RADIO_STATUS.pack(int(time.monotonic() - t0), 0, 0, self.channel or 25, a, b, c))
            await asyncio.sleep(0.02)

    def ack(self, stage: int, err: int = 0) -> None:
        self.emit(proto.T_UPDATE_ACK, proto.UPDATE_ACK.pack(stage, len(self.flash), err))

    def from_app(self, data: bytes) -> None:
        for t, p in self.dec.feed(data):
            if t == proto.T_SET_CHANNEL:
                self.channel = p[0]
            elif t == proto.T_PING:
                self.pings.append(p[0])
                if self.state == TRIAL and p[0] & proto.PING_RADIO_HEARD:
                    if self.fail_trial:
                        self.version, self.state = self.old_version, ROLLED_BACK
                    else:
                        self.state = CONFIRMED
                    self.boot()
            elif t == proto.T_UPDATE_BEGIN:
                (self.size,) = proto.UPDATE_BEGIN.unpack_from(p)
                self.flash.clear()
                self.ack(t)
            elif t == proto.T_UPDATE_DATA:
                (off,) = proto.UPDATE_DATA.unpack_from(p)
                chunk = p[proto.UPDATE_DATA.size :]
                if self.refuse_at is not None and off >= self.refuse_at:
                    self.ack(t, 0x103)
                elif off + len(chunk) <= len(self.flash):
                    self.ack(t)  # a resend: already written
                elif off != len(self.flash):
                    self.ack(t, 0x103)
                else:
                    self.flash += chunk
                    self.ack(t)
            elif t == proto.T_UPDATE_END:
                self.ack(t, 0 if len(self.flash) == self.size else 0x104)
                if len(self.flash) == self.size:
                    asyncio.get_running_loop().call_later(0.05, self.restart)
            elif t == proto.T_UPDATE_ABORT:
                self.aborts += 1

    def restart(self) -> None:
        """esp_restart into the new image: the USB device goes away and comes back."""
        self.old_version = self.version
        self.version, self.state = bridge.image_info(bytes(self.flash))["version"], TRIAL
        self.task.cancel()
        self.reader.feed_eof()


async def until(cond, timeout=10.0) -> None:
    t0 = time.monotonic()
    while not cond():
        if time.monotonic() - t0 > timeout:
            raise AssertionError("timed out")
        await asyncio.sleep(0.01)


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(usb, "PING_S", 0.02)
    monkeypatch.setattr(usb, "TRIAL_WAIT_S", 10.0)


def usb_sniffer(radio: FakeRadio, got: list | None = None) -> usb.UsbSniffer:
    sink = got if got is not None else []
    return usb.UsbSniffer("usb_sniffer", "USB sniffer", "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit-if00",
                          lambda s, ts, ch, rssi, lqi, psdu, late: sink.append((ts, psdu)), lambda ts, n: None,
                          lambda: 25, opener=radio.opener)


async def started(sn: usb.UsbSniffer) -> asyncio.Task:
    ready = asyncio.Event()
    ready.set()
    task = asyncio.create_task(sn.run(ready, lambda: None))
    await until(lambda: sn.connected and sn.boot.get("chip") and sn.radio)
    return task


def test_link_sets_channel_pings_and_reports_the_radio():
    async def go():
        radio = FakeRadio()
        sn = usb_sniffer(radio)
        task = await started(sn)
        await until(lambda: proto.PING_RADIO_HEARD in radio.pings)
        st = sn.web.status
        assert radio.channel == 25
        assert st["radio"] == "0.3.0" and st["radio_chip"] == "ESP32-C5" and st["radio_link"] is True
        assert st["link"] == "usb" and st["updates"] is True
        assert sn.summary()["kind"] == "usb" and sn.summary()["radio_chip"] == "ESP32-C5"
        assert sn.where().startswith("/dev/serial/by-id/")
        task.cancel()

    asyncio.run(go())


def test_update_over_the_cable_is_kept_after_its_trial():
    async def go():
        radio = FakeRadio()
        sn = usb_sniffer(radio)
        task = await started(sn)
        img = radio_image("0.3.1")
        res = await sn.web.update("radio", img)
        assert res["ok"], res
        assert "kept it" in res["message"]
        assert bytes(radio.flash) == img
        assert radio.opens == 2  # it came back after the restart
        assert sn.boot["version"] == "0.3.1" and sn.boot["state"] == "confirmed"
        assert sn.web.updating is None and sn.web.last_result is res
        assert radio.aborts == 0
        task.cancel()

    asyncio.run(go())


def test_update_that_fails_its_trial_says_so():
    async def go():
        radio = FakeRadio()
        radio.fail_trial = True
        sn = usb_sniffer(radio)
        task = await started(sn)
        res = await sn.web.update("radio", radio_image("0.3.1"))
        assert not res["ok"]
        assert "failed its trial" in res["message"] and "0.3.0" in res["message"]
        task.cancel()

    asyncio.run(go())


def test_wrong_chip_and_unknown_chip_are_refused_before_sending():
    async def go():
        radio = FakeRadio()
        sn = usb_sniffer(radio)
        task = await started(sn)
        res = await sn.web.update("radio", radio_image("0.3.1", chip=ESP32_C6))
        assert not res["ok"] and "ESP32-C6" in res["message"] and "ESP32-C5" in res["message"]
        res = await sn.web.update("bridge", radio_image("0.3.1"))
        assert not res["ok"] and "no bridge" in res["message"]
        assert not radio.flash and radio.size == 0
        task.cancel()

        old = FakeRadio(chip=None)  # radio firmware before 0.3 says nothing about its chip
        sn2 = usb_sniffer(old)
        ready = asyncio.Event()
        ready.set()
        task2 = asyncio.create_task(sn2.run(ready, lambda: None))
        await until(lambda: sn2.connected and sn2.boot)
        res = await sn2.web.update("radio", radio_image("0.3.1"))
        assert not res["ok"] and "which chip" in res["message"]
        task2.cancel()

    asyncio.run(go())


def test_radio_refusing_a_block_stops_the_update_and_aborts():
    async def go():
        radio = FakeRadio()
        radio.refuse_at = proto.UPDATE_CHUNK * 2
        sn = usb_sniffer(radio)
        task = await started(sn)
        res = await sn.web.update("radio", radio_image("0.3.1"))
        assert not res["ok"] and "ESP_ERR_INVALID_STATE" in res["message"]
        assert radio.aborts == 1
        task.cancel()

    asyncio.run(go())


def test_missing_device_is_reported_and_retried():
    async def go():
        radio = FakeRadio()
        radio.missing = True
        sn = usb_sniffer(radio)
        ready = asyncio.Event()
        ready.set()
        task = asyncio.create_task(sn.run(ready, lambda: None))
        await until(lambda: sn.last_error)
        assert sn.last_error.startswith("Can't open /dev/serial/by-id/") and not sn.connected
        task.cancel()

    asyncio.run(go())


def fake_sysfs(root, name: str, vendor: str | None):
    """sys/class/tty/<name>/device inside a USB device folder that has idVendor (a real sysfs links
    there; nesting the folders gives the same walk up)."""
    usb_dev = root / "sys" / "devices" / "usb1" / "1-4"
    dev = usb_dev / "1-4.1.0" / name  # (sysfs says 1-4:1.0; Windows has no colons)
    dev.mkdir(parents=True)
    if vendor:
        (usb_dev / "idVendor").write_text(vendor + "\n")
    link = root / "sys" / "class" / "tty" / name
    link.mkdir(parents=True)
    try:
        os.symlink(dev, link / "device", target_is_directory=True)
    except (OSError, NotImplementedError):  # Windows without symlink rights: nest instead
        (link / "device").mkdir()
        if vendor:
            (link / "idVendor").write_text(vendor + "\n")
    return str(root / "sys")


def test_only_an_esp32s_own_usb_port_is_opened(tmp_path):
    sys_root = fake_sysfs(tmp_path / "a", "ttyACM0", "303a")
    assert usb.usb_vendor("/dev/ttyACM0", sys_root) == "303a"
    assert usb.device_problem("/dev/ttyACM0", sys_root) == ""

    # the Zigbee / Thread dongles in the device list (Sonoff MG24: Silicon Labs, 10c4)
    sys_root = fake_sysfs(tmp_path / "b", "ttyUSB1", "10c4")
    why = usb.device_problem("/dev/ttyUSB1", sys_root)
    assert "10c4" in why and "Zigbee or Thread dongle" in why

    # a built-in serial port: no USB vendor; an Espressif by-id name with no sysfs is still accepted
    empty = str(tmp_path / "none")
    assert usb.device_problem("/dev/ttyS0", empty).startswith("won't open /dev/ttyS0")
    assert usb.device_problem("/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_10:BD-if00", empty) == ""


def test_refused_device_never_reaches_open(monkeypatch):
    async def go():
        opened = []
        monkeypatch.setattr(usb, "device_problem", lambda path, sys_root="/sys": f"won't open {path}: USB vendor 10c4")
        monkeypatch.setattr(usb.os, "open", lambda *a, **k: opened.append(a) or 99)
        sn = usb.UsbSniffer("u", "U", "/dev/ttyUSB1", lambda *a: None, lambda *a: None, lambda: 25)
        ready = asyncio.Event()
        ready.set()
        task = asyncio.create_task(sn.run(ready, lambda: None))
        await until(lambda: sn.last_error)
        task.cancel()
        assert not opened and not sn.connected
        assert sn.last_error.startswith("Won't open /dev/ttyUSB1: USB vendor 10c4")

    asyncio.run(go())


def test_bridge_images_still_default_to_a_c6_radio():
    info = bridge.image_info(radio_image("0.3.1", chip=ESP32_C6))
    assert bridge.check_image(info, "radio", {}) == []
    c5 = bridge.image_info(radio_image("0.3.1"))
    assert c5["chip"] == "ESP32-C5"
    assert any("ESP32-C6" in p for p in bridge.check_image(c5, "radio", {}))
    assert bridge.check_image(c5, "radio", {"radio_chip": "ESP32-C5"}) == []


# ---------------------------------------------------------------- timing

W0 = 1_800_000_000.0


@pytest.fixture
def clock(monkeypatch):
    c = Clock(W0)
    monkeypatch.setattr(sniffers, "time", c)
    monkeypatch.setattr(usb, "time", c)
    return c


def frame(radio_us: int, psdu: bytes) -> bytes:
    return proto.FRAME_HDR.pack(radio_us, 25, -60, 200, 0) + psdu


def test_frames_follow_the_radio_clock_and_its_restart(clock):
    got = []
    sn = usb_sniffer(FakeRadio(), got)
    restarts = []
    sn.on_clock_restart = lambda: restarts.append(clock.t)
    psdu = mac_data(0x1111, 0x0000, 1)
    boot_us = 7_000_000

    def heard_at(t: float, latency: float, boot: int = boot_us, since: float = W0, ppm: float = -10.0) -> None:
        clock.t = t + latency
        sn.handle(proto.T_FRAME, frame(int(boot + (t - since) * (1 + ppm * 1e-6) * 1e6), psdu))

    # 10 ppm slow radio clock, USB delivery 1-4 ms
    t = W0
    for k in range(2000):
        clock.t = t
        heard_at(t, 0.001 + (k % 7) * 0.0005, since=W0)
        t += 0.5
    errs = [ts - (W0 + i * 0.5) for i, (ts, _) in enumerate(got)]
    assert max(abs(e) for e in errs[-500:]) < 0.002
    assert not restarts

    # the radio restarts (an update, no replug): its clock starts over near zero
    got.clear()
    t2 = t + 3.0
    for k in range(50):
        heard_at(t2 + k * 0.1, 0.002, boot=300_000, since=t2)
    assert len(restarts) == 1
    assert all(abs(ts - (t2 + i * 0.1)) < 0.004 for i, (ts, _) in enumerate(got))


def test_frames_kept_while_the_port_was_closed_dont_skew_the_clock(clock):
    """What happened on the HA box with 0.6.1: the radio had been writing into its USB buffer for a
    minute before the app opened the port, the first (stale) frame paired the clock 53 s off, and the
    merger took the correction for drift and kept it as the sniffer's skew."""
    got = []
    sn = usb.UsbSniffer("ha_box", "HA box", "/dev/ttyACM0", lambda s, ts, ch, rssi, lqi, psdu, late: got.append((ts, late)),
                        lambda ts, n: None, lambda: 25, opener=FakeRadio().opener)
    moves = []
    sn.on_offset = moves.append
    sn.greet(FakeWriter(FakeRadio()))
    psdu = mac_data(0x1111, 0x0000, 1)
    boot_wall = W0 - 120.0  # the radio booted 2 minutes before the port opened

    def us(t: float) -> int:
        return int((t - boot_wall) * 1e6)

    # the first read: 300 frames heard over the last 60 s, all delivered at once on open
    clock.t = W0
    stale = [W0 - 60 + k * 0.2 for k in range(300)]
    for t in stale:
        sn.handle(proto.T_FRAME, frame(us(t), psdu))
    assert not got  # held while the clock is paired
    # then live frames, delivered 1-3 ms after they were heard
    live = [W0 + 0.01 + k * 0.05 for k in range(60)]
    for k, t in enumerate(live):
        clock.t = t + 0.001 + (k % 3) * 0.001
        sn.handle(proto.T_FRAME, frame(us(t), psdu))
    assert len(got) == len(stale) + len(live)
    heard = stale + live
    assert max(abs(ts - t) for (ts, _), t in zip(got, heard)) < 0.005  # every frame at the time it was heard
    assert all(late for (_, late), t in zip(got, heard) if W0 - t > 5.5)  # the old ones as late frames
    assert not any(late for (_, late), t in zip(got, heard) if t >= W0)
    assert all(abs(m) < 0.005 for m in moves)  # nothing the merger would take for a 53 s skew
    assert abs(sn.clock_drift_ms()) < 5


def test_a_stale_receive_stamp_is_not_a_radio_restart(clock):
    """ESP-IDF's driver can hand a frame the timestamp its receive slot got long ago (the radio was
    busy draining its USB backlog). 0.6.2-0.6.3 took the clock going backwards for a restart."""
    got = []
    sn = usb.UsbSniffer("ha_box", "HA box", "/dev/ttyACM0", lambda s, ts, ch, rssi, lqi, psdu, late: got.append(ts),
                        lambda ts, n: None, lambda: 25, opener=FakeRadio().opener)
    restarts, moves = [], []
    sn.on_clock_restart = lambda: restarts.append(1)
    sn.on_offset = moves.append
    sn.greet(FakeWriter(FakeRadio()))
    psdu = mac_data(0x1111, 0x0000, 1)
    boot_wall = W0 - 600.0  # up 10 minutes

    def heard(t: float, stamp_t: float | None = None) -> None:
        clock.t = t + 0.001
        sn.handle(proto.T_FRAME, frame(int(((stamp_t if stamp_t is not None else t) - boot_wall) * 1e6), psdu))

    times = [W0 + k * 0.1 for k in range(40)]
    for k, t in enumerate(times):
        heard(t, stamp_t=t - 95.0 if k in (5, 25) else None)  # one stale stamp while held, one after
    assert not restarts and sn.bad_stamps == 2
    assert all(abs(ts - t) < 0.11 for ts, t in zip(got, times))  # the stale two get their neighbour's time
    assert all(abs(m) < 0.005 for m in moves)

    # a real restart (an update over the cable): the clock starts near zero
    t2 = times[-1] + 2.0
    for k in range(10):
        clock.t = t2 + k * 0.1 + 0.001
        sn.handle(proto.T_FRAME, frame(1_500_000 + k * 100_000, psdu))
    assert len(restarts) == 1
    assert abs(got[-1] - (t2 + 0.9)) < 0.005
