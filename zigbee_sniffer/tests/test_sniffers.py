import json
import random

import pytest

import proto
import sniffers
from zbs_helpers import Clock, frame_at, mac_data

W0 = 1_800_000_000.0
DAY = 86400.0


@pytest.fixture
def clock(monkeypatch):
    c = Clock(W0)
    monkeypatch.setattr(sniffers, "time", c)
    return c


@pytest.fixture
def sniffer():
    got = []
    sn = sniffers.Sniffer("main", "Main", "", 6638, 80,
                          lambda s, ts, ch, rssi, lqi, psdu, late: got.append((ts, late, psdu)),
                          lambda ts, n: None, lambda: 25)
    sn.got = got
    return sn


def bridge_us(wall: float, ppm: float, boot_us: int = 3_600_000_000) -> int:
    """The bridge's clock at wall time `wall` for a clock off by `ppm` (negative = slow)."""
    return int(boot_us + (wall - W0) * (1 + ppm * 1e-6) * 1e6)


def hello(sn, clock, ppm, latency=0.004):
    clock.t = W0 + latency
    sn.handle(proto.T_HELLO, json.dumps({"bridge": "0.3.5", "bridge_us": bridge_us(W0, ppm), "backlog_bytes": 0}).encode())


def run_link(sn, clock, ppm, days=3.0, step=10.0, seed=3):
    """Frames heard every `step` s for `days`, each delivered 2-30 ms later; returns the timing
    errors (ts - when heard) and late flags of the last 100."""
    rnd = random.Random(seed)
    psdu = mac_data(0x1111, 0x0000, 1)
    hello(sn, clock, ppm)
    t = W0 + 1.0
    while t < W0 + days * DAY:
        clock.t = t + 0.002 + rnd.random() * 0.028
        sn.handle(proto.T_FRAME_AT, frame_at(bridge_us(t, ppm), psdu))
        sn.got[-1] = (sn.got[-1][0] - t, sn.got[-1][1], None)
        t += step
    return sn.got[-100:]


@pytest.mark.parametrize("ppm", [-20.0, -45.0])
def test_slow_bridge_clock_is_followed(clock, sniffer, ppm):
    tail = run_link(sniffer, clock, ppm)
    assert all(abs(err) < 0.03 for err, _, _ in tail), max(abs(e) for e, _, _ in tail)
    assert not any(late for _, late, _ in tail)
    # + = the bridge runs slow; after 3 days 20 ppm is 5.2 s (a single pairing at HELLO would be that far off)
    expected = -ppm * 1e-6 * 3 * DAY * 1000
    assert abs(sniffer.clock_drift_ms() - expected) < 0.05 * abs(expected)


def test_fast_bridge_clock_is_pulled_down(clock, sniffer):
    tail = run_link(sniffer, clock, +20.0)
    assert all(abs(err) < 0.03 for err, _, _ in tail)
    assert not any(late for _, late, _ in tail)
    assert sniffer.clock_drift_ms() < -0.95 * 20e-6 * 3 * DAY * 1000


def test_backlog_frames_are_late_and_leave_the_clock_alone(clock, sniffer):
    psdu = mac_data(0x1111, 0x0000, 1)
    hello(sniffer, clock, 0.0)
    clock.t = W0 + 0.01
    for k in range(20):  # buffered while the app was away: heard 300..110 s ago
        heard = W0 - 300 + k * 10
        sniffer.handle(proto.T_FRAME_AT, frame_at(bridge_us(heard, 0.0), psdu))
    assert all(late for _, late, _ in sniffer.got)
    assert sniffer.buffered_frames == 20
    assert abs(sniffer.got[0][0] - (W0 - 300)) < 0.05  # placed in time by the bridge's clock
    clock.t = W0 + 5.003
    sniffer.handle(proto.T_FRAME_AT, frame_at(bridge_us(W0 + 5.0, 0.0), psdu))
    ts, late, _ = sniffer.got[-1]
    assert not late
    assert abs(ts - (W0 + 5.0)) < 0.01
    assert sniffer.health and sum(r[6] for r in sniffer.health.values()) == 20


def test_hello_that_is_not_a_json_object_is_tolerated(clock, sniffer):
    sniffer.handle(proto.T_HELLO, b"[1, 2, 3]")
    assert sniffer.hello == {"raw": "[1, 2, 3]"}
    sniffer.handle(proto.T_HELLO, b"\xff\xfe not json")
    assert "raw" in sniffer.hello
    sniffer.handle(proto.T_HELLO, b'{"bridge": "0.3", "backlog_bytes": 120}')
    assert sniffer.backlog_bytes == 120


def test_frame_before_any_hello_is_timed_by_arrival(clock, sniffer):
    clock.t = W0 + 50.0
    sniffer.handle(proto.T_FRAME_AT, frame_at(123_456_789, mac_data(0x1111, 0x0000, 1)))
    ts, late, _ = sniffer.got[-1]
    assert abs(ts - (W0 + 50.0)) < 1e-6 and not late


def test_short_messages_are_ignored(clock, sniffer):
    sniffer.handle(proto.T_FRAME_AT, b"\x00" * 8)  # only the time, no frame
    sniffer.handle(proto.T_FRAME, b"\x00" * 3)
    sniffer.handle(proto.T_RADIO_STATUS, b"\x00")
    assert sniffer.got == []


def test_status_messages_count_drops_and_reboots(clock):
    drops = []
    sn = sniffers.Sniffer("up", "Upstairs", "", 6639, 80, lambda *a: None, lambda ts, n: drops.append(n), lambda: 25)
    sn.handle(proto.T_RADIO_STATUS, proto.RADIO_STATUS.pack(1000, 50000, 10, 25, 0, 2, 2))
    sn.handle(proto.T_RADIO_STATUS, proto.RADIO_STATUS.pack(1005, 50100, 14, 25, 0, 2, 2))
    assert drops == [4]  # the first status is only a base
    sn.handle(proto.T_RADIO_STATUS, proto.RADIO_STATUS.pack(12, 30, 2, 25, 0, 2, 3))  # rebooted, newer firmware
    assert drops == [4, 2]
    kinds = [e["kind"] for e in sn.events]
    assert "radio_reboot" in kinds and "firmware_update" in kinds
    sn.handle(proto.T_BRIDGE_STATUS, proto.BRIDGE_STATUS.pack(500, 1000, 3, 0, -61, 1))
    sn.handle(proto.T_BRIDGE_STATUS, proto.BRIDGE_STATUS.pack(505, 1100, 7, 0, -71, 1))
    r = sn.rec()
    assert r[3] == 2 and r[2] == -132 and r[4] == -71 and r[5] == -61 and r[8] == 4  # Wi-Fi RSSI n/sum/min/max, CRC


class FakeWriter:
    def __init__(self) -> None:
        self.sent = b""

    def write(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        pass


def test_a_bad_message_does_not_end_the_link(monkeypatch):
    """The frame path raising on one frame must not drop the bridge connection (an exception out of
    the link loop used to end the link, or the whole app). No sockets: open_connection is faked."""
    import asyncio

    got, calls = [], []

    def on_frame(s, ts, ch, rssi, lqi, psdu, late):
        if not calls:
            calls.append("boom")
            raise ValueError("the frame path failed once")
        got.append(psdu)

    sn = sniffers.Sniffer("main", "Main", "127.0.0.1", 6638, 80, on_frame, lambda ts, n: None, lambda: 21)
    data = (proto.encode(proto.T_HELLO, b'{"bridge": "0.3.5", "bridge_us": 3600000000, "backlog_bytes": 0}')
            + proto.encode(proto.T_FRAME_AT, frame_at(3_600_000_100, b"first"))
            + proto.encode(proto.T_FRAME_AT, frame_at(3_600_000_200, b"second")))
    writer = FakeWriter()

    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        async def fake_open(host, port):
            return reader, writer

        monkeypatch.setattr(sniffers.asyncio, "open_connection", fake_open)
        ready = asyncio.Event()
        ready.set()
        task = asyncio.create_task(sn.run(ready, lambda: None))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if any(e["kind"] == "sniffer_disconnected" for e in sn.events):
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
    assert calls == ["boom"] and got == [b"second"]
    assert sn.bad_messages == 1
    msgs = proto.Decoder().feed(writer.sent)
    assert msgs[0] == (proto.T_CLIENT_HELLO, proto.CLIENT_HELLO.pack(proto.CLIENT_FRAME_AT))
    assert msgs[1] == (proto.T_SET_CHANNEL, bytes([21]))
    disc = [e for e in sn.events if e["kind"] == "sniffer_disconnected"]
    assert len(disc) == 1 and "closed by the bridge" in disc[0]["detail"]
