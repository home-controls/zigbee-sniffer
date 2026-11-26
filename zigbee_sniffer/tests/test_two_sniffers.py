"""0.5.3: what changes with several sniffers. The merger's watermark, its memory after a restart and
its match window; which sniffers heard each stored frame; a device's signal per sniffer; each
sniffer's antenna gain in the coverage model; sniffer marks on device charts."""

import math
import random
import sqlite3
import time

import pytest

import analysis
import mapping
import merge
import pcap
import report
from analysis import Batch
from store import Store
from test_report import make_names, state
from zbs_helpers import ack, mac_data, nwk


class Sink:
    def __init__(self) -> None:
        self.emitted: list[merge.Tx] = []
        self.late: list[tuple] = []

    def emit(self, tx):
        self.emitted.append(tx)

    def late_copy(self, tx, sid, rssi, lqi):
        self.late.append((tx, sid))


def merger():
    s = Sink()
    return merge.Merger(s.emit, s.late_copy, several=True, ref="a"), s


def data(seq, body=b"x", ack_req=True):
    return mac_data(0x1111, 0x0000, seq, nwk(0x1111, 0x0000, seq, body), ack=ack_req)


# ---------------------------------------------------------------- the watermark

def test_a_sniffer_back_with_its_buffer_holds_the_others_so_everything_goes_out_in_order():
    """b drops off at 99.5 and comes back at 105 with what it buffered meanwhile: a's frames from
    100-104 wait for it, merge with b's copies, and go out in time order with the frame only b
    heard (102.5) in its place - not seconds late as an out-of-order extra."""
    m, s = merger()
    m.link("a", True, now=90.0)
    m.link("b", True, now=90.0)
    m.add("b", 99.0, 25, -70, 0, data(1, b"before"), False, arrival=99.01)
    m.add("a", 99.0, 25, -60, 0, data(1, b"before"), False, arrival=99.01)
    m.link("b", False, now=99.5)
    for i in range(5):  # a, live
        t = 100.0 + i
        m.add("a", t, 25, -60, 0, data(10 + i, b"live%d" % i), False, arrival=t + 0.01)
        m.release(now=t + 0.5)
    assert not any(tx.ts >= 100.0 for tx in s.emitted)  # held for b
    assert m.waiting and m.waiting[0] == "b"
    m.link("b", True, now=105.0)
    backlog = [(100.0 + i, data(10 + i, b"live%d" % i)) for i in range(5)] + [(102.5, data(30, b"only b"))]
    for k, (t, f) in enumerate(sorted(backlog)):
        m.add("b", t + 0.0002, 25, -72, 0, f, True, arrival=105.1 + 0.01 * k)
    m.add("a", 105.2, 25, -60, 0, data(41, b"a live"), False, arrival=105.21)
    m.add("b", 105.2, 25, -72, 0, data(40, b"b live again"), False, arrival=105.21)
    m.release(now=105.7)
    out = [tx for tx in s.emitted if 100.0 <= tx.ts < 105.0]
    assert [round(tx.ts, 1) for tx in out] == [100.0, 101.0, 102.0, 102.5, 103.0, 104.0]
    assert [tx.ts for tx in s.emitted] == sorted(tx.ts for tx in s.emitted)  # in time order
    assert all(len(tx.copies) == 2 for tx in out if round(tx.ts, 1) != 102.5)
    assert not s.late  # every copy arrived before its transmission went out


def test_a_sniffer_that_stays_away_is_waited_for_only_so_long():
    m, s = merger()
    m.link("a", True, now=90.0)
    m.link("b", True, now=90.0)
    m.add("b", 99.0, 25, -70, 0, data(1), False, arrival=99.0)
    m.link("b", False, now=99.5)
    m.add("a", 100.0, 25, -60, 0, data(2), False, arrival=100.0)
    m.heard("a", now=101.0)  # a's bridge status, every second
    m.release(now=101.0)
    assert len(s.emitted) == 0
    end = 99.5 + merge.WAIT_S + 0.1
    m.heard("a", now=end)
    m.release(now=end)
    assert len(s.emitted) == 2


def test_a_stalled_link_holds_the_others_but_a_quiet_radio_does_not():
    m, s = merger()
    m.link("a", True, now=90.0)
    m.link("b", True, now=90.0)
    m.add("b", 99.0, 25, -70, 0, data(1), False, arrival=99.0)
    m.add("a", 100.0, 25, -60, 0, data(2), False, arrival=100.0)
    m.heard("a", now=100.6)
    m.release(now=100.6)  # b sent nothing at all for 1.6 s: stalled
    assert not any(tx.ts == 100.0 for tx in s.emitted)
    m.heard("b", now=100.65)  # a status from b: its link is fine, its radio just heard nothing
    m.release(now=100.7)
    assert [tx.ts for tx in s.emitted] == [99.0, 100.0]


def test_nothing_waits_longer_than_max_hold():
    m, s = merger()
    m.link("a", True, now=0.0)
    m.link("b", True, now=0.0)
    m.add("a", 100.0, 25, -60, 0, data(2), False, arrival=100.0)
    for k in range(70):  # b keeps trickling out an old buffer
        m.add("b", 50.0 + k * 0.1, 25, -70, 0, data(100 + k, b"old%d" % k), True, arrival=100.0 + k)
        m.release(now=100.0 + k)
    assert any(tx.ts == 100.0 for tx in s.emitted)


def test_without_connection_events_the_merger_behaves_as_before():
    """Links it wasn't told about are never waited for (a fixed hold)."""
    m, s = merger()
    m.add("a", 10.0, 25, -60, 0, data(1), False)
    m.add("b", 10.001, 25, -70, 0, data(1), False)
    m.release(now=20.0)
    assert len(s.emitted) == 1 and len(s.emitted[0].copies) == 2


# ---------------------------------------------------------------- after a restart

def test_seeded_transmissions_absorb_a_backlog_from_before_the_restart():
    m, s = merger()
    f, a = data(9, b"seed"), ack(9)
    n = m.seed([(1.0, data(1), ("old", 1)), (1000.0, f, ("2026-11-09/x.pcap", 7)),
                (1000.002, a, ("2026-11-09/x.pcap", 8))], now=1000.5 + merge.MEMORY_S - 100)
    assert n == 2  # the one older than the merger's memory is skipped
    now = 1000.0 + merge.MEMORY_S - 60
    m.link("b", True, now=now)
    m.add("b", 1000.0004, 25, -70, 0, f, True, arrival=now)
    m.add("b", 1000.0024, 25, -70, 0, a, True, arrival=now)
    m.release(now=now + 1)
    assert s.emitted == []
    assert [(tx.ref, sid) for tx, sid in s.late] == [(("2026-11-09/x.pcap", 7), "b"), (("2026-11-09/x.pcap", 8), "b")]


# ---------------------------------------------------------------- the match window

def test_window_narrows_once_copies_line_up_and_keeps_a_retry_apart():
    m, s = merger()
    t = 1000.0
    for i in range(40):  # copies 0.2 ms apart
        f = data(i % 256, b"w%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0002, 25, -70, 0, f, False, arrival=t + 0.012)
        m.release(now=t + 0.5)
        t += 0.2
    assert m.window(t + 2) <= 0.005
    stats = m.match_stats()
    assert stats["by_sniffer"]["b"]["p95_ms"] < 1
    # a heard only the original, b only its retry 6 ms later: two transmissions
    f = data(77, b"retry")
    m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
    m.add("b", t + 0.006, 25, -70, 0, f, False, arrival=t + 0.016)
    m.release(now=t + 1)
    assert sum(1 for tx in s.emitted if tx.key == merge.frame_key(f)) == 2
    m.link("b", True, now=t + 2)  # a new connection pairs its clock afresh: wide again
    assert m.window(t + 3) == merge.WINDOW_S


def test_a_clock_step_moves_the_correction_so_copies_still_match_in_a_narrow_window():
    """b's clock pairing steps 5 ms (a faster frame showed it was late): with the window down to a
    few ms, its copies would stop matching (each transmission written twice) unless the correction
    moves with it."""
    m, s = merger()
    t = 1000.0
    for i in range(40):
        f = data(i % 256, b"s%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0002, 25, -70, 0, f, False, arrival=t + 0.012)
        m.release(now=t + 0.5)
        t += 0.2
    w = m.window(t + 2)
    assert w <= 0.005
    m.offset_moved("b", -0.0008)  # the pairing creeps / steps a little: b's times come out 0.8 ms earlier
    n0 = len(s.emitted)
    for i in range(40, 60):
        f = data(i % 256, b"s%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0002 - 0.0008, 25, -70, 0, f, False, arrival=t + 0.012)
        m.release(now=t + 0.5)
        t += 0.2
    m.release(now=t + 5)
    new = s.emitted[n0:]
    assert len(new) == 20 and all(len(tx.copies) == 2 for tx in new)
    assert m.window(t + 2) <= 0.005  # still narrow
    m.offset_moved("a", 0.0006)  # the reference moves: the others are carried along
    f = data(200, b"after ref move")
    m.add("a", t + 0.0006, 25, -60, 0, f, False, arrival=t + 0.01)
    m.add("b", t + 0.0002 - 0.0008, 25, -70, 0, f, False, arrival=t + 0.012)
    m.release(now=t + 5)
    assert len(s.emitted[-1].copies) == 2
    m.offset_moved("b", -0.005)  # a real step: frames already waiting are on the old timeline
    assert m.window(t + 6) == merge.WINDOW_S


def test_a_burst_keeps_its_spacing_when_the_clock_pairing_steps(monkeypatch):
    """Three frames 5 ms apart arrive together while the pairing is 20 ms too late: stepping frame
    by frame put the last two at the arrival time; stepping once per burst keeps 5 ms."""
    import proto
    import sniffers
    from zbs_helpers import Clock, frame_at

    clock = Clock(1000.0)
    monkeypatch.setattr(sniffers, "time", clock)
    got = []
    sn = sniffers.Sniffer("a", "A", "h", 1, 80, lambda s_, ts, *rest: got.append(ts), lambda *a: None, lambda: 25)
    sn.handle(proto.T_HELLO, b'{"bridge_us": 0}')  # paired at 1000.0, while the bridge's 0 was really 999.98
    clock.t = 1000.035  # the burst: heard at 999.98 + 0.040, 0.045, 0.050 (bridge us 40000, 45000, 50000)
    msgs = [(proto.T_FRAME_AT, frame_at(b, data(i))) for i, b in enumerate((40000, 45000, 50000))]
    sn.prime(msgs)
    for t_, p in msgs:
        sn.handle(t_, p)
    assert [round(b - a, 4) for a, b in zip(got, got[1:])] == [0.005, 0.005]


def test_a_reconnect_reports_the_jump_from_the_last_pairing(monkeypatch):
    """The merger's correction follows every move of a sniffer's clock pairing. Over a long
    connection a bridge's drift adds up (here its clock runs 0.1 % fast); a reconnect pairs afresh,
    and that jump must be reported too, or the correction is off by all of it (copies seconds apart:
    every transmission written twice after the first Wi-Fi drop)."""
    import proto
    import sniffers
    from zbs_helpers import Clock, frame_at

    clock = Clock(5000.0)
    monkeypatch.setattr(sniffers, "time", clock)
    moves = []
    sn = sniffers.Sniffer("a", "A", "h", 1, 80, lambda *a: None, lambda *a: None, lambda: 25)
    sn.on_offset = moves.append

    def bus(t):  # the bridge's clock: started at 4000, 0.1 % fast
        return int((t - 4000.0) * 1.001 * 1e6)

    sn.handle(proto.T_HELLO, json_hello(bus(clock.t)))
    for i in range(300):  # 300 s of frames, delivered 1 ms after they're heard
        clock.t += 1.0
        sn.handle(proto.T_FRAME_AT, frame_at(bus(clock.t - 0.001), data(i % 256)))
    first, last = sn.offset0, sn.offset
    assert last - first < -0.25  # the drift the merger was told about (0.3 s)
    sn.offset, sn.anchor, sn.offset0 = None, None, None  # what a new connection does
    clock.t += 5.0
    sn.handle(proto.T_HELLO, json_hello(bus(clock.t)))
    clock.t += 0.5
    sn.handle(proto.T_FRAME_AT, frame_at(bus(clock.t - 0.001), data(1)))
    assert abs(sum(moves) - (sn.offset - first)) < 1e-9  # every move, the reconnect's jump included


def json_hello(bridge_us: int) -> bytes:
    return ('{"bridge_us": %d}' % bridge_us).encode()


def test_the_first_read_with_hello_and_buffered_frames_is_timed_from_the_hello(monkeypatch):
    """The first read holds the HELLO and frames buffered 19 s earlier: priming before the HELLO is
    handled must not pair the clocks from a buffered frame's arrival."""
    import proto
    import sniffers
    from zbs_helpers import Clock, frame_at

    clock = Clock(2000.0)
    monkeypatch.setattr(sniffers, "time", clock)
    got = []
    sn = sniffers.Sniffer("a", "A", "h", 1, 80, lambda s_, ts, *rest: got.append(ts), lambda *a: None, lambda: 25)
    msgs = [(proto.T_HELLO, b'{"bridge_us": 100000000}'),  # bridge time 100 s = our 2000.0
            (proto.T_FRAME_AT, frame_at(81_000_000, data(1)))]  # heard at bridge time 81 s: 19 s ago
    sn.prime(msgs)
    for t_, p in msgs:
        sn.handle(t_, p)
    assert abs(got[0] - 1981.0) < 0.01


def test_frames_that_ask_for_no_ack_always_use_the_wide_window():
    m, s = merger()
    t = 1000.0
    for i in range(40):
        f = data(i % 256, b"n%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0002, 25, -70, 0, f, False, arrival=t + 0.012)
        m.release(now=t + 0.5)
        t += 0.2
    f = data(99, b"broadcast", ack_req=False)  # (a Link Status, say): never resent, so 20 ms apart is still one
    m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
    m.add("b", t + 0.02, 25, -70, 0, f, False, arrival=t + 0.03)
    m.release(now=t + 5)
    assert len(s.emitted[-1].copies) == 2


def test_wide_window_before_learning_merges_copies_far_apart():
    m, s = merger()
    f = data(5)
    m.add("a", 10.0, 25, -60, 0, f, False)
    m.add("b", 10.15, 25, -70, 0, f, False)
    m.release(now=20.0)
    assert len(s.emitted) == 1


# ---------------------------------------------------------------- which sniffers heard each stored frame

def test_copies_file_round_trip_and_late_copies(tmp_path):
    w = pcap.RotatingPcap(tmp_path)
    t = time.time()
    rel, n, _ = w.write(t, pcap.tap_packet(data(1), 25, -60, 10))
    w.write_copies(rel, n, [("main", -83, 10), ("sniffer_2", -72, 10)])
    rel2, n2, _ = w.write(t + 0.1, pcap.tap_packet(data(2), 25, -61, 10))
    w.write_copies(rel2, n2, [("main", -61, 10)])
    w.write_copies(rel, n, [("sniffer_3", -90)])  # came late
    w.flush()
    got = pcap.read_copies(tmp_path / rel)
    assert got[n] == [("main", -83), ("sniffer_2", -72), ("sniffer_3", -90)]
    assert got[n2] == [("main", -61)]
    w.write_copies(rel2, n2, [("sniffer_2", -70)])
    w.flush()
    assert pcap.read_copies(tmp_path / rel)[n2] == [("main", -61), ("sniffer_2", -70)]  # read on from where it was
    w.close()


def test_copies_of_frames_a_crash_cut_off_are_dropped(tmp_path):
    w = pcap.RotatingPcap(tmp_path)
    t = time.time()
    for i in range(3):
        rel, n, end = w.write(t + i * 0.01, pcap.tap_packet(data(i), 25, -60, 10))
        w.write_copies(rel, n, [("main", -60 - i)])
    w.close()
    path = tmp_path / rel
    size = path.stat().st_size
    with open(path, "r+b") as f:
        f.truncate(size - 3)  # frame 3 half written
    w2 = pcap.RotatingPcap(tmp_path)
    rel3, n3, _ = w2.write(t + 1, pcap.tap_packet(data(9), 25, -50, 10))
    w2.write_copies(rel3, n3, [("sniffer_2", -50)])
    w2.close()
    assert n3 == 3
    assert pcap.read_copies(path)[3] == [("sniffer_2", -50)]


# ---------------------------------------------------------------- a device's signal per sniffer

@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "history.db")
    yield s
    s.db.close()
    s.rdb.close()


def _heard(b: Batch, minute: int, addr: str, per: dict) -> None:
    """One minute of a device: per = {sniffer: rssi} for 3 frames each; dev_min gets the best copy."""
    best = max(per.values())
    d = b.dev_rec(minute, addr)
    d[analysis.TX] += 3
    d[analysis.RSSI_SUM] += 3 * best
    for sid, r in per.items():
        b.sniff[(minute, addr, sid)] = [3, 3 * r, r, r]


def test_signal_is_the_best_sniffers_and_weaker_compares_each_with_its_own_normal(store):
    now = time.time()
    now_min = int(now // 60) * 60
    x, y, z = "0x7001", "0x7002", "0x7003"
    b = Batch()
    for m in range(now_min - 30 * 3600, now_min - 2 * 3600, 600):  # the week before: both sniffers
        _heard(b, m, x, {"main": -80, "s2": -60})
        _heard(b, m, y, {"main": -80, "s2": -60})
    for m in range(now_min - 50 * 60, now_min, 60):  # the last hour
        _heard(b, m, x, {"main": -82})  # Sniffer 2 is offline: x is fine at Main
        _heard(b, m, y, {"main": -90, "s2": -71})  # y really is weaker at both
        _heard(b, m, z, {"main": -95, "s2": -70})
    store.write(b)
    nm = make_names([(0x7001, "Ex", "Router"), (0x7002, "Why", "Router"), (0x7003, "Zed", "Router")])
    rep = report.Report(store, nm, state(now))
    rep.sniffer_names = {"main": "Main", "s2": "Sniffer 2"}
    rows = {r["addr"]: r for r in rep._devices("1h")["devices"]}
    assert not any(f["code"] == "weaker" for f in rows[x]["flags"])  # (best-copy baseline -60: a false alarm before)
    assert rows[x]["rssi_avg"] == -82 and rows[x]["rssi_sniffer_name"] == "Main"
    assert rows[x]["baseline"]["rssi_avg"] == -80  # Main's normal, not the best copy's
    weaker = [f for f in rows[y]["flags"] if f["code"] == "weaker"]
    assert weaker and "every sniffer" in weaker[0]["text"] and "Sniffer 2 11 dB" in weaker[0]["text"]
    assert rows[z]["rssi_avg"] == -70 and rows[z]["rssi_sniffer"] == "s2"
    assert [s_["sniffer"] for s_ in rows[z]["signal"]] == ["s2", "main"]
    assert any(p[1] == -70 for p in rows[z]["spark"])  # the trend follows Sniffer 2


def test_faint_names_the_best_sniffer_and_device_charts_get_a_line_per_sniffer(store):
    now = time.time()
    now_min = int(now // 60) * 60
    b = Batch()
    for m in range(now_min - 30 * 60, now_min, 60):
        _heard(b, m, "0x7004", {"main": -94, "s2": -91})
    b.events.append({"ts": now - 600, "kind": "sniffer_added", "addr": "sniffer", "other": "s2", "ieee": "",
                     "detail": "Sniffer 2: started listening (192.168.1.62)", "file": "", "n": 0})
    store.write(b)
    rep = report.Report(store, make_names([(0x7004, "Far", "Router")]), state(now))
    rep.sniffer_names = {"main": "Main", "s2": "Sniffer 2"}
    row = next(r for r in rep._devices("1h")["devices"] if r["addr"] == "0x7004")
    faint = next(f for f in row["flags"] if f["code"] == "faint")
    assert "every sniffer" in faint["text"] and "Sniffer 2" in faint["text"]
    dev = rep._device("0x7004", "1h", row)
    assert [s_["name"] for s_ in dev["signal_series"]] == ["Main", "Sniffer 2"]
    assert any(mk["kind"] == "sniffer_added" for mk in dev["marks"])  # sniffer changes go on device charts


def test_old_history_gets_the_new_sniffer_columns(tmp_path):
    path = tmp_path / "history.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sniffer_health (sniffer TEXT NOT NULL, minute INTEGER NOT NULL, up_s INTEGER NOT NULL DEFAULT 0, "
               "disconnects INTEGER NOT NULL DEFAULT 0, rssi_sum INTEGER NOT NULL DEFAULT 0, rssi_n INTEGER NOT NULL DEFAULT 0, "
               "rssi_min INTEGER, rssi_max INTEGER, buffered INTEGER NOT NULL DEFAULT 0, backlog_max INTEGER NOT NULL DEFAULT 0, "
               "crc INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (sniffer, minute)) WITHOUT ROWID")
    db.execute("INSERT INTO sniffer_health (sniffer, minute, up_s) VALUES ('main', 60, 30)")
    db.commit()
    db.close()
    st = Store(path)
    st.write_sniffer({("main", 60): [30, 0, 0, 0, None, None, 0, 0, 2, 10, 3, 12]}, [])
    t = st.sniffer_totals("main", 0)
    assert (t["up_s"], t["crc"], t["heard"], t["solo"], t["total"]) == (60, 2, 10, 3, 12)
    assert st.sniffer_ids() == {"main"}
    assert st.crc_minutes("main", 0) == [(60, 2)]
    st.db.close()
    st.rdb.close()


# ---------------------------------------------------------------- antenna gain in the coverage model

def test_coverage_model_fits_each_sniffers_antenna_gain():
    rnd = random.Random(3)
    sniffers = {"main": (2.0, 2.0), "s2": (16.0, 9.0)}
    samples = []
    for i in range(30):
        x, y, a = rnd.uniform(0, 18), rnd.uniform(0, 11), rnd.gauss(-40, 3)
        for sid, (sx, sy) in sniffers.items():
            d = max(0.5, math.hypot(x - sx, y - sy))
            r = a - 27 * math.log10(d) + (17 if sid == "s2" else 0) + rnd.gauss(0, 2)
            samples.append({"device": f"d{i}", "sniffer": sid, "d": d, "floors": 0, "rssi": r, "n": 40})
    m = mapping.fit(samples, ref="main")
    gains = {g["sniffer"]: g["db"] for g in m["gains"]}
    assert gains["main"] == 0 and abs(gains["s2"] - 17) < 2.5
    assert abs(m["n"] - 2.7) < 0.3 and m["rmse"] < 3.5
    blind = mapping.fit([{k: v for k, v in s_.items() if k != "sniffer"} for s_ in samples])
    assert blind["rmse"] > 2 * m["rmse"]  # without the gain the model is badly off


def test_a_bridge_that_restarted_is_paired_afresh_not_moved_by_its_old_uptime(monkeypatch):
    """Sniffer 2's bridge restarted after 38.7 h: its clock started over, the new pairing's offset
    leapt by the old uptime, and 0.5.3-0.5.9 moved the merger's correction by that leap, filing every
    frame 38.7 h back. A restart now starts the correction afresh; a plain reconnect still moves it."""
    import proto
    import sniffers
    from zbs_helpers import Clock

    clock = Clock(500_000.0)
    monkeypatch.setattr(sniffers, "time", clock)
    moves, restarts = [], []
    sn = sniffers.Sniffer("b", "B", "h", 1, 80, lambda *a: None, lambda *a: None, lambda: 25)
    sn.on_offset, sn.on_clock_restart = moves.append, lambda: restarts.append(1)
    boot = 500_000.0 - 139_000.0  # the bridge has been up 139,000 s

    def connect(bridge_us):
        sn.offset, sn.anchor, sn.offset0 = None, None, None  # what a new connection does
        sn.handle(proto.T_HELLO, json_hello(bridge_us))
        clock.t += 0.2
        sn.handle(proto.T_FRAME_AT, frame_at_now(bridge_us + 200_000))

    def frame_at_now(bus):
        from zbs_helpers import frame_at
        return frame_at(bus, data(1))

    connect(int((clock.t - boot) * 1e6))
    clock.t += 30
    sn.handle(proto.T_FRAME_AT, frame_at_now(int((clock.t - boot) * 1e6)))
    clock.t += 60  # Wi-Fi drop, same clock: a plain reconnect
    connect(int((clock.t - boot) * 1e6))
    assert not restarts and moves and max(abs(m) for m in moves) < 1
    moves.clear()
    clock.t += 600  # the bridge restarted 10 s ago: its clock reads 10 s
    boot = clock.t - 10
    connect(int((clock.t - boot) * 1e6))
    assert restarts == [1] and not any(abs(m) > 1 for m in moves)


def test_merger_starts_a_restarted_sniffers_correction_afresh_and_drops_absurd_ones():
    m, s = merger()
    m.link("a", True, now=0.0)
    m.link("b", True, now=0.0)
    m.skew["b"] = 0.0021
    m.clock_restarted("b")
    assert "b" not in m.skew and m.window(10.0) == merge.WINDOW_S
    m.skew["b"] = 0.002
    m.offset_moved("b", 139_401.35)  # a leap no two sniffers' clocks can be apart
    assert "b" not in m.skew
    m.skew["b"] = 0.002
    m.clock_restarted("a")  # the reference restarting leaves the others' corrections
    assert m.skew["b"] == 0.002


def test_a_pairing_step_before_any_match_doesnt_invent_a_correction():
    """What happened with the USB sniffer on the HA box: its first pairing was late (the app's
    startup held up its reads; in 0.6.0-0.6.1 also a minute of frames the radio had kept), the next
    live frame stepped it back 1.6 s (53 s before), and that step became b's correction although no
    copy had ever matched, so nothing b heard matched again."""
    m, s = merger()
    m.link("a", True, now=0.0)
    m.link("b", True, now=0.0)
    m.offset_moved("b", -1.64)
    m.offset_moved("a", 0.003)  # the reference moving doesn't make one up for b either
    assert "b" not in m.skew
    t = 1000.0
    for i in range(30):  # b's frames now carry the right times: they match, and b's correction is learned
        f = data(i % 256, b"u%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0001, 25, -50, 0, f, False, arrival=t + 0.002)
        m.release(now=t + 0.5)
        t += 0.2
    m.release(now=t + 5)
    assert all(len(tx.copies) == 2 for tx in s.emitted[-30:])
    assert abs(m.skew["b"]) < 0.001
