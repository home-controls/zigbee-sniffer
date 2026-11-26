"""0.5.4: firmware downloads as sessions (resumed, ETA, restarted, Zigbee2MQTT's versions), a device's
signal against each sniffer's own normal, and answers cached until the history changes."""

import json
import time

import pytest

import names as names_mod
import report
import tshark
from analysis import Batch
from store import Store
from test_report import ev, make_names, state

BULB = 0x4401
ADDR = f"0x{BULB:04x}"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "history.db")
    yield s
    s.db.close()
    s.rdb.close()


def test_fw_version_formats():
    assert report.fw_version(0x01002B00) == "1.0.43.0"
    assert report.fw_version(None) == "" and report.fw_version(0) == ""
    assert tshark.fw_version("0x01002b00") == "1.0.43.0"


def _ota_rows(start, minutes, lo0, step, size, blocks=60):
    """(minute, device) -> [blocks, highest offset, size, lowest offset] for a download from lo0."""
    out = {}
    for k in range(minutes):
        lo = lo0 + k * step
        out[(start + 60 * k, ADDR)] = [blocks, lo + step, size, lo]
    return out


def test_a_resumed_download_that_finished_and_restarted(store):
    now = time.time()
    m0 = int(now // 60) * 60 - 20 * 60
    size = 300_000
    rows = _ota_rows(m0, 3, 291_000, 3_000, size)  # picked up at 97 %, finished in 3 minutes
    evs = [ev(m0 + 170, "ota_done", ADDR, "0x0000"),
           {**ev(m0 + 175, "ota_done", ADDR, "z2m"), "detail": "firmware updated from 100 to 200 (Zigbee2MQTT)"},
           ev(m0 + 200, "device_announce", ADDR, "z2m")]
    store.write_decoded("f.pcap", 10, 1, evs, {}, {}, rows)
    rep = report.Report(store, make_names([(BULB, "Porch", "Router")]), state(now))
    o = rep.ota(now - 3600, now)[ADDR]
    assert o["state"] == "done" and o["from"] == 0.97 and o["progress"] == 1.0
    assert o["bytes"] == 9_000 and o["duration"] == 180
    assert o["result"].startswith("firmware updated from 100 to 200")  # Zigbee2MQTT's result, with versions, wins
    assert o["restarted"] == m0 + 200
    flag = next(f for f in rep._devices("1h")["devices"][0]["flags"] if f["code"] == "ota")
    assert "picked up at 97%" in flag["text"] and "restarted" in flag["text"]


def test_a_download_in_progress_has_an_eta_and_two_downloads_are_two_sessions(store):
    now = time.time()
    m_now = int(now // 60) * 60
    size = 600_000
    first = _ota_rows(m_now - 120 * 60, 5, 0, 10_000, size)  # an hour and a half ago: stopped at 50 KB
    second = _ota_rows(m_now - 4 * 60, 5, 50_000, 30_000, size)  # now: picked up there, 30 KB a minute
    store.write_decoded("f.pcap", 10, 1, [], {}, {}, {**first, **second})
    rep = report.Report(store, make_names([(BULB, "Porch", "Router")]), state(now))
    o = rep.ota(now - 3 * 3600, now)[ADDR]
    assert len(o["sessions"]) == 2 and o["sessions"][0]["state"] == "stalled"
    assert o["state"] == "updating" and 0.3 < o["progress"] < 0.35 and o["from"] == round(50_000 / size, 3)
    assert o["rate"] == 500  # 150 KB in 5 minutes
    assert o["eta"] == 800  # the other 400 KB at 500 B/s


def test_zigbee2mqtt_firmware_status_from_state_json(store, tmp_path, monkeypatch):
    z2m = tmp_path / "z2m"
    z2m.mkdir()
    ieee = "0x00124b0044010007"
    (z2m / "state.json").write_text(json.dumps({
        ieee: {"state": "ON", "update": {"state": "available", "installed_version": 0x01002A00,
                                          "latest_version": 0x01002B00, "latest_release_notes": "Version: 43.0"}},
        "0x00124b00ffffffff": {"update": {"state": "idle", "installed_version": 1, "latest_version": 1}},
        "0x00124b00eeeeeeee": {"brightness": 3}}))
    monkeypatch.setattr(names_mod, "Z2M_DIR", z2m)
    monkeypatch.setitem(names_mod._updates, "mtime", None)
    got = names_mod.load_z2m_updates()
    assert got[ieee] == {"state": "available", "installed": 0x01002A00, "latest": 0x01002B00, "notes": "Version: 43.0"}
    assert "0x00124b00eeeeeeee" not in got
    nm = make_names([(BULB, "Porch", "Router")])
    nm.by_ieee[ieee] = "Porch"
    nm.nwk_ieee[BULB] = ieee
    rep = report.Report(store, nm, state(time.time()))
    fw = rep.firmware(time.time() - 3600, time.time())
    assert [a["name"] for a in fw["available"]] == ["Porch"]
    assert fw["available"][0]["installed"] == "1.0.42.0" and fw["available"][0]["latest"] == "1.0.43.0"


def _heard(b: Batch, minute: int, addr: str, per: dict) -> None:
    best = max(per.values())
    d = b.dev_rec(minute, addr)
    d[0] += 3
    d[1] += 3 * best
    for sid, r in per.items():
        b.sniff[(minute, addr, sid)] = [3, 3 * r, r, r]


def test_each_sniffers_normal_and_change_and_the_charts_reference(store):
    now = time.time()
    now_min = int(now // 60) * 60
    addr = "0x7101"
    b = Batch()
    for m in range(now_min - 30 * 3600, now_min - 2 * 3600, 600):
        _heard(b, m, addr, {"main": -80})  # Sniffer 2 is new: no normal there
    for m in range(now_min - 50 * 60, now_min, 60):
        _heard(b, m, addr, {"main": -90, "s2": -70})
    store.write(b)
    rep = report.Report(store, make_names([(0x7101, "Lamp", "Router")]), state(now))
    rep.sniffer_names = {"main": "Main", "s2": "Sniffer 2"}
    data = rep._devices("1h")
    assert data["sniffers"] == [{"id": "main", "name": "Main"}, {"id": "s2", "name": "Sniffer 2"}]
    row = next(r for r in data["devices"] if r["addr"] == addr)
    sig = {x["sniffer"]: x for x in row["signal"]}
    assert sig["main"]["normal"] == -80 and sig["main"]["change"] == -10
    assert sig["s2"]["normal"] is None and sig["s2"]["change"] is None
    series = {x["sniffer"]: x for x in rep._device(addr, "1h", row)["signal_series"]}
    assert series["main"]["ref"] == -80 and series["main"]["ref_kind"] == "normal"
    assert series["s2"]["ref"] == -70 and series["s2"]["ref_kind"] == "range"  # no normal yet: its own average


def test_answers_are_kept_until_the_history_is_written(store):
    rep = report.Report(store, make_names([]), state(time.time()))
    calls = []

    def compute():
        calls.append(1)
        return len(calls)

    assert rep._cached_sync(("x",), 0, compute) == 1
    assert rep._cached_sync(("x",), 0, compute) == 1  # (ttl 0, but nothing new was written)
    rep.history_written()
    assert rep._cached_sync(("x",), 0, compute) == 2


def test_device_sniffer_buckets_totals_match_the_buckets(store):
    now = time.time()
    m0 = int(now // 60) * 60 - 600
    b = Batch()
    for k, r in enumerate((-60, -70, -80)):
        b.sniff[(m0 + 60 * k, "0x0001", "main")] = [2, 2 * r, r, r]
    store.write(b)
    totals, sparks = store.device_sniffer_buckets(now - 3600, 120)
    t = totals["0x0001"]["main"]
    assert (t["n"], t["rs"], t["mn"], t["mx"]) == (6, -420, -80, -60)
    assert sum(len(v) for v in sparks["0x0001"].values()) == 2  # three minutes in two 2-minute buckets


def test_downloads_stored_before_the_lowest_offset_was_kept_dont_claim_a_start(store):
    """Minutes written before 0.5.4 have no lowest offset: the download's start and size are unknown,
    not "from 0 %" with the whole image."""
    now = time.time()
    m0 = int(now // 60) * 60 - 10 * 60
    store.write_decoded("f.pcap", 10, 1, [], {}, {}, {(m0, ADDR): [179, 533_000, 533_426]})  # (3 values: 0.5.3)
    rep = report.Report(store, make_names([(BULB, "Porch", "Router")]), state(now))
    o = rep.ota(now - 3600, now)[ADDR]
    assert o["from"] is None and o["bytes"] is None and o["rate"] is None and o["progress"] == 0.999


def test_a_sniffers_normals_need_half_a_day_and_start_again_when_it_is_moved(store):
    """Two hours at a desk is no normal; and once moved, what it heard where it was before isn't."""
    now = time.time()
    now_min = int(now // 60) * 60
    addr = "0x7201"
    b = Batch()
    for m in range(now_min - 30 * 3600, now_min - 2 * 3600, 600):
        _heard(b, m, addr, {"main": -80, "old": -60})  # "old": 28 h of history
    for m in range(now_min - 4 * 3600, now_min - 2 * 3600, 600):
        b.sniff[(m, addr, "new")] = [3, -3 * 70, -70, -70]  # "new": only 2 h
    store.write(b)
    rep = report.Report(store, make_names([(0x7201, "Lamp", "Router")]), state(now))
    by = rep.baselines(now - 3600)[addr]["rssi_by_sniffer"]
    assert by == {"main": -80, "old": -60}  # "new" isn't settled yet
    assert rep.sniffer_hours["new"] <= 3 and rep.sniffer_hours["old"] >= 12  # (2 h span over 3 clock hours)
    rep.sniffer_moves["old"] = now - 10 * 3600  # moved 10 hours ago: only what it heard since counts
    rep.forget_baselines()
    by = rep.baselines(now - 3600)[addr]["rssi_by_sniffer"]
    assert "old" not in by and rep.sniffer_hours["old"] < 12



def test_normal_hours_follow_the_baseline_window_asked_for(store):
    """The Sniffer page's hours are those of the 1-hour view's normals, whatever range was worked out last."""
    now = time.time()
    now_min = int(now // 60) * 60
    b = Batch()
    for m in range(now_min - 20 * 3600, now_min - 2 * 3600, 600):
        b.sniff[(m, "0x0009", "main")] = [3, -240, -80, -80]
    store.write(b)
    rep = report.Report(store, make_names([]), state(now))
    rep.baselines(now - 86400)  # the 24-hour view: nothing before it
    assert rep.normal_hours(now - 3600)["main"] >= 12
