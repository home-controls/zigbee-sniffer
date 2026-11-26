import time
from types import SimpleNamespace

import pytest

import analysis
import names as names_mod
import report
from analysis import Batch
from store import Store

ROUTERS = [0x1000 + i for i in range(10)]
D, E = 0x2000, 0x3000  # D: route errors only inside the incident; E: its own, hours earlier


def ieee_of(short: int) -> str:
    return f"0x00124b00{short:04x}{(short * 7919) & 0xFFFF:04x}"


def make_names(devs) -> names_mod.Names:
    n = names_mod.Names()
    for short, name, kind in devs:
        ieee = ieee_of(short)
        n.by_ieee[ieee], n.by_nwk[short], n.nwk_ieee[short] = name, name, ieee
        n.devices[ieee] = {"name": name, "ieee": ieee, "type": kind, "model": "", "vendor": "", "power": "",
                           "nwk": f"0x{short:04x}"}
    return n


def state(now):
    return SimpleNamespace(seen={}, msg_seen={}, listening=True, last_frame_ts=now, key_loaded=True)


def ev(ts, kind, addr, other=""):
    return {"ts": ts, "kind": kind, "addr": addr, "other": other, "ieee": "", "detail": "", "file": "", "n": 0}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "history.db")
    yield s
    s.db.close()
    s.rdb.close()


@pytest.fixture
def surge(store):
    """A day of normal traffic (100 frames a minute), then 20 minutes at 4x with route failures
    from the 10 routers and D inside them; E has route failures of its own 3 hours earlier."""
    now = time.time()
    now_min = int(now // 60) * 60
    start = now_min - 30 * 60
    surge_min = set(range(start, start + 20 * 60, 60))
    b = Batch()
    for m in range(now_min - 26 * 3600, now_min + 60, 60):
        ours = 400 if m in surge_min else 100
        r = b.net_rec(m)
        r[0], r[3], r[4], r[5], r[6] = ours, ours * 900, ours * 1000, ours // 2, ours // 100  # ours, air, air, uni, retry
        if m >= now_min - 6 * 3600:
            for a in [*ROUTERS, D, E]:
                b.dev_rec(m, f"0x{a:04x}")[0] = 2
    for i, a in enumerate(ROUTERS):
        b.events.append(ev(start + 60 * i + 5, "route_failure_up", f"0x{a:04x}", "0x5555"))
    for k in range(2, 10):
        b.events.append(ev(start + 60 * k + 20, "route_failure_up", f"0x{D:04x}", "0x6666"))
        b.events.append(ev(start + 60 * k + 21, "route_failure_up", f"0x{D:04x}", "0x6666"))  # same minute
    for k in range(6):
        b.events.append(ev(now_min - 3 * 3600 + 60 * k + 10, "route_failure_up", f"0x{E:04x}", "0x7777"))
    store.write(b)
    devs = [(a, f"Router {i}", "Router") for i, a in enumerate(ROUTERS)] + [(D, "Dee", "Router"), (E, "Eee", "Router")]
    rep = report.Report(store, make_names(devs), state(now))
    return SimpleNamespace(rep=rep, now=now, start=start)


def test_burst_of_route_failures_and_traffic_is_one_incident(surge):
    incs = surge.rep.incidents(surge.now - 6 * 3600, surge.now)
    assert len(incs) == 1
    inc = incs[0]
    assert inc["start"] == surge.start and inc["end"] == surge.start + 20 * 60
    assert inc["title"].startswith("Traffic surge")
    assert inc["evidence"]["traffic_x"] == 4.0
    assert inc["evidence"]["devices_n"] == 11  # the 10 routers and D, not E
    assert {d["addr"] for d in inc["devices"]} == {f"0x{a:04x}" for a in [*ROUTERS, D]}


def test_route_errors_inside_an_incident_are_context_not_the_device(surge):
    rows = {r["addr"]: r for r in surge.rep._devices("6h")["devices"]}
    d_flag = next(f for f in rows[f"0x{D:04x}"]["flags"] if f["code"] == "uplink_errors")
    assert d_flag["sev"] == "info" and d_flag["context"] == "incident"
    assert "8 of those minutes" in (d_flag["detail"] or "")
    e_flag = next(f for f in rows[f"0x{E:04x}"]["flags"] if f["code"] == "uplink_errors")
    assert e_flag["sev"] == "warn" and e_flag["context"] is None
    assert not any(f["code"] == "uplink_errors" for f in rows[f"0x{ROUTERS[0]:04x}"]["flags"])  # one minute only


def test_quiet_network_has_no_incident(store):
    now = time.time()
    now_min = int(now // 60) * 60
    b = Batch()
    for m in range(now_min - 26 * 3600, now_min + 60, 60):
        b.net_rec(m)[0] = 100
    store.write(b)
    rep = report.Report(store, make_names([]), state(now))
    assert rep.incidents(now - 6 * 3600, now) == []


def test_ieee_dedup_folds_an_old_short_address_into_the_current_row(store):
    now = time.time()
    now_min = int(now // 60) * 60
    new = 0x2222  # the old address is 0x1111
    ieee = ieee_of(new)
    b = Batch()
    for m in range(now_min - 5 * 3600, now_min - 3 * 3600, 60):
        b.dev_rec(m, "0x1111")[0] = 1
    for m in range(now_min - 2 * 3600, now_min, 60):
        b.dev_rec(m, "0x2222")[0] = 2
    b.ieee[("0x1111", ieee)] = [now - 5 * 3600, now - 3 * 3600]  # the history knows the old pair
    b.ieee[("0x2222", ieee)] = [now - 2 * 3600, now]
    store.write(b)
    rep = report.Report(store, make_names([(new, "Kitchen Keypad", "Router")]), state(now))
    rows = rep._devices("6h")["devices"]
    mine = [r for r in rows if r["ieee"] == ieee]
    assert len(mine) == 1
    assert mine[0]["addr"] == "0x2222" and mine[0]["name"] == "Kitchen Keypad"
    assert mine[0]["tx"] == 120 * 1 + 120 * 2
    assert not any(r["addr"] == "0x1111" for r in rows)


def test_silence_counts_relayed_messages_and_only_while_listening(store):
    """X was last heard 5 hours ago: silent. Y's own frames stopped too, but its messages still come
    in through a router a minute ago: not silent. With no sniffer connected nobody is silent."""
    now = time.time()
    now_min = int(now // 60) * 60
    x, y = 0x7101, 0x7102
    b = Batch()
    for m in range(now_min - 6 * 3600, now_min - 5 * 3600, 60):
        for a in (x, y):
            b.dev_rec(m, f"0x{a:04x}")[0] = 5
    b.dev_rec(now_min - 60, f"0x{y:04x}")[analysis.MSGS] = 1  # a message of its own, heard relayed
    b.seen.update({f"0x{x:04x}": (now - 5 * 3600, -70, 120), f"0x{y:04x}": (now - 5 * 3600, -75, 110)})
    b.msg_seen[f"0x{y:04x}"] = now - 60
    store.write(b)
    nm = make_names([(x, "Ex", "Router"), (y, "Why", "Router")])
    rows = {r["addr"]: r for r in report.Report(store, nm, state(now))._devices("6h")["devices"]}
    assert any(f["code"] == "silent" and f["sev"] == "high" for f in rows[f"0x{x:04x}"]["flags"])
    assert not any(f["code"] in ("silent", "not_heard") for f in rows[f"0x{y:04x}"]["flags"])
    deaf = state(now)
    deaf.listening = False
    rows = {r["addr"]: r for r in report.Report(store, nm, deaf)._devices("6h")["devices"]}
    assert not any(f["code"] in ("silent", "not_heard") for r in rows.values() for f in r["flags"])


def test_firmware_updates_of_many_devices_are_one_incident_and_shown_per_device(store):
    """What the house is doing now: Zigbee2MQTT updating 20 bulbs at once."""
    now = time.time()
    now_min = int(now // 60) * 60
    ota_start = now_min - 40 * 60
    bulbs = [0x4000 + i for i in range(20)]
    b = Batch()
    for m in range(now_min - 26 * 3600, now_min + 60, 60):
        ours = 900 if m >= ota_start else 100
        r = b.net_rec(m)
        r[0], r[4], r[5], r[6] = ours, ours * 2000, ours // 2, ours // 50
        if m >= now_min - 6 * 3600:
            for a in bulbs:
                b.dev_rec(m, f"0x{a:04x}")[0] = 1
    store.write(b)
    ota = {}
    for m in range(ota_start, now_min + 60, 60):
        for a in bulbs:
            ota[(m, f"0x{a:04x}")] = [30, (m - ota_start) // 60 * 1920 + 1920, 307200]
    done, failed = f"0x{bulbs[0]:04x}", f"0x{bulbs[1]:04x}"
    for a in (done, failed):  # these two ended earlier: no blocks in the last 10 minutes
        for m in range(now_min - 10 * 60, now_min + 60, 60):
            ota.pop((m, a), None)
    evs = [ev(now_min - 11 * 60 + 50, "ota_done", done, "0x0000"),
           ev(now_min - 11 * 60 + 55, "ota_failed", failed, "0x0000")]
    store.write_decoded("f.pcap", 100, 1, evs, {}, {}, ota)
    rep = report.Report(store, make_names([(a, f"Bulb {i}", "Router") for i, a in enumerate(bulbs)]), state(now))
    incs = rep.incidents(now - 6 * 3600, now)
    assert len(incs) == 1
    inc = incs[0]
    assert inc["title"] == "Firmware updates of 20 devices" and inc["end"] is None  # still going on
    assert inc["cause"] is None  # (the title says it; not repeated as the cause)
    assert inc["detail"].startswith("1 done, 18 updating, 1 failed")
    states = rep.ota(now - 6 * 3600, now)
    assert states[done]["state"] == "done" and states[failed]["state"] == "failed"
    busy = states[f"0x{bulbs[5]:04x}"]
    assert busy["state"] == "updating" and 0.2 < busy["progress"] < 0.3
    rows = {r["addr"]: r for r in rep._devices("6h")["devices"]}
    flag = next(f for f in rows[f"0x{bulbs[5]:04x}"]["flags"] if f["code"] == "ota")
    assert flag["context"] == "ota" and flag["text"].startswith("Downloading firmware")
    assert next(f for f in rows[failed]["flags"] if f["code"] == "ota")["sev"] == "warn"
