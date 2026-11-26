import sqlite3

import pytest

from analysis import Batch
from store import Store

M = 1_800_000_000  # a minute boundary


def ev(ts, kind, addr, other="", file="", n=0):
    return {"ts": ts, "kind": kind, "addr": addr, "other": other, "ieee": "", "detail": "", "file": file, "n": n}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "history.db")
    yield s
    s.db.close()
    s.rdb.close()


def test_write_is_additive(store):
    for part in range(2):
        b = Batch()
        r = b.dev_rec(M, "0x1111")
        r[0], r[1], r[2], r[3] = 3, -180, -65 + part, -55 - part  # tx, rssi_sum, rssi_min, rssi_max
        b.net_rec(M)[0] = 10
        b.link_rec(M - M % 3600, "0x1111", "0x2222")[:] = [4, 1, 0]
        b.files["2027/x.pcap"] = (1000 * (part + 1), 10 * (part + 1))
        store.write(b)
    d = store.devices(M - 60)["0x1111"]
    assert d["tx"] == 6 and d["rssi_sum"] == -360 and d["rssi_min"] == -65 and d["rssi_max"] == -55
    assert store.net_totals(M - 60)["ours"] == 20
    assert store.link_tx(M - 3600) == [{"src": "0x1111", "dst": "0x2222", "uni": 8, "retry": 2, "noack": 0}]
    assert store.file("2027/x.pcap")["offset"] == 2000 and store.file("2027/x.pcap")["frames"] == 20


def test_event_counts_route_errors_in_distinct_minutes(store):
    b = Batch()
    b.events = [
        ev(M + 1, "network_status", "0x3c4d", "0x1a2b"), ev(M + 5, "network_status", "0x3c4d", "0x1a2b"),
        ev(M + 30, "network_status", "0x3c4d", "0x1a2b"), ev(M + 61, "network_status", "0x3c4d", "0x1a2b"),
        ev(M + 2, "route_failure_up", "0x1a2b", "0x3c4d"), ev(M + 50, "route_failure_up", "0x1a2b", "0x3c4d"),
        ev(M + 3, "leave", "0x3c4d"), ev(M + 4, "leave", "0x3c4d"), ev(M + 70, "leave", "0x3c4d"),
        ev(M + 6, "sniffer_disconnected", "sniffer", "main"),
    ]
    store.write(b)
    counts = store.event_counts(M - 1)
    assert counts["0x3c4d"]["network_status"] == 2  # 4 statuses, 2 minutes
    assert counts["0x3c4d"]["leave"] == 3  # other kinds: every event
    assert counts["0x1a2b"]["route_failure_up"] == 1
    assert counts["0x1a2b"]["network_status_reported"] == 2
    assert "sniffer" not in counts
    assert sorted(store.event_minutes(M - 1, ("route_failure_up",))) == [(M, "0x1a2b", "route_failure_up")]


def test_seen_and_msg_seen(store):
    b = Batch()
    b.seen["0x1111"] = (M + 10.0, -60, 200)
    b.msg_seen["0x1111"] = M + 20.0
    b.msg_seen["0x2222"] = M + 30.0  # heard only through relays
    store.write(b)
    b = Batch()
    b.seen["0x1111"] = (M + 5.0, -70, 100)  # older: ignored
    b.msg_seen["0x2222"] = M + 25.0
    store.write(b)
    assert store.seen() == {"0x1111": (M + 10.0, -60, 200)}
    assert store.msg_seen() == {"0x1111": M + 20.0, "0x2222": M + 30.0}


def test_rename_file_moves_offsets_and_event_links(store):
    store.set_file("2026-11-01/zigbee_2026-11-01_07.pcap", offset=5000, frames=50, ev_offset=3000, ev_frames=30)
    b = Batch()
    b.events = [ev(M, "leave", "0x1111", file="2026-11-01/zigbee_2026-11-01_07.pcap", n=12)]
    store.write(b)
    store.rename_file("2026-11-01/zigbee_2026-11-01_07.pcap", "2026-11-01/zigbee_2026-11-01_00.pcap")
    assert store.file("2026-11-01/zigbee_2026-11-01_07.pcap") is None
    assert store.file("2026-11-01/zigbee_2026-11-01_00.pcap") == {
        "rel": "2026-11-01/zigbee_2026-11-01_00.pcap", "offset": 5000, "frames": 50, "ev_offset": 3000, "ev_frames": 30}
    assert store.events(M - 1, "0x1111")[0]["file"] == "2026-11-01/zigbee_2026-11-01_00.pcap"
    store.rename_file("no/such.pcap", "x.pcap")  # unknown: nothing happens
    assert store.file("x.pcap") is None


def test_set_file_ignores_unknown_columns(store):
    store.set_file("a.pcap", offset=10, bogus=1)
    assert store.file("a.pcap")["offset"] == 10


def test_prune(store):
    b = Batch()
    b.dev_rec(M - 7200, "0x1111")[0] = 1
    b.dev_rec(M, "0x1111")[0] = 1
    b.events = [ev(M - 7200, "leave", "0x1111"), ev(M, "leave", "0x1111")]
    b.files = {"gone.pcap": (100, 1), "kept.pcap": (100, 1)}
    store.write(b)
    store.prune(M - 3600, {"kept.pcap"})
    assert store.devices(0)["0x1111"]["minutes"] == 1
    assert len(store.events(0, "0x1111")) == 1
    assert set(store.files()) == {"kept.pcap"}


def test_damaged_database_is_moved_aside(tmp_path):
    path = tmp_path / "history.db"
    path.write_bytes(b"this is not a database " * 400)
    s = Store(path)
    try:
        assert s.recovered and "moved aside" in s.recovered
        assert list(tmp_path.glob("history.db.damaged-*"))
        b = Batch()
        b.net_rec(M)[0] = 5
        s.write(b)
        assert s.net_totals(M - 60)["ours"] == 5
        assert s.files() == {}  # empty: the app counts the captures into the fresh history
    finally:
        s.db.close()
        s.rdb.close()


def test_healthy_database_is_not_touched(tmp_path):
    path = tmp_path / "history.db"
    s = Store(path)
    b = Batch()
    b.net_rec(M)[0] = 7
    s.write(b)
    s.db.close()
    s.rdb.close()
    s2 = Store(path)
    try:
        assert s2.recovered == "" and s2.net_totals(M - 60)["ours"] == 7
        assert not list(tmp_path.glob("*.damaged-*"))
    finally:
        s2.db.close()
        s2.rdb.close()


def test_old_seen_table_gets_msg_ts(tmp_path):
    path = tmp_path / "history.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE seen (addr TEXT PRIMARY KEY, ts REAL, rssi INTEGER, lqi INTEGER)")
    db.execute("INSERT INTO seen VALUES ('0x1111', 5.0, -60, 200)")
    db.commit()
    db.close()
    s = Store(path)
    try:
        assert s.seen() == {"0x1111": (5.0, -60, 200)} and s.msg_seen() == {}
    finally:
        s.db.close()
        s.rdb.close()


def test_write_decoded_marks_progress_and_adds_ota(store):
    store.set_file("f.pcap", offset=9000, frames=90)
    store.write_decoded("f.pcap", 4000, 40, [ev(M, "ota_start", "0x5555")], {(M, "0x5555", "link_status"): 3},
                        {(M - M % 3600, "0x1111", "0x2222"): [1, 2, 3, M + 1.0, 2, 3]}, {(M, "0x5555"): [10, 640, 307200]})
    store.write_decoded("f.pcap", 6000, 60, [], {}, {}, {(M, "0x5555"): [5, 960, 0], (M + 60, "0x5555"): [4, 1216, 0]})
    rec = store.file("f.pcap")
    assert (rec["offset"], rec["frames"], rec["ev_offset"], rec["ev_frames"]) == (9000, 90, 6000, 60)
    o = store.ota(M - 60)["0x5555"]
    assert (o["blocks"], o["offset_max"], o["size"], o["first"], o["last"]) == (19, 1216, 307200, M, M + 60)
    assert sorted(store.ota_minutes(M - 60)) == [(M, "0x5555"), (M + 60, "0x5555")]
    assert store.links(M - 3600)[0]["last_in"] == 2
