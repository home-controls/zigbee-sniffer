"""Counting repaired capture files into the history again (recount.py, Store.forget)."""

import json
import logging
import time

import pcap
import recount
from analysis import NET_FIELDS, Batch
from test_store import ev, store  # noqa: F401 - the store fixture

H = 1_800_000_000 - 1_800_000_000 % 3600  # an hour boundary
REL = "2027-01-15/zigbee_2027-01-15_08.pcap"


def health(**kw):
    r = [0, 0, 0, 0, None, None, 0, 0, 0, 0, 0, 0]
    for k, v in kw.items():
        r[("up_s", "disconnects", "rssi_sum", "rssi_n", "rssi_min", "rssi_max", "buffered", "backlog_max", "crc",
           "heard", "solo", "total").index(k)] = v
    return r


def one(store, sql, *args):  # noqa: F811
    return [tuple(r) for r in store.db.execute(sql, args).fetchall()]


def test_forget_takes_a_files_hour_out_and_keeps_what_didnt_come_from_captures(store):  # noqa: F811
    for hour, rel in ((H, REL), (H + 3600, "2027-01-15/zigbee_2027-01-15_09.pcap")):
        b = Batch()
        b.dev_rec(hour + 60, "0x1111")[0] = 5
        b.net_rec(hour + 60)[0] = 7
        b.net_rec(hour + 60)[NET_FIELDS.index("dropped")] = 3
        b.net_rec(hour + 120)[0] = 2  # a minute with nothing else: goes away entirely
        b.hops[(hour, "0x1111", "0x0000", "0x1111", "0x0000")] = [4, -240]
        b.link_rec(hour, "0x1111", "0x0000")[:] = [4, 1, 0]
        b.sniff[(hour + 60, "0x1111", "sniffer_2")] = [2, -140, -71, -69]
        b.files[rel] = (5000, 50)
        b.events.append(ev(hour + 70, "device_announce", "0x1111", file=rel, n=12))
        store.write(b)
        store.write_sniffer({("sniffer_2", hour + 60): health(up_s=60, rssi_sum=-700, rssi_n=10, rssi_min=-75,
                                                               rssi_max=-65, heard=9, solo=2, total=11)},
                            [ev(hour + 80, "z2m_restart", "z2m")])
    store.forget([(REL, H)])

    assert one(store, "SELECT minute FROM dev_min") == [(H + 3660,)]
    assert one(store, "SELECT minute, ours, dropped FROM net_min ORDER BY minute") == [
        (H + 60, 0, 3), (H + 3660, 7, 3), (H + 3720, 2, 0)]  # the bridges' drops stay
    assert one(store, "SELECT hour FROM hops") == [(H + 3600,)]
    assert one(store, "SELECT hour FROM link_tx") == [(H + 3600,)]
    assert one(store, "SELECT minute FROM dev_sniffer_min") == [(H + 3660,)]
    assert one(store, "SELECT kind, ts FROM events ORDER BY ts") == [
        ("z2m_restart", H + 80), ("device_announce", H + 3670), ("z2m_restart", H + 3680)]
    assert one(store, "SELECT minute, up_s, rssi_n, rssi_min, heard, solo, total FROM sniffer_health "
                      "ORDER BY minute") == [(H + 60, 60, 10, -75, 0, 0, 0), (H + 3660, 60, 10, -75, 9, 2, 11)]
    assert store.file(REL) is None and store.file("2027-01-15/zigbee_2027-01-15_09.pcap")["frames"] == 50


def test_connected_minutes(store):  # noqa: F811
    store.write_sniffer({("main", H): health(up_s=60), ("sniffer_2", H): health(up_s=12),
                         ("sniffer_2", H + 60): health(crc=1), ("main", H + 3600): health(up_s=60)}, [])
    assert store.connected_minutes(H, H + 3600) == {H: {"main", "sniffer_2"}}


class FakeStore:
    def __init__(self):
        self.forgotten = []

    def forget(self, files):
        self.forgotten.append(files)


def test_a_request_takes_the_old_counts_out_once_and_ends_when_done(tmp_path, caplog):
    (tmp_path / REL).parent.mkdir()
    pcap.write_file(tmp_path / REL, [])
    (tmp_path / "2027-01-15" / "notes.pcap").write_bytes(b"")
    (tmp_path / recount.REQUEST).write_text(json.dumps(
        {"files": [REL, "2027-01-15/zigbee_2027-01-15_09.pcap", "2027-01-15/notes.pcap"], "reason": "repaired"}))
    fs = FakeStore()
    start = time.mktime(time.strptime("2027-01-15_08", "%Y-%m-%d_%H"))
    with caplog.at_level(logging.INFO):
        assert recount.start(tmp_path, fs) == {REL: start}
    assert fs.forgotten == [[(REL, start)]]
    assert "2 files aren't captures here" in caplog.text and "again (repaired)" in caplog.text
    # a restart before the counting is done carries on without taking the new counts out again
    assert recount.start(tmp_path, fs) == {REL: start} and len(fs.forgotten) == 1
    recount.finish(tmp_path)
    assert recount.start(tmp_path, fs) == {} and len(fs.forgotten) == 1


def test_a_broken_request_is_ignored(tmp_path, caplog):
    (tmp_path / recount.REQUEST).write_text("{files")
    fs = FakeStore()
    assert recount.start(tmp_path, fs) == {} and fs.forgotten == []
    assert "Ignoring recount.json" in caplog.text


def test_coverage_counts_who_heard_our_transmissions(store):  # noqa: F811
    cov = recount.Coverage({H: {"main", "sniffer_2"}})
    ours = {"m": {"src": "0x1111", "type": "data"}, "ours": True}
    cov.add(H + 1, ours, [("main", -60), ("sniffer_2", -70)])
    cov.add(H + 2, ours, [("sniffer_2", -70)])
    cov.add(H + 3, {"m": {"type": "ack"}, "ours": True}, [("main", -60)])  # an ACK has no sender
    cov.add(H + 4, {"m": {"src": "0x9999"}, "ours": False}, [("main", -60)])  # another network
    cov.add(H + 5, ours, None)  # no .sniffers line: nothing to tell
    cov.add(H + 61, ours, [("sniffer_3", -80)])  # heard it, so it was listening
    rows = cov.take()
    assert cov.take() == {}
    store.write_sniffer(rows, [])
    t = {s: store.sniffer_totals(s, H) for s in ("main", "sniffer_2", "sniffer_3")}
    assert (t["main"]["heard"], t["main"]["solo"], t["main"]["total"]) == (1, 0, 2)
    assert (t["sniffer_2"]["heard"], t["sniffer_2"]["solo"], t["sniffer_2"]["total"]) == (2, 1, 2)
    assert (t["sniffer_3"]["heard"], t["sniffer_3"]["solo"], t["sniffer_3"]["total"]) == (1, 1, 1)
    assert t["main"]["rssi_min"] is None
