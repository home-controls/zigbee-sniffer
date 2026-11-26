"""0.5.8: fixes from the delivery review of 2026-11-10 (both sniffers, 24 h of captures): disconnect
reasons that printed nothing, the names reload logged every 10 minutes, the no-ACK finding mixing
real losses with ACKs the sniffers missed, an original merged onto the MAC retry another sniffer
heard alone, and an ACK written twice when only one sniffer heard the frame it answers."""

import asyncio
import json
import logging
import time

import analysis
import merge
import names as names_mod
import report
import sniffers
from analysis import Batch
from test_report import make_names, state, store  # noqa: F401 - the store fixture
from zbs_helpers import ack, mac_data, nwk

# ---------------------------------------------------------------- log lines


def test_a_disconnect_says_why_even_when_the_exception_has_no_text():
    assert str(asyncio.TimeoutError()) == ""  # what made the log say "Connection lost: "
    assert sniffers.why(asyncio.TimeoutError(), "no data for 30 s") == "no data for 30 s"
    assert sniffers.why(TimeoutError(), "no answer in 10 s") == "no answer in 10 s"
    assert sniffers.why(ConnectionError("closed by the bridge"), "x") == "closed by the bridge"
    assert sniffers.why(OSError(113, "No route to host"), "x") == "[Errno 113] No route to host"
    assert sniffers.why(ConnectionResetError(), "x") == "ConnectionResetError"


def _z2m(path, lamp_name: str) -> None:
    (path / "configuration.yaml").write_text(
        f"devices:\n  '0x00124b0000000001':\n    friendly_name: {lamp_name}\n")
    (path / "database.db").write_text(
        json.dumps({"id": 1, "type": "Coordinator", "ieeeAddr": "0x00124b00000000ff", "nwkAddr": 0}) + "\n"
        + json.dumps({"id": 2, "type": "Router", "ieeeAddr": "0x00124b0000000001", "nwkAddr": 4660}) + "\n")


def test_device_names_are_logged_when_they_change_not_on_every_reload(tmp_path, monkeypatch, caplog):
    z2m = tmp_path / "z2m"
    z2m.mkdir()
    _z2m(z2m, "Lamp")
    monkeypatch.setattr(names_mod, "Z2M_DIR", z2m)
    n = names_mod.Names()
    with caplog.at_level(logging.INFO, logger="names"):
        for _ in range(3):  # startup, then every 10 minutes
            n.reload()
    assert [r.getMessage() for r in caplog.records] == ["Loaded 2 device names"]
    caplog.clear()
    _z2m(z2m, "Desk Lamp")
    with caplog.at_level(logging.INFO, logger="names"):
        n.reload()
    assert [r.getMessage() for r in caplog.records] == ["Device names changed (2 now); renamed: Lamp -> Desk Lamp"]
    assert n.by_nwk[4660] == "Desk Lamp"


# ---------------------------------------------------------------- the no-ACK finding


def test_no_ack_finding_tells_real_losses_from_acks_the_sniffers_missed(store):  # noqa: F811
    """Three devices, each with no ACK heard for 40% of the 600 frames sent to it. Its neighbour sent
    200 of them again to "Lossy" (real losses), 55 to "Mixed", 10 to "Fine" (there the sender carried
    on: the sniffers missed the ACKs)."""
    now = time.time()
    now_min = int(now // 60) * 60
    devs = {0x7201: ("Lossy", 200), 0x7202: ("Mixed", 55), 0x7203: ("Fine", 10)}
    b = Batch()
    for m in range(now_min - 3600, now_min, 60):
        for a in devs:
            r = b.dev_rec(m, f"0x{a:04x}")
            r[analysis.TX], r[analysis.RSSI_SUM] = 5, -350
            r[analysis.RX], r[analysis.NOACK] = 10, 4
    hour = int((now_min - 1800) // 3600) * 3600
    for a, (_, resent) in devs.items():
        b.link[(hour, "0x1000", f"0x{a:04x}")] = [600, resent, 240]
    store.write(b)
    nm = make_names([(a, name, "Router") for a, (name, _) in devs.items()] + [(0x1000, "Neighbour", "Router")])
    rows = {r["name"]: r for r in report.Report(store, nm, state(now))._devices("6h")["devices"]}

    lossy = rows["Lossy"]
    assert (lossy["rx"], lossy["noack"], lossy["rx_lost"], lossy["noack_missed"]) == (600, 240, 200, 40)
    [f] = [f for f in lossy["flags"] if f["code"] == "no_ack"]
    assert f["sev"] == "warn"
    assert f["text"] == "Lost 33.3% of the frames sent to it (200 of 600 had to be sent again)"
    assert "40 carried on (ACKs the sniffers missed)" in f["detail"]

    [f] = [f for f in rows["Mixed"]["flags"] if f["code"] == "no_ack"]
    assert f["sev"] == "info" and "55 of them sent again" in f["text"]

    fine = rows["Fine"]
    assert fine["noack_missed"] == 230
    assert not any(f["code"] == "no_ack" for f in fine["flags"])  # nothing wrong with it


# ---------------------------------------------------------------- merging original and retry


class Sink:
    def __init__(self) -> None:
        self.emitted: list[merge.Tx] = []

    def emit(self, tx):
        self.emitted.append(tx)

    def late_copy(self, tx, sid, rssi, lqi):
        pass


def _merger():
    s = Sink()
    return merge.Merger(s.emit, s.late_copy, several=True, ref="a"), s


def _data(seq, body):
    return mac_data(0x1111, 0x0000, seq, nwk(0x1111, 0x0000, seq, body), ack=True)


def _sent(s, f, t0):
    return sorted((round(tx.ts - t0, 4), sorted(c[0] for c in tx.copies))
                  for tx in s.emitted if tx.key == merge.frame_key(f))


def test_an_original_merged_onto_a_retry_heard_alone_is_taken_back_off_it():
    """Nothing learned yet (wide window). Sniffer a heard only the MAC retry and its copy came in
    first; b heard the original 2.5 ms earlier and then the retry. b's original lands on a's retry
    (the only candidate); b's retry then takes its place and the original stands alone, at its time."""
    m, s = _merger()
    t = 1000.0
    f = _data(42, b"orig")
    m.add("a", t + 0.0025, 25, -80, 0, f, False, arrival=t + 0.010)  # a: the retry only
    m.add("b", t, 25, -60, 0, f, False, arrival=t + 0.020)           # b: the original...
    m.add("b", t + 0.0025, 25, -61, 0, f, False, arrival=t + 0.021)  # ...and the retry
    m.release(now=t + 1)
    assert _sent(s, f, t) == [(0.0, ["b"]), (0.0025, ["a", "b"])]
    retry = next(tx for tx in s.emitted if tx.key == merge.frame_key(f) and len(tx.copies) == 2)
    assert {c[0]: c[1] for c in retry.copies} == {"a": -80, "b": -61}  # the retry's own signal
    assert m.repaired == 1


def test_once_copies_line_up_the_window_stays_under_a_retrys_gap():
    """Copies 0.2 ms apart: the window narrows to ~1.1 ms (it was at least 3 ms, wider than the 1.7 ms
    to a quick MAC retry). Then b's original comes in first and a's retry, heard alone 2 ms later,
    no longer lands on it."""
    m, s = _merger()
    t = 1000.0
    for i in range(40):
        f = _data(i % 256, b"w%d" % i)
        m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
        m.add("b", t + 0.0002, 25, -70, 0, f, False, arrival=t + 0.012)
        m.release(now=t + 0.5)
        t += 0.2
    assert m.window(t + 2) < merge.RETRY_GAP_S
    f = _data(99, b"quick retry")
    m.add("b", t, 25, -60, 0, f, False, arrival=t + 0.010)           # b: the original
    m.add("a", t + 0.002, 25, -80, 0, f, False, arrival=t + 0.011)   # a: the retry only
    m.add("b", t + 0.002, 25, -61, 0, f, False, arrival=t + 0.012)   # b: the retry
    m.release(now=t + 1)
    got = _sent(s, f, t)
    assert [heard for _, heard in got] == [["b"], ["a", "b"]]
    assert abs(got[1][0] - 0.002) < 0.0005
    assert m.repaired == 0


def test_an_ack_one_sniffer_heard_alone_merges_with_the_others_paired_copy():
    """a heard the frame and its ACK; b missed the frame and heard only the ACK, so b's copy has no
    frame to pair with. It is still the same ACK: one transmission, heard by both, whichever copy
    comes in first (until 0.5.8 it was written twice - a fifth of all ACKs with two sniffers)."""
    for b_first in (False, True):
        m, s = _merger()
        t = 1000.0
        f, a_ack = _data(7, b"asks"), ack(7)
        copies = [("a", t, f, t + 0.010), ("a", t + 0.0015, a_ack, t + 0.011),
                  ("b", t + 0.0015, a_ack, t + 0.005 if b_first else t + 0.030)]
        for sid, ts, psdu, arrival in sorted(copies, key=lambda c: c[3]):
            m.add(sid, ts, 25, -60 if sid == "a" else -75, 0, psdu, False, arrival=arrival)
        m.release(now=t + 1)
        acks = [tx for tx in s.emitted if tx.key[:8] == merge.frame_key(a_ack)]
        assert len(acks) == 1, b_first
        assert sorted(c[0] for c in acks[0].copies) == ["a", "b"]
        assert len(s.emitted) == 2  # the frame and its ACK


def test_unrelated_acks_with_the_same_number_stay_apart():
    """Two ACKs with the same sequence number 30 ms apart (two different links) are two ACKs, even
    when the sniffer that heard the second couldn't pair it."""
    m, s = _merger()
    t = 1000.0
    f = _data(9, b"asks")
    m.add("a", t, 25, -60, 0, f, False, arrival=t + 0.01)
    m.add("a", t + 0.0015, 25, -60, 0, ack(9), False, arrival=t + 0.011)
    m.add("b", t + 0.0315, 25, -70, 0, ack(9), False, arrival=t + 0.04)
    m.release(now=t + 1)
    assert sum(1 for tx in s.emitted if tx.key[:8] == merge.frame_key(ack(9))) == 2


def test_the_app_reports_the_version_it_ships_as():
    """main.VERSION is what the status, the Home Assistant device and the header show: 0.5.8 shipped
    still saying 0.5.7."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    shipped = re.search(r'^version: "([^"]+)"', (root / "config.yaml").read_text(), re.M).group(1)
    reported = re.search(r'^VERSION = "([^"]+)"', (root / "app" / "main.py").read_text(), re.M).group(1)
    assert reported == shipped
