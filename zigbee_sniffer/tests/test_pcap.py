import os

import pcap

T = 1_800_000_000.0 + 1800  # half past an hour


def packet(i: int) -> bytes:
    return pcap.tap_packet(bytes([0x41, 0x88, i & 0xFF]) + b"p" * (i % 7), 25, -60 - i % 20, 100 + i % 50)


def test_tap_round_trip():
    psdu = b"\x41\x88\x01\x2c\x85\xff\xff\x00\x00\x09\x12"
    ch, rssi, lqi, back = pcap.parse_tap(pcap.tap_packet(psdu, 25, -73, 214))
    assert (ch, rssi, lqi, back) == (25, -73, 214, psdu)


def test_record_rounding_carries_into_seconds():
    rec = pcap.record(10.9999999, b"x")
    assert int.from_bytes(rec[0:4], "little") == 11 and int.from_bytes(rec[4:8], "little") == 0


def test_read_record_with_growing_index(tmp_path):
    path = tmp_path / "a.pcap"
    pcap.write_file(path, [(T + i, packet(i)) for i in range(5)])
    assert pcap.read_record(path, 3) == (T + 2, packet(2))
    assert pcap.read_record(path, 6) is None and pcap.read_record(path, 0) is None
    with open(path, "ab") as f:  # the file grows: the index is extended, not rebuilt
        for i in range(5, 9):
            f.write(pcap.record(T + i, packet(i)))
    assert pcap.read_record(path, 9) == (T + 8, packet(8))
    assert pcap.read_record(path, 1) == (T, packet(0))


def test_read_record_after_the_file_shrank(tmp_path):
    path = tmp_path / "b.pcap"
    pcap.write_file(path, [(T + i, packet(i)) for i in range(6)])
    assert pcap.read_record(path, 6) is not None
    pcap.write_file(path, [(T + 100 + i, packet(100 + i)) for i in range(2)])  # rewritten, shorter
    assert pcap.read_record(path, 6) is None
    assert pcap.read_record(path, 2) == (T + 101, packet(101))


def test_read_record_ignores_a_half_written_record(tmp_path):
    path = tmp_path / "c.pcap"
    pcap.write_file(path, [(T + i, packet(i)) for i in range(3)])
    with open(path, "ab") as f:
        f.write(pcap.record(T + 3, packet(3))[:10])
    assert pcap.read_record(path, 4) is None
    assert pcap.read_record(path, 3) == (T + 2, packet(2))


def test_chunk_end(tmp_path):
    path = tmp_path / "d.pcap"
    recs = [(T + i, pcap.tap_packet(b"\x41\x88" + bytes([i]) + b"q" * 20, 25, -60, 100)) for i in range(10)]
    pcap.write_file(path, recs)
    size = 16 + len(recs[0][1])
    start, end = len(pcap.GLOBAL_HEADER), path.stat().st_size
    assert end == start + 10 * size
    assert pcap.chunk_end(path, start, end, 10 * size) == (end, None)
    assert pcap.chunk_end(path, start, end, int(3.5 * size)) == (start + 3 * size, 3)
    assert pcap.chunk_end(path, start + 3 * size, end, 4 * size) == (start + 7 * size, 4)
    # from the stretch's end on a record boundary, the next chunk carries on where this one stopped
    first, n = pcap.chunk_end(path, start, end, 5 * size - 1)
    assert (first, n) == (start + 4 * size, 4)


def test_scan_and_rotating_writer_carry_on_after_a_crash(tmp_path):
    w = pcap.RotatingPcap(tmp_path)
    for i in range(4):
        rel, n, end = w.write(T + i, packet(i))
    w.close()
    path = tmp_path / rel
    assert pcap.scan(path) == (4, end)
    with open(path, "ab") as f:
        f.write(b"\x01\x02\x03")  # half a record left by a crash
    w2 = pcap.RotatingPcap(tmp_path)
    rel2, n2, end2 = w2.write(T + 10, packet(10))
    w2.close()
    assert rel2 == rel and n2 == 5
    assert pcap.scan(path) == (5, end2)


def _write(path, times):
    path.parent.mkdir(parents=True, exist_ok=True)
    pcap.write_file(path, [(t, packet(int(t) % 100)) for t in times])


def test_rename_moves_a_misnamed_file(tmp_path):
    wrong = tmp_path / "2000-01-01" / "zigbee_2000-01-01_00.pcap"
    _write(wrong, [T, T + 1, T + 2])
    moved = pcap.rename_to_local_time(tmp_path)
    target = pcap.path_for(tmp_path, T)
    rel = str(target.relative_to(tmp_path)).replace("\\", "/")
    assert moved == [("2000-01-01/zigbee_2000-01-01_00.pcap", rel, None)]
    assert target.exists() and not wrong.exists() and not (tmp_path / "2000-01-01").exists()
    assert [ts for _, ts, _ in pcap.iter_records(target)] == [T, T + 1, T + 2]
    assert pcap.rename_to_local_time(tmp_path) == []  # nothing left to do


def test_rename_appends_to_an_existing_hour(tmp_path):
    target = pcap.path_for(tmp_path, T)
    _write(target, [T, T + 1])
    with open(target, "ab") as f:
        f.write(b"\x00" * 9)  # a half record at its end
    good_end = pcap.scan(target)[1]
    wrong = tmp_path / "2000-01-01" / "zigbee_2000-01-01_05.pcap"
    _write(wrong, [T + 2, T + 3, T + 4])
    moved = pcap.rename_to_local_time(tmp_path)
    assert len(moved) == 1 and moved[0][2] == good_end  # where the appended records start
    assert [ts for _, ts, _ in pcap.iter_records(target)] == [T, T + 1, T + 2, T + 3, T + 4]
    assert not wrong.exists()


def test_rename_finishes_an_interrupted_run(tmp_path):
    aside = tmp_path / "2000-01-01" / ("zigbee_2000-01-01_03.pcap" + pcap.MOVING)
    _write(aside, [T + 5])
    pcap.rename_to_local_time(tmp_path)
    assert pcap.path_for(tmp_path, T).exists() and not aside.exists()


def test_rename_leaves_empty_and_foreign_files(tmp_path):
    empty = tmp_path / "2000-01-01" / "zigbee_2000-01-01_07.pcap"
    empty.parent.mkdir(parents=True)
    empty.write_bytes(pcap.GLOBAL_HEADER)
    assert pcap.rename_to_local_time(tmp_path) == []
    assert empty.exists()
    os.remove(empty)


def test_rotating_writer_reopens_a_closed_hour_without_losing_count(tmp_path):
    w = pcap.RotatingPcap(tmp_path)
    hours = [T + h * 3600 for h in range(5)]  # more hours than files kept open
    first_rel = w.write(hours[0], packet(0))[0]
    w.write(hours[0] + 1, packet(1))
    for h in hours[1:]:
        w.write(h, packet(2))
    assert len(w._open) == w.MAX_OPEN
    rel, n, end = w.write(hours[0] + 2, packet(3))  # a late frame for the first hour (a bridge's backlog)
    assert rel == first_rel and n == 3
    w.close()
    assert pcap.scan(tmp_path / rel) == (3, end)
    assert w.rel == str(pcap.path_for(tmp_path, hours[-1]).relative_to(tmp_path)).replace("\\", "/")


def test_only_date_folders_hold_captures(tmp_path):
    """0.6.3 took a backup folder's copy of an hour (.repair-backup-.../zigbee_..._10.pcap) for a
    misnamed capture at startup and appended it to the live file of that hour."""
    import time as _t
    ts = _t.mktime(_t.strptime("2026-11-21_10:30", "%Y-%m-%d_%H:%M"))
    live = pcap.path_for(tmp_path, ts)
    live.parent.mkdir(parents=True)
    body = pcap.GLOBAL_HEADER + pcap.record(ts, pcap.tap_packet(b"\x02\x00\x01", 25, -60, 200))
    live.write_bytes(body)
    for folder in (".repair-backup", "set-aside"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / live.name).write_bytes(body)
    assert pcap.capture_files(tmp_path) == [live]
    assert pcap.rename_to_local_time(tmp_path) == []
    assert live.read_bytes() == body
    assert (tmp_path / ".repair-backup" / live.name).exists() and (tmp_path / "set-aside" / live.name).exists()
