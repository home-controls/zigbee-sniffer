import asyncio

import pytest

import decode
import names as names_mod
import pcap
from zbs_helpers import PAN, ack, mac_data, nwk

T = 1_800_000_000.0


class FakeTshark:
    """fields() answers one row per record of the file it is given, or None (tshark failed)."""

    enabled = True

    def __init__(self) -> None:
        self.fail = False
        self.calls = 0

    async def fields(self, path, fields, dfilter="", occurrence="a", background=False, timeout=300):
        self.calls += 1
        if self.fail:
            return None
        return [{"_ws.col.protocol": "ZigBee", "_ws.col.info": f"frame {i}"} for i, _ in enumerate(pcap.iter_records(path))]


def write_frames(path, start, n, mode="wb"):
    with open(path, mode) as f:
        if mode == "wb":
            f.write(pcap.GLOBAL_HEADER)
        for i in range(start, start + n):
            psdu = mac_data(0x1111, 0x2222, i % 256, nwk(0x1111, 0x0000, i % 256))
            f.write(pcap.record(T + i, pcap.tap_packet(psdu, 25, -60, 200)))
            f.write(pcap.record(T + i + 0.001, pcap.tap_packet(ack(i % 256), 25, -55, 210)))


@pytest.fixture(autouse=True)
def fresh_cache():
    decode._cache.clear()
    decode._locks.clear()
    yield
    decode._cache.clear()
    decode._locks.clear()


def test_decoded_is_incremental(tmp_path):
    path = tmp_path / "zigbee.pcap"
    write_frames(path, 0, 5)
    ts = FakeTshark()
    rows = asyncio.run(decode.decoded(path, ts, PAN))
    assert len(rows) == 10 and [r[decode.N] for r in rows] == list(range(1, 11))
    assert rows[0][decode.SRC] == "0x1111" and rows[1][decode.MTYPE] == "ack" and rows[1][decode.OURS]
    write_frames(path, 5, 3, mode="ab")
    rows = asyncio.run(decode.decoded(path, ts, PAN))
    assert len(rows) == 16 and rows[-1][decode.N] == 16
    assert not any(r[decode.RETRY] for r in rows)
    assert rows[10][decode.INFO] == "frame 0"  # tshark only saw the new stretch
    assert ts.calls == 2


def test_tshark_failure_does_not_turn_frames_into_retries(tmp_path):
    path = tmp_path / "zigbee.pcap"
    write_frames(path, 0, 3)
    ts = FakeTshark()
    asyncio.run(decode.decoded(path, ts, PAN))
    write_frames(path, 3, 3, mode="ab")
    ts.fail = True
    rows = asyncio.run(decode.decoded(path, ts, PAN))  # shown without tshark's columns
    assert len(rows) == 12
    ts.fail = False
    rows = asyncio.run(decode.decoded(path, ts, PAN))
    assert len(rows) == 12
    assert not any(r[decode.RETRY] for r in rows)


def test_page_filters_and_focus(tmp_path):
    path = tmp_path / "zigbee.pcap"
    write_frames(path, 0, 50)
    rows = asyncio.run(decode.decoded(path, FakeTshark(), PAN))
    n = names_mod.Names()
    p = decode.page(rows, n, limit=10)
    assert p["total"] == 100 and len(p["rows"]) == 10 and p["focus"] is None
    p = decode.page(rows, n, at_ts=T + 23.5, limit=10)  # the page holding the first frame at or after that time
    assert p["focus"] == 49 and p["offset"] == 40
    p = decode.page(rows, n, around_n=77, limit=20)
    assert p["focus"] == 77 and p["offset"] == 60
    p = decode.page(rows, n, addr="0x2222", limit=500)
    assert p["total"] == 50
    p = decode.page(rows, n, q="coordinator", limit=500)  # 0x0000 is labelled "Coordinator (0x0000)"
    assert p["total"] == 50
    assert decode.page(rows, n, retries=True)["total"] == 0
    assert p["rows"][0]["nwk_dst"] == "Coordinator (0x0000)"
