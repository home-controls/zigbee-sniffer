import pytest

import tshark

KEY_COLON = "01:03:05:07:09:0b:0d:0f:00:02:04:06:08:0a:0c:0d"
KEY_HEX = "0103050709" "0b0d0f0002" "0406080a0c0d"

TEXT = """Frame 12: 63 bytes on wire (504 bits), 63 bytes captured (504 bits)
IEEE 802.15.4 Data, Dst: 0x7d68, Src: 0x0000
ZigBee Network Layer Data, Dst: 0x7d68, Src: 0x0000
    ZigBee Security Header
        Security Control Field: 0x28, Key Id: Network Key, Extended Nonce
        Frame Counter: 4711
        Key Sequence Number: 0
        Message Integrity Code: 1a2b3c4d
        [Key: @KEY@]
        [Key Label: Zigbee2MQTT network key]
ZigBee Application Support Layer Command
    Frame Control Field: Command (0x21)
    Counter: 12
    Command Frame: Transport Key
        Command Identifier: Transport Key (0x05)
        Key Type: Standard Network Key (0x01)
        Key: @KEY@
        Sequence Number: 0
        Extended Destination: 00:12:4b:00:24:cb:9c:e3
0000  41 88 2c 2c 85 68 7d 00 00 08 02 68 7d 00 00 1e   A.,,.h}....h}...
0010  0c 28 67 12 00 00 00 12 4b 00 01 02 03 04 00 aa   .(g.....K.......
Decrypted ZigBee Payload (35 bytes):
0000  21 0c 05 01 01 03 05 07 09 0b 0d 0f 00 02 04 06   !...............
0010  08 0a 0c 0d 00 e3 9c cb 24 00 4b 12 00 00 00 00   ........$.K.....
0020  00 00 00                                          ...
""".replace("@KEY@", KEY_COLON)

JSON = f"""{{
  "zbee.sec.key": "{KEY_COLON}",
  "zbee.sec.decryption_key": "{KEY_COLON}",
  "zbee_aps.cmd.key": "{KEY_COLON}",
  "zbee_aps.cmd.key_raw": ["{KEY_HEX}", 41, 16, 0, 30],
  "zbee_aps.cmd.key_type": "1",
  "zbee.sec.counter": "4711"
}}"""


def test_redact_text_hides_every_key_form():
    out = tshark.redact(TEXT)
    assert KEY_COLON not in out
    assert "[Key: hidden]" in out
    assert "[Key Label: hidden]" in out
    assert "        Key: hidden" in out
    # the decrypted payload of a Transport Key holds the key in hex: dropped
    assert "05 07 09 0b" not in out and "0a 0c 0d" not in out
    assert "Decrypted ZigBee Payload (35 bytes): (hidden: it carries a key)" in out
    # everything else stays
    for keep in ("Key Type: Standard Network Key (0x01)", "Sequence Number: 0", "Frame Counter: 4711",
                 "Key Sequence Number: 0", "0000  41 88 2c 2c", "Extended Destination: 00:12:4b:00:24:cb:9c:e3"):
        assert keep in out


def test_redact_json():
    out = tshark.redact(JSON)
    assert KEY_COLON not in out and KEY_HEX not in out
    assert out.count('"hidden"') == 4
    assert '"zbee_aps.cmd.key_type": "1"' in out and '"zbee.sec.counter": "4711"' in out


def test_redact_keeps_decrypted_hex_of_other_frames():
    text = "ZigBee Cluster Library Frame\nDecrypted ZigBee Payload (8 bytes):\n0000  18 0c 0a 00 00 10 01 00   ........\n"
    assert tshark.redact(text) == text


# ---------------------------------------------------------------- _digest

T = 1_800_000_000.0


def row(n, ts, src, dst, seq, **fields):
    r = {"frame.number": str(n), "frame.time_epoch": f"{ts:.6f}", "zbee_nwk.src": src, "zbee_nwk.dst": dst,
         "zbee_nwk.seqno": str(seq), "_ws.col.info": "info"}
    r.update({k.replace("__", "."): v for k, v in fields.items()})
    return r


def nwk_status(n, ts, reporter, code, target, seq):
    return row(n, ts, reporter, "0xfffd", seq, **{"zbee_nwk.cmd.id": "0x03", "zbee_nwk.cmd.status": f"0x{code:02x}",
                                                  "zbee_nwk.cmd.route.dest": target})


@pytest.fixture
def ts_(tmp_path):
    return tshark.Tshark(tmp_path, enabled=False)


def test_network_status_kinds(ts_):
    rows = [nwk_status(1, T, "0x1a2b", 0x0C, "0x3c4d", 10),
            nwk_status(2, T + 1, "0x1a2b", 0x0D, "0x5e6f", 11),
            nwk_status(3, T + 2, "0x7777", 0x11, "0x8888", 12),
            nwk_status(4, T + 3, "0x7777", 0x02, "0x9999", 13)]
    events, cmds, links, ota = ts_._digest(rows, "2027-01-15/zigbee_2027-01-15_08.pcap", 101)
    by_kind = {e["kind"]: e for e in events}
    up = by_kind["route_failure_up"]
    assert (up["addr"], up["other"]) == ("0x1a2b", "0x3c4d")  # the reporter's uplink, not the originator
    assert (by_kind["address_conflict"]["addr"], by_kind["address_conflict"]["other"]) == ("0x5e6f", "0x1a2b")
    assert (by_kind["bad_frame_counter"]["addr"], by_kind["bad_frame_counter"]["other"]) == ("0x8888", "0x7777")
    assert (by_kind["network_status"]["addr"], by_kind["network_status"]["other"]) == ("0x9999", "0x7777")
    assert [e["n"] for e in events] == [101, 102, 103, 104]
    assert cmds[(int(T // 60) * 60, "0x1a2b", "network_status")] == 2
    assert not links and not ota


def test_relayed_broadcast_counted_once(ts_):
    rows = [nwk_status(1, T, "0x1a2b", 0x0C, "0x3c4d", 10), nwk_status(2, T + 0.02, "0x1a2b", 0x0C, "0x3c4d", 10)]
    events, cmds, _, _ = ts_._digest(rows, "f", 1)
    assert len(events) == 1
    assert sum(cmds.values()) == 1


def ota_row(n, ts, src, dst, seq, **ota):
    fields = {"zbee_aps.cluster": "0x0019"}
    for k, v in ota.items():
        fields["zbee_zcl_general.ota." + k.replace("__", ".")] = v
    return row(n, ts, src, dst, seq, **fields)


def test_ota_blocks_dedup_across_relays_and_progress(ts_):
    dev = "0x5555"
    rows = [
        ota_row(1, T, "0x0000", dev, 39, cmd__srv_tx__id="0x02", status="0x00", image__size="307200"),
        ota_row(2, T + 1, "0x0000", dev, 40, cmd__srv_tx__id="0x05", status="0x00", file__offset="1024", data_size="64"),
        ota_row(3, T + 1.01, "0x0000", dev, 40, cmd__srv_tx__id="0x05", status="0x00", file__offset="1024", data_size="64"),
        ota_row(4, T + 2, "0x0000", dev, 41, cmd__srv_tx__id="0x05", status="0x00", file__offset="1088", data_size="64"),
        ota_row(5, T + 3, dev, "0x0000", 7, cmd__srv_rx__id="0x03", file__offset="1152"),
    ]
    events, _, _, ota = ts_._digest(rows, "f", 1)
    rec = ota[(int(T // 60) * 60, dev)]
    assert rec == [2, 1152, 307200, 1024]  # two blocks (the relayed copy not counted), highest offset, image size, lowest block offset
    kinds = [e["kind"] for e in events]
    assert kinds.count("ota_start") == 1 and kinds.count("ota_offer") == 1
    assert next(e for e in events if e["kind"] == "ota_start")["addr"] == dev


def test_ota_blocks_counted_when_the_coordinators_nwk_seq_wraps(ts_):
    rows = []
    for i in range(1000):  # 30 block responses a second, round robin over 20 bulbs, each relayed once
        dev = f"0x{0x4000 + i % 20:04x}"
        for k in range(2):
            rows.append(ota_row(2 * i + k + 1, T + i / 30 + k * 0.004, "0x0000", dev, i % 256, cmd__srv_tx__id="0x05",
                                status="0x00", file__offset=str((i // 20) * 64), data_size="64"))
    _, _, _, ota = ts_._digest(rows, "f", 1)
    assert sum(v[0] for v in ota.values()) == 1000


def test_ota_done_and_failed(ts_):
    rows = [ota_row(1, T, "0x5555", "0x0000", 50, cmd__srv_rx__id="0x06", status="0x00"),
            ota_row(2, T + 0.01, "0x5555", "0x0000", 50, cmd__srv_rx__id="0x06", status="0x00"),  # relayed
            ota_row(3, T + 5, "0x6666", "0x0000", 9, cmd__srv_rx__id="0x06", status="0x95")]
    events, _, _, _ = ts_._digest(rows, "f", 1)
    assert [(e["kind"], e["addr"]) for e in events] == [("ota_done", "0x5555"), ("ota_failed", "0x6666")]
    assert "aborted" in events[1]["detail"]


def test_link_status_costs(ts_):
    r = row(1, T, "0x1111", "0xfffc", 3, **{"zbee_nwk.cmd.id": "8", "zbee_nwk.cmd.link.address": "0x2222,0x3333",
                                             "zbee_nwk.cmd.link.incoming_cost": "1,3",
                                             "zbee_nwk.cmd.link.outgoing_cost": "2,7"})
    r2 = dict(r, **{"frame.number": "2", "frame.time_epoch": f"{T + 15:.6f}", "zbee_nwk.cmd.link.incoming_cost": "1,5"})
    _, cmds, links, _ = ts_._digest([r, r2], "f", 1)
    hour = int(T // 3600) * 3600
    assert links[(hour, "0x1111", "0x2222")] == [2, 2, 4, T + 15, 1, 2]
    assert links[(hour, "0x1111", "0x3333")] == [2, 8, 14, T + 15, 5, 7]
    assert cmds[(int(T // 60) * 60, "0x1111", "link_status")] == 2


def test_announce_event(ts_):
    r = row(1, T, "0x841a", "0xfffd", 77, **{"zbee_aps.zdp_cluster": "0x0013", "zbee_zdp.nwk_addr": "0x841a",
                                              "zbee_zdp.ext_addr": "00:12:4b:00:84:1a:b4:d6"})
    events, _, _, _ = ts_._digest([r, dict(r, **{"frame.number": "2"})], "f", 1)
    assert [(e["kind"], e["addr"], e["ieee"]) for e in events] == [("announce", "0x841a", "0x00124b00841ab4d6")]


def test_events_disabled_returns_empty(tmp_path):
    import asyncio
    t = tshark.Tshark(tmp_path, enabled=False)
    assert asyncio.run(t.events(tmp_path / "x.pcap", "x", 24, 24, 1, None)) == ([], {}, {}, {})


def test_missing_binary_gives_none_not_empty(tmp_path):
    """fields() must say "failed" (None), not "no frames" ([]), when tshark can't run."""
    import asyncio
    t = tshark.Tshark(tmp_path, enabled=True, binary=str(tmp_path / "no-such-tshark"))
    assert asyncio.run(t.fields(tmp_path / "x.pcap", ["frame.number"])) is None
    assert t.last_error
