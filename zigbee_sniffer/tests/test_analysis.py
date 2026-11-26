
import analysis as an_mod
from analysis import Analyzer
from zbs_helpers import PAN, ack, mac_cmd, mac_data, nwk

T0 = 1_800_000_000.0  # on a minute and hour boundary
MIN, HOUR = int(T0 // 60) * 60, int(T0 // 3600) * 3600


def test_retry_noack_and_link_counters():
    a = Analyzer(PAN)
    f = mac_data(0x1111, 0x2222, 5, nwk(0x1111, 0x0000, 77))
    a.feed(T0, -60, 200, f)
    info = a.feed(T0 + 0.03, -61, 200, f)  # no ACK came: sent again
    assert info["retry"] is True
    a.feed(T0 + 0.031, -55, 220, ack(5))  # this time it was acknowledged
    b = a.batch
    src, dst = b.dev[(MIN, "0x1111")], b.dev[(MIN, "0x2222")]
    assert src[an_mod.UNI] == 2 and src[an_mod.RETRY] == 1 and src[an_mod.TX] == 2
    assert dst[an_mod.RX] == 2 and dst[an_mod.NOACK] == 1
    assert b.link[(HOUR, "0x1111", "0x2222")] == [2, 1, 1]  # [unicast, resent, no ACK]
    net = b.net[MIN]
    assert net[an_mod.N_UNI] == 2 and net[an_mod.N_RETRY] == 1 and net[an_mod.N_NOACK] == 1
    assert net[an_mod.N_OURS] == 3  # the ACK took the PAN of the frame it answers
    assert src[an_mod.MSGS] == 1  # one NWK message, however often it was sent


def test_same_seq_after_the_retry_window_is_not_a_retry():
    a = Analyzer(PAN)
    f = mac_data(0x1111, 0x2222, 5)
    a.feed(T0, -60, 200, f)
    a.feed(T0 + 0.001, -60, 200, ack(5))
    assert a.feed(T0 + 5.0, -60, 200, f)["retry"] is False


def test_link_counters_per_receiver():
    a = Analyzer(PAN)
    for i, dst in enumerate((0x2222, 0x2222, 0x3333)):
        a.feed(T0 + i, -60, 200, mac_data(0x1111, dst, i))
        a.feed(T0 + i + 0.001, -60, 200, ack(i))
    assert a.batch.link[(HOUR, "0x1111", "0x2222")] == [2, 0, 0]
    assert a.batch.link[(HOUR, "0x1111", "0x3333")] == [1, 0, 0]


def test_relayed_message_counts_once_and_marks_msg_seen():
    a = Analyzer(PAN)
    hop1 = mac_data(0x5555, 0x7777, 10, nwk(0x5555, 0x0000, 42))  # end device -> its parent
    hop2 = mac_data(0x7777, 0x0000, 3, nwk(0x5555, 0x0000, 42, radius=29))  # parent relays it
    a.feed(T0, -80, 100, hop1)
    a.feed(T0 + 0.001, -80, 100, ack(10))
    a.feed(T0 + 0.01, -50, 220, hop2)
    a.feed(T0 + 0.011, -50, 220, ack(3))
    b = a.batch
    assert b.dev[(MIN, "0x5555")][an_mod.MSGS] == 1
    assert b.dev[(MIN, "0x7777")][an_mod.RELAY] == 1
    assert b.msg_seen["0x5555"] == T0 + 0.01
    assert (HOUR, "0x7777", "0x0000", "0x5555", "0x0000") in b.hops


def test_other_networks_and_scans():
    a = Analyzer(PAN)
    a.feed(T0, -80, 100, mac_data(0x1A01, 0x0000, 1, b"x" * 20, pan=0x551B))
    beacon_req = bytes([0x03, 0x08, 0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0x07])
    a.feed(T0 + 1, -80, 100, beacon_req)
    net = a.batch.net[MIN]
    assert net[an_mod.N_OTHERS] == 1 and net[an_mod.N_UNNAMED] == 1 and net[an_mod.N_SCANS] == 1
    assert net[an_mod.N_OURS] == 0
    assert not any(addr == "0x1a01" for _, addr in a.batch.dev)


def test_poll_counted():
    a = Analyzer(PAN)
    a.feed(T0, -70, 150, mac_cmd(0x5555, 0x7777, 9, 4))
    assert a.batch.dev[(MIN, "0x5555")][an_mod.POLL] == 1


def test_address_change_needs_confirmation():
    a = Analyzer(PAN)
    ieee = "00124b0001020304"
    a.seed_addresses([("0x1234", "0x" + ieee)])
    for i in range(an_mod.ADDRESS_CONFIRM):
        a.feed(T0 + i, -60, 200, mac_data(0x4321, 0xFFFF, i, nwk(0x4321, 0xFFFD, i, src64=ieee), ack=False))
        kinds = [e["kind"] for e in a.batch.events]
        assert ("address_change" in kinds) == (i == an_mod.ADDRESS_CONFIRM - 1)
    ev = a.batch.events[-1]
    assert ev["addr"] == "0x4321" and ev["other"] == "0x1234" and ev["ieee"] == "0x" + ieee


def test_pruning_stays_bounded_with_many_keys():
    """Every frame a new (src, dst, seq) and NWK (src, seq): the memories keep only their windows
    (10 s for resends, 30 s for messages), however many keys go by."""
    a = Analyzer(PAN)
    n, fps = 60000, 150.0
    for i in range(n):
        src, dst = 0x0100 + i % 97, 0x0200 + (i // 97) % 89
        f = mac_data(src, dst, i % 256, nwk(src, 0x0000, (i // 7) % 256, b"z" * 6))
        a.feed(T0 + i / fps, -60, 200, f)
    assert len(a._recent) <= 10 * fps + 2
    assert len(a._recent_q) <= 10 * fps + 2
    assert len(a._msgs) <= 30 * fps + 2
    assert len(a._msgs_q) <= 30 * fps + 2


def test_take_hands_over_the_batch():
    a = Analyzer(PAN)
    a.feed(T0, -60, 200, mac_data(0x1111, 0x2222, 1))
    b = a.take()
    assert b and b.dev
    assert not a.batch


def test_messages_counted_when_a_source_wraps_its_nwk_seq_quickly():
    a = Analyzer(PAN)
    for i in range(1000):  # the coordinator sends 30 messages a second (image blocks to 20 bulbs)
        t = T0 + i / 30
        a.feed(t, -50, 220, mac_data(0x0000, 0x1000 + i % 5, i % 256, nwk(0x0000, 0x4000 + i % 20, i % 256)))
        a.feed(t + 0.001, -60, 200, ack(i % 256))
        a.feed(t + 0.005, -60, 200, mac_data(0x1000 + i % 5, 0x4000 + i % 20, (i + 7) % 256,
                                              nwk(0x0000, 0x4000 + i % 20, i % 256, radius=29)))  # relayed: not again
        a.feed(t + 0.006, -60, 200, ack((i + 7) % 256))
    msgs = sum(r[an_mod.MSGS] for (_, addr), r in a.batch.dev.items() if addr == "0x0000")
    assert msgs == 1000


def test_each_sniffers_signal_is_kept():
    a = Analyzer(PAN)
    a.feed(T0, -60, 200, mac_data(0x1111, 0x0000, 1), copies=[("main", -60, 200), ("up", -78, 120)])
    a.feed(T0 + 1, -58, 200, mac_data(0x1111, 0x0000, 2), copies=[("main", -58, 205)])
    a.sniffer_rssi(T0 + 2, "0x1111", "up", -80)  # a copy that turned up after the frame was counted
    assert a.batch.sniff[(MIN, "0x1111", "main")] == [2, -118, -60, -58]
    assert a.batch.sniff[(MIN, "0x1111", "up")] == [2, -158, -80, -78]
