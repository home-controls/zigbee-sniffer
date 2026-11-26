
import merge
from zbs_helpers import ack, mac_data, nwk


class Sink:
    def __init__(self) -> None:
        self.emitted: list[merge.Tx] = []
        self.late: list[tuple] = []

    def emit(self, tx):
        self.emitted.append(tx)

    def late_copy(self, tx, sid, rssi, lqi):
        self.late.append((tx, sid, rssi, lqi))


def merger(several=True, ref="a"):
    s = Sink()
    return merge.Merger(s.emit, s.late_copy, several=several, ref=ref), s


def data(seq=5, src=0x1111, dst=0x2222, body=b"payload"):
    return mac_data(src, dst, seq, nwk(src, 0x0000, seq, body))


def test_single_sniffer_passes_straight_through():
    m, s = merger(several=False)
    f = data()
    m.add("main", 10.0, 25, -60, 200, f, False)
    assert len(s.emitted) == 1
    tx = s.emitted[0]
    assert tx.ts == 10.0 and tx.psdu == f and tx.copies == [("main", -60, 200)]
    m.release(now=1e9)
    assert len(s.emitted) == 1


def test_two_sniffers_copies_merge():
    m, s = merger()
    f = data()
    m.add("a", 100.0, 25, -70, 150, f, False)
    m.add("b", 100.02, 25, -55, 220, f, False)
    m.release(now=100.1)  # still waiting for copies
    assert s.emitted == []
    m.release(now=101.0)
    assert len(s.emitted) == 1
    assert {c[0] for c in s.emitted[0].copies} == {"a", "b"}
    assert m.matched == 1
    assert s.emitted[0].psdu == b""  # dropped once emitted: matching needs only the key


def test_mac_retry_at_same_sniffer_stays_separate():
    m, s = merger()
    f = data()
    m.add("a", 10.0, 25, -60, 200, f, False)
    m.add("a", 10.004, 25, -60, 200, f, False)  # the same bytes again: a MAC retry
    m.add("b", 10.001, 25, -50, 200, f, False)  # the other sniffer's copy of one of them
    m.release(now=20.0)
    assert len(s.emitted) == 2
    assert sum(len(tx.copies) for tx in s.emitted) == 3


def test_late_copy_after_release():
    m, s = merger()
    f = data()
    m.add("a", 10.0, 25, -60, 200, f, False)
    m.release(now=11.0)
    assert len(s.emitted) == 1
    m.add("b", 10.05, 25, -48, 230, f, True)  # from b's backlog after a Wi-Fi drop
    m.release(now=12.0)
    assert len(s.emitted) == 1
    assert len(s.late) == 1 and s.late[0][1:] == ("b", -48, 230)
    assert {c[0] for c in s.emitted[0].copies} == {"a", "b"}


def test_ack_paired_and_after_its_frame_when_other_sniffers_ack_copy_comes_first():
    """b's clock is 3 ms behind a's. a's copy of the data frame comes first (so the transmission
    has a's time), then b's data and b's ACK, then a's ACK. Unpaired, b's ACK (99.9985) would sort
    before the data (100.000)."""
    m, s = merger()
    f, a_ = data(seq=5), ack(5)
    m.add("a", 100.000, 25, -60, 200, f, False)
    m.add("b", 99.997, 25, -70, 180, f, False)
    m.add("b", 99.9985, 25, -71, 180, a_, False)
    m.add("a", 100.0015, 25, -62, 200, a_, False)
    m.release(now=200.0)
    assert len(s.emitted) == 2  # one data frame, one ACK
    first, second = s.emitted
    assert first.key == merge.frame_key(f)  # the data frame goes out first
    assert len(first.copies) == 2 and len(second.copies) == 2  # one data, one ACK: each heard by both
    assert first.ts < second.ts  # the ACK comes after the frame it answers
    assert second.ts - first.ts < 0.01


def test_unpaired_acks_from_different_exchanges_do_not_merge():
    m, s = merger()
    m.add("a", 50.000, 25, -60, 200, ack(9), False)
    m.add("b", 50.100, 25, -60, 200, ack(9), False)  # same 3 bytes, 100 ms later: another exchange
    m.release(now=60.0)
    assert len(s.emitted) == 2


def test_unpaired_acks_within_10ms_merge():
    m, s = merger()
    m.add("a", 50.000, 25, -60, 200, ack(9), False)
    m.add("b", 50.004, 25, -60, 200, ack(9), False)
    m.release(now=60.0)
    assert len(s.emitted) == 1 and len(s.emitted[0].copies) == 2


def test_acks_paired_to_different_frames_do_not_merge():
    """a hears 0x1111's frame (seq 9) and its ACK; b hears 0x3333's frame (also seq 9) and its ACK
    60 ms later. The two ACKs are byte-identical but answer different transmissions."""
    m, s = merger()
    fx, fy = data(seq=9, src=0x1111), data(seq=9, src=0x3333)
    m.add("a", 50.000, 25, -60, 200, fx, False)
    m.add("a", 50.001, 25, -60, 200, ack(9), False)
    m.add("b", 50.060, 25, -60, 200, fy, False)
    m.add("b", 50.061, 25, -60, 200, ack(9), False)
    m.release(now=60.0)
    assert len(s.emitted) == 4
    assert all(len(tx.copies) == 1 for tx in s.emitted)


def test_skew_learning_converges():
    m, s = merger(ref="a")
    for i in range(300):
        f = data(seq=i % 256, body=i.to_bytes(4, "little"))  # every frame unique
        t = 1000.0 + i * 0.5
        if i % 2:
            m.add("a", t, 25, -60, 200, f, False)
            m.add("b", t + 0.080, 25, -60, 200, f, False)
        else:  # b's copy first: the correction is learned the other way round
            m.add("b", t + 0.080, 25, -60, 200, f, False)
            m.add("a", t, 25, -60, 200, f, False)
        m.release(now=t + 1.0)
    assert m.skew_ms("a") is None  # the reference keeps its own clock
    assert abs(m.skew_ms("b") - 80.0) < 2.0
    assert len(s.emitted) == 300
    assert all(len(tx.copies) == 2 for tx in s.emitted)


def test_skew_correction_lets_far_apart_copies_match():
    """Once learned, b's times are corrected: copies 200 ms apart on the raw clocks (close to the
    0.25 s window) still match, and the merged time is a's."""
    m, s = merger(ref="a")
    for i in range(200):
        f = data(seq=i % 256, body=b"w" + i.to_bytes(4, "little"))
        t = 2000.0 + i
        m.add("a", t, 25, -60, 200, f, False)
        m.add("b", t + 0.2, 25, -60, 200, f, False)
        m.release(now=t + 1.0)
    f = data(seq=1, body=b"last")
    m.add("b", 3000.2, 25, -60, 200, f, False)  # b first, with its raw clock
    m.add("a", 3000.0, 25, -60, 200, f, False)
    m.release(now=3002.0)
    last = s.emitted[-1]
    assert len(last.copies) == 2
    assert abs(last.ts - 3000.0) < 0.01


def test_copy_matches_the_nearest_identical_transmission():
    m, s = merger()
    f = data(seq=5)
    m.add("a", 10.000, 25, -60, 200, f, False)  # a: the original (no ACK came)...
    m.add("a", 10.020, 25, -60, 200, f, False)  # ...and its retry
    m.add("b", 10.020, 25, -70, 200, f, False)  # b heard only the retry
    m.add("a", 10.021, 25, -60, 200, ack(5), False)
    m.add("b", 10.021, 25, -70, 200, ack(5), False)
    m.release(now=20.0)
    assert len(s.emitted) == 3  # original, retry, one ACK
    original, retry, ack_tx = s.emitted
    assert [c[0] for c in original.copies] == ["a"]
    assert {c[0] for c in retry.copies} == {"a", "b"} and {c[0] for c in ack_tx.copies} == {"a", "b"}


def test_late_copies_do_not_teach_skew():
    m, s = merger(ref="a")
    f = data()
    m.add("a", 10.0, 25, -60, 200, f, False)
    m.add("b", 10.2, 25, -60, 200, f, True)  # a backlog frame
    assert m.skew_ms("b") is None
