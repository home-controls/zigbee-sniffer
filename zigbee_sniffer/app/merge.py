"""Several sniffers hear the same transmission: count it once, keep every sniffer's signal.

A copy is the same transmission when its bytes are identical and it was heard within the match
window of a copy from another sniffer that this sniffer hasn't matched yet (a MAC retry has
identical bytes too, but it is a second copy at the *same* sniffer, so it stays a transmission of
its own). Copies are remembered for MEMORY_S, longer than a bridge buffers frames, so a sniffer's
backlog after a Wi-Fi drop is matched against what the others delivered live. A copy that turns up
after its transmission went out still adds its signal.

When a transmission goes out (the watermark): each bridge sends its frames in the order it heard
them, its buffer first. So a transmission can go out once every sniffer has delivered frames past
its time, or can't have more: a live sniffer's copies arrive within HOLD_S. A sniffer that is
delivering its buffer, has gone quiet mid-stream (a stall) or has just dropped its connection
holds the others back until it has caught up (at most WAIT_S, and nothing waits longer than
MAX_HOLD_S after it arrived). Frames from a bridge update, a Wi-Fi drop or an app restart are
then written in time order, next to their ACKs, instead of seconds late.

Timing:

- Clock skew. Each sniffer times frames on its own bridge's clock (sniffers.py keeps each one
  close to ours), and what is left between two sniffers is measured from the copies that match:
  every sniffer's times are corrected toward the reference (first) sniffer's. Each sniffer's
  clock pairing also moves on its own (a few ms at a time); the correction moves with it
  (`offset_moved`), so copies stay lined up to well under a millisecond.
- The match window starts wide (WINDOW_S, while the skew is unknown) and narrows to a few times
  what matched copies actually differ by, once enough have been measured: under the ~1.7 ms a MAC
  retry needs, so a retry one sniffer heard stays apart from the original the other heard; only
  frames that ask for an ACK can be resent, so only they use it. A new connection starts wide
  again (its clock is paired afresh).
- Original and retry mixed up anyway (wide window, or a retry right behind its original): when the
  sniffer that heard both sends the retry and finds its original already sitting on the
  transmission at the retry's time, the two swap places (`_repair`).
- ACKs. A 3-byte ACK holds only a sequence number, so unrelated ACKs often share their bytes, and
  an ACK's copy from another sniffer can arrive before the frame it answers. So an ACK is paired
  with the frame that asked for it in the *same* sniffer's stream, timed from that frame's
  transmission, and merged with ACKs paired to the same transmission. A sniffer that heard the
  ACK but not its frame has nothing to pair it with: its copy matches the other copies by bytes,
  within the narrow window and ACK_WINDOW_S (it was written as a second ACK until 0.5.8, about a
  fifth of all ACKs with two sniffers).

After an app restart the memory is seeded from the end of the captures (`seed`), so a bridge's
backlog of frames from before the restart isn't written a second time.

With one sniffer there is nothing to match: frames go straight through, with no delay.
"""

import collections
import hashlib
import logging
import heapq
import itertools
import time

WINDOW_S = 0.25  # match window while the copies' timing is unknown
# A MAC retry starts at least ~1.7 ms after its original (the frame's airtime, macAckWaitDuration
# 864 us, CCA and turnaround), so once copies are seen to line up the window stays under that:
# 3 x p99 + WINDOW_SLACK_S, at least WINDOW_MIN_S (1.4 ms when copies line up within 0.3 ms).
WINDOW_MIN_S = 0.001
WINDOW_SLACK_S = 0.0005
RETRY_GAP_S = 0.0015  # closer than this, two copies of a frame that asks for an ACK can't be original + retry
LEARN_N = 30  # matched copies within LEARN_S needed to narrow the window
LEARN_S = 10.0
ACK_WINDOW_S = 0.01  # an ACK no frame of that sniffer asked for: only a near-certain match
HOLD_S = 0.4  # a live sniffer's copies arrive within this
CATCHUP_S = 1.0  # a frame this late (arrival - heard) comes from a bridge's buffer
STALL_S = 1.5  # a connected sniffer that sent nothing at all for this long has stalled
WAIT_S = 30.0  # how long the others wait for a stalled, catching-up or just-disconnected sniffer
MAX_HOLD_S = 60.0  # nothing waits longer than this after it arrived
MARGIN_S = 0.05  # a sniffer's times can step back this much (its clock pairing moves)
STEP_S = 0.001  # a clock-pairing move this big widens the match window again
MAX_SKEW_S = 300.0  # two sniffers' clocks can't be this far apart once paired: a correction past it is a bug, dropped

log = logging.getLogger("merge")
MEMORY_S = 1500
ACK_PAIR_S = 0.05  # an ACK comes within ~1 ms of the frame that asked for it (macAckWaitDuration)
SKEW_ALPHA = 0.05


def _frame_kind(psdu: bytes) -> tuple[int, bool, int | None]:
    """(MAC frame type, ACK requested, sequence number) from the first header bytes."""
    if len(psdu) < 3:
        return -1, False, None
    fc = psdu[0]
    return fc & 7, bool(fc & 0x20), psdu[2]


def frame_key(psdu: bytes) -> bytes:
    return hashlib.blake2b(psdu, digest_size=8).digest()


class Tx:
    """One transmission and the sniffers that heard it: copies = [(sniffer id, rssi, lqi)]."""

    __slots__ = ("ts", "channel", "psdu", "key", "copies", "at", "late", "src", "n", "arrived", "pending", "ref", "solo",
                 "raw")

    def __init__(self, ts, channel, psdu, key, copy, late, n=0, arrived=0.0):
        self.ts, self.channel, self.psdu, self.key = ts, channel, psdu, key
        self.copies = [copy] if copy else []
        self.at = {copy[0]: ts} if copy else {}  # sniffer -> its copy's (corrected) time
        self.late = late
        self.src = None  # set when emitted: the MAC source, if it is one of our devices
        self.n = n
        self.arrived = arrived
        self.pending = False
        self.ref = None  # set when emitted: (capture file, frame number)
        self.solo = None  # set when emitted: the one sniffer that heard it, if only one did
        self.raw = None  # an ACK: the key of its bytes alone (its own key may add the frame it answers)

    def heard_by(self, sid: str) -> bool:
        return any(c[0] == sid for c in self.copies)


class Merger:
    def __init__(self, emit, late_copy, several: bool, ref: str | None = None) -> None:
        self.emit = emit  # emit(tx): a new transmission, in time order
        self.late_copy = late_copy  # late_copy(tx, sniffer id, rssi, lqi): one more sniffer heard it
        self.several = several
        self.ref = ref  # the sniffer whose clock the others are corrected to
        self._pending: list = []  # heap of (ts, n, tx)
        self._pending_by_key: dict[bytes, list[Tx]] = {}
        self._recent: dict[bytes, list[Tx]] = {}
        self._recent_q: collections.deque = collections.deque()  # (time remembered, tx)
        self._acks: dict[bytes, list[Tx]] = {}  # ACK transmissions by their bytes alone, pending and remembered
        self._arrivals: collections.deque = collections.deque()  # (arrival, tx) of pending transmissions
        self._n = itertools.count(1)
        self._asked: dict[str, tuple[int, Tx, float]] = {}  # sniffer -> (seq, tx, its time) of its last frame asking for an ACK
        self._links: dict[str, dict] = {}  # sniffer -> {"up", "since", "mark", "lag", "last"}
        self._resid: collections.deque = collections.deque(maxlen=4000)  # (arrival, sniffer, |time difference|)
        self._win, self._win_at = WINDOW_S, 0.0
        self.skew: dict[str, float] = {}  # sniffer -> seconds its times run ahead of the reference sniffer's
        self.matched = 0  # copies matched to a transmission another sniffer heard
        self.repaired = 0  # originals taken back off a MAC retry they had been matched to (_repair)
        self.waiting: tuple[str, float] | None = None  # (sniffer, seconds behind) holding the others back
        self.seeded = 0

    # ------------------------------------------------------------ the sniffers' links

    def _link(self, sid: str) -> dict:
        lk = self._links.get(sid)
        if lk is None:  # up=None: not told about its connection, so never waited for
            lk = self._links[sid] = {"up": None, "since": 0.0, "mark": None, "lag": 0.0, "last": 0.0}
        return lk

    def link(self, sid: str, up: bool, now: float | None = None) -> None:
        """A sniffer's connection opened or closed. A new connection pairs its clock afresh, so the
        match window starts wide again."""
        now = now or time.time()
        lk = self._link(sid)
        lk["up"], lk["since"], lk["last"] = up, now, now
        if up:
            self._resid.clear()
            self._win, self._win_at = WINDOW_S, 0.0
            self._asked.pop(sid, None)

    def heard(self, sid: str, now: float | None = None) -> None:
        """Something (a frame or a status) came from this sniffer: it isn't stalled."""
        self._link(sid)["last"] = now or time.time()

    def _cutoff(self, now: float) -> float:
        """Transmissions up to this time can go out: no sniffer can still deliver a copy of them."""
        cut, who = now - HOLD_S, None
        for sid, lk in self._links.items():
            if lk["mark"] is None or lk["up"] is None:
                continue
            if lk["up"]:
                quiet = now - lk["last"]
                if quiet > STALL_S:  # connected, but nothing at all for a while: its frames are held up
                    if quiet > WAIT_S:
                        continue
                elif lk["lag"] <= CATCHUP_S:  # live
                    continue
                # (otherwise it is delivering its buffer)
            elif now - lk["since"] > WAIT_S:
                continue
            w = lk["mark"] - MARGIN_S
            if w < cut:
                cut, who = w, sid
        while self._arrivals and self._arrivals[0][0] < now - MAX_HOLD_S:
            _, tx = self._arrivals.popleft()
            if tx.pending and tx.ts > cut:
                cut = tx.ts
        self.waiting = (who, round(now - cut, 1)) if who and now - cut > HOLD_S + 0.5 else None
        return cut

    # ------------------------------------------------------------ timing

    def offset_moved(self, sid: str, delta: float) -> None:
        """A sniffer's clock pairing moved by `delta` (its frames' times move by as much: a step when a
        faster frame shows the pairing was late, a creep while none does). Each sniffer's pairing
        moves on its own, a few ms at a time, so move the correction with it: copies then stay lined
        up to the microsecond and the match window can stay narrow. The reference sniffer's move
        carries the others along (everyone keeps to its timeline)."""
        if not self.several or not delta:
            return
        if abs(delta) > STEP_S:
            # A real step (not the creep): frames already waiting are on the old timeline, so for a
            # moment their copies can be that far apart. Match wide until it is measured again.
            self._resid.clear()
            self._win, self._win_at = WINDOW_S, 0.0
        # Only a correction already learned from matched copies moves. A sniffer with none yet has
        # nothing to keep lined up: its frames simply carry the new times, and matching learns it.
        # (0.6.0-0.6.1 made one up from the move: a USB sniffer whose first pairing was late by the
        # app's startup, or by a minute of frames the radio kept, got that as a "correction", and
        # with it nothing it heard ever matched.)
        if sid == self.ref:
            for s in list(self.skew):
                if s != self.ref:
                    self.skew[s] -= delta
                    self._sane(s)
        elif sid in self.skew:
            self.skew[sid] += delta
            self._sane(sid)

    def clock_restarted(self, sid: str) -> None:
        """A sniffer's bridge restarted: its clock started over and was paired afresh, so what its
        correction had learned no longer applies; learn it again (wide window meanwhile). The
        reference's restart leaves the others' corrections: they are to its timeline, which the new
        pairing keeps (to within a few ms)."""
        if not self.several:
            return
        if sid != self.ref:
            self.skew.pop(sid, None)
        self._resid.clear()
        self._win, self._win_at = WINDOW_S, 0.0

    def _sane(self, sid: str) -> None:
        """A correction of minutes is no correction: the sniffers are in one house, their clocks paired
        to ours. Drop it and learn it again rather than file every frame that far off."""
        s = self.skew.get(sid)
        if s is not None and abs(s) > MAX_SKEW_S:
            log.warning("The timing correction for %s reached %.0f s, which can't be right: starting it again", sid, s)
            self.skew.pop(sid, None)
            self._resid.clear()
            self._win, self._win_at = WINDOW_S, 0.0

    def skew_ms(self, sid: str) -> float | None:
        s = self.skew.get(sid)
        return round(s * 1000, 1) if s is not None else None

    def window(self, now: float) -> float:
        """The match window: a few times what matched copies differ by, once that is known."""
        if now - self._win_at < 1.0:
            return self._win
        recent = sorted(r for t, _, r in self._resid if now - t <= LEARN_S)
        if len(recent) < LEARN_N:
            w = WINDOW_S
        else:
            p99 = recent[int(0.99 * (len(recent) - 1))]
            w = min(WINDOW_S, max(WINDOW_MIN_S, 3 * p99 + WINDOW_SLACK_S))
        self._win, self._win_at = w, now
        return w

    def match_stats(self) -> dict:
        """How closely copies from different sniffers line up (per sniffer: the copies it matched
        to a transmission another sniffer heard first), and the match window in use."""
        by: dict[str, list[float]] = {}
        for _, sid, r in self._resid:
            by.setdefault(sid, []).append(r)
        out = {}
        for sid, rs in by.items():
            rs.sort()
            out[sid] = {"n": len(rs), "p50_ms": round(rs[len(rs) // 2] * 1000, 2),
                        "p95_ms": round(rs[int(0.95 * (len(rs) - 1))] * 1000, 2)}
        return {"window_ms": round(self._win * 1000, 1), "by_sniffer": out}

    def _learn_skew(self, sid: str, ts: float, tx: Tx) -> None:
        """A copy from `sid` (at corrected time ts) matched a transmission first heard by another
        sniffer: nudge the non-reference sniffer's correction by what is left between them."""
        first = tx.copies[0][0]
        r = max(-WINDOW_S, min(WINDOW_S, ts - tx.ts))
        if sid != self.ref:
            self.skew[sid] = self.skew.get(sid, 0.0) + SKEW_ALPHA * r
            self._sane(sid)
        elif first != self.ref:
            self.skew[first] = self.skew.get(first, 0.0) - SKEW_ALPHA * r
            self._sane(first)

    def _match(self, key: bytes, ts: float, sid: str, window: float):
        """The nearest transmission with these bytes that this sniffer hasn't heard yet (nearest, not
        first: when one sniffer heard only a MAC retry, its copy belongs to the retry)."""
        return self._nearest((self._pending_by_key.get(key, ()), self._recent.get(key, ())), ts, sid, window)

    @staticmethod
    def _nearest(groups, ts: float, sid: str, window: float):
        best, gap = None, window
        for txs in groups:
            for tx in txs:
                d = abs(tx.ts - ts)
                if d <= gap and not tx.heard_by(sid):
                    best, gap = tx, d
        return best, bool(best and best.pending)

    # ------------------------------------------------------------ frames

    def add(self, sid: str, ts: float, channel: int, rssi: int, lqi: int, psdu: bytes, late: bool,
            arrival: float | None = None) -> None:
        if not self.several:
            self.emit(Tx(ts, channel, psdu, b"", (sid, rssi, lqi), late))
            return
        arrival = arrival or time.time()
        ts -= self.skew.get(sid, 0.0)
        lk = self._link(sid)
        lk["mark"] = ts if lk["mark"] is None else max(lk["mark"], ts)
        lk["lag"], lk["last"] = arrival - ts, arrival
        ftype, ack_req, seq = _frame_kind(psdu)
        key, window, paired = frame_key(psdu), WINDOW_S, False
        raw = key
        if ftype == 2:  # an ACK: pair it with the frame this sniffer heard ask for it
            asked = self._asked.pop(sid, None)
            if asked and asked[0] == seq and 0 <= ts - asked[2] <= ACK_PAIR_S:
                data = asked[1]
                ts = data.ts + (ts - asked[2])  # after its frame on the merged timeline, whoever heard what first
                key += data.n.to_bytes(8, "little")
                paired = True
            else:
                window = min(self.window(arrival), ACK_WINDOW_S)
        elif ack_req:  # a MAC retry of it can follow within a few ms: as narrow as the timing allows
            window = self.window(arrival)
        # (a frame that asks for no ACK is never resent at the MAC layer: the wide window can't mix it up)
        tx, waiting = self._match(key, ts, sid, window)
        if tx is None and ftype == 2:
            # One sniffer heard the frame and its ACK, the other only the ACK: one copy is paired, the
            # other isn't, so their keys differ. Same bytes within a few ms is the same ACK (another
            # ACK with the same sequence number that close is rare), so match on the bytes too.
            tx, waiting = self._nearest((self._acks.get(raw, ()),), ts, sid, min(self.window(arrival), ACK_WINDOW_S))
        if tx is not None:
            if not paired and not late and tx.copies:
                r = abs(ts - tx.ts)
                self._resid.append((arrival, sid, r))
                # Learn only from copies that line up within the window in use: a wrong match (two
                # identical frames tens of ms apart, under the wide window) would knock the
                # correction off by a few ms. A real timing jump still shows: the wide-window
                # matches' differences widen the window within a second, and then it is learned.
                if r <= self._win:
                    self._learn_skew(sid, ts, tx)
            tx.copies.append((sid, rssi, lqi))
            tx.at[sid] = ts
            self.matched += 1
            if not waiting:
                self.late_copy(tx, sid, rssi, lqi)
        else:
            tx = self._repair(key, ts, sid, rssi, lqi, arrival) if ack_req and ftype in (1, 3) else None
            if tx is None:
                tx = self._new(ts, channel, psdu, key, (sid, rssi, lqi), late, arrival, raw if ftype == 2 else None)
        if ack_req and ftype in (1, 3) and seq is not None:
            self._asked[sid] = (seq, tx, ts)

    def _new(self, ts, channel, psdu, key, copy, late, arrival, raw=None) -> Tx:
        tx = Tx(ts, channel, psdu, key, copy, late, next(self._n), arrival)
        tx.pending = True
        heapq.heappush(self._pending, (ts, tx.n, tx))
        self._pending_by_key.setdefault(key, []).append(tx)
        self._arrivals.append((arrival, tx))
        if raw is not None:
            self._index_ack(tx, raw)
        return tx

    def _index_ack(self, tx: Tx, raw: bytes) -> None:
        """ACKs by their bytes alone, paired or not (pending and remembered, like the keys)."""
        tx.raw = raw
        self._acks.setdefault(raw, []).append(tx)

    def _repair(self, key: bytes, ts: float, sid: str, rssi: int, lqi: int, arrival: float) -> Tx | None:
        """`sid` sent a copy that no waiting transmission can take, because the one at its time already
        has a copy from `sid` - one that sits a retry's gap away from it. Then that earlier copy was an
        original, matched to the MAC retry another sniffer heard alone (that sniffer's copy came in
        first, and the window couldn't tell them apart). This copy is the retry's: it takes the earlier
        copy's place, and the original becomes a transmission of its own, at its own time."""
        for tx in self._pending_by_key.get(key, ()):
            mine = tx.at.get(sid)
            if mine is None or len(tx.copies) < 2 or abs(mine - tx.ts) - abs(ts - tx.ts) < RETRY_GAP_S:
                continue
            i = next(i for i, c in enumerate(tx.copies) if c[0] == sid)
            original = tx.copies[i]
            tx.copies[i] = (sid, rssi, lqi)
            tx.at[sid] = ts
            self._new(mine, tx.channel, tx.psdu, key, original, tx.late, arrival)
            self.repaired += 1
            return tx
        return None

    def release(self, now: float | None = None) -> None:
        """Send out the transmissions no sniffer can still add a copy to, in time order."""
        if not self.several:
            return
        now = now or time.time()
        cutoff = self._cutoff(now)
        while self._pending and (self._pending[0][0] <= cutoff or len(self._pending) > 50000):
            _, _, tx = heapq.heappop(self._pending)
            waiting = self._pending_by_key[tx.key]
            waiting.remove(tx)
            if not waiting:
                del self._pending_by_key[tx.key]
            tx.pending = False
            self.emit(tx)
            tx.psdu = b""  # matching needs only the key and the time from here on
            self._remember(tx, now)
        while self._recent_q and self._recent_q[0][0] < now - MEMORY_S:
            _, tx = self._recent_q.popleft()
            for index, k in ((self._recent, tx.key), (self._acks, tx.raw)):
                kept = index.get(k) if k is not None else None
                if kept:
                    try:
                        kept.remove(tx)
                    except ValueError:
                        pass
                    if not kept:
                        del index[k]

    def _remember(self, tx: Tx, at: float) -> None:
        self._recent.setdefault(tx.key, []).append(tx)
        self._recent_q.append((at, tx))

    def seed(self, records, now: float | None = None) -> int:
        """Remember transmissions already written (the end of the captures, after a restart):
        records = (time, psdu, (file, frame number)) in file order. A bridge's backlog from before
        the restart then matches them instead of being written again. Which sniffers heard them
        isn't known, so a copy from any sniffer matches."""
        if not self.several:
            return 0
        now = now or time.time()
        asked: tuple[int, Tx, float] | None = None
        rows = []
        for ts, psdu, ref in records:
            if ts < now - MEMORY_S:
                continue
            ftype, ack_req, seq = _frame_kind(psdu)
            key = raw = frame_key(psdu)
            if ftype == 2 and asked and asked[0] == seq and 0 <= ts - asked[2] <= ACK_PAIR_S:
                key += asked[1].n.to_bytes(8, "little")
            tx = Tx(ts, 0, b"", key, None, True, next(self._n))
            tx.ref = ref
            if ftype == 2:
                self._index_ack(tx, raw)
            rows.append(tx)
            asked = (seq, tx, ts) if ack_req and ftype in (1, 3) and seq is not None else None
        rows.sort(key=lambda t: t.ts)
        for tx in rows:
            self._remember(tx, tx.ts)  # forgotten MEMORY_S after it was heard
        self.seeded += len(rows)
        return len(rows)

    def status(self) -> dict:
        return {"waiting_for": self.waiting[0] if self.waiting else None,
                "behind_s": self.waiting[1] if self.waiting else None,
                "window_ms": round(self._win * 1000, 1), "pending": len(self._pending), "seeded": self.seeded,
                "repaired": self.repaired}
