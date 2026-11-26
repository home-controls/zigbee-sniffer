"""What each frame says about the network, read from the clear headers (no key needed).

One Analyzer runs on the live stream, and the same code replays stored captures, so the
history is the same whichever way a frame came in. Per minute and device it counts:

- tx       frames the device transmitted over the air (these carry the RSSI/LQI the sniffer saw)
- uni      unicast frames it sent that asked for an ACK (retries included)
- retry    MAC retransmissions: the same frame sent again because no ACK came back
- relay    frames it forwarded for another device (NWK source is not the MAC sender)
- poll     data requests (a sleepy end device asking its parent for waiting messages)
- msgs     NWK messages it originated, heard at any hop (so also devices the sniffer can't hear)
- rx       unicast frames sent to it over the air that asked for an ACK
- noack    of those, how many had no ACK heard (it didn't get them - or the sniffer missed the ACK)
- air      airtime its transmissions used, in microseconds

and per hour, the hops: which device handed frames to which, for whom (NWK source and
destination), and per link (MAC sender -> receiver) the unicast frames, resends and missing
ACKs, so a device's resends can be pinned on one neighbour. MAC commands also give events:
association (a device joining), orphan notifications (an end device that lost its parent) and
short-address changes. Events inside encrypted NWK commands (leave, rejoin, route errors) come
from the tshark pass (tshark.py).
"""

import collections

import mac

AIR_OVERHEAD = 8  # bytes on air besides the PSDU: preamble 4, SFD 1, PHR 1, the FCS 2 the radio strips
US_PER_BYTE = 32  # 250 kbit/s
ACK_WINDOW_S = 0.02
RETRY_WINDOW_S = 1.0
MSG_WINDOW_S = 5.0  # relays of one message arrive within about a second; the NWK seq wraps every 256 messages
ADDRESS_CONFIRM = 3  # frames that must agree before a short<->IEEE change is believed (one bad frame isn't enough)
BROADCAST = {"0xffff", "0xfffd", "0xfffc", "0xfffb"}

DEV_FIELDS = ("tx", "rssi_sum", "rssi_min", "rssi_max", "lqi_sum", "uni", "retry", "relay", "poll", "msgs",
              "rx", "noack", "air")
NET_FIELDS = ("ours", "others", "unnamed", "air_ours", "air_all", "uni", "retry", "noack", "bcast", "scans",
              "dropped")
(TX, RSSI_SUM, RSSI_MIN, RSSI_MAX, LQI_SUM, UNI, RETRY, RELAY, POLL, MSGS, RX, NOACK, AIR) = range(len(DEV_FIELDS))
(N_OURS, N_OTHERS, N_UNNAMED, N_AIR_OURS, N_AIR_ALL, N_UNI, N_RETRY, N_NOACK, N_BCAST, N_SCANS,
 N_DROPPED) = range(len(NET_FIELDS))


def unicast(addr: str | None) -> bool:
    return bool(addr) and addr not in BROADCAST


class Batch:
    """Counters gathered since the last write to the history."""

    def __init__(self) -> None:
        self.dev: dict[tuple[int, str], list] = {}  # (minute, addr) -> DEV_FIELDS
        self.net: dict[int, list] = {}  # minute -> NET_FIELDS
        self.hops: dict[tuple[int, str, str, str, str], list] = {}  # (hour, mac src, mac dst, nwk src, nwk dst) -> [n, rssi sum]
        self.seen: dict[str, tuple[float, int, int]] = {}  # addr -> (last heard, rssi, lqi)
        self.ieee: dict[tuple[str, str], list] = {}  # (short, ieee) -> [first, last]
        self.events: list[dict] = []
        self.files: dict[str, tuple[int, int]] = {}  # capture file -> (bytes analyzed, frames analyzed)
        self.sniff: dict[tuple[int, str, str], list] = {}  # (minute, addr, sniffer) -> [n, rssi sum, min, max]
        self.link: dict[tuple[int, str, str], list] = {}  # (hour, mac src, mac dst) -> [unicast, resent, no ACK]
        self.msg_seen: dict[str, float] = {}  # addr -> last NWK message it originated (heard at any hop)

    def __bool__(self) -> bool:
        return bool(self.dev or self.net or self.events or self.files or self.sniff or self.link or self.msg_seen)

    def link_rec(self, hour: int, src: str, dst: str) -> list:
        r = self.link.get((hour, src, dst))
        if r is None:
            r = self.link[(hour, src, dst)] = [0, 0, 0]
        return r

    def dev_rec(self, minute: int, addr: str) -> list:
        r = self.dev.get((minute, addr))
        if r is None:
            r = self.dev[(minute, addr)] = [0, 0, None, None, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        return r

    def net_rec(self, minute: int) -> list:
        r = self.net.get(minute)
        if r is None:
            r = self.net[minute] = [0] * len(NET_FIELDS)
        return r


class Analyzer:
    def __init__(self, our_pan: int | None) -> None:
        self.pans = mac.PanTracker(our_pan)
        self.batch = Batch()
        self.our_ieee: set[str] = set()  # our devices' IEEE addresses (an orphan notification names no PAN)
        self._recent: dict[tuple, float] = {}  # (src, dst, seq) -> ts, to spot retransmissions
        self._msgs: dict[tuple, float] = {}  # (nwk src, nwk seq) -> ts, to count each message once
        self._recent_q: collections.deque = collections.deque()  # (ts, key) in arrival order, for pruning
        self._msgs_q: collections.deque = collections.deque()
        self._await: tuple | None = None  # (dst, seq, ts, minute, src) of the last frame waiting for an ACK
        self._ieee: dict[str, str] = {}  # short -> IEEE, as last heard
        self._short: dict[str, str] = {}  # IEEE -> short
        self._claims: dict[tuple[str, str], int] = {}  # (short, IEEE) heard but not yet believed -> frames

    def take(self) -> Batch:
        b, self.batch = self.batch, Batch()
        return b

    def seed_addresses(self, pairs) -> None:
        """Known (short, IEEE) pairs, so an address change after a restart is still noticed."""
        for short, ieee in pairs:
            self._ieee[short] = ieee
            self._short[ieee] = short

    def sniffer_rssi(self, ts: float, addr: str, sniffer: str, rssi: int) -> None:
        """How one sniffer heard one of our devices' transmissions (for the map and per-sniffer signal)."""
        key = (int(ts // 60) * 60, addr, sniffer)
        r = self.batch.sniff.get(key)
        if r is None:
            self.batch.sniff[key] = [1, rssi, rssi, rssi]
        else:
            r[0] += 1
            r[1] += rssi
            r[2] = min(r[2], rssi)
            r[3] = max(r[3], rssi)

    def add_dropped(self, ts: float, n: int) -> None:
        if n > 0:
            self.batch.net_rec(int(ts // 60) * 60)[N_DROPPED] += n

    def _event(self, ts, kind, addr="", other="", ieee="", detail="", ref=None) -> None:
        self.batch.events.append({"ts": ts, "kind": kind, "addr": addr or "", "other": other or "",
                                  "ieee": ieee or "", "detail": detail, "file": ref[0] if ref else "",
                                  "n": ref[1] if ref else 0})

    def _learn(self, short: str, ieee: str, ts: float, ref) -> None:
        b = self.batch
        old_short, old_ieee = self._short.get(ieee), self._ieee.get(short)
        if (old_short and old_short != short) or (old_ieee and old_ieee != ieee):
            # A change of address - or a frame with a flipped bit. Believe it once it repeats.
            n = self._claims.get((short, ieee), 0) + 1
            if n < ADDRESS_CONFIRM:
                self._claims[(short, ieee)] = n
                if len(self._claims) > 4096:
                    self._claims.clear()
                return
            self._claims.pop((short, ieee), None)
        rec = b.ieee.get((short, ieee))
        if rec:
            rec[1] = ts
        else:
            b.ieee[(short, ieee)] = [ts, ts]
        if old_short and old_short != short:
            self._event(ts, "address_change", short, old_short, ieee, f"was {old_short}", ref)
            if self._ieee.get(old_short) == ieee:
                del self._ieee[old_short]
        elif old_ieee and old_ieee != ieee:
            self._event(ts, "address_reused", short, "", ieee, f"short address taken over from {old_ieee}", ref)
        self._short[ieee] = short
        self._ieee[short] = ieee

    @staticmethod
    def _remember(d: dict, q: collections.deque, key, ts: float, keep_s: float) -> None:
        """d[key] = ts, forgetting entries older than keep_s in arrival order: O(1) per frame however
        busy the channel is (a scan of the whole dict per frame cost 0.3 ms at OTA traffic)."""
        d[key] = ts
        q.append((ts, key))
        while q and (ts - q[0][0] > keep_s or len(q) > 500000):
            old_ts, old = q.popleft()
            if d.get(old) == old_ts:
                del d[old]

    def feed(self, ts: float, rssi: int, lqi: int, psdu: bytes, ref=None, copies=None) -> dict:
        """Count one transmission; returns {"m": parsed headers, "pan", "ours", "retry"}. `rssi` is the
        best of the sniffers that heard it; `copies` = [(sniffer, rssi, lqi)] for each of them."""
        m = mac.parse(psdu)
        pan = self.pans.pan(m, ts)
        ours = self.pans.is_ours(pan)
        b = self.batch
        minute = int(ts // 60) * 60
        air = (len(psdu) + AIR_OVERHEAD) * US_PER_BYTE
        net = b.net_rec(minute)
        ftype = m.get("type")
        src, dst = m.get("src"), m.get("dst")
        cmd = m.get("cmd") if ftype == "command" else None

        # The frame before asked for an ACK: did this frame answer it?
        aw = self._await
        if aw:
            self._await = None
            if not (ftype == "ack" and m.get("seq") == aw[1] and 0 <= ts - aw[2] <= ACK_WINDOW_S):
                b.dev_rec(aw[3], aw[0])[NOACK] += 1
                b.net_rec(aw[3])[N_NOACK] += 1
                if aw[4]:
                    b.link_rec(int(aw[2] // 3600) * 3600, aw[4], aw[0])[2] += 1

        net[N_AIR_ALL] += air
        if cmd == 7:
            net[N_SCANS] += 1
        info = {"m": m, "pan": pan, "ours": ours, "retry": False}
        if not ours:
            net[N_UNNAMED if pan is None else N_OTHERS] += 1
            if cmd == 6 and src in self.our_ieee:  # names no PAN, but it is one of ours
                self._event(ts, "orphan", src, "", src, "lost its parent and is looking for it", ref)
            return info
        net[N_OURS] += 1
        net[N_AIR_OURS] += air
        if ftype == "ack":
            return info

        d = None
        if src:
            d = b.dev_rec(minute, src)
            d[TX] += 1
            d[RSSI_SUM] += rssi
            d[RSSI_MIN] = rssi if d[RSSI_MIN] is None else min(d[RSSI_MIN], rssi)
            d[RSSI_MAX] = rssi if d[RSSI_MAX] is None else max(d[RSSI_MAX], rssi)
            d[LQI_SUM] += lqi
            d[AIR] += air
            b.seen[src] = (ts, rssi, lqi)
            for sniffer, r, _ in copies or ():
                self.sniffer_rssi(ts, src, sniffer, r)

        retry = False
        if unicast(dst) and m.get("ack_req") and ftype in ("data", "command"):
            key = (src, dst, m.get("seq"))
            prev = self._recent.get(key)
            retry = prev is not None and abs(ts - prev) <= RETRY_WINDOW_S  # (a backlog can come out of order)
            self._remember(self._recent, self._recent_q, key, ts, 10 * RETRY_WINDOW_S)
            if d is not None:
                d[UNI] += 1
                d[RETRY] += retry
                lk = b.link_rec(int(ts // 3600) * 3600, src, dst)
                lk[0] += 1
                lk[1] += retry
            net[N_UNI] += 1
            net[N_RETRY] += retry
            b.dev_rec(minute, dst)[RX] += 1
            self._await = (dst, m.get("seq"), ts, minute, src)
        elif dst in BROADCAST:
            net[N_BCAST] += 1
        info["retry"] = retry

        nwk = m.get("nwk") or {}
        nsrc, ndst = nwk.get("src"), nwk.get("dst")
        if nsrc:
            if d is not None and nsrc != src:
                d[RELAY] += 1
            # One message, however many routers relay it: same NWK source, destination and sequence,
            # within a few seconds of its first sighting (later sightings don't extend that, or a busy
            # source whose sequence wraps every 256 messages would stop counting).
            key = (nsrc, ndst, nwk.get("seq"))
            last = self._msgs.get(key)
            if last is None or abs(ts - last) > MSG_WINDOW_S:
                b.dev_rec(minute, nsrc)[MSGS] += 1
                self._remember(self._msgs, self._msgs_q, key, ts, MSG_WINDOW_S)
            if ts > b.msg_seen.get(nsrc, 0):
                b.msg_seen[nsrc] = ts
            if nwk.get("src64"):
                self._learn(nsrc, nwk["src64"], ts, ref)

        if cmd == 4 and d is not None:
            d[POLL] += 1
        elif cmd == 1 and src:
            self._event(ts, "association", src, dst, src if len(src) == 18 else "", "asked to join (association request)", ref)
        elif cmd == 2 and dst:
            status = m.get("assoc_status")
            text = f"was given {m.get('assoc_addr')}" if status == 0 else f"was refused (status {status})"
            self._event(ts, "association_response", m.get("assoc_addr") if status == 0 else dst, src,
                        dst if len(dst or "") == 18 else "", f"joined: {text}", ref)
        elif cmd == 6 and src:
            self._event(ts, "orphan", src, "", src, "lost its parent and is looking for it", ref)

        if src and not retry:
            hour = int(ts // 3600) * 3600
            h = b.hops.get((hour, src, dst or "", nsrc or "", ndst or ""))
            if h is None:
                b.hops[(hour, src, dst or "", nsrc or "", ndst or "")] = [1, rssi]
            else:
                h[0] += 1
                h[1] += rssi
        return info
