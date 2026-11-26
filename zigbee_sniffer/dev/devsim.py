"""Fake sniffer bridge for local testing of the Zigbee Sniffer app.

Writes `--backfill` hours of captures into the capture dir, then serves live frames on a TCP port
speaking the bridge protocol. NWK commands and ZDO are sent without NWK security so tshark can
dissect them without a key (real networks encrypt them).
"""

import argparse
import asyncio
import json
import random
import struct
import sys
import time
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"  # zigbee_sniffer/app, next to this dev/ folder
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))
import pcap  # noqa: E402
import proto  # noqa: E402

PAN = 0x852C
R, E, C = "Router", "EndDevice", "Coordinator"
# addr, name, type, rssi at sniffer, next hop, loss per hop
DEVS = [
    (0x0000, "Coordinator", C, -62, None, 0.0),
    (0x24CB, "Dining Room Hanging Light", R, -61, 0x0000, 0.01),
    (0x774A, "Kitchen Keypad", R, -58, 0x0000, 0.01),
    (0xCC94, "Main Stairs Light", R, -54, 0x0000, 0.01),
    (0x4CAE, "Master Keypad", R, -63, 0x4E65, 0.02),
    (0x4E65, "Upper floor stairs", R, -63, 0xCC94, 0.02),
    (0x1DF7, "Top of stairs 2", R, -61, 0x4E65, 0.03),
    (0x7D68, "Man Door", R, -64, 0x0000, 0.02),
    (0xDC75, "Garden Router", R, -66, 0x24CB, 0.02),
    (0x0494, "Garage Entrance 1", R, -67, 0x7D68, 0.02),
    (0xCD20, "Garage Entrance 2", R, -69, 0x7D68, 0.03),
    (0xA495, "Dual Outlet", R, -70, 0x774A, 0.02),
    (0x0842, "Bedroom 2", R, -71, 0x4E65, 0.04),
    (0x2239, "Laundry Room", R, -73, 0x774A, 0.03),
    (0xF605, "Garage Inside Lights", R, -74, 0x0494, 0.04),
    (0x0D41, "Master Stairs Bottom", R, -85, 0x4CAE, 0.06),
    (0x837C, "Master Stairs Top", R, -85, 0x4CAE, 0.05),
    (0x6856, "Front Door Keypad", R, -85, 0x24CB, 0.05),
    (0xA15B, "Garage Entrance", R, -88, 0xF605, 0.07),
    (0x6DA2, "Back Porch Light", R, -91, 0xDC75, 0.08),
    (0xA406, "Shed Plug", R, -92, 0x24CB, 0.06),
    (0x1954, "Office Cans", R, -93, 0x0842, 0.10),
    (0x841A, "Accent 2", R, -95, 0xDC75, 0.12),
    (0xCA0D, "Master Bath Lights", R, -95, 0x837C, 0.10),
    (0xC112, "Floor Lamp", R, -97, 0xA406, 0.30),
    (0x6688, "Craft Room", R, -100, 0xA406, 0.35),
    (0x40A8, "Air Quality Sensor", E, -83, 0x2239, 0.03),
    (0x7577, "Office Door", E, -77, 0x0842, 0.03),
    (0xD2F5, "Closet Door", E, -83, 0x837C, 0.05),
    (0x951C, "Guest Bath Motion", E, -79, 0x774A, 0.03),
    (0x5A11, "Freezer Temp", E, -99, 0xC112, 0.25),
]
NOT_HEARD = [(0x3E21, "Garage Sensor", E), (0x9A9A, "Spare Switch", R)]
ADDRS = {d[0]: d for d in DEVS}


def ieee_of(addr: int) -> str:
    return f"00124b00{addr:04x}{(addr * 7919) & 0xFFFF:04x}"


def write_z2m(z2m: Path) -> None:
    z2m.mkdir(parents=True, exist_ok=True)
    lines = ["homeassistant: true", "advanced:", "  pan_id: 34092", "  channel: 25",
             "  network_key: [1, 3, 5, 7, 9, 11, 13, 15, 0, 2, 4, 6, 8, 10, 12, 13]", "devices:"]
    db = []
    for i, (addr, name, kind, *_rest) in enumerate([*DEVS, *[(a, n, k) for a, n, k in NOT_HEARD]]):
        ieee = "0x" + ieee_of(addr)
        if kind != C:
            lines += [f"  '{ieee}':", f"    friendly_name: {json.dumps(name)}"]
        db.append(json.dumps({"id": i + 1, "type": kind, "ieeeAddr": ieee, "nwkAddr": addr,
                              "manufName": "Control4" if kind == R else ("Texas Instruments" if kind == C else "Aqara"),
                              "modelId": "C4-DIM1-Z" if kind == R else ("CC2652" if kind == C else "MCCGQ11LM"),
                              "powerSource": "Battery" if kind == E else "Mains (single phase)"}))
    (z2m / "configuration.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (z2m / "database.db").write_text("\n".join(db) + "\n", encoding="utf-8")
    # Zigbee2MQTT's device state with firmware status (state.json): every router up to date, but two
    # with a newer image available
    routers = [a for a, _n, k, *_r in DEVS if k == R]
    state = {"0x" + ieee_of(a): {"update": {"state": "available" if i < 2 else "idle", "installed_version": 0x01002A00,
                                            "latest_version": 0x01002B00 if i < 2 else 0x01002A00,
                                            "latest_release_notes": "Version: 43.0" if i < 2 else None}}
             for i, a in enumerate(routers)}
    (z2m / "state.json").write_text(json.dumps(state), encoding="utf-8")


class Net:
    def __init__(self, t0: float) -> None:
        self.t = t0
        self.out: list[tuple[float, bytes, int, int]] = []
        self.mac_seq: dict[int, int] = {}
        self.nwk_seq: dict[int, int] = {}
        self.aps = 0
        self.next: dict[tuple, float] = {}
        for addr, name, kind, *_ in DEVS:
            if kind != E:
                self.next[("ls", addr)] = t0 + random.random() * 15
            else:
                self.next[("poll", addr)] = t0 + random.random() * 7
            self.next[("report", addr)] = t0 + random.random() * 60
        self.next[("mto",)] = t0 + 5
        self.next[("coord_cmd",)] = t0 + 3
        self.next[("other",)] = t0
        self.next[("thread",)] = t0
        self.next[("beacon_req",)] = t0 + 30
        self.next[("flap",)] = t0 + 600
        self.silent_after = time.time() - 2400  # Closet Door goes quiet 40 min before "now"

    # -------------------------------------------------- frame builders
    def ms(self, a):
        self.mac_seq[a] = (self.mac_seq.get(a, random.randrange(256)) + 1) & 0xFF
        return self.mac_seq[a]

    def ns(self, a):
        self.nwk_seq[a] = (self.nwk_seq.get(a, random.randrange(256)) + 1) & 0xFF
        return self.nwk_seq[a]

    def emit(self, ts, psdu, sender):
        base = ADDRS[sender][3] if sender in ADDRS else -80
        rssi = int(round(base + random.gauss(0, 2.2)))
        lqi = max(0, min(255, int((rssi + 105) * 2.4)))
        self.out.append((ts, psdu, rssi, lqi))

    @staticmethod
    def mac(src, dst, payload, seq, ack=True, ftype=1, pan=PAN):
        fc = ftype | (0x20 if ack else 0) | 0x40 | (2 << 10) | (2 << 14)
        return struct.pack("<HBHHH", fc, seq, pan, dst, src) + payload

    @staticmethod
    def nwk(src, dst, payload, seq, ftype=0, radius=30, src64=None, secure=False):
        fc = ftype | (2 << 2) | (1 << 6) | (0x0200 if secure else 0) | (0x1000 if src64 else 0)
        hdr = struct.pack("<HHHBB", fc, dst, src, radius, seq)
        if src64:
            hdr += bytes.fromhex(src64)[::-1]
        return hdr + payload

    def zcl_report(self, cluster):
        self.aps = (self.aps + 1) & 0xFF
        if cluster == 0x0006:
            attrs = struct.pack("<HBB", 0x0000, 0x10, random.randrange(2))
        elif cluster == 0x0008:
            attrs = struct.pack("<HBB", 0x0000, 0x20, random.randrange(256))
        else:
            attrs = struct.pack("<HBh", 0x0000, 0x29, random.randrange(1800, 2600))
        return struct.pack("<BBHHBB", 0x00, 1, cluster, 0x0104, 1, self.aps) + bytes([0x18, random.randrange(256), 0x0A]) + attrs

    def secured(self, n):
        aux = bytes([0x28]) + struct.pack("<I", random.randrange(1 << 31)) + bytes(8) + b"\x00"
        return aux + random.randbytes(n) + random.randbytes(4)

    # -------------------------------------------------- behaviours
    def path_to_coord(self, a):
        p = [a]
        while ADDRS[p[-1]][4] is not None:
            p.append(ADDRS[p[-1]][4])
        return p

    def hop(self, ts, a, b, nwk_payload):
        """One MAC hop with retries; returns (time after, delivered)."""
        loss = max(ADDRS[a][5], ADDRS[b][5]) if a in ADDRS and b in ADDRS else 0.02
        seq = self.ms(a)
        for attempt in range(4):
            psdu = self.mac(a, b, nwk_payload, seq)
            self.emit(ts, psdu, a)
            end = ts + (len(psdu) + 8) * 32e-6  # on air: preamble, SFD, PHR and FCS besides the PSDU
            if random.random() > loss:
                if random.random() > 0.02:  # the sniffer misses a few ACKs
                    self.emit(end + 0.000192, struct.pack("<HB", 0x0002, seq), b)  # after the turnaround
                return end + 0.002, True
            # No ACK: the sender waits macAckWaitDuration (864 us), backs off 0-7 slots of 320 us,
            # then CCA and turnaround - a real retry comes 2-5 ms after its original.
            ts = end + 0.000864 + random.randint(0, 7) * 0.00032 + 0.00032
        return ts, False

    def message(self, ts, path, nsrc, ndst, payload, ftype=0):
        nseq = self.ns(nsrc)
        for a, b in zip(path, path[1:]):
            ts, ok = self.hop(ts, a, b, self.nwk(nsrc, ndst, payload, nseq, ftype))
            if not ok:
                # the router that couldn't deliver tells the network
                st = bytes([0x03, 0x02]) + struct.pack("<H", ndst)
                s2 = self.ns(a)
                self.emit(ts, self.mac(a, 0xFFFF, self.nwk(a, 0xFFFD, st, s2, ftype=1, radius=5), self.ms(a), ack=False), a)
                return ts
            ts += 0.003 + random.random() * 0.01
        return ts

    def broadcast(self, ts, origin, ndst, payload, ftype=1, radius=30, src64=None, relays=True):
        nseq = self.ns(origin)
        self.emit(ts, self.mac(origin, 0xFFFF, self.nwk(origin, ndst, payload, nseq, ftype, radius, src64), self.ms(origin), ack=False), origin)
        if relays:
            for addr, _, kind, *_ in DEVS:
                if kind == R and addr != origin and random.random() < 0.85:
                    ts += 0.002 + random.random() * 0.02
                    self.emit(ts, self.mac(addr, 0xFFFF, self.nwk(origin, ndst, payload, nseq, ftype, radius - 1, src64), self.ms(addr), ack=False), addr)
        return ts

    def link_status(self, ts, a):
        nbrs = set()
        if ADDRS[a][4] is not None:
            nbrs.add(ADDRS[a][4])
        nbrs |= {d[0] for d in DEVS if d[4] == a and d[2] != E}
        rnd = random.Random(a)
        nbrs |= set(rnd.sample([d[0] for d in DEVS if d[2] != E and d[0] != a], 3))
        entries = b""
        for nb in sorted(nbrs):
            loss = max(ADDRS[a][5], ADDRS[nb][5])
            cost = max(1, min(7, 1 + int(loss * 18 + random.random() * 1.5)))
            out = max(1, min(7, cost + random.choice((-1, 0, 0, 1))))
            entries += struct.pack("<HB", nb, cost | (out << 4))
        payload = bytes([0x08, len(nbrs) | 0x60]) + entries
        self.emit(ts, self.mac(a, 0xFFFF, self.nwk(a, 0xFFFC, payload, self.ns(a), ftype=1, radius=1), self.ms(a), ack=False), a)

    def run_until(self, t_end: float) -> None:
        while True:
            key, t = min(self.next.items(), key=lambda kv: kv[1])
            if t >= t_end:
                self.t = t_end
                return
            self.t = t
            kind = key[0]
            if kind == "ls":
                self.link_status(t, key[1])
                self.next[key] = t + 15 + random.uniform(-0.5, 0.5)
            elif kind == "poll":
                a = key[1]
                if not (a == 0xD2F5 and t > self.silent_after):
                    parent = ADDRS[a][4]
                    seq = self.ms(a)
                    fc = 3 | 0x20 | 0x40 | (2 << 10) | (2 << 14)
                    self.emit(t, struct.pack("<HBHHH", fc, seq, PAN, parent, a) + b"\x04", a)
                    if random.random() > ADDRS[a][5]:
                        self.emit(t + 0.001, struct.pack("<HB", 0x0002, seq), parent)
                self.next[key] = t + 7.5 + random.uniform(-0.3, 0.3)
            elif kind == "report":
                a = key[1]
                if a != 0x0000 and not (a == 0xD2F5 and t > self.silent_after):
                    cl = 0x0402 if ADDRS[a][2] == E else random.choice((0x0006, 0x0008))
                    payload = self.zcl_report(cl) if random.random() < 0.7 else self.secured(18)
                    self.message(t, self.path_to_coord(a), a, 0x0000, payload)
                self.next[key] = t + (random.uniform(120, 300) if ADDRS[a][2] == E else random.uniform(20, 70))
            elif kind == "mto":
                payload = bytes([0x01, 0x08, self.ns(0) & 0xFF]) + struct.pack("<H", 0xFFFC) + b"\x00"
                self.broadcast(t, 0x0000, 0xFFFC, payload)
                self.next[key] = t + 120
            elif kind == "coord_cmd":
                target = random.choice([d for d in DEVS if d[2] == R])[0]
                path = list(reversed(self.path_to_coord(target)))
                self.message(t, path, 0x0000, target, self.zcl_report(0x0006))
                self.next[key] = t + random.uniform(10, 30)
            elif kind == "other":
                src = random.choice((0x1A01, 0x1A02, 0x1A03))
                self.emit(t, self.mac(src, 0x0000, self.secured(20), random.randrange(256), pan=0x551B), 0x7D68)
                self.next[key] = t + random.uniform(3, 8)
            elif kind == "thread":
                self.emit(t, self.mac(0x4400, 0xFFFF, random.randbytes(30), random.randrange(256), ack=False, pan=0x7962), 0x24CB)
                self.next[key] = t + random.uniform(1, 4)
            elif kind == "beacon_req":
                fc = 3 | (2 << 10)
                self.emit(t, struct.pack("<HBHH", fc, random.randrange(256), 0xFFFF, 0xFFFF) + b"\x07", 0x0D41)
                self.next[key] = t + random.uniform(120, 400)
            elif kind == "flap":
                a = 0x841A  # Accent 2 leaves and rejoins
                parent = ADDRS[a][4]
                ieee = ieee_of(a)
                tt = self.broadcast(t, a, 0xFFFD, bytes([0x04, 0x20]), radius=1, src64=ieee, relays=False)
                tt += 2.0
                self.message(tt, [a, parent], a, parent, bytes([0x06, 0x8E]), ftype=1)
                tt += 0.05
                self.message(tt, [parent, a], parent, a, bytes([0x07]) + struct.pack("<HB", a, 0), ftype=1)
                tt += 0.3
                self.aps = (self.aps + 1) & 0xFF
                zdo = bytes([random.randrange(256)]) + struct.pack("<H", a) + bytes.fromhex(ieee)[::-1] + b"\x8e"
                aps = struct.pack("<BBHHBB", 0x08, 0, 0x0013, 0x0000, 0, self.aps) + zdo
                self.broadcast(tt, a, 0xFFFD, aps, ftype=0, src64=ieee)
                self.next[key] = t + random.uniform(900, 1800)


async def serve(args, net: Net) -> None:
    """Bridge 0.3: buffers while no app takes frames, HELLO first, FRAME_AT after a CLIENT_HELLO."""
    loop = asyncio.get_running_loop()
    clients: dict[asyncio.StreamWriter, str] = {}  # writer -> "pending" | "at" | "plain"
    buffer: list[tuple] = []
    wall0 = time.time()
    bus = lambda ts: int((ts - wall0) * 1e6) + 5_000_000  # bridge clock: us since its boot
    state = {"down_until": 0.0, "radio_frames": 0, "dropped": 0, "next_drop": time.time() + args.drop_every}
    start_mono = time.monotonic()

    def frame_msg(fr, at: bool) -> bytes:
        ts, psdu, rssi, lqi = fr
        body = proto.FRAME_HDR.pack(int((ts - wall0) * 1e6) + 10_000_000, 25, rssi, lqi, 0) + psdu
        return proto.encode(0x06, struct.pack("<Q", bus(ts)) + body) if at else proto.encode(proto.T_FRAME, body)

    async def handle(reader, writer):
        if time.time() < state["down_until"]:
            writer.close()
            return
        writer.write(proto.encode(proto.T_HELLO, json.dumps(
            {"bridge": "sim-0.3", "bridge_us": bus(time.time()), "backlog_bytes": len(buffer) * 50}).encode()))
        clients[writer] = "pending"
        dec, mode, deadline = proto.Decoder(), "plain", loop.time() + 3
        try:
            while loop.time() < deadline and mode != "at":
                data = await asyncio.wait_for(reader.read(256), timeout=max(0.01, deadline - loop.time()))
                if not data:
                    break
                for t, pl in dec.feed(data):
                    if t == 0x12 and len(pl) >= 4 and struct.unpack("<I", pl[:4])[0] & 1:
                        mode = "at"
        except asyncio.TimeoutError:
            pass
        if mode == "at":
            for fr in buffer:
                writer.write(frame_msg(fr, True))
            print(f"client took the backlog: {len(buffer)} frames", flush=True)
        else:
            state["dropped"] += len(buffer)
            print(f"old-style client: dropped {len(buffer)} buffered frames", flush=True)
        buffer.clear()
        clients[writer] = mode
        try:
            await reader.read()
        except (ConnectionError, OSError):
            pass
        finally:
            clients.pop(writer, None)

    fw = {"radio": "0.2.1", "radio_firmware": "rolled_back", "bridge": "0.3.5+devkitc", "bridge_firmware": "confirmed",
          "last_update": "none since boot", "radio_updating": False}

    async def http(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = head.decode(errors="replace").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        hdr = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)}
        body = await reader.readexactly(int(hdr.get("content-length", 0) or 0))
        status, text, ctype = 200, "", "application/json"
        if method == "GET" and path == "/":
            text = json.dumps({**fw, "bridge_partition": "ota_1", "radio_link": True, "wifi_rssi": -58,
                               "wifi_channel": 11, "wifi_ap": "22:0b:8b:32:a4:79", "uptime_s": int(time.monotonic() - start_mono),
                               "ha_connected": bool(clients), "client": "buffered" if any(m == "at" for m in clients.values()) else "none",
                               "psram_bytes": 8388608, "buffer_bytes": 6291456, "backlog_bytes": len(buffer) * 50,
                               "buffer_full_drops": 0, "live_only_skips": state["dropped"], "uart_frames": state["radio_frames"],
                               "uart_crc_errors": 1, "updates": True})
        elif method == "POST" and path in ("/update/radio", "/update/bridge"):
            target = path.rsplit("/", 1)[1]
            ctype = "text/plain"
            if hdr.get("x-update-token") != "devtoken":
                status, text = 401, "Wrong or missing X-Update-Token"
            else:
                version = body[48:80].split(b"\0")[0].decode(errors="replace")
                fw["radio_updating"] = target == "radio"
                await asyncio.sleep(4)
                fw[target], fw[f"{target}_firmware"], fw["radio_updating"] = version, "trial", False
                text = f"{target} updated to {version}; it runs on trial"
                fw["last_update"] = text
        else:
            status, text = 404, "not found"
        data = text.encode()
        writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        await writer.drain()
        writer.close()

    await asyncio.start_server(http, "127.0.0.1", 8080)
    server = await asyncio.start_server(handle, "127.0.0.1", args.port)
    print(f"fake bridge 0.3 on 127.0.0.1:{args.port}, dropping every {args.drop_every}s for {args.down}s", flush=True)
    last_status = 0.0
    async with server:
        while True:
            await asyncio.sleep(0.05)
            now = time.time()
            if args.drop_every and now >= state["next_drop"]:
                for w in list(clients):
                    w.transport.abort()
                clients.clear()
                state["down_until"] = now + args.down
                state["next_drop"] = now + args.down + args.drop_every
                print(f"Wi-Fi drop for {args.down}s", flush=True)
            net.out.clear()
            net.run_until(now)
            takers = [w for w, m in clients.items() if m in ("at", "plain")]
            for fr in sorted(net.out):
                state["radio_frames"] += 1
                if not takers:
                    buffer.append(fr)
                    continue
                for w in takers:
                    w.write(frame_msg(fr, clients.get(w) == "at"))
            if now - last_status > 5 and takers:
                last_status = now
                up = int(time.monotonic() - start_mono)
                rs = proto.RADIO_STATUS.pack(up, state["radio_frames"], 0, 25, 0, 1, 0)
                bs = proto.BRIDGE_STATUS.pack(up, state["radio_frames"], 0, state["dropped"], -61, 1)
                for w in takers:
                    w.write(proto.encode(proto.T_RADIO_STATUS, rs))
                    w.write(proto.encode(proto.T_BRIDGE_STATUS, bs))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--backfill", type=float, default=0)
    ap.add_argument("--port", type=int, default=6638)
    ap.add_argument("--drop-every", type=float, default=0)
    ap.add_argument("--down", type=float, default=20)
    args = ap.parse_args()
    random.seed(7)
    write_z2m(args.root / "z2m")
    data = args.root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "options.json").write_text(json.dumps({
        "sniffer_host": "127.0.0.1", "sniffer_port": args.port, "channel": 25, "retention_days": 7,
        "max_storage_mb": 2000, "decode": True, "update_token": "devtoken"}))
    now = time.time()
    net = Net(now - args.backfill * 3600)
    if args.backfill:
        writer = pcap.RotatingPcap(args.root / "captures")
        t = net.t
        while t < now - 1:
            t2 = min(now - 1, t + 600)
            net.out.clear()
            net.run_until(t2)
            for ts, psdu, rssi, lqi in sorted(net.out):
                writer.write(ts, pcap.tap_packet(psdu, 25, rssi, lqi))
            t = t2
        writer.close()
        print(f"backfilled {args.backfill} h", flush=True)
    asyncio.run(serve(args, net))


if __name__ == "__main__":
    main()
