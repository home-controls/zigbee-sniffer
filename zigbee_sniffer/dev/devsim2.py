"""Two fake sniffer bridges in one simulated house, for testing several sniffers and the map.

Devices sit on two floors of a 20 x 12 m house; each bridge hears a frame at
    rssi = A_device - 27 log10(distance) - 13 * floors between + noise
(n = 2.7, 13 dB per floor), plus the bridge's antenna gain (--up-gain for "up"; 0 for "main"),
and not at all below -100 dBm. "main" stays connected; "up" drops
its Wi-Fi now and then and delivers its backlog afterwards. positions.json says where
everything is, so the test can place it on the app's map.
"""

import argparse
import asyncio
import json
import math
import random
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent  # devsim.py sits next to this file (and puts ../app on sys.path)
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from devsim import DEVS, Net, ieee_of, pcap, proto, write_z2m  # noqa: E402

W_M, H_M, FLOOR_H = 20.0, 12.0, 3.0
rnd = random.Random(11)
rnd_lag = random.Random(13)
HEAR_DBM = -100  # a bridge hears nothing weaker (--hear-dbm: higher, so each hears only part of the house)
POS = {0x0000: (0, 10.0, 6.0)}
STRENGTH = {}
for i, (addr, name, kind, *_r) in enumerate(DEVS):
    if addr != 0x0000:
        POS[addr] = (i % 2, rnd.uniform(1, W_M - 1), rnd.uniform(1, H_M - 1))
    STRENGTH[addr] = rnd.gauss(-40, 4)
SNIFFERS = [
    {"id": "main", "name": "Main", "port": 6638, "http": 8080, "pos": (0, 4.0, 3.0), "offset_us": 10_000_000, "drops": False,
     "gain": 0.0},
    {"id": "upstairs", "name": "Upstairs", "port": 6639, "http": 8081, "pos": (1, 15.0, 8.0), "offset_us": 77_000_000, "drops": True,
     "gain": 0.0},
]


def rssi_at(sender, sn) -> int | None:
    if sender not in POS:
        return int(rnd.gauss(-82, 3))
    lv, x, y = POS[sender]
    slv, sx, sy = sn["pos"]
    floors = abs(lv - slv)
    d = max(0.5, math.sqrt((x - sx) ** 2 + (y - sy) ** 2 + (floors * FLOOR_H) ** 2))
    r = STRENGTH[sender] - 27 * math.log10(d) - 13 * floors + sn["gain"] + rnd.gauss(0, 2.5)
    return int(round(r)) if r > HEAR_DBM else None


class HouseNet(Net):
    def emit(self, ts, psdu, sender):
        self.out.append((ts, psdu, sender))


class FakeBridge:
    def __init__(self, cfg, args):
        self.cfg, self.args = cfg, args
        self.clients: dict = {}
        self.buffer: list = []
        self.wall0 = time.time()
        self.down_until = 0.0
        self.next_drop = time.time() + args.drop_every
        self.frames = 0
        self.dropped = 0
        self.start_mono = time.monotonic()

    def bus(self, ts):
        return int((ts - self.wall0) * 1e6) + self.cfg["offset_us"]

    def msg(self, fr, at):
        ts, psdu, rssi = fr
        bus = self.bus(ts)
        if bus < 0:
            return b""  # heard before this bridge booted (its clock starts later): a real one never has it
        body = proto.FRAME_HDR.pack(bus, 25, rssi, max(0, min(255, (rssi + 105) * 2)), 0) + psdu
        return proto.encode(0x06, struct.pack("<Q", bus) + body) if at else proto.encode(proto.T_FRAME, body)

    async def handle(self, reader, writer):
        if time.time() < self.down_until:
            writer.close()
            return
        writer.write(proto.encode(proto.T_HELLO, json.dumps({"bridge": f"sim-{self.cfg['id']}", "bridge_us": self.bus(time.time()),
                                                             "backlog_bytes": len(self.buffer) * 50}).encode()))
        self.clients[writer] = "pending"
        loop = asyncio.get_running_loop()
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
            for fr in self.buffer:
                writer.write(self.msg(fr, True))
            print(f"{self.cfg['id']}: client took the backlog of {len(self.buffer)} frames", flush=True)
        self.buffer.clear()
        self.clients[writer] = mode
        try:
            await reader.read()
        except (ConnectionError, OSError):
            pass
        finally:
            self.clients.pop(writer, None)

    async def http(self, reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        text = json.dumps({"bridge": "0.3.5+devkitc", "bridge_firmware": "confirmed", "bridge_partition": "ota_0",
                           "radio": "0.2.2", "radio_firmware": "confirmed", "radio_link": True,
                           "wifi_rssi": -52 if self.cfg["id"] == "main" else -71, "wifi_channel": 11,
                           "wifi_ap": "22:0b:8b:32:a4:79", "uptime_s": int(time.monotonic() - self.start_mono),
                           "ha_connected": bool(self.clients), "client": "buffered", "psram_bytes": 8388608,
                           "buffer_bytes": 6291456, "backlog_bytes": len(self.buffer) * 50, "buffer_full_drops": 0,
                           "live_only_skips": 0, "uart_frames": self.frames, "uart_crc_errors": 0, "updates": True,
                           "last_update": "none since boot"}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(text) + text)
        await writer.drain()
        writer.close()

    def tick(self, frames, now):
        if self.cfg["drops"] and self.args.drop_every and now >= self.next_drop:
            for w in list(self.clients):
                w.transport.abort()
            self.clients.clear()
            self.down_until = now + self.args.down
            self.next_drop = now + self.args.down + self.args.drop_every
            print(f"{self.cfg['id']}: Wi-Fi drop for {self.args.down}s", flush=True)
        takers = [w for w, m in self.clients.items() if m in ("at", "plain")]
        out: dict = {}
        for ts, psdu, sender in frames:
            r = rssi_at(sender, self.cfg)
            if r is None:
                continue
            self.frames += 1
            if not takers:
                self.buffer.append((ts, psdu, r))
                continue
            for w in takers:
                out.setdefault(w, []).append(self.msg((ts, psdu, r), self.clients.get(w) == "at"))
        if out:
            # Wi-Fi and TCP: each bridge's frames reach the app some ms late, independently of the other
            # bridge's, so either sniffer's copy of a frame can come in first (--jitter-ms; < the 50 ms tick,
            # so one bridge's frames keep their order).
            lag = rnd_lag.uniform(0, self.args.jitter_ms / 1000)

            def send(out=out):
                for w, msgs in out.items():
                    if not w.transport.is_closing():
                        w.write(b"".join(msgs))

            if lag:
                asyncio.get_running_loop().call_later(lag, send)
            else:
                send()
        return takers


async def serve(args, net):
    bridges = [FakeBridge(c, args) for c in SNIFFERS]
    for b in bridges:
        await asyncio.start_server(b.handle, "127.0.0.1", b.cfg["port"])
        await asyncio.start_server(b.http, "127.0.0.1", b.cfg["http"])
    print("fake bridges: " + ", ".join(f"{b.cfg['id']} on {b.cfg['port']}" for b in bridges), flush=True)
    last_status = 0.0
    while True:
        await asyncio.sleep(0.05)
        now = time.time()
        net.out.clear()
        net.run_until(now)
        frames = sorted(net.out)
        status = now - last_status > 5
        if status:
            last_status = now
        for b in bridges:
            takers = b.tick(frames, now)
            if status and takers:
                up = int(time.monotonic() - b.start_mono)
                rs = proto.RADIO_STATUS.pack(up, b.frames, 0, 25, 0, 2, 2)
                bs = proto.BRIDGE_STATUS.pack(up, b.frames, 0, b.dropped, -52 if b.cfg["id"] == "main" else -71, 1)
                for w in takers:
                    w.write(proto.encode(proto.T_RADIO_STATUS, rs))
                    w.write(proto.encode(proto.T_BRIDGE_STATUS, bs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--backfill", type=float, default=0)
    ap.add_argument("--drop-every", type=float, default=0)
    ap.add_argument("--down", type=float, default=20)
    ap.add_argument("--up-gain", type=float, default=0, help="dB the upstairs bridge's antenna hears louder than main's")
    ap.add_argument("--jitter-ms", type=float, default=0,
                    help="each bridge's frames reach the app up to this many ms late (< 50), so either copy can come first")
    ap.add_argument("--hear-dbm", type=float, default=-100,
                    help="a bridge hears nothing weaker; around -80 each hears ~80%% and some frames only one hears")
    args = ap.parse_args()
    args.jitter_ms = max(0.0, min(args.jitter_ms, 45.0))
    global HEAR_DBM
    HEAR_DBM = args.hear_dbm
    SNIFFERS[1]["gain"] = args.up_gain
    random.seed(7)
    write_z2m(args.root / "z2m")
    data = args.root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "options.json").write_text(json.dumps({
        "sniffer_host": "127.0.0.1", "sniffer_port": 6638, "sniffer_name": "Main", "channel": 25, "retention_days": 7,
        "max_storage_mb": 2000, "decode": True, "update_token": "devtoken",
        "more_sniffers": [{"name": "Upstairs", "host": "127.0.0.1", "port": 6639, "http_port": 8081}]}))
    (args.root / "positions.json").write_text(json.dumps({
        "size_m": [W_M, H_M], "floor_height_m": FLOOR_H,
        "devices": {"0x" + ieee_of(a): {"level": p[0], "x": p[1] / W_M, "y": p[2] / H_M} for a, p in POS.items()},
        "sniffers": {s["id"]: {"level": s["pos"][0], "x": s["pos"][1] / W_M, "y": s["pos"][2] / H_M} for s in SNIFFERS}}))
    now = time.time()
    net = HouseNet(now - args.backfill * 3600)
    if args.backfill:
        writer = pcap.RotatingPcap(args.root / "captures")
        t = net.t
        while t < now - 1:
            t2 = min(now - 1, t + 600)
            net.out.clear()
            net.run_until(t2)
            for ts, psdu, sender in sorted(net.out):
                r = rssi_at(sender, SNIFFERS[0])
                if r is not None:
                    writer.write(ts, pcap.tap_packet(psdu, 25, r, 60))
            t = t2
        writer.close()
        print(f"backfilled {args.backfill} h", flush=True)
    asyncio.run(serve(args, net))


if __name__ == "__main__":
    main()
