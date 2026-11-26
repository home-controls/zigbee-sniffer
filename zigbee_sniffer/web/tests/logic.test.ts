import { test } from "node:test";
import assert from "node:assert/strict";
import {
  bucketSecs, capturesLink, csvCell, dropLoneGaps, fillBuckets, foldHops, frameHay, hourFile, kindOk, niceTicks, parseHash,
  pingStats, pingWord, seriesMap, splitDecode, treeOpen, worst,
} from "../src/logic.ts";
import * as f from "../src/fmt.ts";

test("hash links: page, argument and query (Zigbee Studio links to #/device/<nwk>)", () => {
  const r = parseHash("#/device/0x072f");
  assert.equal(r.page, "device");
  assert.equal(r.arg, "0x072f");
  const c = parseHash("#/captures?file=2026-11-25%2Fzigbee_2026-11-25_17.pcap&n=12&q=Report%20Attributes");
  assert.equal(c.page, "captures");
  assert.equal(c.q.get("file"), "2026-11-25/zigbee_2026-11-25_17.pcap");
  assert.equal(c.q.get("n"), "12");
  assert.equal(c.q.get("q"), "Report Attributes");
  assert.equal(parseHash("").page, "overview");
  assert.equal(parseHash("#/devices?f=attention").q.get("f"), "attention");
});

test("captures links round-trip through parseHash", () => {
  const link = capturesLink({ file: "2026-11-25/zigbee_2026-11-25_17.pcap", addr: "0x841a", q: "a&b" });
  const r = parseHash(link);
  assert.equal(r.q.get("file"), "2026-11-25/zigbee_2026-11-25_17.pcap");
  assert.equal(r.q.get("addr"), "0x841a");
  assert.equal(r.q.get("q"), "a&b");
  assert.equal(capturesLink({ t: 1795654560.7 }), "#/captures?t=1795654560");
});

test("a bucket's covered seconds: partial first and current buckets, none when too little has passed", () => {
  const now = 10_000, x0 = now - 3600;
  assert.equal(bucketSecs(7200, 900, x0, now), 900); // a whole bucket in the middle
  assert.equal(bucketSecs(9900, 900, x0, now, now - 30), 70); // the current one, up to the last history write
  assert.equal(bucketSecs(9990, 900, x0, now, now - 5), null); // only 5 s in: no rate yet
  assert.equal(bucketSecs(9000, 900, x0, now), 900);
});

test("rows to a series and to one slot per bucket", () => {
  const rows = [[0, 5, null], [60, 7, 3], [180, 1, 2]];
  assert.deepEqual([...seriesMap(rows, 1)], [[0, 5], [60, 7], [180, 1]]);
  assert.deepEqual([...seriesMap(rows, 2)], [[60, 3], [180, 2]]);
  assert.deepEqual([...seriesMap(rows, 0, (r) => r[1] * 2)], [[0, 10], [60, 14], [180, 2]]);
  assert.deepEqual(fillBuckets(rows, 0, 180, 60).map((r) => (r ? r[0] : null)), [0, 60, null, 180]);
});

test("nice ticks cover the range with round steps", () => {
  const t = niceTicks(0, 87, 4);
  assert.deepEqual(t.ticks, [0, 20, 40, 60, 80, 100]);
  assert.equal(niceTicks(5, 5).ticks.length >= 2, true);
});

test("CSV cells are quoted only when they need it", () => {
  assert.equal(csvCell("plain"), "plain");
  assert.equal(csvCell(null), "");
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell("x;y"), '"x;y"');
  assert.equal(csvCell(-71.5), "-71.5");
});

test("frame kinds and the live filter", () => {
  const ack = { type: "ack", kind: "Ack" }, data = { type: "data", kind: "NWK data", info: "ZCL: Report" };
  const ls = { type: "data", kind: "Link Status", info: "" }, beacon = { type: "beacon", kind: "Beacon" };
  assert.equal(kindOk("noack", ack), false);
  assert.equal(kindOk("noack", data), true);
  assert.equal(kindOk("data", data), true);
  assert.equal(kindOk("data", ls), false);
  assert.equal(kindOk("nwkcmd", ls), true);
  assert.equal(kindOk("mac", beacon), true);
  assert.equal(kindOk("retry", { ...data, retry: true }), true);
  assert.equal(kindOk("", ack), true);
  const fr: any = { ts: 1, rssi: -60, kind: "NWK data", ours: false, pan: "0x551b", src_name: "Test Keypad", heard_by: [{ name: "Upstairs" }] };
  const hay = frameHay(fr, () => "12:00:00.000");
  assert.ok(hay.includes("test keypad") && hay.includes("pan 0x551b") && hay.includes("upstairs"));
  assert.equal(frameHay(fr, () => "changed"), hay); // cached on the frame
});

test("gap rows only between frames", () => {
  const g = { gap: true }, a = { id: 1 }, b = { id: 2 };
  assert.deepEqual(dropLoneGaps([g, a, g, g, b, g]), [a, g, b]);
});

test("tshark's text: the tree by indent, the hex dump apart", () => {
  const text = [
    "Frame 1: 46 bytes on wire",
    "    Arrival Time: now",
    "IEEE 802.15.4 Command, Src: 0x5a11",
    "    Frame Control Field: 0x8863",
    "        .... .... .... .011 = Frame Type: Command",
    "    Sequence Number: 163",
    "",
    "0000  00 00 24 00  ..$.",
    "0010  63 88        c.",
  ].join("\r\n");
  const { tree, hex } = splitDecode(text);
  assert.equal(tree.length, 2);
  assert.equal(tree[1].children.length, 2);
  assert.equal(tree[1].children[0].children[0].text, ".... .... .... .011 = Frame Type: Command");
  assert.ok(hex.startsWith("0000  00 00 24 00"));
  assert.equal(treeOpen(tree[0], 0), false); // "Frame 1" stays folded
  assert.equal(treeOpen(tree[1], 0), true);
  assert.equal(treeOpen(tree[1].children[0], 1), false); // Frame Control Field stays folded
});

test("ping sums: answered, median and max", () => {
  const res = [{ ok: true, rtt: 40 }, { ok: false, req: true }, { ok: true, rtt: 20 }, { ok: true, rtt: 90 }];
  assert.deepEqual(pingStats(res), { answered: 3, total: 4, pct: 75, median: 40, max: 90 });
  assert.equal(pingStats([{ ok: true, rtt: 10 }, { ok: true, rtt: 30 }]).median, 20);
  assert.deepEqual(pingStats([]), { answered: 0, total: 0, pct: 0, median: null, max: null });
  const ms = (v: number) => `${v} ms`;
  assert.equal(pingWord({ ok: true, rtt: 12 }, ms), "12 ms");
  assert.equal(pingWord({ ok: false, req: true }, ms), "no reply");
  assert.equal(pingWord({ ok: false }, ms), "request not heard");
  assert.equal(pingWord({ ok: false, none: true }, ms), "no trace");
  assert.equal(pingWord({ ok: false, err: "x" }, ms), "error");
});

test("resends of one hop fold into one step", () => {
  const steps = foldHops([
    { from: "0x0000", to: "0x1111", acked: false, rssi: -70 },
    { from: "0x0000", to: "0x1111", acked: true, rssi: -68 },
    { from: "0x1111", to: "0x2222", acked: true, rssi: -50 },
  ]);
  assert.equal(steps.length, 2);
  assert.deepEqual([steps[0].tries, steps[0].acked, steps[0].rssi], [2, true, -68]);
});

test("a link's cost is its worse direction", () => {
  assert.equal(worst({ ab: 3, ba: 5 }), 5);
  assert.equal(worst({ ab: null, ba: 2 }), 2);
  assert.equal(worst({}), null);
});

test("the hour file is named in local time", () => {
  const t = new Date(2026, 10, 25, 17, 30).getTime() / 1000;
  assert.equal(hourFile(t), "2026-11-25/zigbee_2026-11-25_17.pcap");
});

test("the Sniffer's words", () => {
  const now = 1_000_000;
  assert.equal(f.ago(null), "—");
  assert.equal(f.ago(null, now, "never"), "never");
  assert.equal(f.ago(now - 3, now), "just now");
  assert.equal(f.ago(now - 300, now), "5 min ago");
  assert.equal(f.ago(now - 3 * 86400, now), "3 d ago");
  assert.equal(f.pct(0.42), "0.4%");
  assert.equal(f.pct(12.6), "13%");
  assert.equal(f.pct(null), "—");
  assert.equal(f.compact(12345), "12.3K");
  assert.equal(f.compact(2_500_000), "2.5M");
  assert.equal(f.num("12"), 12);
  assert.equal(f.num(""), null);
  assert.equal(f.num("x"), null);
  assert.equal(f.dbm(-71.6), "-72 dBm");
  assert.equal(f.plural(1, "device"), "1 device");
  assert.equal(f.plural(3, "device"), "3 devices");
});
