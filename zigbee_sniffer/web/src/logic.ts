// The page's pure logic: hash links, chart buckets and ticks, CSV cells, frame filters, the
// tshark decode tree, ping sums, capture file names. No DOM, so `npm test` runs it in Node.

import { pad } from "./fmt";

// ------------------------------------------------------------------ links

export interface Route { page: string; arg: string; q: URLSearchParams }

/** "#/device/0x072f", "#/captures?file=2026-11-25%2Fzigbee_2026-11-25_17.pcap&n=12". */
export function parseHash(hash: string): Route {
  const h = hash.replace(/^#\/?/, "");
  const qi = h.indexOf("?");
  const path = qi < 0 ? h : h.slice(0, qi);
  const parts = path.split("/");
  let arg = "";
  try { arg = decodeURIComponent(parts[1] || ""); } catch { arg = parts[1] || ""; }
  return { page: parts[0] || "overview", arg, q: new URLSearchParams(qi < 0 ? "" : h.slice(qi + 1)) };
}

/** A link into Captures: the hour holding time `t` (and a device), or frame `n` of a file. */
export function capturesLink(o: { t?: number; addr?: string; file?: string; n?: number; q?: string }): string {
  const p = new URLSearchParams();
  if (o.file) p.set("file", o.file);
  if (o.n) p.set("n", String(o.n));
  if (o.t) p.set("t", String(Math.floor(o.t)));
  if (o.addr) p.set("addr", o.addr);
  if (o.q) p.set("q", o.q);
  const s = p.toString();
  return "#/captures" + (s ? "?" + s : "");
}

export const deviceLink = (addr: string) => `#/device/${encodeURIComponent(addr)}`;

// ------------------------------------------------------------------ chart data

/** The history is written every 30 s; api/status says when it last was (history_until). Without
 * that, assume the newest data lags the clock by about half the interval. */
export const STORE_LAG = 15;

/** Seconds of bucket t that the data covers within [x0, now] (the first and the current bucket are
 * partial), or null when too little of the bucket has passed to give a rate. */
export function bucketSecs(t: number, b: number, x0: number, now: number, historyUntil?: number | null): number | null {
  const hu = historyUntil ?? null;
  const until = hu !== null && hu <= now && hu > now - 120 ? hu : now - STORE_LAG;
  const end = t + b > until ? until : t + b;
  const s = end - Math.max(t, Math.floor(x0 / 60) * 60);
  return s >= Math.min(b, 20) ? s : null;
}

/** Rows [t, ...] to a Map t -> value (column `idx`, or what `f` makes of the row; nulls left out). */
export function seriesMap<R extends any[]>(rows: R[], idx: number, f?: (r: R) => any): Map<number, any> {
  const m = new Map<number, any>();
  for (const r of rows || []) {
    const v = f ? f(r) : r[idx];
    if (v !== null && v !== undefined) m.set(r[0], v);
  }
  return m;
}

/** One entry per bucket from x0 to x1: the row for that bucket, or null. */
export function fillBuckets<R extends any[]>(points: R[], x0: number, x1: number, b: number): (R | null)[] {
  const map = new Map((points || []).map((p) => [p[0], p]));
  const out: (R | null)[] = [];
  for (let t = Math.floor(x0 / b) * b; t <= x1; t += b) out.push(map.get(t) || null);
  return out;
}

export function niceTicks(min: number, max: number, count = 4): { lo: number; hi: number; ticks: number[] } {
  if (!(max > min)) max = min + 1;
  const raw = (max - min) / count, mag = 10 ** Math.floor(Math.log10(raw)), e = raw / mag;
  const step = (e >= 7.5 ? 10 : e >= 3.5 ? 5 : e >= 1.5 ? 2 : 1) * mag;
  const lo = Math.floor(min / step) * step, hi = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = lo; v <= hi + step / 2; v += step) ticks.push(+v.toFixed(10));
  return { lo, hi, ticks };
}

const TIME_STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800];

/** Axis ticks on round local times; hour and day steps follow the calendar, so a DST change doesn't
 * shift them. */
export function timeTicks(x0: number, x1: number, width: number): { ticks: number[]; step: number } {
  const want = Math.max(2, Math.floor(width / 84));
  const step = TIME_STEPS.find((s) => (x1 - x0) / s <= want) || 172800;
  const ticks: number[] = [];
  if (step >= 3600) {
    const hrs = step / 3600;
    const day = new Date(x0 * 1000);
    day.setHours(0, 0, 0, 0);
    for (let guard = 0; guard < 400 && day.getTime() / 1000 <= x1; guard++) {
      if (hrs >= 24) {
        const t = day.getTime() / 1000;
        if (t >= x0) ticks.push(t);
        day.setDate(day.getDate() + hrs / 24);
      } else {
        for (let h = 0; h < 24; h += hrs) {
          const t = new Date(day.getFullYear(), day.getMonth(), day.getDate(), h).getTime() / 1000;
          if (t >= x0 && t <= x1 && ticks[ticks.length - 1] !== t) ticks.push(t);
        }
        day.setDate(day.getDate() + 1);
      }
    }
  } else {
    const off = new Date(x0 * 1000).getTimezoneOffset() * 60;
    for (let t = Math.ceil((x0 - off) / step) * step + off; t <= x1; t += step) ticks.push(t);
  }
  return { ticks, step };
}

export function tickLabel(t: number, step: number): string {
  const d = new Date(t * 1000);
  if (step >= 86400) return d.toLocaleDateString([], { weekday: "short", day: "numeric" });
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** "14:15–14:30", with the day in front when it isn't today. */
export function bucketLabel(t: number, b: number, now = Date.now() / 1000): string {
  const a = new Date(t * 1000), z = new Date((t + b) * 1000);
  const hm = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const day = a.toDateString() === new Date(now * 1000).toDateString() ? "" : a.toLocaleDateString([], { weekday: "short", day: "numeric" }) + " ";
  return `${day}${hm(a)}–${hm(z)}`;
}

/** A column with rounded top corners. */
export function colPath(x: number, y: number, w: number, h: number, r: number): string {
  if (h <= 0) return "";
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

// ------------------------------------------------------------------ files

/** A spreadsheet cell: quoted when it holds a separator, a quote or a line break. */
export function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",;\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** The hour file holding unix time t, named in local time. */
export function hourFile(t: number): string {
  const d = new Date(t * 1000), day = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  return `${day}/zigbee_${day}_${pad(d.getHours())}.pcap`;
}

/** The hour in a capture file name ("…_17.pcap" -> "17"). */
export const fileHour = (file: string) => (file.match(/_(\d\d)\.pcap$/) || [])[1] || "??";

// ------------------------------------------------------------------ frames

export type FrameKind = "noack" | "" | "data" | "nwkcmd" | "mac" | "ack" | "retry";

export function kindOk(kind: FrameKind | string, f: any): boolean {
  switch (kind) {
    case "data": return f.type === "data" && !/command/i.test(f.kind) && !/Link Status|Route|Leave|Rejoin|Network Status/.test(f.kind);
    case "nwkcmd": return f.type === "data" && /command|Link Status|Route|Leave|Rejoin|Network Status|Timeout/.test((f.kind || "") + (f.info || ""));
    case "mac": return f.type === "command" || f.type === "beacon";
    case "ack": return f.type === "ack";
    case "retry": return !!f.retry;
    case "noack": return f.type !== "ack";
    default: return true;
  }
}

/** What the live filter searches: the fields the table shows (cached on the frame). */
export function frameHay(f: any, time: (ts: number) => string): string {
  if (f._h) return f._h;
  const parts = [time(f.ts), f.rssi, f.kind, f.retry ? "resent" : "", f.late ? "buffered" : "", f.ours ? "" : `PAN ${f.pan || "none"}`,
    f.src, f.src_name, f.dst, f.dst_name, f.nwk_src, f.nwk_src_name, f.nwk_dst, f.nwk_dst_name, f.proto, f.info,
    ...(Array.isArray(f.heard_by) ? f.heard_by.map((h: any) => h.name) : [])];
  return (f._h = parts.filter((x) => x !== null && x !== undefined && x !== "").join(" ").toLowerCase());
}

/** A gap row is shown only between two frames (never first, last or next to another gap). */
export function dropLoneGaps<T extends { gap?: boolean }>(list: T[]): T[] {
  return list.filter((f, i) => !f.gap || (i > 0 && i < list.length - 1 && !list[i - 1].gap));
}

export interface TreeNode { text: string; children: TreeNode[] }

/** tshark's text decode: the indented tree (4 spaces a level) and the hex dump after it. */
export function splitDecode(text: string): { tree: TreeNode[]; hex: string } {
  const lines = text.replace(/\r/g, "").split("\n");
  let cut = lines.findIndex((l) => /^[0-9a-f]{4}  /.test(l));
  if (cut < 0) cut = lines.length;
  while (cut > 0 && lines[cut - 1].trim() !== "" && !/^[0-9a-f]{4}  /.test(lines[cut - 1])) cut--;
  const root: TreeNode = { text: "", children: [] };
  const stack: { node: TreeNode; level: number }[] = [{ node: root, level: -1 }];
  for (const line of lines.slice(0, cut).filter((l) => l.trim())) {
    const level = Math.floor((line.match(/^ */)![0].length) / 4);
    const node = { text: line.trim(), children: [] };
    while (stack.length > 1 && stack[stack.length - 1].level >= level) stack.pop();
    stack[stack.length - 1].node.children.push(node);
    stack.push({ node, level });
  }
  return { tree: root.children, hex: lines.slice(cut).join("\n").trim() };
}

/** Layers open, their payload one level down too; bit-level fields (Frame Control etc.) stay folded. */
export function treeOpen(n: TreeNode, depth: number): boolean {
  return depth === 0 ? !/^(Frame \d|IEEE 802\.15\.4 TAP)/.test(n.text)
    : depth === 1 && !/^(Frame Control Field|Security Control Field|FCF|Capability Information|\[)/i.test(n.text);
}

// ------------------------------------------------------------------ ping

export interface PingResult { ok: boolean; rtt?: number | null; req?: boolean; none?: boolean; err?: string }

export function pingStats(res: PingResult[]): { answered: number; total: number; pct: number; median: number | null; max: number | null } {
  const ok = res.filter((x) => x.ok);
  const rtts = ok.map((x) => x.rtt).filter((v): v is number => v !== null && v !== undefined).sort((a, b) => a - b);
  const m = rtts.length;
  const median = m ? (m % 2 ? rtts[(m - 1) / 2] : (rtts[m / 2 - 1] + rtts[m / 2]) / 2) : null;
  return { answered: ok.length, total: res.length, pct: Math.round((100 * ok.length) / Math.max(1, res.length)), median, max: m ? rtts[m - 1] : null };
}

export function pingWord(x: PingResult, ms: (v: number) => string): string {
  return x.ok ? ms(x.rtt ?? 0) : x.err ? "error" : x.none ? "no trace" : x.req ? "no reply" : "request not heard";
}

/** A message's hops, with resends of the same hop folded into one step. */
export function foldHops<H extends { from: string; to: string; acked?: boolean; rssi?: number }>(hops: H[]): (H & { tries: number })[] {
  const steps: (H & { tries: number })[] = [];
  for (const h of hops || []) {
    const last = steps[steps.length - 1];
    if (last && last.from === h.from && last.to === h.to) {
      last.tries++;
      last.acked = last.acked || h.acked;
      last.rssi = h.rssi;
      continue;
    }
    steps.push({ ...h, tries: 1 });
  }
  return steps;
}

// ------------------------------------------------------------------ mesh

/** A link's cost: the worse of its two directions, or null when neither is known. */
export const worst = (e: { ab?: number | null; ba?: number | null }) => Math.max(e.ab ?? 0, e.ba ?? 0) || null;

export const BROADCASTS = new Set(["0xffff", "0xfffd", "0xfffc", "0xfffb"]);
