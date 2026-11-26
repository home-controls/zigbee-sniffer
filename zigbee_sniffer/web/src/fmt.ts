// The Sniffer's own wording for numbers, times and sizes, on top of the kit's (kit/format.ts):
// "—" for no value, "just now", "5 min ago". Pure functions (no DOM), so the tests can run them.

const DASH = "—";
export const pad = (n: number, w = 2) => String(n).padStart(w, "0");

/** A number from an API field, or null (bridge-reported values may be missing or not numbers). */
export function num(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

export function n(v: number | null | undefined): string {
  return v === null || v === undefined || !Number.isFinite(v) ? DASH : Math.round(v).toLocaleString();
}

export function compact(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  const a = Math.abs(v);
  if (a >= 1e6) return (v / 1e6).toFixed(a >= 1e7 ? 0 : 1) + "M";
  if (a >= 1e4) return (v / 1e3).toFixed(a >= 1e5 ? 0 : 1) + "K";
  return Number.isInteger(v) ? v.toLocaleString() : (+v.toFixed(a >= 10 ? 1 : 2)).toLocaleString();
}

/** A percentage already in 0-100: "0.4%", "12%". */
export function pct(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  return (v > 0 && v < 10 ? v.toFixed(1) : String(Math.round(v))) + "%";
}

export function dbm(v: number | null | undefined): string {
  return v === null || v === undefined ? DASH : Math.round(v) + " dBm";
}

export function hm(ts: number): string {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function clock(ts: number): string {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function clockMs(ts: number): string {
  const d = new Date(ts * 1000);
  return `${clock(ts)}.${pad(d.getMilliseconds(), 3)}`;
}

/** The time of day, with the weekday in front when it isn't today. */
export function when(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return DASH;
  const d = new Date(ts * 1000);
  if (d.toDateString() === new Date(now * 1000).toDateString()) return hm(ts);
  return d.toLocaleDateString([], { weekday: "short" }) + " " + hm(ts);
}

/** "just now", "40 s ago", "5 min ago", "3.2 h ago", "4 d ago"; `never` when there is no time. */
export function ago(ts: number | null | undefined, now = Date.now() / 1000, never = DASH): string {
  if (!ts) return never;
  const s = Math.max(0, now - ts);
  if (s < 10) return "just now";
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${(s / 3600).toFixed(s < 36000 ? 1 : 0)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** A span of time ("40 s", "12 min", "3 h 5 min", "2 d 4 h") and a size ("1.5 MiB"): the kit's words. */
export { duration as dur, bytes } from "./kit/format";

export function mb(v: number | null | undefined): string {
  if (v === null || v === undefined) return DASH;
  return v >= 100 ? Math.round(v).toLocaleString() : (+v.toFixed(1)).toLocaleString();
}

export const plural = (k: number, one: string, many = one + "s") => `${k} ${k === 1 ? one : many}`;

export const TYPE_WORD: Record<string, string> = { Router: "Router", EndDevice: "End device", Coordinator: "Coordinator" };
export const RANGE_WORD: Record<string, string> = { "1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours", "7d": "last 7 days" };
export const BUCKET_WORD: Record<number, string> = { 60: "minute", 300: "5 minutes", 900: "15 minutes", 3600: "hour" };
export const CTX_WORD: Record<string, string> = { incident: "during incident", ota: "during firmware update" };
