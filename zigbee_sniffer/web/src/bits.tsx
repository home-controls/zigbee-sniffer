// The Sniffer's small building blocks on top of the kit: severity marks, device links, link costs,
// signal meters, sparklines, findings, incidents, events and firmware downloads.

import type { ComponentChildren } from "preact";
import { Icon } from "./kit/icons";
import { Chip, Stat } from "./kit/ui";
import * as f from "./fmt";
import { BROADCASTS, capturesLink, deviceLink } from "./logic";
import { several } from "./store";

export type Sev = "high" | "warn" | "info" | "good";
const SEV_WORD: Record<Sev, string> = { high: "Problem", warn: "Warning", info: "Note", good: "OK" };
const SEV_ICON: Record<Sev, string> = { high: "alert", warn: "alert", info: "info", good: "check" };
export const SEV_TONE: Record<string, "bad" | "warn" | "muted" | "ok"> = { high: "bad", warn: "warn", info: "muted", good: "ok" };

export function SevIcon({ sev }: { sev?: string }) {
  const k = (sev && sev in SEV_WORD ? sev : "info") as Sev;
  return (
    <span class={`sev sev-${k}`} title={SEV_WORD[k]}>
      <span class="sr-only">{SEV_WORD[k]}: </span>
      <Icon name={SEV_ICON[k]} size={16} />
    </span>
  );
}

export function Spin() {
  return <span class="spin" aria-hidden="true" />;
}

export function Loading({ children = "Loading…" }: { children?: ComponentChildren }) {
  return <div class="empty"><Spin /> {children}</div>;
}

export function PageError({ err, what = "Couldn't load this page" }: { err: string | null; what?: string }) {
  if (!err) return null;
  return <p class="note warn"><Icon name="alert" size={16} /> {what}: {err}</p>;
}

export function DevLink({ addr, name }: { addr?: string | null; name?: string | null }) {
  if (!addr) return null;
  return <a href={deviceLink(addr)} class="name">{name || addr}</a>;
}

/** A device by name (a link), a bare address, or "broadcast". */
export function AddrLabel({ addr, name }: { addr?: string | null; name?: string | null }) {
  if (!addr) return null;
  if (BROADCASTS.has(addr)) return <span class="muted">broadcast</span>;
  return name ? <DevLink addr={addr} name={name} /> : <span class="mono">{addr}</span>;
}

export type CostClass = "good" | "fair" | "poor" | "bad" | "unknown";
export function costClass(c: number | null | undefined): CostClass {
  if (!c) return "unknown";
  return c <= 2 ? "good" : c <= 4 ? "fair" : c <= 6 ? "poor" : "bad";
}

export function CostChip({ c }: { c: unknown }) {
  const v = f.num(c);
  if (!v) return <span class="cost cost-unknown" title="not known yet">–</span>;
  return <span class={`cost cost-${costClass(v)}`} title={`link cost ${v} (1 best, 7 worst)`}>{v}</span>;
}

export function CostLegend() {
  return (
    <span class="chart-legend map-legend">
      <span>Link cost</span>
      <span><CostChip c={1} /> <CostChip c={2} /> good</span>
      <span><CostChip c={3} /> <CostChip c={4} /> fair</span>
      <span><CostChip c={5} /> <CostChip c={6} /> poor</span>
      <span><CostChip c={7} /> bad</span>
    </span>
  );
}

export const level = (rssi: number | null | undefined) => (rssi === null || rssi === undefined ? "none" : rssi >= -75 ? "good" : rssi >= -88 ? "ok" : "faint");

/** Where a signal sits between -105 and -35 dBm: its average and the min-max span. */
export function Meter({ avg, min, max }: { avg: number | null; min?: number | null; max?: number | null }) {
  if (avg === null) return <span class="muted">not heard directly</span>;
  const lo = -105, hi = -35, w = 64;
  const x = (v: number) => Math.max(0, Math.min(w, ((v - lo) / (hi - lo)) * w));
  const l = level(avg);
  const hasSpan = min !== null && min !== undefined && max !== null && max !== undefined;
  return (
    <span class="sig-meter" title={`average ${Math.round(avg)} dBm${hasSpan ? `, range ${min} to ${max}` : ""}`}>
      <span class="track">
        {hasSpan && <span class={`span lvl-${l}`} style={{ left: `${x(min!)}px`, width: `${Math.max(3, x(max!) - x(min!))}px` }} />}
        <span class={`avg lvl-${l}`} style={{ left: `${x(avg) - 1}px` }} />
      </span>
      <span class="num">{Math.round(avg)}</span>
    </span>
  );
}

export function Spark({ vals, w = 96, h = 24, color = "var(--series-1)", min, max, minSpan = 0 }: {
  vals: (number | null)[]; w?: number; h?: number; color?: string; min?: number; max?: number; minSpan?: number;
}) {
  const fin = vals.filter((v): v is number => v !== null && v !== undefined);
  if (!fin.length) return <svg class="spark" width={w} height={h} aria-hidden="true" />;
  let lo = min ?? Math.min(...fin), hi = max ?? Math.max(...fin);
  if (hi - lo < minSpan) { const mid = (hi + lo) / 2; lo = mid - minSpan / 2; hi = mid + minSpan / 2; }
  if (hi === lo) { hi += 1; lo -= 1; }
  const len = vals.length;
  const X = (i: number) => 2 + (i * (w - 6)) / Math.max(1, len - 1);
  const Y = (v: number) => h - 3 - ((v - lo) / (hi - lo)) * (h - 6);
  let d = "", pen = false, last = 0;
  vals.forEach((v, i) => {
    if (v === null || v === undefined) { pen = false; return; }
    d += `${pen ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`;
    pen = true;
    last = i;
  });
  return (
    <svg class="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
      <path d={d} fill="none" stroke={color} stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" />
      <circle cx={X(last)} cy={Y(vals[last]!)} r="2.4" fill={color} />
    </svg>
  );
}

/** A number tile; a link when `href` is given. */
export function Tile({ label, value, sub, href, extra, title, tone }: {
  label: string; value: ComponentChildren; sub?: ComponentChildren; href?: string; extra?: ComponentChildren; title?: string; tone?: string;
}) {
  const inner = <Stat label={label} value={value} tone={tone} sub={<>{extra}{sub && <div>{sub}</div>}</>} />;
  return href ? <a class="tile" href={href} title={title}>{inner}</a> : <div class="tile" title={title}>{inner}</div>;
}

export const Unit = ({ children }: { children: ComponentChildren }) => <span class="unit"> {children}</span>;

// ------------------------------------------------------------------ findings

export interface Finding { sev: string; text: string; context?: string | null; detail?: string | null; addr?: string; name?: string }

export const FindingTag = ({ x }: { x?: Finding }) => (x && x.context && f.CTX_WORD[x.context] ? <> <span class="tag">{f.CTX_WORD[x.context]}</span></> : null);

export function FindingsList({ flags, empty, who }: { flags: Finding[] | null | undefined; empty: string; who?: boolean }) {
  if (!flags || !flags.length) return <ul class="flist"><li class="ok"><SevIcon sev="good" /><div>{empty}</div></li></ul>;
  return (
    <ul class="flist">
      {flags.map((x) => (
        <li>
          <SevIcon sev={x.sev} />
          <div>
            <div>
              {who && <><span class="who">{x.addr ? <DevLink addr={x.addr} name={x.name} /> : x.name}</span> </>}
              <span class="what">{x.text}</span><FindingTag x={x} />
            </div>
            {x.detail && <div class="fdetail">{x.detail}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}

// ------------------------------------------------------------------ incidents

/** Incidents, ongoing and newest first: title, span, likely cause, detail or evidence, devices, a
 * link to the frames at the start. */
export function Incidents({ list, addr }: { list: any[]; addr?: string }) {
  const now = Date.now() / 1000;
  const sorted = list.slice().sort((a, b) => Number(b.end == null) - Number(a.end == null) || (f.num(b.start) || 0) - (f.num(a.start) || 0));
  return (
    <ul class="flist">
      {sorted.map((i) => {
        const start = f.num(i.start) || 0, end = f.num(i.end);
        const ev = i.evidence || {};
        const bits: string[] = [];
        if (f.num(ev.traffic_x) !== null) bits.push(`traffic ×${(+ev.traffic_x).toFixed(1)} the usual`);
        if (f.num(ev.busy_pct) !== null) bits.push(`channel busy ${f.pct(+ev.busy_pct)}`);
        if (f.num(ev.retry_pct) !== null) bits.push(`resent ${f.pct(+ev.retry_pct)}`);
        if (f.num(ev.route_failures)) bits.push(`${f.n(+ev.route_failures)} route failures`);
        if (f.num(ev.devices_n)) bits.push(`${f.n(+ev.devices_n)} devices`);
        if (f.num(ev.ota_n)) bits.push(`${f.n(+ev.ota_n)} firmware updates`);
        const devs: any[] = Array.isArray(i.devices) ? i.devices : [];
        return (
          <li>
            <SevIcon sev={i.sev} />
            <div class="inc">
              <div>
                <b>{i.title}</b>{end ? null : <> <Chip tone="warn">ongoing</Chip></>}{" "}
                <span class="ink2">{f.when(start)} – {end ? f.when(end) : "now"} <span class="muted">({end ? f.dur(end - start) : "ongoing for " + f.dur(now - start)})</span></span>
              </div>
              {i.cause && <div class="ink2">Likely cause: {i.cause}</div>}
              {i.detail && <div class="fdetail">{i.detail}</div>}
              {bits.length > 0 && !i.detail && <div class="fdetail">{bits.join(" · ")}</div>}
              <div class="inc-foot">
                {devs.length > 0 && (
                  <details>
                    <summary>{f.plural(devs.length, "device")}</summary>
                    <div class="dev-links">{devs.map((x) => <DevLink addr={x.addr} name={x.name || x.addr} />)}</div>
                  </details>
                )}
                <a href={capturesLink({ t: start, addr })}>frames at the start</a>
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ------------------------------------------------------------------ events

export const EV_SEV: Record<string, Sev> = {
  leave: "high", rejoin: "warn", rejoin_response: "warn", network_status: "warn", orphan: "warn",
  address_change: "warn", address_reused: "warn", network_report: "warn", announce: "info", association: "info",
  association_response: "info", ed_timeout: "info", network_update: "info",
  sniffer_offline: "high", sniffer_back: "info", sniffer_disconnected: "info", sniffer_connected: "info",
  bridge_reboot: "warn", radio_reboot: "warn", firmware_update: "info", channel: "info",
};

/** Events; `me` is the device whose page this is (its name is left out of its own events). */
export function EventsTable({ events, me }: { events: any[] | null | undefined; me?: string }) {
  if (!events || !events.length) return <div class="empty">No events in this time range.</div>;
  return (
    <div class="table-wrap">
      <table class="data dense">
        <tbody>
          {events.map((e) => (
            <tr>
              <td class="muted nowrap" title={new Date(e.ts * 1000).toLocaleString()}>{f.when(e.ts)}</td>
              <td><SevIcon sev={EV_SEV[e.kind] || "info"} /></td>
              <td class="wrap">
                {e.addr && e.addr !== me && e.addr !== "sniffer" && <><DevLink addr={e.addr} name={e.name || e.addr} /> </>}
                <span class="ink2">{e.detail || e.what || e.kind}</span>
              </td>
              <td class="num">
                {e.file && e.n ? <a href={capturesLink({ file: e.file, n: f.num(e.n) || 0 })} title="Open this frame in Captures" aria-label="Open this frame in Captures">↗</a> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------ firmware downloads

const OTA_TONE: Record<string, "warn" | "ok" | "bad" | "info"> = { updating: "info", stalled: "warn", done: "ok", failed: "bad" };

export const OtaBadge = ({ o }: { o: any }) => <Chip tone={OTA_TONE[o.state] || "muted" as any}>{o.state || ""}</Chip>;

/** A download's progress (0-1); `from` is where it picked up after an earlier one was cut off (shaded). */
export function OtaBar({ p, from }: { p: unknown; from?: unknown }) {
  const v = f.num(p);
  if (v === null) return null;
  const pc = Math.max(0, Math.min(100, v * 100)), fr = Math.max(0, Math.min(pc, (f.num(from) || 0) * 100));
  return (
    <span class="ota-progress">
      <span class="pbar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(pc)}
        title={fr ? `picked up at ${Math.round(fr)}% (an earlier download was cut off)` : undefined}>
        {fr > 0 && <b style={{ width: `${fr.toFixed(1)}%` }} />}
        <i style={{ left: `${fr.toFixed(1)}%`, width: `${(pc - fr).toFixed(1)}%` }} />
      </span>
      {Math.round(pc)}%
    </span>
  );
}

/** What a firmware download is doing, in words: "about 3 min left", "restarted 21:14", "aborted". */
export function otaStatus(o: any): string {
  const hmOf = (ts: unknown) => (f.num(ts) ? f.hm(+ts!) : "");
  if (o.state === "updating") return [f.num(o.eta) ? `about ${f.dur(+o.eta)} left` : "", f.num(o.rate) ? `${f.bytes(+o.rate * 60)}/min` : ""].filter(Boolean).join(" · ");
  if (o.state === "stalled") return `no block since ${hmOf(o.last_ts)}`;
  if (o.state === "done") return o.restarted ? `restarted ${hmOf(o.restarted)}` : `finished ${hmOf(o.result_ts || o.last_ts)}`;
  return o.result ? String(o.result).replace(/^firmware (download ended|update failed)[^:]*: ?/i, "") : "";
}

export function otaDownload(o: any): string {
  const parts: string[] = [];
  if (f.num(o.bytes)) parts.push(`${f.bytes(+o.bytes)} in ${f.dur(+o.duration)}`);
  if (f.num(o.from)) parts.push(`picked up at ${Math.round(o.from * 100)}%`);
  if (f.num(o.size)) parts.push(`image ${f.bytes(+o.size)}`);
  return parts.join(" · ");
}

/** Zigbee2MQTT's view of a device's firmware: "1.0.43.0 → 1.0.44.0" (update available) or "1.0.43.0" (latest). */
export function FwVersion({ z }: { z: any }) {
  if (!z || !(z.installed || z.latest)) return <span class="muted">—</span>;
  const t = z.notes || undefined;
  if (z.latest && z.installed && z.latest !== z.installed) return <span title={t}>{z.installed} → <b>{z.latest}</b></span>;
  return <span title={t}>{z.installed || z.latest}{z.state === "idle" && <span class="sub"> latest</span>}</span>;
}

export function OtaTable({ list }: { list: any[] }) {
  return (
    <div class="table-wrap">
      <table class="data dense">
        <thead><tr><th>Device</th><th>Download</th><th>Progress</th><th title="Zigbee2MQTT: installed → latest">Version</th><th>Data</th><th>Started</th></tr></thead>
        <tbody>
          {list.map((o) => (
            <tr>
              <td><DevLink addr={o.addr} name={o.name || o.addr} /></td>
              <td><OtaBadge o={o} /> <span class="sub">{otaStatus(o)}</span></td>
              <td><OtaBar p={o.progress} from={o.from} /></td>
              <td><FwVersion z={o.z2m} /></td>
              <td class="muted">{otaDownload(o)}</td>
              <td class="muted nowrap" title={o.started ? new Date(o.started * 1000).toLocaleString() : undefined}>
                {o.started ? <>{f.hm(o.started)} <span class="sub">{f.ago(o.started)}</span></> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function OtaAvailable({ list }: { list: any[] }) {
  if (!list || !list.length) return null;
  return (
    <details class="fw-avail" open={list.length <= 4}>
      <summary><b>{list.length}</b> firmware update{list.length === 1 ? "" : "s"} available in Zigbee2MQTT</summary>
      <ul>
        {list.map((a) => (
          <li><DevLink addr={a.addr} name={a.name} /> <span class="muted"><FwVersion z={a} /></span>{a.state && a.state !== "available" && <> <Chip>{a.state}</Chip></>}</li>
        ))}
      </ul>
    </details>
  );
}

/** The sniffers that heard a frame, after its signal: "×2" (hover for each), or the one's name. */
export function HeardBy({ hb }: { hb: any[] | undefined }) {
  if (!Array.isArray(hb) || !hb.length) return null;
  if (hb.length > 1) return <span class="sub"> ×{hb.length}</span>;
  return several.value ? <span class="sub"> {hb[0].name}</span> : null;
}
export const heardTitle = (hb: any[] | undefined) => (Array.isArray(hb) && hb.length ? hb.map((h) => `${h.name} ${h.rssi} dBm`).join(" · ") : undefined);
