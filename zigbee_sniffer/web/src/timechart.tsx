// The Sniffer's time chart, drawn like the kit's charts (same classes: legend, crosshair, tooltip,
// table view) but with what the Sniffer's history needs: one slot per bucket (columns, lines, a
// min-max band, stacks), partial buckets shaded, incidents as bands behind, events as marks,
// labelled reference lines, and a click (or a second tap) on a bucket opens its frames in Captures.

import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { useWidth } from "./kit/chart";
import { compact, clock } from "./fmt";
import { bucketLabel, capturesLink, colPath, niceTicks, tickLabel, timeTicks } from "./logic";
import { SevIcon } from "./bits";

export type Val = number | [number, number] | null;
export interface Series {
  name: string; color: string; kind: "col" | "line" | "band"; data: Map<number, any>;
  stack?: boolean; fmt?: (v: number) => string; legend?: boolean;
  /** A sparse series (a device heard now and then): dashed across the gaps, so it reads as one line. */
  connect?: boolean;
}
export interface Mark { ts: number; kind: string; text?: string }
export interface Incident { start: number; end?: number | null; sev: string; title: string }

const MARK_WARN = new Set(["z2m_offline", "ota_failed", "sniffer_disconnected", "sniffer_offline"]);
const INC_COLOR: Record<string, string> = { high: "var(--bad)", warn: "var(--warn)", info: "var(--muted)" };
const M = { l: 44, r: 12, t: 10, b: 22 };

export function TipRow({ color, value, label, rect }: { color?: string | null; value: ComponentChildren; label: ComponentChildren; rect?: boolean }) {
  return (
    <div class="tip-row">
      {color ? <i class={`key ${rect ? "rect" : "line"}`} style={{ background: color }} /> : <i class="key none" />}
      <b>{value}</b><span class="muted">{label}</span>
    </div>
  );
}

export function TimeChart(c: {
  x0: number; x1: number; bucket: number; series: Series[]; label: string; height?: number;
  yMin?: number; yMax?: number; yMaxAuto?: boolean; zero?: boolean; yFmt?: (v: number) => string; ticks?: number;
  thresholds?: { y: number; label: string }[]; marks?: Mark[]; incidents?: Incident[];
  tip?: (i: number, t: number) => ComponentChildren; capAddr?: string; pick?: boolean; emptyText?: string;
}) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const [pinned, setPinned] = useState(false);
  const lastType = useRef("mouse");
  // a pinned tooltip (touch) goes away on a tap anywhere else
  useEffect(() => {
    if (!pinned) return;
    const off = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) { setPinned(false); setHover(null); } };
    document.addEventListener("pointerdown", off, true);
    return () => document.removeEventListener("pointerdown", off, true);
  }, [pinned]);

  const W = Math.max(260, width), H = c.height || 170;
  const pw = W - M.l - M.r, ph = H - M.t - M.b;
  const b = c.bucket, x0 = Math.floor(c.x0 / b) * b, n = Math.max(1, Math.ceil((c.x1 - x0) / b));
  const xEnd = x0 + n * b;
  const times = Array.from({ length: n }, (_, i) => x0 + i * b);
  const slot = pw / n, X = (i: number) => M.l + i * slot, TX = (t: number) => M.l + ((t - x0) / (n * b)) * pw;
  const partial = (i: number) => times[i] + b > c.x1;
  const marks = (c.marks || []).filter((m) => typeof m.ts === "number" && m.ts >= x0 && m.ts <= xEnd);
  const incs = (c.incidents || []).filter((i) => typeof i.start === "number" && i.start <= xEnd && (i.end ?? c.x1) >= x0);
  const series = c.series.map((s) => ({ ...s, vals: times.map((t) => (s.data.has(t) ? s.data.get(t) : null)) as any[], y0: [] as number[], y1: [] as number[] }));
  const base = times.map(() => 0);
  for (const s of series.filter((x) => x.stack)) {
    s.y0 = base.slice();
    s.vals.forEach((v, i) => { if (v !== null) base[i] += v; });
    s.y1 = base.slice();
  }
  let lo = Infinity, hi = -Infinity, any = false;
  for (const s of series) {
    s.vals.forEach((v, i) => {
      if (v === null || v === undefined) return;
      any = true;
      const vs = s.kind === "band" ? v : s.stack ? [s.y1[i]] : [v];
      for (const x of vs) if (x !== null && x !== undefined) { lo = Math.min(lo, x); hi = Math.max(hi, x); }
    });
  }
  if (!any) { lo = 0; hi = 1; }
  if (c.zero !== false) lo = Math.min(0, lo);
  if (c.yMin !== undefined) lo = c.yMin;
  if (c.yMax !== undefined) hi = Math.max(c.yMax, c.yMaxAuto ? hi : c.yMax);
  if (c.zero === false && any) { const padv = Math.max(2, (hi - lo) * 0.1); lo -= padv; hi += padv; }
  const yt = niceTicks(lo, hi, c.ticks || 4);
  const Y = (v: number) => M.t + ph - ((v - yt.lo) / (yt.hi - yt.lo || 1)) * ph;
  const yFmt = c.yFmt || compact;
  const tt = timeTicks(x0, xEnd, pw);
  const bw = Math.max(1, Math.min(24, slot - Math.min(2, slot * 0.3)));
  const cx = (i: number) => X(i) + slot / 2;

  const shapes: preact.JSX.Element[] = [];
  for (const s of series) {
    if (s.kind === "col") {
      s.vals.forEach((v, i) => {
        if (!v) return;
        const y0 = s.stack ? s.y0[i] : 0, y1 = s.stack ? s.y1[i] : v;
        const top = Y(y1), bot = Y(y0) - (y0 > 0 && slot > 4 ? 2 : 0);
        const isTop = !s.stack || series.filter((o) => o.stack && o.kind === "col").every((o) => o === s || o.y1[i] <= y1);
        shapes.push(<path d={colPath(X(i) + (slot - bw) / 2, top, bw, Math.max(0.5, bot - top), isTop && bw > 5 ? 4 : bw > 3 ? 1 : 0)}
          fill={s.color} opacity={partial(i) ? 0.5 : undefined} />);
      });
    } else if (s.kind === "band") {
      let seg: [number, [number, number]][] = [];
      const flush = () => {
        if (seg.length === 1) {
          const [i, v] = seg[0];
          shapes.push(<rect x={cx(i) - 2} y={Y(v[1])} width={4} height={Math.max(1, Y(v[0]) - Y(v[1]))} fill={s.color} opacity={0.18} rx={2} />);
        } else if (seg.length) {
          const top = seg.map(([i, v]) => `${cx(i).toFixed(1)},${Y(v[1]).toFixed(1)}`);
          const bot = seg.slice().reverse().map(([i, v]) => `${cx(i).toFixed(1)},${Y(v[0]).toFixed(1)}`);
          shapes.push(<polygon points={`${top.join(" ")} ${bot.join(" ")}`} fill={s.color} opacity={0.14} />);
        }
        seg = [];
      };
      s.vals.forEach((v, i) => { if (v && v[0] !== null) seg.push([i, v]); else flush(); });
      flush();
    } else {
      let seg: [number, number][] = [];
      const flush = () => {
        if (seg.length === 1) shapes.push(<circle cx={cx(seg[0][0])} cy={Y(seg[0][1])} r={2.5} fill={s.color} />);
        else if (seg.length) shapes.push(<polyline points={seg.map(([i, v]) => `${cx(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" ")}
          fill="none" stroke={s.color} stroke-width={2} stroke-linejoin="round" stroke-linecap="round" />);
        seg = [];
      };
      s.vals.forEach((v, i) => { if (v !== null && v !== undefined) seg.push([i, s.stack ? s.y1[i] : v]); else flush(); });
      flush();
      if (s.connect) {
        let prev: [number, number] | null = null;
        s.vals.forEach((v, i) => {
          if (v === null || v === undefined) return;
          if (prev && i - prev[0] > 1) shapes.push(<line x1={cx(prev[0])} y1={Y(prev[1])} x2={cx(i)} y2={Y(v)} stroke={s.color} stroke-width={1.2} stroke-dasharray="3 4" opacity={0.7} />);
          prev = [i, v];
        });
      }
    }
  }

  const idxAt = (e: PointerEvent | MouseEvent) => {
    const box = (e.currentTarget as SVGRectElement).getBoundingClientRect();
    return Math.max(0, Math.min(n - 1, Math.floor(((e.clientX - box.left) / box.width) * n)));
  };
  const open = (i: number) => {
    if (c.pick === false) return;
    setPinned(false);
    setHover(null);
    location.hash = capturesLink({ t: times[i], addr: c.capAddr });
  };
  const onClick = (e: MouseEvent) => {
    const i = idxAt(e);
    if (lastType.current === "touch") {
      if (pinned && hover === i) { open(i); return; }
      setPinned(true);
      setHover(i);
      return;
    }
    open(i);
  };

  const legend = series.filter((s) => s.legend !== false);
  const tipBody = (i: number) => {
    const t0 = times[i], t1 = t0 + b;
    const here = marks.filter((m) => m.ts >= t0 && m.ts < t1);
    return (
      <>
        <div class="tip-head">{bucketLabel(t0, b)}{partial(i) ? " (so far)" : ""}</div>
        {c.tip ? c.tip(i, t0) : series.map((s) => {
          const v = s.vals[i];
          if (s.kind === "band") return v && v[0] !== null ? <TipRow value={`${v[0]} to ${v[1]}`} label={s.name} /> : null;
          return <TipRow color={s.color} rect={s.kind === "col"} value={v === null || v === undefined ? "—" : (s.fmt || yFmt)(v)} label={s.name} />;
        })}
        {incs.filter((inc) => inc.start < t1 && (inc.end ?? c.x1) >= t0).map((inc) => <div class="tip-inc"><SevIcon sev={inc.sev} /> {inc.title}</div>)}
        {here.slice(0, 6).map((m) => <div class={`tip-mark ${MARK_WARN.has(m.kind) ? "warn" : ""}`}>{clock(m.ts)} {m.text || m.kind}</div>)}
        {here.length > 6 && <div class="tip-mark">+{here.length - 6} more</div>}
        {c.pick !== false && <div class="tip-hint">{pinned ? "Tap again" : "Click"} to see these frames in Captures</div>}
      </>
    );
  };
  const tableSeries = series.filter((s) => s.kind !== "band");
  return (
    <div class="chart tchart" ref={ref}>
      {legend.length >= 2 && (
        <div class="chart-legend">
          {legend.map((s) => <span><i class={`key ${s.kind === "col" ? "rect" : s.kind === "band" ? "band" : "line"}`} style={{ background: s.color }} />{s.name}</span>)}
        </div>
      )}
      <div class="chart-box">
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={c.label}>
          {incs.map((inc) => {
            const s = Math.max(inc.start, x0), e = Math.min(inc.end ?? c.x1, xEnd);
            return <rect class="inc-band" x={TX(s)} y={M.t} width={Math.max(2, TX(e) - TX(s))} height={ph} fill={INC_COLOR[inc.sev] || INC_COLOR.info} />;
          })}
          {yt.ticks.map((v) => (
            <g>
              <line class="grid" x1={M.l} x2={W - M.r} y1={Y(v)} y2={Y(v)} />
              <text class="tick" x={M.l - 6} y={Y(v) + 4} text-anchor="end">{yFmt(v)}</text>
            </g>
          ))}
          {tt.ticks.map((t) => {
            const x = TX(t);
            return x >= M.l + 12 && x <= W - M.r - 12 ? <text class="tick" x={x} y={H - 6} text-anchor="middle">{tickLabel(t, tt.step)}</text> : null;
          })}
          <line class="baseline" x1={M.l} x2={W - M.r} y1={Y(yt.lo)} y2={Y(yt.lo)} />
          {(c.thresholds || []).filter((th) => th.y > yt.lo && th.y < yt.hi).map((th) => (
            <g>
              <line class="thresh" x1={M.l} x2={W - M.r} y1={Y(th.y)} y2={Y(th.y)} />
              <text class="tick ref" x={W - M.r - 2} y={Y(th.y) - 4} text-anchor="end">{th.label}</text>
            </g>
          ))}
          {shapes}
          {marks.map((m) => <line class={`mark ${MARK_WARN.has(m.kind) ? "warn" : ""}`} x1={TX(m.ts)} x2={TX(m.ts)} y1={M.t} y2={M.t + ph} />)}
          {!any && <text class="nodata" x={M.l + pw / 2} y={M.t + ph / 2} text-anchor="middle">{c.emptyText || "No data in this time range yet"}</text>}
          {hover !== null && <line class="crosshair" x1={cx(hover)} x2={cx(hover)} y1={M.t} y2={M.t + ph} />}
          <rect class={`hit ${c.pick === false ? "nopick" : ""}`} x={M.l} y={M.t} width={pw} height={ph} fill="transparent"
            onPointerDown={(e) => { lastType.current = e.pointerType; }}
            onPointerMove={(e) => { if (e.pointerType !== "touch") setHover(idxAt(e)); }}
            onPointerLeave={(e) => { if (e.pointerType !== "touch" && !pinned) setHover(null); }}
            onClick={onClick} />
        </svg>
        {hover !== null && hover < n && (
          <div class="chart-tip" style={cx(hover) > W / 2 ? { right: `${W - cx(hover) + 10}px` } : { left: `${cx(hover) + 10}px` }}>{tipBody(hover)}</div>
        )}
      </div>
      {any && (
        <details class="chart-table">
          <summary>Table</summary>
          <div class="table-wrap">
            <table class="data">
              <thead><tr><th>Time</th>{tableSeries.map((s) => <th class="num">{s.name}</th>)}</tr></thead>
              <tbody>
                {times.map((t, i) => tableSeries.some((s) => s.vals[i] !== null && s.vals[i] !== undefined) && (
                  <tr><td>{bucketLabel(t, b)}</td>{tableSeries.map((s) => {
                    const v = s.vals[i];
                    return <td class="num">{v === null || v === undefined ? "—" : (s.fmt || yFmt)(v)}</td>;
                  })}</tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}
