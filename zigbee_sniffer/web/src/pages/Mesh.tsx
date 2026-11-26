// Mesh: who hears whom, from the routers' Link Status (every 15 s), as a force layout. Drag a device
// to move it (it stays there while the app is open), click it to open it, find one by name. Below:
// the weakest links and the routers with the fewest good neighbours.

import { useRef, useState } from "preact/hooks";
import { Card } from "../kit/ui";
import { Icon } from "../kit/icons";
import { useWidth } from "../kit/chart";
import { api } from "../api";
import { usePoll } from "../poll";
import { pref, range, several } from "../store";
import * as f from "../fmt";
import { deviceLink, worst } from "../logic";
import { AddrLabel, CostChip, CostLegend, costClass, DevLink, Loading, PageError } from "../bits";

// kept while the page is away, so coming back finds the same picture
const POS = new Map<string, { x: number; y: number }>();
const PINNED = new Set<string>();
const COORD = "0x0000";
let lastQuery = ""; // the search, kept while the app is open

type Fit = { kx: number; ky: number; ox: number; oy: number };

function layout(nodes: any[], edges: any[], kids: any[], W: number, H: number, relayout: boolean): void {
  const idx = new Map(nodes.map((n, i) => [n.addr, i]));
  const fresh = nodes.some((n) => !POS.has(n.addr));
  for (const n of nodes) {
    if (POS.has(n.addr)) continue;
    const parent = kids.find((k) => k.child === n.addr);
    const near = parent && POS.get(parent.parent);
    POS.set(n.addr, near ? { x: near.x + (Math.random() - 0.5) * 40, y: near.y + (Math.random() - 0.5) * 40 }
      : n.addr === COORD ? { x: W / 2, y: H / 2 } : { x: W / 2 + (Math.random() - 0.5) * W * 0.7, y: H / 2 + (Math.random() - 0.5) * H * 0.7 });
  }
  if (!relayout && !fresh) return;
  const P = nodes.map((n) => POS.get(n.addr)!);
  const springs: [number, number, number, number][] = edges.map((e) => [idx.get(e.a)!, idx.get(e.b)!, 55 + 22 * (worst(e) || 4), 0.06] as [number, number, number, number])
    .concat(kids.map((k) => [idx.get(k.child)!, idx.get(k.parent)!, 26, 0.12] as [number, number, number, number]));
  const iters = relayout ? 420 : 160;
  const vel = P.map(() => ({ x: 0, y: 0 }));
  for (let it = 0; it < iters; it++) {
    const a = 1 - it / iters;
    for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) {
      let dx = P[i].x - P[j].x, dy = P[i].y - P[j].y;
      const d2 = Math.max(dx * dx + dy * dy, 30), fr = (2600 / d2) * a;
      const d = Math.sqrt(d2); dx /= d; dy /= d;
      vel[i].x += dx * fr; vel[i].y += dy * fr; vel[j].x -= dx * fr; vel[j].y -= dy * fr;
    }
    for (const [i, j, L, k] of springs) {
      let dx = P[j].x - P[i].x, dy = P[j].y - P[i].y;
      const d = Math.max(1, Math.hypot(dx, dy)), fr = (d - L) * k * a;
      dx /= d; dy /= d;
      vel[i].x += dx * fr; vel[i].y += dy * fr; vel[j].x -= dx * fr; vel[j].y -= dy * fr;
    }
    P.forEach((p, i) => {
      vel[i].x += (W / 2 - p.x) * 0.004 * (H / W) * a; vel[i].y += (H / 2 - p.y) * 0.004 * a;
      if (PINNED.has(nodes[i].addr) || (nodes[i].addr === COORD && !PINNED.size && relayout && it < 5)) { vel[i].x = vel[i].y = 0; return; }
      p.x += Math.max(-20, Math.min(20, vel[i].x)); p.y += Math.max(-20, Math.min(20, vel[i].y));
      vel[i].x *= 0.6; vel[i].y *= 0.6;
    });
  }
}

/** Fit the layout to the panel: scale each axis, but stretch one at most 1.8x more than the other. */
function fitOf(nodes: any[], W: number, H: number): Fit {
  if (!nodes.length) return { kx: 1, ky: 1, ox: 0, oy: 0 };
  const P = nodes.map((n) => POS.get(n.addr)!);
  const xs = P.map((p) => p.x), ys = P.map((p) => p.y);
  const padX = Math.min(110, W * 0.12), padY = 30;
  const minX = Math.min(...xs), minY = Math.min(...ys), bw = Math.max(1, Math.max(...xs) - minX), bh = Math.max(1, Math.max(...ys) - minY);
  let kx = (W - 2 * padX) / bw, ky = (H - 2 * padY) / bh;
  const k = Math.min(kx, ky);
  kx = Math.min(kx, k * 1.8); ky = Math.min(ky, k * 1.8);
  return { kx, ky, ox: (W - bw * kx) / 2 - minX * kx, oy: (H - bh * ky) / 2 - minY * ky };
}

export function Mesh() {
  const { data, err } = usePoll(30000, () => api(`api/mesh?range=${range.value}`), [range.value]);
  const [links, setLinks] = useState(() => pref.get("mesh.links", "best"));
  const [ed, setEd] = useState(() => pref.flag("mesh.ed", true));
  const [labels, setLabels] = useState(() => pref.flag("mesh.labels", true));
  const [q, setQ] = useState(() => lastQuery);
  const [hit, setHit] = useState(0);
  const [arranged, setArranged] = useState(0);
  const [hover, setHover] = useState<string | null>(null);
  const [tip, setTip] = useState<{ x: number; y: number; body: preact.ComponentChildren } | null>(null);
  const [, setVer] = useState(0);
  const [ref, W] = useWidth();
  const H = Math.round(Math.max(420, Math.min(720, W * 0.62)));
  const svgRef = useRef<SVGSVGElement>(null);
  const done = useRef({ data: null as any, key: "", w: 0 });
  const drag = useRef<{ addr: string; id: number; sx: number; sy: number; moved: boolean; fit: Fit; vx: number; vy: number } | null>(null);

  const setQuery = (v: string) => { setQ(v); setHit(0); lastQuery = v; };

  let body: preact.ComponentChildren = null;
  let tables: preact.ComponentChildren = null;
  let found = "";
  if (data) {
    const childSet = new Set(data.children.map((c: any) => c.child));
    const nodes: any[] = data.nodes.filter((n: any) => ed || !childSet.has(n.addr) || data.edges.some((e: any) => e.a === n.addr || e.b === n.addr));
    const idx = new Map(nodes.map((n, i) => [n.addr, i]));
    let edges: any[] = data.edges.filter((e: any) => idx.has(e.a) && idx.has(e.b));
    if (links === "best") {
      const keep = new Set<any>();
      for (const n of nodes) edges.filter((e) => e.a === n.addr || e.b === n.addr).sort((x, y) => (worst(x) || 9) - (worst(y) || 9)).slice(0, 3).forEach((e) => keep.add(e));
      edges = edges.filter((e) => keep.has(e));
    } else if (links === "weak") edges = edges.filter((e) => (worst(e) || 0) >= 5);
    const kids: any[] = ed ? data.children.filter((c: any) => idx.has(c.child) && idx.has(c.parent)) : [];
    // lay out again: the first time, after Re-arrange, or when the links or end devices shown change
    const key = `${links}|${ed}|${arranged}`;
    if (done.current.data !== data || done.current.key !== key) {
      layout(nodes, edges, kids, W, H, !done.current.data || done.current.key !== key);
      done.current = { data, key, w: W };
    }
    // find
    const ql = q.trim().toLowerCase();
    const hits = ql ? nodes.filter((n) => (n.name || "").toLowerCase().includes(ql) || n.addr.includes(ql)).map((n) => n.addr) : [];
    const focus = hits.length ? hits[((hit % hits.length) + hits.length) % hits.length] : null;
    found = !ql ? "" : !hits.length ? "no match" : hits.length > 1 ? `${(((hit % hits.length) + hits.length) % hits.length) + 1} of ${hits.length} · Enter for the next` : "";
    const fit = drag.current?.moved ? drag.current.fit : fitOf(nodes, W, H);
    const SX = (x: number) => x * fit.kx + fit.ox, SY = (y: number) => y * fit.ky + fit.oy;
    const fp = focus ? POS.get(focus) : undefined;
    const VX = drag.current?.moved ? drag.current.vx : fp ? W / 2 - SX(fp.x) : 0;
    const VY = drag.current?.moved ? drag.current.vy : fp ? H / 2 - SY(fp.y) : 0;
    const at = (a: string): [number, number] => { const p = POS.get(a)!; return [SX(p.x), SY(p.y)]; };
    const active = hover || focus;
    const near = new Set<string>();
    if (active) {
      near.add(active);
      edges.forEach((e) => { if (e.a === active) near.add(e.b); if (e.b === active) near.add(e.a); });
      kids.forEach((k) => { if (k.child === active) near.add(k.parent); if (k.parent === active) near.add(k.child); });
    }
    const byAddr = new Map(nodes.map((n) => [n.addr, n]));
    const nameOf = (a: string) => byAddr.get(a)?.name || a;
    const local = (e: PointerEvent): [number, number] => { const r = svgRef.current!.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    const nodeTip = (n: any, e: PointerEvent) => {
      const [x, y] = local(e);
      const nb = edges.filter((l) => l.a === n.addr || l.b === n.addr).length;
      setTip({ x, y, body: (
        <>
          <div class="tip-head">{f.TYPE_WORD[n.type] || "Device"} · {n.addr}</div>
          <div class="tip-title">{n.name}</div>
          <div class="tip-row"><b>{n.rssi_avg != null ? `${Math.round(n.rssi_avg)} dBm` : "—"}</b> <span class="muted">{several.value ? "at the sniffer that hears it best" : "at the sniffer"}</span></div>
          {n.mesh && <div class="tip-row"><b>{n.mesh.best}–{n.mesh.worst}</b> <span class="muted">link costs, {nb} links</span></div>}
          <div class="tip-row"><b>{f.ago(n.last_seen, undefined, "never")}</b> <span class="muted">last heard</span></div>
        </>
      ) });
    };
    const onDown = (n: any) => (e: PointerEvent) => {
      e.preventDefault();
      svgRef.current?.setPointerCapture(e.pointerId);
      drag.current = { addr: n.addr, id: e.pointerId, sx: e.clientX, sy: e.clientY, moved: false, fit, vx: VX, vy: VY };
      setTip(null);
    };
    const onMove = (e: PointerEvent) => {
      const d = drag.current;
      if (!d || d.id !== e.pointerId) return;
      if (!d.moved && Math.hypot(e.clientX - d.sx, e.clientY - d.sy) < 3) return;
      d.moved = true;
      const [x, y] = local(e);
      const p = POS.get(d.addr)!;
      p.x = (x - d.vx - d.fit.ox) / d.fit.kx;
      p.y = (y - d.vy - d.fit.oy) / d.fit.ky;
      PINNED.add(d.addr);
      setVer((v) => v + 1);
    };
    const onUp = () => {
      const d = drag.current;
      drag.current = null;
      if (d && !d.moved) location.hash = deviceLink(d.addr);
      else setVer((v) => v + 1);
    };
    body = nodes.length ? (
      <svg ref={svgRef} class="mesh" width={W} height={H} viewBox={`0 0 ${W} ${H}`} onPointerMove={onMove} onPointerUp={onUp}
        onPointerCancel={() => { drag.current = null; setVer((v) => v + 1); }} onPointerLeave={() => !drag.current && setTip(null)}>
        <g transform={`translate(${VX.toFixed(1)},${VY.toFixed(1)})`}>
          {kids.map((k) => {
            const [x1, y1] = at(k.child), [x2, y2] = at(k.parent);
            return <line class={`kid ${active && k.child !== active && k.parent !== active ? "faded" : ""}`} x1={x1} y1={y1} x2={x2} y2={y2} />;
          })}
          {edges.map((l) => {
            const [x1, y1] = at(l.a), [x2, y2] = at(l.b);
            return (
              <g class={active && l.a !== active && l.b !== active ? "faded" : ""}>
                <line class={`link mesh-link cost-line-${costClass(worst(l))}`} x1={x1} y1={y1} x2={x2} y2={y2} />
                <line class="link-hit" x1={x1} y1={y1} x2={x2} y2={y2}
                  onPointerMove={(e) => {
                    if (drag.current) return;
                    const [x, y] = local(e as PointerEvent);
                    setTip({ x, y, body: (
                      <>
                        <div class="tip-head">Link · updated {f.ago(l.ts)}</div>
                        <div class="tip-row"><CostChip c={l.ab} /> <span class="muted">{nameOf(l.a)} → {nameOf(l.b)}</span></div>
                        <div class="tip-row"><CostChip c={l.ba} /> <span class="muted">{nameOf(l.b)} → {nameOf(l.a)}</span></div>
                      </>
                    ) });
                  }}
                  onPointerLeave={() => setTip(null)} />
              </g>
            );
          })}
          {nodes.map((n) => {
            const [x, y] = at(n.addr);
            const r = n.addr === COORD ? 10 : n.type === "EndDevice" ? 4.5 : 7;
            const cls = n.addr === COORD ? "n-coord" : n.sev >= 3 ? "n-bad" : n.sev >= 2 ? "n-warn" : n.type === "EndDevice" ? "n-end" : "n-router";
            const isFound = n.addr === focus;
            const showName = (labels && (n.type !== "EndDevice" || nodes.length < 40)) || isFound;
            return (
              <g class={`node ${active && !near.has(n.addr) ? "faded" : ""}`} transform={`translate(${x.toFixed(1)},${y.toFixed(1)})`}
                onPointerDown={onDown(n) as any}
                onPointerEnter={(e) => { if (!drag.current) { setHover(n.addr); nodeTip(n, e as PointerEvent); } }}
                onPointerLeave={() => { if (!drag.current) { setHover(null); setTip(null); } }}>
                <circle r={r + 7} class="hit" />
                {isFound && <circle r={r + 5} class="ring" />}
                <circle r={r} class={`dot ${cls}`} />
                {showName && <text x={r + 4} y={4} class="node-name">{n.name}</text>}
              </g>
            );
          })}
        </g>
      </svg>
    ) : <div class="empty">No mesh data yet: Link Status frames need the network key.</div>;

    const sorted = data.edges.slice().sort((a: any, b: any) => (worst(b) || 0) - (worst(a) || 0));
    const routers = data.nodes.filter((n: any) => n.mesh && n.mesh.own).sort((a: any, b: any) => a.mesh.good - b.mesh.good || b.mesh.best - a.mesh.best);
    const nm = new Map<string, string>(data.nodes.map((n: any) => [n.addr, n.name]));
    tables = (
      <div class="grid two">
        <Card title="Weakest links" actions={<span class="muted small">worst direction first</span>}>
          {sorted.length ? (
            <div class="table-wrap scroll">
              <table class="data dense">
                <thead><tr><th>Link</th><th title="cost from the first to the second">→</th><th title="cost from the second to the first">←</th><th>Updated</th></tr></thead>
                <tbody>
                  {sorted.slice(0, 40).map((e: any) => (
                    <tr><td><AddrLabel addr={e.a} name={nm.get(e.a)} /> <span class="muted">↔</span> <AddrLabel addr={e.b} name={nm.get(e.b)} /></td>
                      <td><CostChip c={e.ab} /></td><td><CostChip c={e.ba} /></td><td class="muted nowrap">{f.ago(e.ts)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div class="empty">No Link Status heard yet (needs the network key).</div>}
        </Card>
        <Card title="Routers by neighbours" actions={<span class="muted small">few or poor neighbours = fragile</span>}>
          {routers.length ? (
            <div class="table-wrap scroll">
              <table class="data dense">
                <thead><tr><th>Router</th><th class="num">Neighbours</th><th class="num">Good (≤3)</th><th>Best</th></tr></thead>
                <tbody>
                  {routers.map((n: any) => (
                    <tr><td><DevLink addr={n.addr} name={n.name} /></td><td class="num">{f.n(f.num(n.mesh.n))}</td><td class="num">{f.n(f.num(n.mesh.good))}</td><td><CostChip c={n.mesh.best} /></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div class="empty">No routers reported yet.</div>}
        </Card>
      </div>
    );
  }

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Mesh</h1>
          <p class="lede">Who hears whom, from the routers' Link Status (every 15 s). Drag to rearrange · click a device to open it.</p>
        </div>
      </div>
      <PageError err={err} />
      <div class="toolbar">
        <select class="select" value={links} aria-label="Links to show" onChange={(e) => { const v = (e.target as HTMLSelectElement).value; setLinks(v); pref.set("mesh.links", v); }}>
          <option value="best">Strongest 3 links per device</option><option value="all">All links</option><option value="weak">Weak links only (cost 5+)</option>
        </select>
        <button type="button" class="btn small" aria-pressed={ed} onClick={() => { setEd(!ed); pref.setFlag("mesh.ed", !ed); }}>End devices</button>
        <button type="button" class="btn small" aria-pressed={labels} onClick={() => { setLabels(!labels); pref.setFlag("mesh.labels", !labels); }}>Names</button>
        <button type="button" class="btn small" onClick={() => { POS.clear(); PINNED.clear(); setArranged(arranged + 1); }}><Icon name="refresh" size={14} /> Re-arrange</button>
        <label class="search">
          <Icon name="search" size={16} />
          <input type="search" value={q} placeholder="Find a device" aria-label="Find a device in the mesh"
            onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); setHit(hit + (e.shiftKey ? -1 : 1)); }
              else if (e.key === "Escape") setQuery("");
            }} />
        </label>
        <span class="muted small" role="status">{found}</span>
      </div>
      <div class="card">
        <div class="mesh-box" ref={ref} style={{ height: `${H}px` }}>
          {!data ? (!err && <Loading />) : body}
          {tip && <div class="chart-tip map-tip" style={{ top: `${tip.y + 12}px`, ...(tip.x > W / 2 ? { right: `${W - tip.x + 12}px` } : { left: `${tip.x + 12}px` }) }}>{tip.body}</div>}
        </div>
        <div class="map-foot">
          <CostLegend />
          <span class="chart-legend map-legend">
            <span><svg width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="6" class="dot n-coord" /></svg>Coordinator</span>
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="5" class="dot n-router" /></svg>Router</span>
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="3.5" class="dot n-end" /></svg>End device</span>
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="5" class="dot n-warn" /></svg>Needs attention</span>
            {ed && <span><i class="key line kid-key" />End device's parent</span>}
          </span>
        </div>
      </div>
      {tables}
    </div>
  );
}
