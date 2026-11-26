// Map: floor plans (an image, or a blank grid in metres) with devices and sniffers placed on them,
// and the Zigbee coverage estimated from what the sniffers hear (a path-loss model: each router's
// strength, how fast signal falls with distance, the loss per floor), or what one sniffer measured.
// Edit layout: rename, set the level, upload a plan, set the scale, place and move, delete a floor.
// Adapted from Zigbee Studio's floor maps (which read and set up this same map through the Sniffer).

import { useEffect, useRef, useState } from "preact/hooks";
import { Card, Search } from "../kit/ui";
import { Icon } from "../kit/icons";
import { useWidth } from "../kit/chart";
import { confirmIt } from "../kit/dialog";
import { toast } from "../kit/toast";
import { api, del, post } from "../api";
import { usePoll } from "../poll";
import { pref, range } from "../store";
import * as f from "../fmt";
import { deviceLink } from "../logic";
import { costClass, CostLegend, Loading, PageError } from "../bits";
import { aspectOf, heatColours, HeatLegend, heatRGB, MapTip, placeLabels, signalWord, typeWord, type Floor } from "../mapbits";

type Item = { key: string; kind: "device" | "sniffer"; addr?: string; name: string; type: string; model?: string };
type Meta = { floors: Floor[]; positions: Record<string, { floor: string; x: number; y: number }>; items: Item[]; floor_height_m: number };
type CovItem = Item & {
  floor: string; x: number; y: number; sev?: number; flags?: string[]; signal?: Record<string, { rssi: number; n: number }>;
  strength?: number | null; strength_from?: string | null;
};
type Model = {
  ok: boolean; why?: string; samples?: number; devices?: number; n?: number; n10: number; n_fixed?: boolean; floor_loss: number;
  floor_loss_fitted?: boolean; rmse?: number; devices_with_strength?: number; gains?: { sniffer: string; name?: string; db: number; ref: boolean }[];
};
type Cov = { model: Model; items: CovItem[]; links: { a: string; b: string; cost: number | null }[]; floors: Floor[]; sniffers: { id: string; name: string }[]; floor_height_m: number };
type Opts = { layer: string; opacity: number; labels: boolean; links: boolean; ends: boolean };

const planUrl = (fl: Floor) => `api/map/floors/${encodeURIComponent(fl.id)}/image?v=${encodeURIComponent(fl.image || "")}`;

async function uploadPlan(fid: string, file: File): Promise<Floor> {
  const url = URL.createObjectURL(file);
  const [w, h] = await new Promise<[number, number]>((res) => {
    const im = new Image();
    im.onload = () => res([im.naturalWidth || 1000, im.naturalHeight || 700]);
    im.onerror = () => res([1000, 700]);
    im.src = url;
  });
  URL.revokeObjectURL(url);
  return post(`api/map/floors/${encodeURIComponent(fid)}/image?w=${w}&h=${h}`, await file.arrayBuffer(), file.type || "image/png");
}

/** Run a map change: a toast for the result or the error; true when it worked. */
async function change(fn: () => Promise<unknown>, okText?: string): Promise<boolean> {
  try {
    await fn();
    if (okText) toast(okText);
    return true;
  } catch (e: any) {
    toast(e?.message || String(e), "error", 7000);
    return false;
  }
}

export function MapPage() {
  const [opts, setOptsState] = useState<Opts>(() => ({
    layer: pref.get("map.layer", "coverage"), opacity: +pref.get("map.opacity", "0.6"),
    labels: pref.flag("map.labels", true), links: pref.flag("map.links", false), ends: pref.flag("map.ends", true),
  }));
  const setOpts = (o: Partial<Opts>) => {
    const n = { ...opts, ...o };
    setOptsState(n);
    pref.set("map.layer", n.layer); pref.set("map.opacity", n.opacity);
    pref.setFlag("map.labels", n.labels); pref.setFlag("map.links", n.links); pref.setFlag("map.ends", n.ends);
  };
  const [edit, setEdit] = useState(false);
  const editRef = useRef(edit);
  editRef.current = edit;
  const [adding, setAdding] = useState(false);
  const [fid, setFid] = useState(() => pref.get("map.floor", ""));
  const pickFloor = (id: string) => { setFid(id); pref.set("map.floor", id); };
  const forceRef = useRef(false);
  const lastRef = useRef<{ meta: Meta; cov: Cov } | null>(null);
  const both = usePoll(60000, async () => {
    // while editing, the 60 s refresh waits (a refresh mustn't move what's being placed); changes still reload
    if (editRef.current && !forceRef.current && lastRef.current) return lastRef.current;
    forceRef.current = false;
    const [meta, cov] = await Promise.all([api<Meta>("api/map"), api<Cov>(`api/map/coverage?range=${range.value}`)]);
    return (lastRef.current = { meta, cov });
  }, [range.value]);
  const { err, refresh } = both;
  const data = both.data;
  const reload = () => { forceRef.current = true; refresh(); };
  const meta = data?.meta, cov = data?.cov || null;
  const floors = meta?.floors || [];
  const floor = floors.find((x) => x.id === fid) || floors[0];

  const layers = [{ v: "coverage", label: "Coverage (estimated, best router)" }, { v: "backup", label: "Backup coverage (second-best router)" },
    ...(cov?.sniffers || []).map((s) => ({ v: `heard:${s.id}`, label: `Heard by ${s.name} (measured)` })), { v: "none", label: "No heat map" }];
  const layer = layers.some((l) => l.v === opts.layer) ? opts.layer : "coverage";
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Map</h1>
          <p class="lede">Where your devices are, and the Zigbee coverage estimated from what the sniffers hear</p>
        </div>
        {floors.length > 0 && (
          <div class="head-actions">
            <div class="seg" role="group" aria-label="Floor">
              {floors.map((x) => <button type="button" aria-pressed={floor?.id === x.id} onClick={() => pickFloor(x.id)}>{x.name}</button>)}
            </div>
            <button type="button" class="btn small" onClick={() => setAdding(!adding)}><Icon name="plus" size={14} /> Floor</button>
            <button type="button" class={`btn small ${edit ? "primary" : ""}`} aria-pressed={edit} title="Place devices, set the scale, rename or delete this floor"
              onClick={() => setEdit(!edit)}><Icon name={edit ? "check" : "pencil"} size={14} /> {edit ? "Done" : "Edit layout"}</button>
          </div>
        )}
      </div>
      <PageError err={err} />
      {!meta ? (!err && <Card><Loading>Loading the floor maps…</Loading></Card>) : (
        <div class="page-sub">
          {(adding || !floors.length) && <NewFloor first={!floors.length} meta={meta} onCancel={() => setAdding(false)}
            onAdded={(fl) => { setAdding(false); setEdit(true); pickFloor(fl.id); reload(); }} />}
          {floor && (
            <>
              {!edit && (
                <div class="toolbar">
                  <select class="select" value={layer} aria-label="Heat map layer" onChange={(e) => setOpts({ layer: (e.target as HTMLSelectElement).value })}>
                    {layers.map((l) => <option value={l.v}>{l.label}</option>)}
                  </select>
                  <label class="opacity">Heat map
                    <input type="range" min="0" max="0.9" step="0.05" value={opts.opacity} aria-label="Heat map opacity"
                      onInput={(e) => setOpts({ opacity: +(e.target as HTMLInputElement).value })} />
                  </label>
                  <button type="button" class="btn small" aria-pressed={opts.labels} onClick={() => setOpts({ labels: !opts.labels })}>Names</button>
                  <button type="button" class="btn small" aria-pressed={opts.links} onClick={() => setOpts({ links: !opts.links })}>Mesh links</button>
                  <button type="button" class="btn small" aria-pressed={opts.ends} onClick={() => setOpts({ ends: !opts.ends })}>End devices</button>
                </div>
              )}
              <FloorView key={floor.id} floor={floor} meta={meta} cov={cov} opts={{ ...opts, layer }} edit={edit} onChanged={reload}
                onDeleted={() => { pickFloor(""); setEdit(false); reload(); }} />
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------- one floor

function FloorView({ floor, meta, cov, opts, edit, onChanged, onDeleted }: {
  floor: Floor; meta: Meta; cov: Cov | null; opts: Opts; edit: boolean; onChanged: () => void; onDeleted: () => void;
}) {
  const [ref, W] = useWidth();
  const H = Math.round(W * aspectOf(floor));
  const canvas = useRef<HTMLCanvasElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [tip, setTip] = useState<{ x: number; y: number; body: preact.ComponentChildren } | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const [scaling, setScaling] = useState<[number, number][] | null>(null);
  const [moving, setMoving] = useState<{ key: string; u: number; v: number } | null>(null);
  const drag = useRef<{ key: string; id: number; sx: number; sy: number; moved: boolean } | null>(null);
  const model = cov?.model;
  const covFloor = cov?.floors.find((x) => x.id === floor.id) || floor;
  const heightM = cov?.floor_height_m ?? meta.floor_height_m;

  // placed routers with a strength, in metres (any floor: a router upstairs reaches down)
  const routers: [CovItem, number, number, number][] = [];
  if (cov && model?.ok) {
    for (const it of cov.items) {
      if (it.kind !== "device" || it.strength == null || !(it.type === "Router" || it.type === "Coordinator")) continue;
      const fl = cov.floors.find((x) => x.id === it.floor);
      if (fl?.size_m) routers.push([it, it.x * fl.size_m[0], it.y * fl.size_m[1], fl.level || 0]);
    }
  }
  const estimate = (u: number, v: number): [number, CovItem][] => {
    if (!model?.ok || !covFloor.size_m) return [];
    const px = u * covFloor.size_m[0], py = v * covFloor.size_m[1], lvl = covFloor.level || 0;
    return routers.map(([it, x, y, l]): [number, CovItem] => {
      const fl = Math.abs(l - lvl);
      const d = Math.max(0.5, Math.hypot(x - px, y - py, fl * heightM));
      return [it.strength! - model.n10 * Math.log10(d) - model.floor_loss * fl, it];
    }).sort((a, b) => b[0] - a[0]);
  };
  const heardAt = (u: number, v: number, sid: string): { v: number; near: number } | null => {
    let ws = 0, vs = 0, near = 1e9;
    const aspect = aspectOf(floor);
    for (const it of cov?.items || []) {
      if (it.kind !== "device" || it.floor !== floor.id || !it.signal?.[sid]) continue;
      const d2 = (it.x - u) ** 2 + ((it.y - v) * aspect) ** 2;
      near = Math.min(near, d2);
      const w = 1 / (d2 + 0.0004);
      ws += w;
      vs += w * it.signal[sid].rssi;
    }
    return ws ? { v: vs / ws, near: Math.sqrt(near) } : null;
  };

  let note = "";
  if (!edit && opts.layer !== "none") {
    if (opts.layer === "coverage" || opts.layer === "backup") {
      if (!covFloor.size_m) note = "Set this floor's scale (Edit layout) to estimate coverage.";
      else if (!model?.ok) note = model?.why ? `Coverage can't be estimated yet: ${model.why}.` : "Coverage can't be estimated yet.";
    }
  }
  let heardNone = false;

  // the heat map: a coarse grid, smoothed by the browser; its opacity is the canvas's
  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    const gw = 160, gh = Math.max(20, Math.round(gw * aspectOf(floor)));
    cv.width = gw;
    cv.height = gh;
    const ctx = cv.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, gw, gh);
    if (edit || opts.layer === "none" || note) return;
    const cols = heatColours(cv);
    const img = ctx.createImageData(gw, gh);
    const sid = opts.layer.startsWith("heard:") ? opts.layer.slice(6) : null;
    const k = opts.layer === "backup" ? 1 : 0;
    for (let j = 0; j < gh; j++) for (let i = 0; i < gw; i++) {
      const u = (i + 0.5) / gw, v = (j + 0.5) / gh, o = (j * gw + i) * 4;
      let val: number | null = null, alpha = 255;
      if (sid) {
        const h = heardAt(u, v, sid);
        if (h) { val = h.v; alpha = Math.round(255 * Math.max(0, 1 - Math.max(0, h.near - 0.12) / 0.25)); }
      } else {
        const e = estimate(u, v);
        if (e[k]) val = e[k][0];
      }
      if (val === null) continue;
      const c = heatRGB(val, cols);
      img.data[o] = c[0]; img.data[o + 1] = c[1]; img.data[o + 2] = c[2]; img.data[o + 3] = alpha;
    }
    ctx.putImageData(img, 0, 0);
  }, [floor, cov, opts.layer, edit, note]);

  if (!edit && opts.layer.startsWith("heard:")) {
    const sid = opts.layer.slice(6);
    heardNone = !(cov?.items || []).some((it) => it.kind === "device" && it.floor === floor.id && it.signal?.[sid]);
  }

  // what's on this floor
  const itemByKey = new Map(meta.items.map((i) => [i.key, i]));
  const covByKey = new Map((cov?.items || []).map((i) => [i.key, i]));
  const placed: CovItem[] = Object.entries(meta.positions).filter(([, p]) => p.floor === floor.id).map(([key, p]) => {
    const c = covByKey.get(key);
    const it = itemByKey.get(key) || { key, kind: key.startsWith("sniffer:") ? "sniffer" : "device", name: key, type: key.startsWith("sniffer:") ? "Sniffer" : "" } as Item;
    return { ...(c || {}), ...it, ...p, sev: c?.sev, floor: floor.id } as CovItem;
  }).filter((it) => edit || opts.ends || it.type !== "EndDevice");
  const pos = (it: CovItem): [number, number] => (moving && moving.key === it.key ? [moving.u * W, moving.v * H] : [it.x * W, it.y * H]);
  const byAddr = new Map(placed.filter((i) => i.addr).map((i) => [i.addr!, i]));
  const links = opts.links && !edit ? (cov?.links || []).filter((l) => byAddr.has(l.a) && byAddr.has(l.b)) : [];

  const local = (e: PointerEvent): [number, number] => {
    const r = svgRef.current!.getBoundingClientRect();
    return [Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)), Math.min(1, Math.max(0, (e.clientY - r.top) / r.height))];
  };
  const save = async (key: string, u: number, v: number) => {
    if (await change(() => post("api/map/positions", { set: { [key]: { floor: floor.id, x: u, y: v } } }))) onChanged();
  };
  const markerTip = (it: CovItem, e: PointerEvent) => {
    const [u, v] = local(e);
    const names = Object.fromEntries((cov?.sniffers || []).map((s) => [s.id, s.name]));
    setTip({ x: u * W, y: v * H, body: (
      <>
        <div class="tip-head">{typeWord(it.kind === "sniffer" ? "Sniffer" : it.type)}{it.model ? ` · ${it.model}` : ""}</div>
        <div class="tip-title">{it.name}</div>
        {Object.entries(it.signal || {}).map(([sid, s]) => <div class="tip-row"><b>{Math.round(s.rssi)} dBm</b> <span class="muted">at {names[sid] || sid}</span></div>)}
        {it.strength != null && (it.type === "Router" || it.type === "Coordinator") && <div class="tip-row"><b>{it.strength} dBm</b> <span class="muted">at 1 m ({it.strength_from})</span></div>}
        {(it.flags || []).map((x) => <div class="muted small">{x}</div>)}
        {edit && <div class="muted small">Drag to move</div>}
      </>
    ) });
  };
  const onMove = (e: PointerEvent) => {
    const d = drag.current;
    if (d) {
      if (d.id !== e.pointerId) return;
      if (!d.moved && Math.hypot(e.clientX - d.sx, e.clientY - d.sy) < 3) return; // a click, not a move
      d.moved = true;
      const [u, v] = local(e);
      setMoving({ key: d.key, u, v });
      return;
    }
    if (e.pointerType === "touch" || edit) return;
    if ((e.target as Element).closest?.(".marker")) return;
    const [u, v] = local(e);
    if (opts.layer === "coverage" || opts.layer === "backup") {
      const p = estimate(u, v);
      if (!p.length) { setTip(null); return; }
      setTip({ x: u * W, y: v * H, body: (
        <>
          <div class="tip-head">Estimated here</div>
          <div class="tip-row"><b>{Math.round(p[0][0])} dBm</b> <span class="muted">{signalWord(p[0][0])}, from {p[0][1].name}</span></div>
          {p[1] && <div class="tip-row"><b>{Math.round(p[1][0])} dBm</b> <span class="muted">backup, from {p[1][1].name}</span></div>}
        </>
      ) });
    } else if (opts.layer.startsWith("heard:")) {
      const h = heardAt(u, v, opts.layer.slice(6));
      setTip(h ? { x: u * W, y: v * H, body: <><div class="tip-head">Interpolated from nearby devices</div><div class="tip-row"><b>{Math.round(h.v)} dBm</b> <span class="muted">{signalWord(h.v)}</span></div></> } : null);
    }
  };
  const onDown = (it: CovItem) => (e: PointerEvent) => {
    if (!edit || armed || scaling) return;
    e.preventDefault();
    e.stopPropagation();
    svgRef.current?.setPointerCapture(e.pointerId);
    drag.current = { key: it.key, id: e.pointerId, sx: e.clientX, sy: e.clientY, moved: false };
    setTip(null);
  };
  const onUp = async (e: PointerEvent) => {
    const d = drag.current;
    if (d) {
      drag.current = null;
      if (d.moved) {
        const [u, v] = local(e);
        await save(d.key, u, v);
        setMoving(null);
      }
      return;
    }
    const [u, v] = local(e);
    if (edit && scaling) { setScaling(scaling.length >= 2 ? [[u, v]] : [...scaling, [u, v]]); return; }
    if (edit && armed) { const key = armed; setArmed(null); await save(key, u, v); return; }
    const m = (e.target as Element).closest?.(".marker") as SVGGElement | null;
    if (m && !edit) {
      const key = m.dataset.key || "";
      if (key.startsWith("sniffer:")) { location.hash = "#/sniffer"; return; }
      const it = covByKey.get(key) || itemByKey.get(key);
      if (it?.addr) location.hash = deviceLink(it.addr);
    }
  };

  const gridPx = floor.size_m ? W / floor.size_m[0] : 40;
  const markR = (it: CovItem) => (it.kind === "sniffer" ? 7 : it.type === "Coordinator" ? 8 : it.type === "EndDevice" ? 4.5 : 6.5);
  const sides = opts.labels ? placeLabels(placed.map((it) => {
    const [x, y] = pos(it);
    return { key: it.key, x, y, r: markR(it), text: it.name, rank: it.kind === "sniffer" ? 0 : it.type === "EndDevice" ? 2 : 1 };
  }), W) : new Map<string, "r" | "l">();
  return (
    <div class={edit ? "floor-layout editing" : "floor-layout"}>
      <Card class="floor-card">
        <div class="floor-box" ref={ref} style={{ height: `${H}px` }}>
          {floor.image ? <img class="floor-plan" src={planUrl(floor)} alt={`Plan of ${floor.name}`} draggable={false} />
            : <div class="floor-grid" style={{ backgroundSize: `${gridPx}px ${gridPx}px` }} />}
          <canvas ref={canvas} class="floor-heat" style={{ opacity: opts.opacity }} />
          <svg ref={svgRef} class={`floor-svg ${edit ? "edit" : ""} ${armed || scaling ? "aiming" : ""}`} width={W} height={H} viewBox={`0 0 ${W} ${H}`}
            onPointerMove={onMove} onPointerUp={onUp} onPointerLeave={() => setTip(null)}
            onPointerCancel={() => { drag.current = null; setMoving(null); }}>
            {links.map((l) => {
              const [x1, y1] = pos(byAddr.get(l.a)!), [x2, y2] = pos(byAddr.get(l.b)!);
              return <line class={`link cost-line-${costClass(l.cost)}`} x1={x1} y1={y1} x2={x2} y2={y2} />;
            })}
            {scaling && scaling.map(([u, v]) => <circle cx={u * W} cy={v * H} r={5} class="scale-pt" />)}
            {scaling && scaling.length === 2 && <line class="scale-line" x1={scaling[0][0] * W} y1={scaling[0][1] * H} x2={scaling[1][0] * W} y2={scaling[1][1] * H} />}
            {placed.map((it) => {
              const [x, y] = pos(it);
              const sniffer = it.kind === "sniffer";
              const r = markR(it), side = sides.get(it.key);
              const cls = sniffer ? "n-sniffer" : it.type === "Coordinator" ? "n-coord" : (it.sev ?? 0) >= 3 ? "n-bad" : (it.sev ?? 0) >= 2 ? "n-warn" : it.type === "EndDevice" ? "n-end" : "n-router";
              return (
                <g class={`marker ${edit ? "drag" : ""}`} data-key={it.key} transform={`translate(${x.toFixed(1)},${y.toFixed(1)})`}
                  onPointerDown={onDown(it) as any} onPointerMove={(e) => !drag.current && !armed && !scaling && markerTip(it, e as PointerEvent)}
                  onPointerLeave={() => setTip(null)}>
                  <circle r={13} class="hit" />
                  {sniffer ? <rect x={-7} y={-7} width={14} height={14} rx={3} class={`dot ${cls}`} /> : <circle r={r} class={`dot ${cls}`} />}
                  {side && <text x={side === "r" ? r + 4 : -r - 4} y={4} text-anchor={side === "r" ? "start" : "end"} class="node-name">{it.name}</text>}
                </g>
              );
            })}
          </svg>
          {(note || heardNone) && <div class="floor-note">{note || "No device on this floor is placed and heard by that sniffer yet."}</div>}
          {tip && <MapTip x={tip.x} y={tip.y} w={W}>{tip.body}</MapTip>}
        </div>
        <div class="map-foot">
          {!edit && opts.layer !== "none" && <HeatLegend />}
          <span class="chart-legend map-legend">
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="5" class="dot n-router" /></svg>Router</span>
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="3.5" class="dot n-end" /></svg>End device</span>
            <span><svg width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="6" class="dot n-coord" /></svg>Coordinator</span>
            <span><svg width="14" height="14" aria-hidden="true"><rect x="1" y="1" width="12" height="12" rx="3" class="dot n-sniffer" /></svg>Sniffer</span>
            <span><svg width="12" height="12" aria-hidden="true"><circle cx="6" cy="6" r="5" class="dot n-warn" /></svg>Needs attention</span>
          </span>
          {links.length > 0 && <CostLegend />}
          {!edit && <ModelNote model={model} sniffers={cov?.sniffers.length || 0} />}
        </div>
      </Card>
      {edit && <EditPanel floor={floor} meta={meta} cov={cov} armed={armed} setArmed={setArmed} scaling={scaling} setScaling={setScaling}
        onChanged={onChanged} onDeleted={onDeleted} />}
    </div>
  );
}

function ModelNote({ model: m, sniffers }: { model: Model | undefined; sniffers: number }) {
  if (!m) return null;
  if (!m.ok) return <p class="muted small">To estimate coverage: place your sniffer{sniffers > 1 ? "s" : ""} and the devices on a floor with a scale ({m.why || ""}).</p>;
  const own = f.num(m.devices_with_strength);
  const gs = (m.gains || []).filter((g) => !g.ref), ref = (m.gains || []).find((g) => g.ref);
  const refName = ref ? ref.name || ref.sniffer : "the first sniffer";
  return (
    <p class="muted small">
      Coverage is estimated from {f.n(f.num(m.samples))} measurements of {f.n(f.num(m.devices))} devices at your placed sniffers: signal falls
      about {Math.round(f.num(m.n10) || 0)} dB per tenfold distance (n = {m.n}{m.n_fixed ? ", assumed" : ""}) and {m.floor_loss} dB per
      floor{m.floor_loss_fitted ? "" : " (assumed)"}; typical error ±{m.rmse} dB (each measurement predicted without itself). Walls only count on
      average, so treat it as a guide.{" "}
      {own !== null
        ? `Each device's own strength is known for ${f.plural(own, "device")} heard by two or more sniffers; the others use the house average (a second sniffer sharpens the map).`
        : "Routers no placed sniffer hears use the strength of others of their model."}
      {gs.length > 0 && ` Antennas: ${gs.map((g) => `${g.name || g.sniffer} hears ${Math.abs(f.num(g.db) || 0)} dB ${(f.num(g.db) || 0) >= 0 ? "louder" : "quieter"}`).join(", ")} than ${refName}; strengths and the map are as ${refName} would hear them.`}
    </p>
  );
}

// ---------------------------------------------------------------------- editing

function EditPanel({ floor, meta, cov, armed, setArmed, scaling, setScaling, onChanged, onDeleted }: {
  floor: Floor; meta: Meta; cov: Cov | null; armed: string | null; setArmed: (k: string | null) => void;
  scaling: [number, number][] | null; setScaling: (p: [number, number][] | null) => void; onChanged: () => void; onDeleted: () => void;
}) {
  const [name, setName] = useState(floor.name);
  const [level, setLevel] = useState(String(floor.level ?? 0));
  const [dist, setDist] = useState("");
  const [unit, setUnit] = useState("1");
  const [wm, setWm] = useState(String(floor.width_m ?? ""));
  const [hm, setHm] = useState(String(floor.height_m ?? ""));
  const [fh, setFh] = useState(String(cov?.floor_height_m ?? meta.floor_height_m));
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const fid = encodeURIComponent(floor.id);
  const run = async (fn: () => Promise<unknown>, okText?: string) => {
    setBusy(true);
    try { if (await change(fn, okText)) onChanged(); } finally { setBusy(false); }
  };
  const remove = async () => {
    const n = Object.values(meta.positions).filter((p) => p.floor === floor.id).length;
    if (!await confirmIt({
      title: `Delete ${floor.name}?`, danger: true, confirm: "Delete floor", typeToConfirm: floor.name,
      body: <p>{n
        ? `${n === 1 ? "The one device or sniffer placed on it loses its place" : `The ${n} devices and sniffers placed on it lose their places`}${floor.image ? ", and its plan is deleted" : ""}. The devices themselves are not touched.`
        : `Nothing is placed on it${floor.image ? "; its plan is deleted" : ""}.`}</p>,
    })) return;
    setBusy(true);
    const ok = await change(() => del(`api/map/floors/${fid}`), `Deleted ${floor.name}`);
    setBusy(false);
    if (ok) onDeleted();
  };
  const saveScale = () => {
    const metres = parseFloat(dist) * parseFloat(unit);
    if (!(metres > 0) || !scaling || scaling.length < 2) { toast("Enter the distance between the two points", "warn"); return; }
    const [a, b] = scaling;
    const px = Math.hypot((a[0] - b[0]) * (floor.img_w || 1000), (a[1] - b[1]) * (floor.img_h || 700));
    if (!(px > 0)) { toast("Click two different points", "warn"); return; }
    run(async () => { await post(`api/map/floors/${fid}`, { scale: px / metres }); setScaling(null); }, "Scale saved");
  };
  const ql = q.trim().toLowerCase();
  const list = meta.items.filter((it) => !ql || it.name.toLowerCase().includes(ql) || (it.addr || "").includes(ql));
  const unplaced = list.filter((it) => !meta.positions[it.key]);
  const here = list.filter((it) => meta.positions[it.key]);
  const floorName = (id: string) => meta.floors.find((x) => x.id === id)?.name || "?";
  const sniffersFirst = [...unplaced.filter((it) => it.kind === "sniffer"), ...unplaced.filter((it) => it.kind !== "sniffer")];
  return (
    <Card class="floor-side" title="Edit layout">
      <div class="form-grid one">
        <label>Name<input type="text" value={name} onInput={(e) => setName((e.target as HTMLInputElement).value)} /></label>
        <label>Level <span class="muted small">0 = ground floor, 1 = the floor above, −1 = basement</span>
          <input type="number" value={level} onInput={(e) => setLevel((e.target as HTMLInputElement).value)} /></label>
      </div>
      <div class="toolbar">
        <button type="button" class="btn small" disabled={busy} onClick={() => run(() => post(`api/map/floors/${fid}`, { name, level: parseInt(level) || 0 }), "Floor saved")}>Save</button>
        <label class="btn small file-btn"><Icon name="upload" size={14} /> {floor.image ? "Replace plan" : "Upload plan"}
          <input type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif" class="sr-only"
            onChange={(e) => { const file = (e.target as HTMLInputElement).files?.[0]; if (file) run(() => uploadPlan(floor.id, file), "Plan uploaded"); }} />
        </label>
        <button type="button" class="btn small danger" disabled={busy} onClick={remove}><Icon name="trash" size={14} /> Delete floor</button>
      </div>

      <h3>Scale</h3>
      {floor.image ? (
        <>
          <p class="muted small">{floor.size_m ? `${floor.size_m[0].toFixed(1)} × ${floor.size_m[1].toFixed(1)} m.` : <><b>Not set</b>: coverage needs it.</>} Mark two points on the plan a known distance apart.</p>
          {!scaling ? <button type="button" class="btn small" onClick={() => { setArmed(null); setScaling([]); }}>Set scale</button> : (
            <div class="note">
              {scaling.length < 2 ? <span>Click two points on the plan a known distance apart ({scaling.length} of 2).</span> : (
                <div class="toolbar">
                  <span>Distance between them</span>
                  <input class="small-input" type="number" step="0.1" value={dist} aria-label="Distance" onInput={(e) => setDist((e.target as HTMLInputElement).value)} />
                  <select class="select small" value={unit} aria-label="Unit" onChange={(e) => setUnit((e.target as HTMLSelectElement).value)}><option value="1">m</option><option value="0.3048">ft</option></select>
                  <button type="button" class="btn small primary" disabled={busy} onClick={saveScale}>Save scale</button>
                </div>
              )}
              <button type="button" class="link-btn" onClick={() => setScaling(null)}>Cancel</button>
            </div>
          )}
        </>
      ) : (
        <div class="toolbar">
          <input class="small-input" type="number" step="0.1" value={wm} aria-label="Width in metres" onInput={(e) => setWm((e.target as HTMLInputElement).value)} />
          <span>×</span>
          <input class="small-input" type="number" step="0.1" value={hm} aria-label="Depth in metres" onInput={(e) => setHm((e.target as HTMLInputElement).value)} />
          <span>m</span>
          <button type="button" class="btn small" disabled={busy} onClick={() => run(() => post(`api/map/floors/${fid}`, { width_m: parseFloat(wm), height_m: parseFloat(hm) }), "Size saved")}>Save size</button>
        </div>
      )}
      <p class="muted small">Floors are taken as drawn on the same grid, so the same spot lines up across levels.</p>
      <div class="toolbar">
        <span class="small">Height between floors</span>
        <input class="small-input" type="number" step="0.1" value={fh} aria-label="Height between floors in metres" onInput={(e) => setFh((e.target as HTMLInputElement).value)} />
        <span>m</span>
        <button type="button" class="btn small" disabled={busy} onClick={() => run(() => post(`api/map/floors/${fid}`, { floor_height_m: parseFloat(fh) }), "Height between floors saved")}>Save</button>
      </div>

      <h3>Place</h3>
      <p class="muted small">Pick a device or sniffer, then click the plan. Drag placed ones to move them.</p>
      <Search value={q} onInput={setQ} placeholder="Search devices to place" />
      <div class="place-list">
        {!sniffersFirst.length && <p class="muted small">{ql ? "Nothing matches." : "Everything is placed."}</p>}
        {sniffersFirst.length > 0 && (
          <div class="place-group">
            {sniffersFirst.map((it) => (
              <button type="button" class={`place ${armed === it.key ? "armed" : ""}`} aria-pressed={armed === it.key}
                onClick={() => { setScaling(null); setArmed(armed === it.key ? null : it.key); }}>
                <span class="tag">{it.kind === "sniffer" ? "Sniffer" : typeWord(it.type) || "?"}</span>{it.name}
              </button>
            ))}
          </div>
        )}
        {here.length > 0 && (
          <div class="place-group">
            <div class="place-head">Placed</div>
            {here.map((it) => (
              <div class="placed">
                <span>{it.name} <span class="sub">{floorName(meta.positions[it.key].floor)}</span></span>
                <button type="button" class="link-btn" disabled={busy} onClick={() => run(() => post("api/map/positions", { clear: [it.key] }))}>Remove</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

function NewFloor({ first, meta, onAdded, onCancel }: { first: boolean; meta: Meta; onAdded: (fl: Floor) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [level, setLevel] = useState(String(meta.floors.length));
  const [file, setFile] = useState<File | null>(null);
  const [w, setW] = useState("");
  const [h, setH] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const add = async () => {
    const wm = parseFloat(w), hm = parseFloat(h);
    if (!file && !(wm > 0 && hm > 0)) { setMsg("Choose a plan image, or give a width and depth."); return; }
    setBusy(true);
    setMsg("");
    try {
      const fl: Floor = await post("api/map/floors", { name: name.trim() || `Floor ${meta.floors.length + 1}`, level: parseInt(level) || 0, width_m: file ? null : wm, height_m: file ? null : hm });
      if (file) await uploadPlan(fl.id, file);
      toast("Floor added");
      onAdded(fl);
    } catch (e: any) {
      setMsg(e?.message || String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title={first ? "Add your first floor" : "Add a floor"}>
      <p class="muted small">Upload a floor plan (PNG, JPG, SVG), then set its scale by marking two points a known distance apart, or start from a blank grid of a given size. Draw every floor's plan on the same grid (same corner, same scale) so levels line up.</p>
      <div class="form-grid">
        <label>Name<input type="text" value={name} placeholder="Main floor" onInput={(e) => setName((e.target as HTMLInputElement).value)} /></label>
        <label>Level<input type="number" value={level} onInput={(e) => setLevel((e.target as HTMLInputElement).value)} /></label>
        <label>Plan image<input type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif" onChange={(e) => setFile((e.target as HTMLInputElement).files?.[0] || null)} /></label>
        <label>or blank, width × depth (m)
          <span class="pair">
            <input type="number" step="0.1" value={w} placeholder="20" aria-label="Width in metres" disabled={!!file} onInput={(e) => setW((e.target as HTMLInputElement).value)} />
            <input type="number" step="0.1" value={h} placeholder="12" aria-label="Depth in metres" disabled={!!file} onInput={(e) => setH((e.target as HTMLInputElement).value)} />
          </span>
        </label>
      </div>
      <div class="toolbar">
        <button type="button" class="btn primary" disabled={busy} onClick={add}>{busy ? "Adding…" : "Add floor"}</button>
        {!first && <button type="button" class="btn" onClick={onCancel}>Cancel</button>}
        {msg && <span class="warn-text small" role="status">{msg}</span>}
      </div>
    </Card>
  );
}
