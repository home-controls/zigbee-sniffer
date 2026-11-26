// Live: the newest frames, every 2 s. The table holds still while the pointer is on it or a frame
// is open; new frames wait behind a button. Filters: kind, other networks, text; one device.

import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../kit/icons";
import { api } from "../api";
import { pref } from "../store";
import * as f from "../fmt";
import { dropLoneGaps, frameHay, kindOk } from "../logic";
import { PageError } from "../bits";
import { FramesTable, frameRef } from "../frames";

const LIVE_CAP = 300; // the most frames one /api/live answer carries

export function Live({ addr }: { addr: string }) {
  const [rows, setRows] = useState<any[]>([]);
  const [shown, setShown] = useState<any[]>([]); // what the table shows (held while hovering or a frame is open)
  const [paused, setPaused] = useState(false);
  const [others, setOthers] = useState(() => pref.flag("live.others", false));
  const [decode, setDecode] = useState(() => pref.flag("live.decode", true));
  const [kind, setKind] = useState(() => pref.get("live.kind", "noack"));
  const [q, setQ] = useState("");
  const [hover, setHover] = useState(false);
  const [unseen, setUnseen] = useState(0);
  const [sel, setSel] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const st = useRef({ after: 0, rows: [] as any[], epoch: 0, busy: false });
  const tbl = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const decodeRef = useRef(decode);
  decodeRef.current = decode;
  const drawer = !!frameRef.value;
  const held = hover || drawer;

  // the table follows the rows unless held
  useEffect(() => {
    if (!held) { setShown(rows); setUnseen(0); }
  }, [rows, held]);

  useEffect(() => {
    let alive = true;
    st.current.after = 0;
    st.current.rows = [];
    setRows([]);
    const ep = ++st.current.epoch;
    const load = async () => {
      if (!alive || document.hidden || pausedRef.current || st.current.busy) return;
      st.current.busy = true;
      try {
        const d = await api(`api/live?after=${st.current.after}${others ? "&others=1" : ""}${decodeRef.current ? "&decode=1" : ""}${addr ? `&addr=${encodeURIComponent(addr)}` : ""}`);
        if (!alive || ep !== st.current.epoch) return;
        setErr(null);
        const fresh: any[] = Array.isArray(d.frames) ? d.frames : [];
        if (!fresh.length) return;
        // more frames than one answer carries arrived since the last one (after a pause): mark the gap
        const skipped = f.num(d.skipped);
        const gap = st.current.after > 0 && st.current.rows.length && (skipped !== null ? skipped > 0 : fresh.length >= LIVE_CAP);
        st.current.after = fresh[fresh.length - 1].id;
        fresh.reverse();
        if (gap) fresh.push({ gap: true, text: skipped ? `${f.n(skipped)} frames skipped here: more arrived than one update carries` : "Some frames were skipped here: more arrived than one update carries (see Captures for all of them)" });
        st.current.rows = fresh.concat(st.current.rows).slice(0, 600);
        setRows(st.current.rows);
        setUnseen((u) => u + fresh.filter((x) => !x.gap).length);
      } catch (e: any) {
        if (alive) setErr(e?.message || String(e));
      } finally {
        st.current.busy = false;
      }
    };
    load();
    const t = window.setInterval(load, 2000);
    const vis = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", vis);
    return () => { alive = false; clearInterval(t); document.removeEventListener("visibilitychange", vis); };
  }, [others, addr]);

  const ql = q.trim().toLowerCase();
  const filter = (list: any[]) => dropLoneGaps(list.filter((x) => x.gap || (kindOk(kind, x) && (!ql || frameHay(x, f.clockMs).includes(ql)))));
  const visible = filter(shown);
  const total = shown.filter((x) => !x.gap).length;
  const waiting = held ? rows.length - shown.length : 0;
  const showNew = () => { setShown(rows); setUnseen(0); if (tbl.current) tbl.current.scrollTop = 0; };
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Live</h1>
          <p class="lede">{visible.filter((x) => !x.gap).length} of the last {total} frames{paused ? " · paused" : ""}</p>
        </div>
      </div>
      <PageError err={err} what="Couldn't load new frames" />
      <div class="toolbar">
        <button type="button" class={`btn small ${paused ? "primary" : ""}`} aria-pressed={paused} onClick={() => setPaused(!paused)}>
          <Icon name={paused ? "play" : "pause"} size={14} /> {paused ? "Resume" : "Pause"}
        </button>
        <button type="button" class="btn small" aria-pressed={decode} onClick={() => { setDecode(!decode); pref.setFlag("live.decode", !decode); }}>Decode summaries</button>
        <button type="button" class="btn small" aria-pressed={others} onClick={() => { setOthers(!others); pref.setFlag("live.others", !others); }}>Other networks</button>
        <select class="select" value={kind} aria-label="Frame kinds" onChange={(e) => { const v = (e.target as HTMLSelectElement).value; setKind(v); pref.set("live.kind", v); }}>
          <option value="noack">All but ACKs</option><option value="">All frames</option><option value="data">Data</option><option value="nwkcmd">Mesh commands</option>
          <option value="mac">MAC commands</option><option value="ack">ACKs</option><option value="retry">Resent only</option>
        </select>
        <label class="search">
          <Icon name="search" size={16} />
          <input type="search" value={q} placeholder="Filter: name, address, text" aria-label="Filter frames" onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
        </label>
        {addr && <span class="pill">Device <b>{addr}</b> <a href="#/live" title="Show every device" aria-label="Show every device"><Icon name="x" size={13} /></a></span>}
        {held && waiting > 0 && unseen > 0 && (
          <button type="button" class="btn small primary" title="New frames are held while the pointer is on the table or a frame is open" onClick={showNew}>
            {f.plural(unseen, "new frame")}
          </button>
        )}
      </div>
      <div class="card flush">
        <div class="table-wrap cap" ref={tbl}
          onPointerEnter={(e) => { if (e.pointerType !== "touch") setHover(true); }}
          onPointerLeave={(e) => { if (e.pointerType !== "touch") setHover(false); }}>
          <FramesTable frames={visible.slice(0, 400)} sel={sel} onOpen={setSel} />
        </div>
      </div>
      <p class="foot">The table holds still while the pointer is on it or a frame is open; new frames wait behind the button above.</p>
    </div>
  );
}
