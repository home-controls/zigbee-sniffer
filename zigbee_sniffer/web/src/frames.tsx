// Frames as a table, and the drawer with a frame's full tshark decode (from the live buffer by its
// live id, else from the capture file and frame number once it has left the buffer).

import { signal } from "@preact/signals";
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "./kit/icons";
import { Chip, KV, copyText } from "./kit/ui";
import { api } from "./api";
import { AddrLabel, HeardBy, heardTitle, Loading } from "./bits";
import * as f from "./fmt";
import { capturesLink, splitDecode, treeOpen, type TreeNode } from "./logic";

export interface FrameRef { live?: string | number | null; file?: string | null; n?: number | null }

export const frameRef = signal<FrameRef | null>(null);
let opener: HTMLElement | null = null;

export function openFrame(ref: FrameRef, from?: HTMLElement | null): void {
  opener = from || (document.activeElement as HTMLElement | null);
  frameRef.value = { ...ref };
}

export function closeFrame(): void {
  if (!frameRef.value) return;
  frameRef.value = null;
  const o = opener;
  opener = null;
  // the page may have re-rendered its rows meanwhile: find the same frame again
  setTimeout(() => {
    const live = o?.dataset?.live;
    const target = o && o.isConnected ? o : live ? (document.querySelector(`tr[data-live="${CSS.escape(live)}"]`) as HTMLElement | null) : null;
    target?.focus({ preventScroll: true });
  }, 0);
}

/** A row opens on click, Enter or Space. */
function rowKeys(open: (el: HTMLElement) => void) {
  return {
    tabIndex: 0,
    onClick: (e: MouseEvent) => { if (!(e.target as Element).closest("a")) open(e.currentTarget as HTMLElement); },
    onKeyDown: (e: KeyboardEvent) => {
      if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) { e.preventDefault(); open(e.currentTarget as HTMLElement); }
    },
  };
}

/** Live frames; `sel` is the live id of the row to keep highlighted; `onOpen` hears which one opened. */
export function FramesTable({ frames, compact, sel, onOpen }: { frames: any[]; compact?: boolean; sel?: string | null; onOpen?: (id: string) => void }) {
  if (!frames.length) return <div class="empty">No frames.</div>;
  return (
    <table class="data dense frames">
      <thead><tr><th>Time</th><th class="num">Signal</th><th>Kind</th><th>Over the air</th><th>Network layer</th>{!compact && <th>Summary</th>}</tr></thead>
      <tbody>
        {frames.map((x) => {
          if (x.gap) return <tr class="gap"><td colSpan={compact ? 5 : 6}>{x.text || "Frames skipped here"}</td></tr>;
          const id = f.num(x.id);
          const file = x.file && f.num(x.n) ? x.file : null;
          const isSel = sel !== null && sel !== undefined && String(x.id) === String(sel);
          const open = (el: HTMLElement) => { onOpen?.(String(x.id)); openFrame({ live: id, file, n: file ? f.num(x.n) : null }, el); };
          return (
            <tr class={`click ${x.ours ? "" : "them"} ${isSel ? "sel" : ""} ${x.retry ? "retry" : ""}`} data-live={id ?? ""} {...rowKeys(open)}>
              <td class="mono">{f.clockMs(x.ts)}</td>
              <td class="num" title={heardTitle(x.heard_by)}>{f.num(x.rssi) ?? ""}<HeardBy hb={x.heard_by} /></td>
              <td>
                {x.kind}
                {x.retry && <> <Chip tone="warn" title="sent again: the first try got no ACK">resent</Chip></>}
                {x.late && <> <Chip tone="muted" title="heard while the app was away; the bridge kept it and delivered it later">buffered</Chip></>}
                {!x.ours && <span class="sub"> PAN {x.pan || "none"}</span>}
              </td>
              <td>
                {x.src || x.dst
                  ? <>{x.src ? <AddrLabel addr={x.src} name={x.src_name} /> : <span class="muted">—</span>} <span class="muted">→</span> {x.dst ? <AddrLabel addr={x.dst} name={x.dst_name} /> : <span class="muted">—</span>}</>
                  : <span class="muted">—</span>}
              </td>
              <td>{x.nwk_src && <><AddrLabel addr={x.nwk_src} name={x.nwk_src_name} /> <span class="muted">→</span> <AddrLabel addr={x.nwk_dst} name={x.nwk_dst_name} /></>}</td>
              {!compact && <td class="wrap">{x.proto && <><span class="sub">{x.proto}</span>{" "}</>}{x.info}</td>}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Stored frames (Captures): numbered, from the capture file. */
export function CaptureRows({ rows, file, sel }: { rows: any[]; file: string; sel: number | null }) {
  return (
    <table class="data dense frames">
      <thead><tr><th class="num">#</th><th>Time</th><th class="num">Signal</th><th>From (air)</th><th>To (air)</th><th>Origin</th><th>Destination</th><th>Summary</th></tr></thead>
      <tbody>
        {rows.map((x) => {
          const n = f.num(x.n);
          const open = (el: HTMLElement) => openFrame({ file, n }, el);
          return (
            <tr class={`click ${x.ours ? "" : "them"} ${n === sel ? "sel" : ""} ${x.retry ? "retry" : ""}`} data-n={n ?? ""} {...rowKeys(open)}>
              <td class="num muted">{n}</td>
              <td class="mono">{f.clockMs(x.ts)}</td>
              <td class="num" title={heardTitle(x.heard_by)}>{f.num(x.rssi) ?? ""}<HeardBy hb={x.heard_by} /></td>
              <td>{x.mac_src}</td><td>{x.mac_dst}</td><td>{x.nwk_src}</td><td>{x.nwk_dst}</td>
              <td class="wrap">
                <span class="sub">{x.proto || x.kind}</span> {x.info || x.kind}
                {x.retry && <> <Chip tone="warn">resent</Chip></>}
                {!x.ours && <span class="sub"> PAN {x.pan || "none"}</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Tree({ nodes, depth }: { nodes: TreeNode[]; depth: number }) {
  return (
    <>
      {nodes.map((n) => n.children.length
        ? <details open={treeOpen(n, depth)}><summary>{n.text}</summary><Tree nodes={n.children} depth={depth + 1} /></details>
        : <div class="leaf">{n.text}</div>)}
    </>
  );
}

const FOCUSABLE = 'button:not([disabled]), a[href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';

export function FrameDrawer() {
  const ref = frameRef.value;
  const box = useRef<HTMLElement>(null);
  const [data, setData] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<boolean | null>(null);
  const [copied, setCopied] = useState("");
  useEffect(() => {
    if (!ref) return;
    let alive = true;
    setData(null); setErr(null); setExpanded(null); setCopied("");
    const parts: string[] = [];
    if (ref.live) parts.push(`live=${encodeURIComponent(String(ref.live))}`);
    if (ref.file && ref.n) parts.push(`file=${encodeURIComponent(ref.file)}&n=${encodeURIComponent(String(ref.n))}`);
    api("api/frame?" + parts.join("&")).then((d) => alive && setData(d), (e) => alive && setErr(e?.message || String(e)));
    setTimeout(() => (box.current?.querySelector("[data-close]") as HTMLElement | null)?.focus(), 0);
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") closeFrame(); };
    document.addEventListener("keydown", esc);
    return () => { alive = false; document.removeEventListener("keydown", esc); };
  }, [ref]);
  if (!ref) return null;
  const trap = (e: KeyboardEvent) => {
    if (e.key !== "Tab" || !box.current) return;
    const els = [...box.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null);
    if (!els.length) return;
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  const dec = data ? splitDecode(String(data.text || "")) : null;
  const copy = async () => {
    const ok = await copyText(String(data?.text || ""));
    setCopied(ok ? "Copied" : "Copy failed");
    setTimeout(() => setCopied(""), 1500);
  };
  return (
    <>
      <div class="drawer-bg" onClick={closeFrame} />
      <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="fr-title" ref={box} onKeyDown={trap}>
        <header>
          <h2 id="fr-title">Frame</h2>
          {data && <span class="muted small">#{f.num(data.n)} in {data.file} · <a href={capturesLink({ file: data.file, n: f.num(data.n) || 0 })} onClick={() => closeFrame()}>open in Captures</a></span>}
          <span class="spacer" />
          {data && (
            <>
              <button type="button" class="btn small" onClick={() => {
                const v = !expanded;
                setExpanded(v);
                box.current?.querySelectorAll("details").forEach((d) => (d.open = v));
              }}>{expanded ? "Collapse all" : "Expand all"}</button>
              <button type="button" class="btn small" onClick={copy}><Icon name="copy" size={14} /> {copied || "Copy"}</button>
            </>
          )}
          <button type="button" class="icon-btn" data-close aria-label="Close" title="Close (Esc)" onClick={closeFrame}><Icon name="x" size={18} /></button>
        </header>
        <div class="drawer-body">
          {err && <p class="note warn"><Icon name="alert" size={16} /> {err}</p>}
          {!data && !err && <Loading>Decoding with tshark…</Loading>}
          {data && dec && (
            <>
              <KV rows={[
                ["Time", <>{new Date(data.ts * 1000).toLocaleString()} <span class="mono">{f.clockMs(data.ts)}</span></>],
                ["Signal", `${f.num(data.rssi) ?? "—"} dBm · LQI ${f.num(data.lqi) ?? "—"}`],
                ["Kind", `${data.kind} · ${f.num(data.len) ?? "—"} bytes`],
              ]} />
              <div class="tree"><Tree nodes={dec.tree} depth={0} /></div>
              {dec.hex && <pre class="hex">{dec.hex}</pre>}
            </>
          )}
        </div>
      </aside>
    </>
  );
}
