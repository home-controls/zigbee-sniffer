// Captures: every frame heard, one file per hour, decrypted with tshark. Pick an hour (or arrive
// with ?t= / ?file=&n= / ?addr= / ?q=), search, page through, open a frame, download the hour as
// .pcap or fully decoded text / JSON.

import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../kit/icons";
import { api } from "../api";
import * as f from "../fmt";
import { fileHour, hourFile } from "../logic";
import { Loading, PageError, Spin } from "../bits";
import { CaptureRows, openFrame } from "../frames";

const LIMIT = 200;

export function Captures({ q: query }: { q: URLSearchParams }) {
  const [list, setList] = useState<any | null>(null);
  const [listErr, setListErr] = useState<string | null>(null);
  const [file, setFile] = useState(query.get("file") || "");
  const [q, setQ] = useState(query.get("q") || "");
  const [addr, setAddr] = useState((query.get("addr") || "").toLowerCase());
  const [retries, setRetries] = useState(false);
  const [others, setOthers] = useState(false);
  const [res, setRes] = useState<any | null>(null);
  const [count, setCount] = useState<preact.ComponentChildren>("");
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState<number | null>(null);
  const tok = useRef(0);
  const alive = useRef(true);
  const tbl = useRef<HTMLDivElement>(null);
  const cur = useRef({ file, q, addr, retries, others, offset: 0 });
  cur.current = { ...cur.current, file, q, addr, retries, others };
  useEffect(() => () => { alive.current = false; }, []);

  const files: any[] = Array.isArray(list) ? list : Array.isArray(list?.files) ? list.files : [];
  const filesRef = useRef<any[]>([]);
  filesRef.current = files;
  const hasFile = (x: string) => filesRef.current.some((y) => y.file === x);

  /** opts: {n} opens the page holding frame n and its decode; {t} the page holding time t (highlighted). */
  const show = async (opts: { n?: number; t?: number; local?: boolean; offset?: number; file?: string } = {}) => {
    const my = ++tok.current;
    const c = cur.current;
    const offset = opts.offset ?? 0;
    const qs = new URLSearchParams({ limit: String(LIMIT), q: c.q.trim(), addr: c.addr.trim().toLowerCase(), others: c.others ? "1" : "0", retries: c.retries ? "1" : "0" });
    const useFile = opts.file ?? c.file;
    if (opts.t && !opts.local) qs.set("t", String(Math.floor(opts.t)));
    else {
      if (!useFile) return;
      qs.set("file", useFile);
      if (opts.n) qs.set("n", String(opts.n)); else qs.set("offset", String(offset));
    }
    setLoading(true);
    setCount(<><Spin /> decoding…</>);
    let d: any;
    try { d = await api("api/decode?" + qs); } catch (e: any) {
      if (my !== tok.current || !alive.current) return;
      setLoading(false);
      // an older backend without `t`: the hour file holding t, if it is there
      const guess = opts.t && !opts.local ? hourFile(opts.t) : null;
      if (guess && hasFile(guess)) { setFile(guess); cur.current.file = guess; return show({ t: opts.t, local: true, file: guess }); }
      setCount(e?.message || String(e));
      return;
    }
    if (my !== tok.current || !alive.current) return;
    setLoading(false);
    const shownFile = d.file && (hasFile(d.file) || !filesRef.current.length) ? d.file : useFile;
    setFile(shownFile);
    cur.current.file = shownFile;
    cur.current.offset = d.offset;
    setRes({ ...d, file: shownFile });
    setCount(`${f.n(d.total)} frames${c.others ? "" : " of our network"} · showing ${d.total ? d.offset + 1 : 0}–${Math.min(d.offset + LIMIT, d.total)}`);
    // the row asked for: the server's `focus` (frame n matching ?t= or ?n=), else found here
    const focus = f.num(d.focus) ?? (opts.n || null);
    const rows: any[] = d.rows || [];
    const at = focus !== null ? rows.find((x) => x.n === focus) : opts.t ? rows.find((x) => x.ts >= opts.t!) || rows[rows.length - 1] : null;
    setSel(at ? at.n : null);
    if (at) {
      setTimeout(() => {
        const tr = tbl.current?.querySelector<HTMLElement>(`tr[data-n="${at.n}"]`);
        tr?.scrollIntoView({ block: "center" });
        if (opts.n && tr) openFrame({ file: shownFile, n: at.n }, tr);
      }, 0);
    }
  };

  useEffect(() => {
    let ok = true;
    api("api/captures").then((r) => {
      if (!ok) return;
      setList(r);
      const fl: any[] = Array.isArray(r) ? r : r?.files || [];
      const want = query.get("file") || "";
      const first = want && fl.some((x) => x.file === want) ? want : fl[0]?.file || "";
      filesRef.current = fl;
      setFile(first);
      cur.current.file = first;
      const t = +(query.get("t") || 0), n = +(query.get("n") || 0);
      if (t) setTimeout(() => show({ t }), 0);
      else if (query.get("file") || query.get("addr") || query.get("q")) setTimeout(() => show({ n }), 0);
    }, (e) => ok && setListErr(e?.message || String(e)));
    return () => { ok = false; };
  }, []);

  const go = () => show({ offset: 0 });
  const selT = useRef<number | undefined>(undefined);
  const pickFile = (v: string) => {
    setFile(v);
    cur.current.file = v;
    clearTimeout(selT.current);
    selT.current = window.setTimeout(() => { if (alive.current) show({ offset: 0, file: v }); }, 350);
  };
  const a = addr.trim().toLowerCase();
  const devQ = /^0x[0-9a-f]{4}$/.test(a) ? `addr=${a}&` : "";
  const enc = encodeURI(file || "");
  const info: string[] = [];
  if (list && !Array.isArray(list)) {
    if (f.num(list.oldest)) info.push(`Captures go back to ${new Date(list.oldest * 1000).toLocaleString([], { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}`);
    if (f.num(list.storage_mb) !== null) info.push(`${f.mb(+list.storage_mb)}${f.num(list.limit_mb) ? ` of ${f.mb(+list.limit_mb)}` : ""} MB`);
    if (f.num(list.retention_days)) info.push(`kept ${f.num(list.retention_days)} days`);
  }
  const byDay: Record<string, any[]> = {};
  for (const x of files) (byDay[x.file.split("/")[0]] ||= []).push(x);
  const offset = cur.current.offset;
  const enter = (e: KeyboardEvent) => { if (e.key === "Enter") go(); };
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Captures</h1>
          <p class="lede">Every frame heard, one file per hour · decrypted with tshark · click a frame for the full decode</p>
          {info.length > 0 && <p class="muted small">{info.join(" · ")}</p>}
        </div>
      </div>
      <PageError err={listErr} what="Couldn't list the captures" />
      <div class="toolbar">
        <select class="select hour-pick" value={file} aria-label="Hour" onChange={(e) => pickFile((e.target as HTMLSelectElement).value)} disabled={!files.length}>
          {Object.entries(byDay).map(([day, l]) => (
            <optgroup label={day}>
              {l.map((x) => <option value={x.file}>{day} {fileHour(x.file)}:00–{fileHour(x.file)}:59 · {f.bytes(x.size)}{x.frames ? ` · ${f.n(x.frames)} frames` : ""}{x.current ? " · recording" : ""}</option>)}
            </optgroup>
          ))}
        </select>
        <label class="search">
          <Icon name="search" size={16} />
          <input type="search" value={q} placeholder="Search decoded text (Leave, Report Attributes…)" aria-label="Search decoded text"
            onInput={(e) => setQ((e.target as HTMLInputElement).value)} onKeyDown={enter} />
        </label>
        <input class="select addr-input" value={addr} placeholder="Device address" aria-label="Device short address"
          onInput={(e) => setAddr((e.target as HTMLInputElement).value)} onKeyDown={enter} />
        <button type="button" class="btn small" aria-pressed={retries} onClick={() => setRetries(!retries)}>Resent only</button>
        <button type="button" class="btn small" aria-pressed={others} onClick={() => setOthers(!others)}>Other networks</button>
        <button type="button" class="btn small primary" onClick={go} disabled={!file}>Show</button>
      </div>
      <div class="toolbar">
        <span class="muted small">Download</span>
        <a class={`btn small ${file ? "" : "disabled"}`} href={file ? "download/" + enc : undefined} aria-disabled={!file} title="The capture as heard, for Wireshark"><Icon name="download" size={14} /> .pcap</a>
        <a class={`btn small ${file ? "" : "disabled"}`} href={file ? `decoded/${enc}?${devQ}format=text` : undefined} aria-disabled={!file} title="Every frame fully decoded and decrypted by tshark (only the device above, if given)">decoded .txt</a>
        <a class={`btn small ${file ? "" : "disabled"}`} href={file ? `decoded/${enc}?${devQ}format=json` : undefined} aria-disabled={!file} title="tshark's JSON of every frame, decrypted (only the device above, if given)">decoded .json</a>
        <span class="spacer" />
        <button type="button" class="btn small" disabled={!res || offset <= 0 || loading} onClick={() => show({ offset: Math.max(0, offset - LIMIT) })}><Icon name="back" size={14} /> Previous</button>
        <button type="button" class="btn small" disabled={!res || offset + LIMIT >= (res?.total || 0) || loading} onClick={() => show({ offset: offset + LIMIT })}>Next <Icon name="chevron" size={14} /></button>
        <span class="muted small" role="status">{count}</span>
      </div>
      <div class="card flush">
        <div class="table-wrap cap" ref={tbl}>
          {!list && !listErr ? <Loading />
            : !files.length ? <div class="empty">No captures stored yet.</div>
              : !res ? <div class="empty">Pick an hour and press Show.</div>
                : (res.rows || []).length ? <CaptureRows rows={res.rows} file={res.file} sel={sel} />
                  : <div class="empty">No frames match.</div>}
        </div>
      </div>
    </div>
  );
}
