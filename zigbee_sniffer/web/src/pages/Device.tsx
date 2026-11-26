// One device: what it is, ping (Zigbee2MQTT reads it, the sniffer traces the round trip), the
// stored hours with its frames, its numbers against its normal, incidents, findings, signal per
// sniffer, traffic, delivery, mesh commands, firmware, mesh neighbours, routes, where its resends go,
// who it talks with over the air, events and its latest frames.

import { useEffect, useRef, useState } from "preact/hooks";
import { Card, Chip, KV } from "../kit/ui";
import { Icon } from "../kit/icons";
import { api, post, sleep } from "../api";
import { usePoll } from "../poll";
import { pref, range, several } from "../store";
import * as f from "../fmt";
import { BROADCASTS, capturesLink, foldHops, pingStats, pingWord, seriesMap, type PingResult } from "../logic";
import {
  AddrLabel, CostChip, EventsTable, FindingsList, Incidents, Loading, Meter, OtaBadge, OtaBar, otaDownload, otaStatus,
  PageError, SevIcon, Spark, Spin, Tile, Unit,
} from "../bits";
import { FramesTable } from "../frames";
import { TimeChart, TipRow } from "../timechart";

const Hint = ({ children, title }: { children: preact.ComponentChildren; title?: string }) => <span class="muted small hint" title={title}>{children}</span>;
export const SNIFFER_COLORS = ["var(--series-1)", "var(--series-2)", "var(--series-3)", "var(--info)", "var(--warn)", "var(--ok)"];
const sc = (i: number) => SNIFFER_COLORS[i % SNIFFER_COLORS.length];

export function Device({ addr }: { addr: string }) {
  const { data: d, err } = usePoll(10000, () => api(`api/device/${encodeURIComponent(addr)}?range=${range.value}`), [addr, range.value]);
  const [ping, setPing] = useState<number>(0); // a ping panel's run (count, 0 = none)
  const [pingKey, setPingKey] = useState(0);
  const [hoursOpen, setHoursOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const startPing = (count: number) => { if (busy) return; setPing(count); setPingKey(pingKey + 1); };
  return (
    <div class="page">
      <a class="back" href="#/devices"><Icon name="back" size={16} /> Devices</a>
      <PageError err={err} />
      {!d ? (!err && <Loading />) : (
        <>
          <Head d={d} busy={busy} onPing={startPing} hoursOpen={hoursOpen} onHours={() => setHoursOpen(!hoursOpen)} />
          {ping > 0 && <PingPanel key={pingKey} addr={addr} count={ping} setBusy={setBusy} onClose={() => setPing(0)} />}
          {hoursOpen && <HoursPanel addr={addr} onClose={() => setHoursOpen(false)} />}
          <Body d={d} />
        </>
      )}
    </div>
  );
}

function Head({ d, busy, onPing, hoursOpen, onHours }: { d: any; busy: boolean; onPing: (n: number) => void; hoursOpen: boolean; onHours: () => void }) {
  const dev = d.device;
  const ota = d.ota && typeof d.ota === "object" ? d.ota : null;
  const live = dev.last_seen && Date.now() / 1000 - dev.last_seen < 120;
  const canPing = dev.known && dev.type !== "Coordinator";
  return (
    <div class="card dev-head">
      <div class="dev-id">
        <h1>{dev.name || dev.addr}</h1>
        <div class="facts">
          <Chip tone="muted">{f.TYPE_WORD[dev.type] || "Not in Zigbee2MQTT"}</Chip>
          {(dev.vendor || dev.model) && <span>{[dev.vendor, dev.model].filter(Boolean).join(" · ")}</span>}
          {dev.power && <span>{dev.power}</span>}
          <span>Short <span class="mono">{dev.addr}</span></span>
          {dev.ieee && <span>IEEE <span class="mono">{dev.ieee}</span></span>}
          <span><span class={`dot ${live ? "ok" : "muted"}`} /> last heard {f.ago(dev.last_seen, undefined, "never")}{f.num(dev.last_rssi) !== null ? ` at ${f.num(dev.last_rssi)} dBm` : ""}</span>
          {ota && <span class="ota-fact">Firmware download <OtaBadge o={ota} /> <OtaBar p={ota.progress} from={ota.from} /> <span class="muted">{otaStatus(ota)}</span></span>}
        </div>
      </div>
      <div class="actions">
        {canPing && (
          <>
            <button type="button" class="btn primary" disabled={busy} title="Ask Zigbee2MQTT to read the device and trace the round trip on air" onClick={() => onPing(1)}>Ping</button>
            <button type="button" class="btn" disabled={busy} title="Five pings in a row: how many get an answer, and how long they take" onClick={() => onPing(5)}>Ping ×5</button>
          </>
        )}
        <a class="btn" href={`#/live?addr=${encodeURIComponent(dev.addr)}`}>Watch live</a>
        <button type="button" class="btn" aria-expanded={hoursOpen} onClick={onHours}>Search captures</button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ ping

function TraceView({ t, running }: { t: any; running: boolean }) {
  const head = t.response_seen ? <><SevIcon sev="good" /> <b>Answered in {f.n(t.rtt_ms)} ms</b></>
    : t.request_seen ? <>{running ? <Spin /> : <SevIcon sev="warn" />} Request heard on air{running ? ", waiting for the reply…" : "; no reply heard (the device didn't answer, or the sniffer missed it)"}</>
      : running ? <><Spin /> Waiting for the request on air…</> : <><SevIcon sev="warn" /> The request wasn't heard on air (Zigbee2MQTT may have queued it, or the sniffer missed it)</>;
  return (
    <>
      <div class="sevline">{head}</div>
      {(t.messages || []).map((m: any) => {
        const steps = foldHops(m.hops || []) as any[];
        const label = m.dir === "request" ? (/Read Attributes/.test(m.info || "") ? "Request" : "From the coordinator") : /Response/.test(m.info || "") ? "Reply" : "From the device";
        return (
          <div class="trace-msg">
            <div class="trace-head"><Chip tone="muted">{label}</Chip> <span class="ink2">{m.info || "(not decoded)"}</span> <span class="muted">at {f.n(m.start_ms)} ms</span></div>
            <div class="path">
              {steps.map((s, i) => (
                <>
                  {i === 0 && <span class="hop"><AddrLabel addr={s.from} name={s.from_name || s.from} /></span>}
                  <span class="hop-link" title={`${s.from_name || s.from} → ${s.to_name || s.to}: heard at ${s.rssi} dBm, ${s.tries} ${s.tries === 1 ? "try" : "tries"}, ${s.acked ? "ACK heard" : "no ACK heard"}, ${s.ms} ms`}>
                    <span class="arr">→</span>
                    <small>{f.num(s.rssi)} dBm{s.tries > 1 && <> · <Chip tone="warn">{s.tries} tries</Chip></>}{s.acked ? " · ACK" : <> · <span class="warn-text">no ACK</span></>}</small>
                  </span>
                  <span class="hop"><AddrLabel addr={s.to} name={s.to_name || s.to} /></span>
                </>
              ))}
            </div>
          </div>
        );
      })}
      {(t.polls || []).length > 0 && <p class="muted small">It polled its parent {f.plural(t.polls.length, "time")} meanwhile (a sleepy end device picks up messages when it polls).</p>}
    </>
  );
}

/** Ping: Zigbee2MQTT reads the device's ZCL version; the sniffer shows the request and the reply hop
 * by hop. `count` > 1 runs that many in a row and sums up how many were answered and how fast. */
function PingPanel({ addr, count, setBusy, onClose }: { addr: string; count: number; setBusy: (b: boolean) => void; onClose: () => void }) {
  const [res, setRes] = useState<PingResult[]>([]);
  const [running, setRunning] = useState(true);
  const [trace, setTrace] = useState<{ t: any; running: boolean } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [none, setNone] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    const ok = () => alive.current;
    setBusy(true);
    (async () => {
      const out: PingResult[] = [];
      try {
        for (let k = 0; k < count && ok(); k++) {
          setTrace(null); setNone(false); setMsg(null);
          let p: any;
          try { p = await post(`api/ping/${encodeURIComponent(addr)}`); } catch (e: any) {
            if (!ok()) return;
            setMsg(e?.message || String(e));
            out.push({ ok: false, err: e?.message });
            setRes([...out]);
            break; // the same error would repeat (no name, MQTT down)
          }
          if (!ok()) return;
          // ask for traces until the reply has been seen for a little while (or time runs out)
          let t: any = null, after = 0;
          const maxSec = count > 1 ? 15 : 20, settle = count > 1 ? 2 : 3;
          for (let i = 0; i < maxSec && after < settle && ok(); i++) {
            await sleep(1000);
            if (!ok()) return;
            try { t = await api(`api/trace/${encodeURIComponent(addr)}?since=${p.t0}`); } catch { continue; }
            if (!ok()) return;
            setTrace({ t, running: true });
            if (t.response_seen) after++;
          }
          if (!ok()) return;
          if (t) setTrace({ t, running: false }); else setNone(true);
          out.push({ ok: !!(t && t.response_seen && t.rtt_ms != null), rtt: t && t.response_seen ? t.rtt_ms : null, req: !!(t && t.request_seen), none: !t });
          setRes([...out]);
          if (k < count - 1) await sleep(1000);
        }
      } finally {
        if (ok()) { setRunning(false); setBusy(false); }
      }
    })();
    return () => { alive.current = false; setBusy(false); };
  }, []);
  const st = pingStats(res);
  return (
    <Card title={count > 1 ? `Ping ×${count}` : "Ping"} class="wide"
      actions={<><Hint>Zigbee2MQTT reads its ZCL version (Basic cluster); the sniffer traces the round trip</Hint>
        <button type="button" class="btn small" onClick={onClose}>Close</button></>}>
      {count > 1 && (
        <div role="status" class="ping-sum">
          <div class="sevline">
            {running ? <><Spin /> Ping {Math.min(count, res.length + 1)} of {count}…</> : <>
              <SevIcon sev={st.answered === st.total && st.total ? "good" : st.answered ? "warn" : "high"} />{" "}
              <b>{st.answered} of {st.total} answered ({st.pct}%)</b>
              {st.median !== null && ` · median ${f.n(st.median)} ms · max ${f.n(st.max)} ms`}
              {res.length < count && ` · stopped after ${res.length}`}
            </>}
          </div>
          {res.length > 0 && (
            <div class="ping-chips">
              {res.map((x, i) => <Chip tone={x.ok ? "ok" : x.req ? "warn" : "bad"} title={x.err}>{i + 1}: {pingWord(x, (v) => `${f.n(v)} ms`)}</Chip>)}
            </div>
          )}
        </div>
      )}
      {msg ? <p class="note warn"><Icon name="alert" size={16} /> {msg}</p>
        : none ? <p class="note warn"><Icon name="alert" size={16} /> No trace came back: the app didn't answer the trace requests. Try again, or check the Sniffer page.</p>
          : trace ? <TraceView t={trace.t} running={trace.running} /> : running ? <Loading>Asking Zigbee2MQTT…</Loading> : null}
    </Card>
  );
}

// ------------------------------------------------------------------ hours with its frames

function HoursPanel({ addr, onClose }: { addr: string; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [hours, setHours] = useState<any[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const r = range.value;
  useEffect(() => {
    let alive = true;
    setHours(null); setErr(null);
    api(`api/device/${encodeURIComponent(addr)}/hours?range=${r}`).then(
      (res) => alive && setHours(Array.isArray(res.hours) ? res.hours : []),
      (e) => alive && setErr(e?.message || String(e)));
    return () => { alive = false; };
  }, [addr, r]);
  return (
    <Card title="Search captures" class="wide"
      actions={<><Hint>stored hours with frames from this device, {f.RANGE_WORD[r]} · each opens Captures filtered to it</Hint>
        <button type="button" class="btn small" onClick={onClose}>Close</button></>}>
      <div class="toolbar">
        <label class="search">
          <Icon name="search" size={16} />
          <input type="search" value={q} placeholder="Also search decoded text (optional)" aria-label="Also search decoded text"
            onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
        </label>
      </div>
      {err ? <p class="note warn"><Icon name="alert" size={16} /> Couldn't list the hours: {err}. <a href={capturesLink({ addr })}>Open Captures for this device (newest hour)</a></p>
        : !hours ? <Loading>Looking through the stored hours…</Loading>
          : !hours.length ? <div class="empty">No frames from this device in the stored captures, {f.RANGE_WORD[r]}.</div> : (
            <div class="table-wrap scroll">
              <table class="data dense">
                <thead><tr><th>Hour</th><th class="num">Its frames</th></tr></thead>
                <tbody>
                  {hours.map((h) => {
                    const st = f.num(h.start);
                    return (
                      <tr>
                        <td><a href={capturesLink({ file: h.file, addr, q: q.trim() || undefined })}>{st !== null ? `${f.when(st)}–${f.hm(st + 3600)}` : h.file}</a></td>
                        <td class="num muted">{f.n(f.num(h.frames))}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
    </Card>
  );
}

// ------------------------------------------------------------------ the rest

function Body({ d }: { d: any }) {
  const [mode, setModeState] = useState(() => pref.get("sigmode", "rel"));
  const setMode = (m: string) => { setModeState(m); pref.set("sigmode", m); };
  const [sel, setSel] = useState<string | null>(null);
  const dev = d.device, b = d.bucket, x1 = d.now, x0 = d.now - d.span;
  const marks = Array.isArray(d.marks) ? d.marks : [];
  const incs: any[] = Array.isArray(d.incidents) ? d.incidents : [];
  const common = { x0, x1, bucket: b, marks, incidents: incs, capAddr: dev.addr };
  const ota = d.ota && typeof d.ota === "object" ? d.ota : null;
  const ed = dev.type === "EndDevice";
  const bl = d.baseline && typeof d.baseline === "object" ? d.baseline : null;
  const blTitle = bl ? `“normal” is this device's typical value${f.num(bl.days) ? ` over the last ${f.num(bl.days)} days` : ""}` : undefined;
  const normal = (v: unknown, fm: (x: number) => string) => (bl && f.num(v) !== null ? ` · normal ${fm(+v!)}` : "");
  const hours = Math.max(1 / 60, d.span / 3600);
  const lqi = f.num(dev.lqi_avg);
  const multiName = several.value && dev.rssi_sniffer_name;
  // series: [b, tx, rssi_avg, rssi_min, rssi_max, lqi_avg, uni, retry, relay, poll, msgs, rx, noack, air]
  const sr: any[] = d.series || [];
  const ss: any[] = (Array.isArray(d.signal_series) ? d.signal_series : []).filter((x: any) => Array.isArray(x.data) && x.data.length);
  const multi = ss.length > 1;
  const sigs: any[] = Array.isArray(dev.signal) ? dev.signal : [];
  const m = multi ? mode : "abs";
  const refName = (x: any) => (x.ref_kind === "range" ? `${x.name} (vs this range: no normal yet)` : x.name);
  const thin = sr.some((r) => r[6] > 0 || r[11] > 0) && !sr.some((r) => r[6] >= 8 || r[11] >= 8);
  const cmds: any[] = d.cmds || [];
  const cmd = (names: string[]) => { const mm = new Map<number, number>(); for (const [t2, c, k] of cmds) if (names.includes(c)) mm.set(t2, (mm.get(t2) || 0) + k); return mm; };
  const hist = d.link_history || {};
  const nh: any[] = Array.isArray(d.next_hops) ? d.next_hops : [];
  const fw = d.firmware && typeof d.firmware === "object" ? d.firmware : null;
  const sess: any[] = ota && Array.isArray(ota.sessions) ? ota.sessions : [];
  const routes = (list: any[], word: string) => list.length > 0 && (
    <>
      <tr class="grp"><td colSpan={2}>{word}</td></tr>
      {list.map((x) => (
        <tr>
          <td class="wrap">
            <div class="path">
              {x.path.map((h: any, i: number) => (
                <>
                  {i > 0 && <span class="arr">→</span>}
                  {h ? <span class={`hop ${h.addr === dev.addr ? "me" : ""}`}>{h.addr === dev.addr ? h.name || h.addr : <AddrLabel addr={h.addr} name={h.name || h.addr} />}</span>
                    : <span class="gap" title="hops the sniffer didn't hear">…</span>}
                </>
              ))}
            </div>
          </td>
          <td class="num muted">{f.n(x.n)}</td>
        </tr>
      ))}
    </>
  );
  const mini = (title: string, rows: any[], withRssi?: boolean) => rows.length > 0 && (
    <>
      <h4>{title}</h4>
      <table class="data dense">
        <tbody>
          {rows.slice(0, 8).map((x) => (
            <tr><td><AddrLabel addr={x.addr} name={x.name || x.addr} /></td><td class="num muted">{f.n(x.n)}</td>
              {withRssi && <td class="num muted">{x.rssi_avg != null ? Math.round(x.rssi_avg) + " dBm" : ""}</td>}</tr>
          ))}
        </tbody>
      </table>
    </>
  );
  const air = [
    mini(ed ? "Sends to (its parent first)" : "Sends to (next hops)", (d.sends_to || []).filter((x: any) => !BROADCASTS.has(x.addr) || x.addr === "0xfffb")),
    mini("Hears from", d.hears_from || [], true), mini("Forwards messages of", d.relays_for || []), mini("Its messages are forwarded by", d.relayed_by || [], true),
  ].filter(Boolean);
  return (
    <>
      <div class="stats">
        <Tile label={multiName ? "Signal" : "Signal at sniffer"} title={blTitle}
          value={dev.rssi_avg == null ? "—" : <>{Math.round(dev.rssi_avg)}<Unit>dBm</Unit></>}
          sub={`${multiName ? `at ${dev.rssi_sniffer_name}, the sniffer that hears it best${sigs.filter((x) => x.sniffer !== dev.rssi_sniffer).map((x) => ` · ${x.name} ${Math.round(x.rssi_avg)}`).join("")} · ` : ""}${lqi !== null ? `LQI ${Math.round(lqi)} · ` : ""}${dev.rssi_min != null ? `range ${f.num(dev.rssi_min)} to ${f.num(dev.rssi_max)} dBm` : "not heard directly"}${normal(bl?.rssi_avg, (v) => Math.round(v) + " dBm")}`} />
        <Tile label="Messages" value={f.n(dev.msgs)} title={blTitle}
          sub={`it originated · ${f.n(dev.tx)} frames on air (${f.compact(dev.tx / hours)}/h)${normal(bl?.tx_per_h, (v) => f.compact(v) + "/h")}`} />
        {ed ? <Tile label="Polls" value={f.n(dev.poll)} sub="data requests to its parent" />
          : <Tile label="Relayed" value={f.n(dev.relay)} title={blTitle} sub={`frames forwarded for others (${f.compact(dev.relay / hours)}/h)${normal(bl?.relay_per_h, (v) => f.compact(v) + "/h")}`} />}
        <Tile label="Resent" value={f.pct(dev.retry_pct)} title={blTitle} sub={`${f.n(dev.retry)} of ${f.n(dev.uni)} unicast frames${normal(bl?.retry_pct, f.pct)}`} />
        <Tile label="No ACK heard" value={f.pct(dev.noack_pct)}
          sub={`${f.n(dev.noack)} of ${f.n(dev.rx)} frames sent to it${dev.noack ? ` · ${f.n(dev.rx_lost ?? 0)} sent again (lost), ${f.n(dev.noack_missed ?? 0)} ACKs the sniffers missed` : ""}`} />
        <Tile label="Mesh neighbours" value={(d.neighbours || []).length || "—"} sub={dev.mesh ? `best link cost ${f.num(dev.mesh.best)}, worst ${f.num(dev.mesh.worst)}` : "no Link Status heard"} />
      </div>
      <div class="split">
        <div class="stack">
          {incs.length > 0 && <Card title="Incidents it was part of" actions={<Hint>{f.RANGE_WORD[d.range]}</Hint>}><Incidents list={incs} addr={dev.addr} /></Card>}
          <Card title="Findings" actions={<Hint>{f.RANGE_WORD[d.range]}</Hint>}>
            <FindingsList flags={dev.flags} empty={`No problems found ${f.RANGE_WORD[d.range]}.`} />
          </Card>
          <Card title="Signal" actions={<>
            <Hint title={multi ? "Sniffers hear every device at different levels (their antennas and where they sit), so one sniffer's dBm can't be compared with another's. \"vs normal\" puts each sniffer's line against its own 7-day average for this device, so the lines lie on top of each other while all is well, and a dip means the device got weaker." : undefined}>
              {!multi ? "average with the min–max band" : m === "rel" ? "0 = its normal at each sniffer · below 0 = weaker" : "as each sniffer hears it"}
            </Hint>
            {multi && (
              <div class="seg" role="group" aria-label="Signal chart">
                <button type="button" aria-pressed={m === "rel"} title="each sniffer against its own normal for this device: 0 is normal" onClick={() => setMode("rel")}>vs normal</button>
                <button type="button" aria-pressed={m === "abs"} title="as each sniffer hears it" onClick={() => setMode("abs")}>dBm</button>
              </div>
            )}
          </>}>
            {sigs.length > 1 && (
              <div class="table-wrap">
                <table class="data dense sigtbl">
                  <thead><tr><th>Sniffer</th><th>Signal</th><th class="num" title="its 7-day average at this sniffer">Normal</th><th>Change</th><th class="num">Frames</th></tr></thead>
                  <tbody>
                    {sigs.map((x, i) => {
                      const k = ss.findIndex((y) => y.sniffer === x.sniffer);
                      const ch = f.num(x.change);
                      return (
                        <tr>
                          <td><i class="key line" style={{ background: sc(k >= 0 ? k : i) }} /> {x.name}{x.sniffer === dev.rssi_sniffer && <span class="sub"> hears it best</span>}</td>
                          <td><Meter avg={f.num(x.rssi_avg)} min={f.num(x.rssi_min)} max={f.num(x.rssi_max)} /></td>
                          <td class="num">{x.normal != null ? Math.round(x.normal) : <span class="muted" title="no 7-day normal at this sniffer yet">—</span>}</td>
                          <td>{ch === null ? <span class="muted">—</span> : Math.abs(ch) < 3 ? <span class="muted">as usual</span>
                            : <span class={`chg ${ch < 0 ? "down" : "up"}${Math.abs(ch) < 8 ? " small" : ""}`}>{ch < 0 ? "▼" : "▲"} {Math.abs(Math.round(ch))} dB</span>}</td>
                          <td class="num muted">{f.n(x.n)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {multi && m === "rel" ? (
              <TimeChart {...common} height={180} zero={false} yFmt={(v) => (v > 0 ? "+" : "") + v} label="Signal against normal"
                series={ss.filter((x) => x.ref != null).map((x) => ({
                  name: refName(x), color: sc(ss.indexOf(x)), kind: "line" as const, connect: true,
                  data: seriesMap(x.data, 0, (r: any) => +(r[1] - x.ref).toFixed(1)), fmt: (v: number) => `${v > 0 ? "+" : ""}${v} dB`,
                }))}
                thresholds={[{ y: 0, label: "normal" }, { y: -8, label: "weaker −8" }]}
                tip={(_i, t) => ss.map((x, k) => {
                  const row = x.data.find((y: any) => y[0] === t);
                  return <TipRow color={sc(k)} value={row ? `${row[1]} dBm (${row[1] - x.ref >= 0 ? "+" : ""}${(row[1] - x.ref).toFixed(1)})` : "—"} label={`${x.name}${row ? ` · ${f.n(row[4])} frames` : " · not heard"}`} />;
                })} />
            ) : multi ? (
              <TimeChart {...common} height={180} zero={false} yFmt={(v) => String(v)} label="Signal at each sniffer"
                series={ss.map((x, i) => ({ name: x.name, color: sc(i), kind: "line" as const, connect: true, data: seriesMap(x.data, 1), fmt: (v: number) => v + " dBm" }))}
                thresholds={[{ y: -88, label: "faint −88" }]}
                tip={(_i, t) => ss.map((x, k) => {
                  const row = x.data.find((y: any) => y[0] === t);
                  return <TipRow color={sc(k)} value={row ? `${row[1]} dBm` : "—"} label={`${x.name}${row ? ` · ${f.n(row[4])} frames` : " · not heard"}`} />;
                })} />
            ) : (
              <TimeChart {...common} height={180} zero={false} yFmt={(v) => String(v)} label="Signal at the sniffer"
                series={[
                  { name: "Min–max", color: "var(--series-1)", kind: "band", data: seriesMap(sr, 0, (r) => (r[3] != null ? [r[3], r[4]] : null)), legend: false },
                  { name: "Average", color: "var(--series-1)", kind: "line", data: seriesMap(sr, 2), fmt: (v) => v + " dBm" },
                ]}
                thresholds={[{ y: -88, label: "faint −88" }]}
                tip={(_i, t) => {
                  const row = sr.find((x) => x[0] === t);
                  if (!row || row[2] == null) return <div class="muted">not heard</div>;
                  return <><TipRow color="var(--series-1)" value={`${row[2]} dBm`} label="average" /><TipRow value={`${row[3]} to ${row[4]}`} label="range" />
                    <TipRow value={row[5] ?? "—"} label="LQI" /><TipRow value={f.n(row[1])} label="frames" /></>;
                }} />
            )}
          </Card>
          <Card title="Traffic it transmitted" actions={<Hint>frames per {f.BUCKET_WORD[b] || `${b / 60} min`}</Hint>}>
            <TimeChart {...common} height={170} label="Traffic"
              series={[
                { name: "Its own", color: "var(--series-1)", kind: "col" as const, stack: true, data: seriesMap(sr, 0, (r) => Math.max(0, r[1] - r[8] - r[9])) },
                ...(sr.some((r) => r[9]) ? [{ name: "Polls", color: "var(--series-2)", kind: "col" as const, stack: true, data: seriesMap(sr, 0, (r) => r[9] || null) }] : []),
                ...(sr.some((r) => r[8]) ? [{ name: "Relayed for others", color: "var(--series-3)", kind: "col" as const, stack: true, data: seriesMap(sr, 0, (r) => r[8] || null) }] : []),
              ]} />
          </Card>
          <Card title="Delivery" actions={<Hint>resent: its frames sent again · no ACK: frames to it with no ACK heard (often an ACK the sniffer missed)</Hint>}>
            <TimeChart {...common} height={160} label="Delivery" yFmt={(v) => v + "%"} yMax={10} yMaxAuto
              emptyText={thin ? "Too few frames per interval to chart (needs 8 or more)" : undefined}
              series={[
                { name: "Resent", color: "var(--series-2)", kind: "line", fmt: f.pct, data: seriesMap(sr, 0, (r) => (r[6] >= 8 ? +((100 * r[7]) / r[6]).toFixed(1) : null)) },
                { name: "No ACK heard", color: "var(--series-3)", kind: "line", fmt: f.pct, data: seriesMap(sr, 0, (r) => (r[11] >= 8 ? +((100 * r[12]) / r[11]).toFixed(1) : null)) },
              ]} />
          </Card>
          {cmds.length > 0 && (
            <Card title="Mesh commands it sent" actions={<Hint>decrypted NWK commands</Hint>}>
              <TimeChart {...common} height={150} label="Mesh commands"
                series={[
                  { name: "Link Status", color: "var(--series-1)", kind: "col" as const, stack: true, data: cmd(["link_status"]) },
                  { name: "Route requests", color: "var(--series-2)", kind: "col" as const, stack: true, data: cmd(["route_request", "mto_route_request"]) },
                  { name: "Route errors", color: "var(--bad)", kind: "col" as const, stack: true, data: cmd(["network_status"]) },
                  { name: "Leave / rejoin", color: "var(--warn)", kind: "col" as const, stack: true, data: cmd(["leave", "rejoin_request", "rejoin_response"]) },
                ].filter((s) => s.data.size)} />
            </Card>
          )}
        </div>
        <div class="stack">
          {(fw || sess.length > 0) && (
            <Card title="Firmware" actions={<Hint>Zigbee2MQTT's version · downloads seen on air</Hint>}>
              {fw && <KV rows={[
                ["Installed", fw.installed || "—"],
                ["Latest", <>{fw.latest || "—"} {fw.state === "available" ? <span class="tag">update available</span> : fw.state === "idle" ? <span class="sub">up to date</span> : fw.state ? <Chip tone="muted">{fw.state}</Chip> : null}</>],
                ...(fw.notes ? [["Notes", <span class="muted">{fw.notes}</span>] as [string, preact.ComponentChildren]] : []),
              ]} />}
              {sess.length > 0 && (
                <div class="table-wrap">
                  <table class="data dense">
                    <thead><tr><th>Started</th><th>Download</th><th>Progress</th><th>Data</th></tr></thead>
                    <tbody>
                      {sess.slice().reverse().map((o) => (
                        <tr>
                          <td class="muted nowrap">{f.num(o.started) ? <>{f.hm(o.started)} <span class="sub">{f.ago(o.started)}</span></> : null}</td>
                          <td><OtaBadge o={o} /> <span class="sub">{otaStatus(o)}</span>{o.result && o.state === "done" && <div class="sub">{o.result}</div>}</td>
                          <td><OtaBar p={o.progress} from={o.from} /></td>
                          <td class="muted">{otaDownload(o)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}
          <Card title="Mesh neighbours" actions={<Hint>Link Status costs, 1 best – 7 worst</Hint>}>
            {(d.neighbours || []).length ? (
              <div class="table-wrap">
                <table class="data dense">
                  <thead><tr><th>Neighbour</th><th title="how well this device hears the neighbour">It hears</th><th title="how well the neighbour hears this device">Hears it</th><th>Trend</th><th>Updated</th></tr></thead>
                  <tbody>
                    {d.neighbours.map((nb: any) => {
                      const h: any[] = hist[nb.addr] || [];
                      return (
                        <tr>
                          <td><AddrLabel addr={nb.addr} name={nb.name || nb.addr} />{!nb.own && <span class="sub" title="from the neighbour's Link Status"> reported</span>}</td>
                          <td><CostChip c={nb.in} /></td><td><CostChip c={nb.out} /></td>
                          <td>{h.length > 1 && <Spark vals={h.map((x) => Math.max(x[1], x[2]))} min={1} max={7} w={70} h={18} color="var(--muted)" />}</td>
                          <td class="muted nowrap">{f.ago(nb.ts)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : <div class="empty">{ed ? "End devices don't send Link Status; see its parent under Over the air." : "No Link Status heard (needs the network key)."}</div>}
          </Card>
          <Card title="How its messages travel" actions={<Hint>usual hops the sniffer heard</Hint>}>
            {(d.routes_out || []).length || (d.routes_in || []).length ? (
              <div class="table-wrap">
                <table class="data dense">
                  <thead><tr><th>Path</th><th class="num">Frames</th></tr></thead>
                  <tbody>{routes(d.routes_out || [], "Outgoing: its own messages")}{routes(d.routes_in || [], "Incoming: messages to it")}</tbody>
                </table>
              </div>
            ) : <div class="empty">No routed messages heard.</div>}
          </Card>
          {nh.length > 0 && (
            <Card title="Where its resends go" actions={<Hint>its unicast frames by the next hop it handed them to; a high share resent points at that hop</Hint>}>
              <div class="table-wrap">
                <table class="data dense">
                  <thead><tr><th>Next hop</th><th class="num">Unicast</th><th class="num">Resent</th><th class="num">%</th></tr></thead>
                  <tbody>{nh.map((x) => <tr><td><AddrLabel addr={x.addr} name={x.name || x.addr} /></td><td class="num">{f.n(f.num(x.uni))}</td><td class="num">{f.n(f.num(x.retry))}</td><td class="num">{f.pct(f.num(x.pct))}</td></tr>)}</tbody>
                </table>
              </div>
            </Card>
          )}
          <Card title="Over the air" actions={<Hint>MAC hops, {f.RANGE_WORD[d.range]}</Hint>}>
            {air.length ? <div class="air">{air}</div> : <div class="empty">Nothing heard.</div>}
          </Card>
          <Card title="Events"><div class="scroll"><EventsTable events={d.events} me={dev.addr} /></div></Card>
        </div>
      </div>
      <Card title="Recent frames" class="wide frames-card" actions={<Hint>from the live buffer · click one (or press Enter) to decode it</Hint>}>
        <div class="table-wrap cap"><FramesTable frames={d.frames || []} sel={sel} onOpen={setSel} /></div>
      </Card>
    </>
  );
}
