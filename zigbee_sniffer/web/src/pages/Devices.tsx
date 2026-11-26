// Devices: every device the sniffers heard (and the ones Zigbee2MQTT knows but they didn't), with
// signal per sniffer, LQI, trend, mesh links, next hop, messages, resends, last heard and findings.
// Filters, search, sortable columns (remembered) and a CSV of the rows shown.

import { useState } from "preact/hooks";
import { Chip, Search } from "../kit/ui";
import { toast } from "../kit/toast";
import { api, downloadText } from "../api";
import { usePoll } from "../poll";
import { pref, range, several } from "../store";
import * as f from "../fmt";
import { csvCell, deviceLink, fillBuckets } from "../logic";
import { AddrLabel, CostChip, DevLink, FindingTag, level, Loading, Meter, PageError, SevIcon, Spark } from "../bits";

const FILTERS: Record<string, [string, (d: any) => boolean]> = {
  all: ["All", () => true],
  attention: ["Need attention", (d) => d.sev >= 2],
  routers: ["Routers", (d) => d.type === "Router" || d.type === "Coordinator"],
  end: ["End devices", (d) => d.type === "EndDevice"],
  faint: ["Faint at sniffer", (d) => d.rssi_avg != null && d.rssi_avg <= -88],
  notheard: ["Not heard", (d) => !(d.tx || d.msgs)],
};
const lower = (s: any) => (s ? String(s).toLowerCase() : null);
type Col = { k: string; label: string; sort: ((d: any) => any) | null; right?: boolean; sid?: string };
const COLS: Col[] = [
  { k: "name", label: "Device", sort: (d) => (d.name || d.addr).toLowerCase() },
  { k: "rssi", label: "Signal at sniffer", sort: (d) => f.num(d.rssi_avg) },
  { k: "lqi", label: "LQI", sort: (d) => f.num(d.lqi_avg), right: true },
  { k: "trend", label: "Trend", sort: null },
  { k: "mesh", label: "Mesh links", sort: (d) => (d.mesh ? f.num(d.mesh.best) : null) },
  { k: "via", label: "Next hop", sort: (d) => (d.via ? lower(d.via.name || d.via.addr) : null) },
  { k: "msgs", label: "Messages", sort: (d) => f.num(d.msgs), right: true },
  { k: "retry", label: "Resent", sort: (d) => f.num(d.retry_pct), right: true },
  { k: "noack", label: "No ACK", sort: (d) => f.num(d.noack_pct), right: true },
  { k: "seen", label: "Last heard", sort: (d) => d.last_seen || null },
  { k: "sev", label: "Findings", sort: (d) => d.sev * 1000 + d.flags.length },
];
const sigOf = (d: any, sid: string) => (Array.isArray(d.signal) ? d.signal.find((x: any) => x.sniffer === sid) || null : null);

/** With 2-3 sniffers the table gets a signal column per sniffer instead of one "best sniffer" column. */
function colsFor(sns: any[]): Col[] {
  if (!Array.isArray(sns) || sns.length < 2 || sns.length > 3) return COLS;
  const i = COLS.findIndex((c) => c.k === "rssi");
  const per: Col[] = sns.map((s) => ({ k: `sig:${s.id}`, label: s.name, sort: (d: any) => f.num(sigOf(d, s.id)?.rssi_avg), sid: s.id }));
  return [...COLS.slice(0, i), ...per, ...COLS.slice(i + 1)];
}

function SigChange({ x }: { x: any }) {
  const ch = f.num(x?.change);
  if (ch === null || Math.abs(ch) < 8) return null;
  return <span class={`chg ${ch < 0 ? "down" : "up"}`} title={`${Math.abs(Math.round(ch))} dB ${ch < 0 ? "weaker" : "stronger"} than its normal at this sniffer`}> {ch < 0 ? "▼" : "▲"}{Math.abs(Math.round(ch))}</span>;
}

function SigCell({ d, sid, name }: { d: any; sid: string; name: string }) {
  const x = sigOf(d, sid);
  if (!x) return <td class="sig"><span class="muted" title={`${name} didn't hear it directly`}>—</span></td>;
  const v = Math.round(x.rssi_avg), best = d.rssi_sniffer === sid;
  const w = Math.max(3, Math.min(36, ((x.rssi_avg + 105) / 70) * 36));
  const title = `${name}: ${v} dBm on average (${x.rssi_min} to ${x.rssi_max}), ${f.n(x.n)} frames${x.normal != null ? `; normal ${Math.round(x.normal)} dBm` : ""}${best ? "; the sniffer that hears it best" : ""}`;
  return <td class="sig" title={title}><span class={`sigbar lvl-${level(x.rssi_avg)}`} style={{ width: `${w.toFixed(0)}px` }} /><span class={best ? "best" : ""}>{v}</span><SigChange x={x} /></td>;
}

export function Devices({ filter }: { filter: string | null }) {
  const [flt, setFlt] = useState(() => (filter && FILTERS[filter] ? filter : pref.get("devf", "all")));
  const [q, setQ] = useState("");
  const [sort, setSort] = useState(() => pref.get("devsort", "sev"));
  const [dir, setDir] = useState(() => +pref.get("devdir", "-1") || -1);
  const { data, err } = usePoll(15000, () => api(`api/devices?range=${range.value}`), [range.value]);
  const pick = (k: string) => { setFlt(k); pref.set("devf", k); };
  const sortBy = (k: string) => {
    const nd = sort === k ? -dir : k === "name" || k === "via" ? 1 : -1;
    setSort(k); setDir(nd);
    pref.set("devsort", k); pref.set("devdir", nd);
  };

  const rows: any[] = data?.devices || [];
  const cols = colsFor(data?.sniffers);
  const perSniffer = cols.some((c) => c.sid);
  const ql = q.toLowerCase();
  let list = rows.filter((FILTERS[flt] || FILTERS.all)[1]);
  if (ql) list = list.filter((d) => [d.name, d.addr, d.ieee, d.model, d.vendor, f.TYPE_WORD[d.type]].join(" ").toLowerCase().includes(ql));
  const col = cols.find((c) => c.k === sort && c.sort) || cols[cols.length - 1];
  const cmp = (x: any, y: any) => (x === null || x === undefined ? (y === null || y === undefined ? 0 : 1) : y === null || y === undefined ? -1 : (x < y ? -1 : x > y ? 1 : 0) * dir);
  list.sort((a, b) => cmp(col.sort!(a), col.sort!(b)) || (a.name || a.addr).localeCompare(b.name || b.addr));

  const exportCsv = () => {
    if (!data) return;
    const sns: any[] = Array.isArray(data.sniffers) && data.sniffers.length > 1 ? data.sniffers : [];
    const head = ["Name", "Short address", "IEEE", "Type", "Model", "Vendor", "Signal avg (dBm)", "Signal min", "Signal max", "Heard best by",
      ...sns.map((s) => `Signal at ${s.name} (dBm)`), "LQI avg",
      "Mesh links", "Best link cost", "Worst link cost", "Next hop", "Messages", "Frames on air", "Unicast", "Resent %", "No ACK %", "Last heard", "Findings"];
    const lines = [head.map(csvCell).join(",")];
    for (const d of list) {
      lines.push([d.name, d.addr, d.ieee, f.TYPE_WORD[d.type] || d.type, d.model, d.vendor, d.rssi_avg, d.rssi_min, d.rssi_max, d.rssi_sniffer_name || "",
        ...sns.map((s) => sigOf(d, s.id)?.rssi_avg ?? ""), d.lqi_avg,
        d.mesh ? d.mesh.n : "", d.mesh ? d.mesh.best : "", d.mesh ? d.mesh.worst : "", d.via ? d.via.name || d.via.addr : "",
        d.msgs, d.tx, d.uni, d.retry_pct, d.noack_pct, d.last_seen ? new Date(d.last_seen * 1000).toISOString() : "",
        d.flags.map((x: any) => x.text).join("; ")].map(csvCell).join(","));
    }
    const day = new Date();
    downloadText(`zigbee-devices-${data.range}-${day.getFullYear()}-${f.pad(day.getMonth() + 1)}-${f.pad(day.getDate())}.csv`, "﻿" + lines.join("\r\n"), "text/csv");
    toast(`Exported ${f.plural(list.length, "device")}`);
  };

  const b = data?.spark_bucket, x1 = data?.now, x0 = data ? data.now - data.span : 0;
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Devices</h1>
          <p class="lede">{data ? `${rows.filter((d) => d.tx || d.msgs).length} heard · ${f.RANGE_WORD[data.range]}` : " "}</p>
        </div>
      </div>
      <PageError err={err} />
      <div class="toolbar">
        <Search value={q} onInput={setQ} placeholder="Search name, address, model" />
        <div class="seg" role="group" aria-label="Filter">
          {Object.entries(FILTERS).map(([k, [label, fn]]) => (
            <button type="button" aria-pressed={flt === k} onClick={() => pick(k)}>{label} <span class="n">{rows.filter(fn).length}</span></button>
          ))}
        </div>
        <span class="spacer" />
        <button type="button" class="btn small" title="The rows shown, as a spreadsheet file" onClick={exportCsv} disabled={!data}>Export CSV</button>
      </div>
      <div class="card flush">
        {!data ? (!err && <Loading />) : (
          <div class="table-wrap cap">
            <table class="data devtbl">
              <thead>
                <tr>
                  {cols.map((c) => {
                    const on = sort === c.k;
                    const label = c.sid ? `Signal at ${c.label}` : c.k === "rssi" && several.value ? "Signal (best sniffer)" : c.label;
                    return (
                      <th class={c.right ? "num" : ""} aria-sort={c.sort ? (on ? (dir > 0 ? "ascending" : "descending") : "none") : undefined}
                        title={c.sid ? `how loud ${c.label} hears each device (dBm); bold: the sniffer that hears it best` : undefined}>
                        {c.sort ? <button type="button" class="th-sort" onClick={() => sortBy(c.k)}>{label}{on && <span class="arrow" aria-hidden="true">{dir > 0 ? "▲" : "▼"}</span>}</button> : label}
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {list.length === 0 && <tr><td colSpan={cols.length} class="empty">No devices match.</td></tr>}
                {list.map((d) => {
                  const pts = fillBuckets(d.spark || [], x0, x1, b);
                  const hasRssi = pts.some((p) => p && p[1] != null);
                  const top = d.flags[0];
                  const sigTitle = Array.isArray(d.signal) && d.signal.length > 1 ? d.signal.map((x: any) => `${x.name}: ${Math.round(x.rssi_avg)} dBm (${f.n(x.n)} frames)`).join("\n") : undefined;
                  return (
                    <tr class="click" onClick={(e) => { if (!(e.target as Element).closest("a, button")) location.hash = deviceLink(d.addr); }}>
                      <td>
                        <div>
                          <DevLink addr={d.addr} name={d.name} />
                          {d.ota && d.ota.state === "updating" ? <> <span class="tag" title="downloading firmware">updating {Math.round((f.num(d.ota.progress) || 0) * 100)}%</span></>
                            : d.fw_update === "available" ? <> <span class="tag" title="Zigbee2MQTT has a newer firmware for it">update available</span></> : null}
                        </div>
                        <div class="sub">{f.TYPE_WORD[d.type] || "unknown"}{d.model ? " · " + d.model : ""} · <span class="mono">{d.addr}</span></div>
                      </td>
                      {perSniffer ? cols.filter((c) => c.sid).map((c) => <SigCell d={d} sid={c.sid!} name={c.label} />) : (
                        <td title={sigTitle}>
                          <Meter avg={f.num(d.rssi_avg)} min={f.num(d.rssi_min)} max={f.num(d.rssi_max)} />
                          {several.value && d.rssi_sniffer_name && <div class="sub">at {d.rssi_sniffer_name}</div>}
                        </td>
                      )}
                      <td class="num">{f.num(d.lqi_avg) === null ? <span class="muted">—</span> : f.n(+d.lqi_avg)}</td>
                      <td title={hasRssi ? `average signal${d.rssi_sniffer_name && several.value ? ` at ${d.rssi_sniffer_name}` : ""}` : "messages (not heard directly)"}>
                        {hasRssi ? <Spark vals={pts.map((p) => (p ? p[1] : null))} minSpan={8} /> : <Spark vals={pts.map((p) => (p ? p[3] : null))} color="var(--muted)" min={0} />}
                      </td>
                      <td class="nowrap">
                        {d.mesh ? <><CostChip c={d.mesh.best} />{d.mesh.worst !== d.mesh.best && <><span class="muted"> – </span><CostChip c={d.mesh.worst} /></>} <span class="sub">{f.n(f.num(d.mesh.n))}</span></> : <span class="muted">—</span>}
                      </td>
                      <td class="via">{d.via ? <AddrLabel addr={d.via.addr} name={d.via.name} /> : d.heard_via ? <><span class="muted">via</span> <AddrLabel addr={d.heard_via.addr} name={d.heard_via.name} /></> : <span class="muted">—</span>}</td>
                      <td class="num">{f.n(d.msgs)}</td>
                      <td class="num">{d.retry_pct == null ? <span class="muted">—</span> : f.pct(d.retry_pct)}</td>
                      <td class="num">{d.noack_pct == null ? <span class="muted">—</span> : f.pct(d.noack_pct)}</td>
                      <td class="nowrap" title={d.last_seen ? new Date(d.last_seen * 1000).toLocaleString() : undefined}>{d.last_seen ? f.ago(d.last_seen) : <span class="muted">never</span>}</td>
                      <td>
                        {top ? (
                          <span class="find-cell" title={d.flags.map((x: any) => x.text + (x.context && f.CTX_WORD[x.context] ? ` (${f.CTX_WORD[x.context]})` : "") + (x.detail ? ` – ${x.detail}` : "")).join("\n")}>
                            <SevIcon sev={top.sev} /> <span class="ink2">{top.text.length > 54 ? top.text.slice(0, 52) + "…" : top.text}</span><FindingTag x={top} />
                            {d.flags.length > 1 && <> <Chip tone="muted">+{d.flags.length - 1}</Chip></>}
                          </span>
                        ) : d.tx || d.msgs ? <SevIcon sev="good" /> : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <p class="foot">Signal is how loud a <i>sniffer</i> hears a device, in dBm. It depends on where the sniffer sits and on its antenna, so compare a device with itself at the same sniffer, not one sniffer with another. With several sniffers there is a column per sniffer: bold is the one that hears the device best, ▼8 means 8 dB weaker than its normal there; LQI is the link quality its radio reports for those frames (0–255, higher is better). Mesh links are the routers' own Link Status costs, 1 (best) to 7 (worst). Resent: unicast frames sent again because no ACK came back. No ACK: frames sent to the device whose ACK the sniffer didn't hear. Empty values sort last.</p>
    </div>
  );
}
