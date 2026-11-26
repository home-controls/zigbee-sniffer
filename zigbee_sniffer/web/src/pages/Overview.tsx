// Overview: incidents, firmware downloads, the numbers, what needs attention, traffic, channel
// busy, delivery, events, route discovery, other networks on the channel and the sniffer's state.

import { Card, KV } from "../kit/ui";
import { Icon } from "../kit/icons";
import { api } from "../api";
import { usePoll } from "../poll";
import { range, status } from "../store";
import * as f from "../fmt";
import { bucketSecs, fillBuckets, seriesMap } from "../logic";
import { EventsTable, FindingsList, Incidents, Loading, OtaAvailable, OtaTable, PageError, Spark, Tile, Unit } from "../bits";
import { TimeChart, TipRow } from "../timechart";

const Hint = ({ children }: { children: preact.ComponentChildren }) => <span class="muted small hint">{children}</span>;

/** Notes that matter for reading this page (connection trouble is in the banner on every page). */
function Notes({ s }: { s: any }) {
  if (!s) return null;
  const out: preact.JSX.Element[] = [];
  if (s.decode && !s.key_loaded) out.push(<p class="note warn"><Icon name="alert" size={16} /> Network key not found in Zigbee2MQTT's configuration: leaves, rejoins, route errors and mesh links can't be decrypted.</p>);
  if (!s.pan_id) out.push(<p class="note warn"><Icon name="alert" size={16} /> Zigbee2MQTT's PAN ID wasn't found, so frames of every network on the channel count as ours.</p>);
  if (s.catching_up) out.push(<p class="note"><Icon name="info" size={16} /> Counting stored captures into the history ({s.catching_up})…</p>);
  return <>{out}</>;
}

export function Overview() {
  const { data: d, err } = usePoll(10000, () => api(`api/overview?range=${range.value}`), [range.value]);
  const s = status.value;
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Overview</h1>
          <p class="lede">What the sniffers heard of your Zigbee network, {f.RANGE_WORD[range.value]}</p>
        </div>
      </div>
      <PageError err={err} />
      <Notes s={s} />
      {!d ? (!err && <Loading />) : <Body d={d} s={s} />}
    </div>
  );
}

function Body({ d, s }: { d: any; s: any }) {
  const t = d.totals, b = d.bucket, x1 = d.now, x0 = d.now - d.span;
  const frames = t.ours + t.others + t.unnamed;
  const minutes = Math.max(1, t.minutes);
  const marks = Array.isArray(d.marks) ? d.marks : [];
  const incs: any[] = Array.isArray(d.incidents) ? d.incidents : [];
  const common = { x0, x1, bucket: b, marks, incidents: incs };
  const hu = s?.history_until;
  const secs = (t0: number) => bucketSecs(t0, b, x0, x1, hu);
  const ota = d.ota && typeof d.ota === "object" ? d.ota : null;
  const otaDevs: any[] = ota && Array.isArray(ota.devices) ? ota.devices : [];
  const otaAvail: any[] = ota && Array.isArray(ota.available) ? ota.available : [];
  const c = d.counts;
  const active = ota ? f.num(ota.active) : null;
  const ongoing = incs.filter((i) => i.end == null).length;
  const att: any[] = d.attention || [];
  const net: any[] = d.net || [];
  const thin = net.some((r) => r[6] > 0) && !net.some((r) => r[6] >= 5);
  const cmd = (name: string) => { const m = new Map<number, number>(); for (const [t2, cm, k] of d.cmds || []) if (cm === name) m.set(t2, (m.get(t2) || 0) + k); return m; };
  const r = s?.radio || {}, br = s?.bridge || {};
  const wr = f.num(br.wifi_rssi);
  return (
    <>
      {incs.length > 0 && (
        <Card title="Incidents" class="wide" actions={<Hint>{f.plural(incs.length, "incident")}, {f.RANGE_WORD[d.range]}{ongoing ? ` · ${ongoing} ongoing` : ""}</Hint>}>
          <Incidents list={incs} />
        </Card>
      )}
      {(otaDevs.length > 0 || otaAvail.length > 0) && (
        <Card title="Firmware updates" class="wide" actions={<Hint>downloads seen on air · versions from Zigbee2MQTT</Hint>}>
          {otaDevs.length > 0 && <OtaTable list={otaDevs} />}
          <OtaAvailable list={otaAvail} />
        </Card>
      )}
      <div class="stats">
        <Tile label="Devices heard" value={<>{c.heard}<Unit>of {c.known}</Unit></>} href="#/devices"
          sub={`${c.routers} routers · ${c.end_devices} end devices${c.not_heard ? ` · ${c.not_heard} not heard` : ""}`} />
        <Tile label="Need attention" value={c.problems} sub="devices with a warning or a problem" href="#/devices?f=attention" tone={c.problems ? "warn" : undefined} />
        {!!active && <Tile label="Updating firmware" value={active} sub={`device${active === 1 ? "" : "s"} receiving an update now`} />}
        <Tile label="Our frames / min" value={f.n(t.ours / minutes)} sub={f.RANGE_WORD[d.range]}
          extra={<Spark w={120} h={22} vals={fillBuckets(net, x0, x1, b).map((row) => {
            if (!row) return null;
            const sc = secs(row[0]);
            return sc ? row[1] / (sc / 60) : null;
          })} />} />
        <Tile label="Channel busy" value={f.pct((t.air_all / (minutes * 60e6)) * 100)} sub={`${f.pct((t.air_ours / (minutes * 60e6)) * 100)} ours`} />
        <Tile label="Frames resent" value={f.pct(t.uni ? (100 * t.retry) / t.uni : null)} sub={`${f.n(t.retry)} of ${f.n(t.uni)} unicast`} />
        <Tile label="Other networks" value={f.pct(frames ? (100 * t.others) / frames : null)} sub={`${(d.networks || []).filter((x: any) => x.pan).length} networks heard`} />
      </div>
      <div class="split">
        <div class="stack">
          <Card title="Needs attention" actions={att.length ? <Hint>{f.plural(att.length, "finding")}, {f.RANGE_WORD[d.range]}</Hint> : undefined}>
            <div class="scroll"><FindingsList flags={att} who empty={`Nothing stands out ${f.RANGE_WORD[d.range]}.`} /></div>
          </Card>
          <Card title="Traffic" actions={<Hint>frames per {f.BUCKET_WORD[b] || `${b / 60} min`}</Hint>}>
            <TimeChart {...common} height={190} label="Frames per bucket"
              series={[
                { name: "Our network", color: "var(--series-1)", kind: "col", stack: true, data: seriesMap(net, 1) },
                { name: "Other networks and unattributed", color: "var(--s-other)", kind: "col", stack: true, data: seriesMap(net, 0, (row) => row[2] + row[3]) },
              ]}
              tip={(_i, tm) => {
                const row = net.find((x) => x[0] === tm);
                if (!row) return <div class="muted">no data (app not running)</div>;
                return (
                  <>
                    <TipRow color="var(--series-1)" rect value={f.n(row[1])} label="our network" />
                    <TipRow color="var(--s-other)" rect value={f.n(row[2])} label="other networks" />
                    <TipRow value={f.n(row[3])} label="naming no network" />
                    {!!row[11] && <TipRow value={f.n(row[11])} label="dropped by the sniffer" />}
                  </>
                );
              }} />
          </Card>
          <div class="grid two">
            <Card title="Channel busy" actions={<Hint>share of time the air carried a frame, all networks</Hint>}>
              <TimeChart {...common} label="Channel busy" yFmt={(v) => v + "%"} yMax={5} yMaxAuto
                series={[{ name: "Airtime used", color: "var(--series-1)", kind: "line", fmt: (v) => v.toFixed(1) + "%", data: seriesMap(net, 0, (row) => {
                  const sc = secs(row[0]);
                  return sc ? +((row[5] / (sc * 1e6)) * 100).toFixed(2) : null;
                }) }]}
                thresholds={[{ y: 30, label: "congested" }]} />
            </Card>
            <Card title="Delivery" actions={<Hint>our unicast frames · a missing ACK is often one the sniffer missed; resends are the real losses</Hint>}>
              <TimeChart {...common} label="Delivery" yFmt={(v) => v + "%"} yMax={10} yMaxAuto
                emptyText={thin ? "Too few frames per interval to chart (needs 5 or more)" : undefined}
                series={[
                  { name: "Resent", color: "var(--series-2)", kind: "line", fmt: f.pct, data: seriesMap(net, 0, (row) => (row[6] >= 5 ? +((100 * row[7]) / row[6]).toFixed(1) : null)) },
                  { name: "No ACK heard", color: "var(--series-3)", kind: "line", fmt: f.pct, data: seriesMap(net, 0, (row) => (row[6] >= 5 ? +((100 * row[8]) / row[6]).toFixed(1) : null)) },
                ]} />
            </Card>
          </div>
        </div>
        <div class="stack">
          <Card title="Recent events" actions={<Hint>joins, leaves, rejoins, route errors</Hint>}>
            <div class="scroll"><EventsTable events={(d.events || []).slice(0, 40)} /></div>
          </Card>
          <Card title="Route discovery" actions={<Hint>mesh repairing its routes</Hint>}>
            <TimeChart {...common} height={150} label="Route discovery"
              series={[
                { name: "Route requests", color: "var(--series-2)", kind: "col", stack: true, data: cmd("route_request") },
                { name: "Route errors", color: "var(--bad)", kind: "col", stack: true, data: cmd("network_status") },
                { name: "Coordinator route refresh", color: "var(--series-1)", kind: "col", stack: true, data: cmd("mto_route_request") },
              ]} />
          </Card>
          <Card title="Other networks on the channel" actions={<Hint>since the app started</Hint>}>
            {(d.networks || []).length ? (
              <div class="table-wrap">
                <table class="data dense">
                  <thead><tr><th>PAN</th><th class="num">Frames</th><th class="num">Share</th><th class="num">Avg signal</th><th class="num">Devices</th><th>Last heard</th></tr></thead>
                  <tbody>
                    {d.networks.map((x: any) => (
                      <tr>
                        <td>{x.pan ? <span class="mono">{x.pan}</span> : <span class="muted">none named</span>}</td>
                        <td class="num">{f.n(x.count)}</td><td class="num">{f.num(x.share) ?? "—"}%</td><td class="num">{f.dbm(x.rssi_avg)}</td>
                        <td class="num">{f.n(x.devices)}</td><td class="muted">{f.ago(x.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div class="empty">None heard.</div>}
          </Card>
          {s && (
            <details class="card more">
              <summary>Sniffer</summary>
              <KV rows={[
                ["Bridge", `${s.host}:${s.port} ${s.connected ? `· connected ${f.ago(s.connected_since)}` : "· not connected"}`],
                ["Channel", String(r.channel ?? s.channel)],
                ["Our network", s.pan_id ? `PAN ${s.pan_id}` : "unknown"],
                ["Radio", `firmware ${r.version || "—"}, up ${f.dur(f.num(r.uptime_s))}, dropped ${f.n(f.num(r.dropped))}`],
                ["Bridge Wi-Fi", wr !== null ? `${wr} dBm, up ${f.dur(f.num(br.uptime_s))}` : "—"],
                ["Bridge drops", `${f.n(f.num(br.tcp_dropped))} frames lost, ${f.n(f.num(br.uart_crc_errors))} UART CRC errors`],
                ["Buffered", `${f.n(s.buffered_frames)} frames delivered late by the bridge since the app started${s.backlog_bytes ? ` · ${f.bytes(s.backlog_bytes)} waiting at the last connect` : ""}`],
                ["Decryption", s.decode ? (s.key_loaded ? "network key loaded" : "no key") : "off"],
                ["Writing", s.current_file || "—"],
                ["Wireshark clients", f.n(f.num(s.live_clients))],
              ]} />
            </details>
          )}
        </div>
      </div>
      {s && <p class="foot">History since {s.history_since ? f.when(s.history_since) : "—"} · {f.bytes(s.history_bytes)} · captures kept {s.retention_days} days · {s.time_zone}</p>}
    </>
  );
}
