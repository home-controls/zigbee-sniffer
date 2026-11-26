// Sniffer: one sniffer at a time (chips to pick, with several): its link, Wi-Fi, buffer, radio and
// bridge, findings, what it adds to the others (and "Moved it"), connection history, events,
// firmware (check an image, then update over Wi-Fi or USB), the channel, and Home Assistant.

import { useRef, useState } from "preact/hooks";
import { Card, Chip, KV, copyText } from "../kit/ui";
import { Icon } from "../kit/icons";
import { confirmIt } from "../kit/dialog";
import { toast } from "../kit/toast";
import { api, post } from "../api";
import { usePoll } from "../poll";
import { pref, range, status } from "../store";
import * as f from "../fmt";
import { bucketSecs, seriesMap } from "../logic";
import { DevLink, EventsTable, FindingsList, Loading, PageError, SevIcon, Spin, Tile, Unit } from "../bits";
import { TimeChart } from "../timechart";

const Hint = ({ children }: { children: preact.ComponentChildren }) => <span class="muted small hint">{children}</span>;
const FW_STATE: Record<string, string> = { running: "running", trial: "on trial", confirmed: "confirmed", rolled_back: "rolled back" };
const CLIENT_WORD: Record<string, string> = { buffered: "the app takes the backlog", live: "an older app, live frames only", none: "no app connected" };
const FwBadge = ({ state }: { state?: string }) => (state ? <Chip tone={state === "rolled_back" ? "bad" : state === "trial" ? "warn" : "muted"}>{FW_STATE[state] || state}</Chip> : null);

const HA_EXAMPLE = `alias: Zigbee trouble
triggers:
  - trigger: event
    event_type: zigbee_sniffer_event
    event_data: { kind: leave }
  - trigger: event
    event_type: zigbee_sniffer_event
    event_data: { kind: sniffer_offline }
actions:
  - action: notify.notify
    data:
      title: Zigbee
      message: "{{ trigger.event.data.device }}: {{ trigger.event.data.detail }}"`;

export function SnifferPage() {
  const [pick, setPick] = useState(() => pref.get("sniffer.sel", ""));
  const { data: d, err, refresh } = usePoll(5000, () => api(`api/sniffer?range=${range.value}${pick ? `&sniffer=${encodeURIComponent(pick)}` : ""}`), [range.value, pick]);
  const choose = (id: string) => { pref.set("sniffer.sel", id); setPick(id); };
  const sns: any[] = d?.sniffers || [];
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <h1>Sniffer</h1>
          <p class="lede">The radio, the bridge, its Wi-Fi, firmware, and what goes to Home Assistant</p>
        </div>
        {sns.length > 1 && (
          <div class="seg" role="group" aria-label="Sniffer">
            {sns.map((x) => <button type="button" aria-pressed={x.id === d.id} onClick={() => choose(x.id)}><span class={`dot ${x.connected ? "ok" : "bad"}`} /> {x.name}</button>)}
          </div>
        )}
      </div>
      <PageError err={err} />
      {!d ? (!err && <Loading />) : <Body key={d.id} d={d} refresh={refresh} />}
    </div>
  );
}

function Body({ d, refresh }: { d: any; refresh: () => void }) {
  const b = d.bridge || {}, L = d.link || {}, x1 = d.now, x0 = d.now - d.span, bk = d.bucket;
  const marks = Array.isArray(d.marks) ? d.marks : [];
  const common = { x0, x1, bucket: bk, marks };
  const me = (d.sniffers || []).find((x: any) => x.id === d.id) || {};
  const clk = f.num(me.clock_offset_ms), skew = f.num(me.skew_ms);
  const ms = (v: number) => `${v > 0 ? "+" : ""}${Math.round(v)} ms`;
  const clkTxt = (clk === null ? "" : ` · clock drift ${ms(clk)}`) + (skew === null ? "" : ` · ${ms(skew)} vs the first sniffer`);
  const wr = f.num(b.wifi_rssi), usb = L.kind === "usb";
  const since = (ts: number | null | undefined) => (ts ? f.ago(ts).replace(" ago", "") : "");
  const sr: any[] = d.series || [];
  const F = d.firmware || { files: [] };
  const usbF = F.kind === "usb";
  const hu = status.value?.history_until;
  return (
    <>
      <div class="stats">
        <Tile label={usb ? "USB link" : "Link to the bridge"} tone={L.connected ? undefined : "bad"}
          title={clk === null && skew === null ? undefined : "clock drift: how far this bridge's clock moved since it connected; vs the first sniffer: the offset between their timestamps"}
          value={L.connected ? <>Connected<Unit>{since(L.connected_since)}</Unit></> : <>Offline<Unit>{since(L.disconnected_since)}</Unit></>}
          sub={(L.connected ? `${f.num(L.fps) ?? "—"} frames/s · ${L.host || ""} · hears ${f.n(f.num(d.devices_heard))} devices` : L.last_error || "") + clkTxt} />
        {usb ? <Tile label="Plugged into" value="this box" sub={`${b.device || L.host || ""} · no bridge or Wi-Fi`} />
          : <Tile label="Bridge Wi-Fi" value={wr !== null ? <>{wr}<Unit>dBm</Unit></> : "—"} sub={f.num(b.wifi_channel) ? `channel ${f.num(b.wifi_channel)} · AP ${b.wifi_ap || ""}` : d.bridge_error || ""} />}
        {!usb && <Tile label="Buffer" value={f.num(b.buffer_bytes) ? f.bytes(f.num(b.backlog_bytes) || 0) : "—"}
          sub={f.num(b.buffer_bytes) ? `waiting, of ${f.bytes(f.num(b.buffer_bytes))} · ${CLIENT_WORD[b.client] || b.client || ""}` : "bridge 0.3+ buffers frames"} />}
        <Tile label="Radio" value={b.radio || L.radio?.version || "—"}
          sub={`${b.radio_chip ? b.radio_chip + " · " : ""}${b.radio_firmware ? FW_STATE[b.radio_firmware] || b.radio_firmware : ""}${b.radio_link === false ? (usb ? " · sends nothing on the USB" : " · not heard by the bridge") : ""}`} />
        {!usb && <Tile label="Bridge" value={b.bridge || L.hello?.bridge || "—"}
          sub={`${b.bridge_firmware ? FW_STATE[b.bridge_firmware] || b.bridge_firmware : ""}${b.bridge_partition ? " · " + b.bridge_partition : ""}${f.num(b.uptime_s) ? " · up " + f.dur(f.num(b.uptime_s)) : ""}`} />}
        <Tile label="Delivered late" value={f.n(f.num(L.buffered_frames))} sub={`since the app started · ${f.n(f.num(b.buffer_full_drops) || 0)} lost to a full buffer`} />
      </div>
      <div class="split">
        <div class="stack">
          <Card title="Findings" actions={<Hint>{f.RANGE_WORD[d.range]}</Hint>}><FindingsList flags={d.findings} empty="The sniffer looks healthy." /></Card>
          {d.coverage && <Coverage d={d} me={me} refresh={refresh} />}
          <div class="grid two">
            <Card title="Connected" actions={<Hint>share of each interval the app had the bridge</Hint>}>
              <TimeChart {...common} height={150} label="Connected" yMin={0} yMax={100} yFmt={(v) => v + "%"}
                series={[{ name: "Connected", color: "var(--series-1)", kind: "line", fmt: (v) => v + "%", data: seriesMap(sr, 0, (r) => {
                  const s = bucketSecs(r[0], bk, x0, x1, hu);
                  return s ? Math.min(100, Math.round((100 * r[1]) / s)) : null;
                }) }]} />
            </Card>
            {!usbF && (
              <Card title="Bridge Wi-Fi signal" actions={<Hint>average with the min–max band</Hint>}>
                <TimeChart {...common} height={150} zero={false} yFmt={(v) => String(v)} label="Bridge Wi-Fi signal"
                  series={[
                    { name: "Min–max", color: "var(--series-1)", kind: "band", data: seriesMap(sr, 0, (r) => (r[4] != null ? [r[4], r[5]] : null)), legend: false },
                    { name: "Average", color: "var(--series-1)", kind: "line", data: seriesMap(sr, 3), fmt: (v) => v + " dBm" },
                  ]} thresholds={[{ y: -75, label: "weak −75" }]} />
              </Card>
            )}
            <Card title="Disconnects" actions={<Hint>connections to the bridge lost</Hint>}>
              <TimeChart {...common} height={150} label="Disconnects"
                series={[{ name: "Disconnects", color: "var(--bad)", kind: "col", data: seriesMap(sr, 0, (r) => r[2] || null) }]} />
            </Card>
            <Card title="Late and lost frames" actions={<Hint>delivered from the bridge's buffer, or dropped</Hint>}>
              <TimeChart {...common} height={150} label="Late and lost frames"
                series={[
                  { name: "Delivered late", color: "var(--series-2)", kind: "col", stack: true, data: seriesMap(sr, 0, (r) => r[6] || null) },
                  { name: "Lost", color: "var(--bad)", kind: "col", stack: true, data: new Map((d.drops || []).filter((x: any) => x[1]).map((x: any) => [x[0], x[1]])) },
                ]} />
            </Card>
          </div>
          <Card title="Events" actions={<Hint>connections, restarts, firmware, channel</Hint>}><div class="scroll"><EventsTable events={d.events} me="sniffer" /></div></Card>
        </div>
        <div class="stack">
          <Firmware d={d} refresh={refresh} />
          <Channel d={d} refresh={refresh} />
          <HomeAssistant d={d} />
        </div>
      </div>
    </>
  );
}

/** What this sniffer adds to the others; "Moved it" starts its signal normals again. */
function Coverage({ d, me, refresh }: { d: any; me: any; refresh: () => void }) {
  const [busy, setBusy] = useState(false);
  const cv = d.coverage, mm = me.match, mg = d.merge || {};
  const solo: any[] = cv.solo_devices || [];
  const N = d.normals || {}, h = f.num(N.hours) || 0, need = f.num(N.needed) || 12;
  const since = N.moved_at ? `since it was moved ${f.ago(N.moved_at)}` : "";
  const moved = async () => {
    if (!await confirmIt({
      title: `Was ${d.name} moved?`, confirm: "It was moved",
      body: "Moved this sniffer, or changed its antenna? Its normals start again from here, and the move is marked on every device's charts. Until it has learned again, there is no \"weaker than usual\" or ▼▲ at this sniffer.",
    })) return;
    setBusy(true);
    try {
      await post(`api/sniffer/moved?sniffer=${encodeURIComponent(d.id)}`, {});
      toast(`${d.name}'s normals start again from here`);
      refresh();
    } catch (e: any) { toast(e?.message || String(e), "error", 7000); } finally { setBusy(false); }
  };
  return (
    <Card title="What it adds" actions={<Hint>{f.RANGE_WORD[d.range]} · our network, against the other sniffers</Hint>}>
      <KV rows={[
        ["Heard by it", cv.heard_pct == null ? <span class="muted">counting (since 0.5.3)</span> : `${f.pct(cv.heard_pct)} of our transmissions while it was connected`],
        ["Only it heard", cv.solo_pct == null ? "—" : <><b>{f.pct(cv.solo_pct)}</b>: no other sniffer heard those</>],
        ["Devices only it hears", <>{f.n(f.num(cv.solo_devices_n) || 0)} of the {f.n(f.num(cv.devices) || 0)} it hears{solo.length > 0 && <>: {solo.map((x, i) => <>{i > 0 && ", "}<DevLink addr={x.addr} name={x.name || x.addr} /></>)}</>}
          {cv.solo_devices_n > solo.length && ` and ${f.n(cv.solo_devices_n - solo.length)} more`}</>],
        ["Its signal", (cv.vs || []).filter((x: any) => x.median_db != null).length
          ? <>{(cv.vs || []).filter((x: any) => x.median_db != null).map((x: any) => <div>{x.median_db > 0 ? "+" : ""}{x.median_db} dB against {x.name} <span class="muted">(median of the {f.n(x.devices)} devices both hear: antenna and place)</span></div>)}</>
          : <span class="muted">no devices heard by both yet</span>],
        ...(mm ? [["Its timing", `copies line up within ${mm.p50_ms} ms of the other sniffer's (half of them), ${mm.p95_ms} ms (95%) · match window ${mg.window_ms} ms`] as [string, preact.ComponentChildren]] : []),
        ["Its normals", <>{h >= need ? `learned from ${f.n(h)} h of history ${since}` : `learning: ${f.n(h)} of ${need} h ${since}, no "weaker than usual" or ▼▲ at this sniffer until then`}{" "}
          <button type="button" class="btn small" disabled={busy} title="Moved this sniffer (or changed its antenna)? Its normals start again from here, and the move is marked on every device's charts" onClick={moved}>Moved it</button></>],
      ]} />
    </Card>
  );
}

function Firmware({ d, refresh }: { d: any; refresh: () => void }) {
  const F = d.firmware || { files: [] };
  const b = d.bridge || {}, L = d.link || {};
  const usbF = F.kind === "usb";
  const [check, setCheck] = useState<{ src: { file?: string; data?: ArrayBuffer }; r?: any; err?: string; busy?: boolean } | null>(null);
  const [sending, setSending] = useState(false);
  const fileIn = useRef<HTMLInputElement>(null);
  const sq = `sniffer=${encodeURIComponent(d.id)}`;
  const inspect = async (src: { file?: string; data?: ArrayBuffer }) => {
    setCheck({ src, busy: true });
    try {
      const r = src.file ? await post(`api/firmware/inspect?${sq}&file=${encodeURIComponent(src.file)}`, null, "application/octet-stream")
        : await post(`api/firmware/inspect?${sq}`, src.data, "application/octet-stream");
      setCheck({ src, r });
    } catch (e: any) { setCheck({ src, err: e?.message || String(e) }); }
  };
  const flash = async () => {
    if (!check?.r) return;
    const r = check.r, i = r.info || {};
    if (!await confirmIt({
      title: `Update the ${r.target} to ${i.version}?`, confirm: `Send ${i.version}`, danger: true,
      body: usbF ? "The radio stops listening while it writes the image over the cable, restarts into it, and keeps it once it hears this app again."
        : r.target === "radio" ? "The radio stops listening for about 30 s while it writes the image." : "The bridge restarts and keeps the image once its Wi-Fi is back for 30 s.",
    })) return;
    setSending(true);
    try {
      await (check.src.file ? post(`api/firmware/${r.target}?${sq}&file=${encodeURIComponent(check.src.file)}`, null, "application/octet-stream")
        : post(`api/firmware/${r.target}?${sq}`, check.src.data, "application/octet-stream"));
      setCheck(null);
      toast(`Sending ${i.version} to the ${r.target}…`);
      refresh();
    } catch (e: any) { setCheck({ ...check, err: e?.message || String(e) }); } finally { setSending(false); }
  };
  const sent = f.num(F.updating?.sent), size = f.num(F.updating?.size);
  const r = check?.r, i = r?.info || {}, problems: string[] = r?.problems || [];
  const ok = r && r.target && !problems.length && F.token_set;
  return (
    <Card title="Firmware" actions={<Hint>updates from this page, over Wi-Fi or the USB cable</Hint>}>
      {F.updating && (
        <p class="note"><Spin /><span>Updating the {F.updating.target} to <b>{F.updating.version}</b> (started {f.ago(F.updating.started)}{usbF && size ? `, ${F.updating.state === "trial" ? "written, waiting for it to restart" : `${Math.round((100 * (sent || 0)) / size)}% sent`}` : ""}).{" "}
          {usbF ? "It stops listening while it writes the image over the cable, restarts into it, and keeps it once it hears this app again." : F.updating.target === "radio" ? "The radio stops listening for about 30 s while it writes the image." : "The bridge restarts and keeps the image once its Wi-Fi is back for 30 s."}</span></p>
      )}
      {F.last_result && (
        <p class={`note ${F.last_result.ok ? "ok" : "warn"}`}><SevIcon sev={F.last_result.ok ? "good" : "high"} />
          <span>{F.last_result.target} {F.last_result.version}: {F.last_result.message} <span class="muted">({f.n(f.num(F.last_result.seconds))} s, {f.ago(F.last_result.finished)})</span></span></p>
      )}
      <div class="table-wrap">
        <table class="data dense">
          <tbody>
            <tr><td>Radio ({b.radio_chip || (usbF ? "chip not reported yet" : "ESP32-C6")})</td><td class="mono">{b.radio || L.radio?.version || "—"}</td><td><FwBadge state={b.radio_firmware} /></td></tr>
            {!usbF && <tr><td>Bridge (ESP32-S3)</td><td class="mono">{b.bridge || L.hello?.bridge || "—"}</td><td><FwBadge state={b.bridge_firmware} /> <span class="sub">{b.bridge_partition || ""}</span></td></tr>}
          </tbody>
        </table>
      </div>
      <p class="muted small">
        {usbF ? "Updates go over the USB cable (no token needed). Pick a radio image below; it is checked before anything is sent."
          : F.updates_enabled === false ? "The bridge was built without an update token, so it refuses updates over Wi-Fi."
            : F.token_set ? "Pick an image below; it is checked before anything is sent."
              : <>Set <b>update_token</b> in this app's Configuration (the bridge's CONFIG_BRIDGE_UPDATE_TOKEN) to update from here.</>}
        {b.last_update && b.last_update !== "none since boot" ? ` Bridge's last update: ${b.last_update}.` : ""}
      </p>
      {F.updates_enabled !== false && (
        <div class="fw-tool">
          <div class="toolbar">
            <label class="btn small file-btn"><Icon name="upload" size={14} /> Choose a .bin…
              <input ref={fileIn} type="file" accept=".bin" class="sr-only" onChange={async (e) => {
                const el = e.target as HTMLInputElement, file = el.files?.[0];
                if (file) inspect({ data: await file.arrayBuffer() });
                el.value = "";
              }} />
            </label>
            {F.folder && <span class="muted small">or put images in {F.folder}</span>}
          </div>
          {(F.files || []).length > 0 && (
            <div class="table-wrap">
              <table class="data dense fw-files">
                <tbody>
                  {F.files.map((x: any) => (
                    <tr>
                      <td class="wrap"><div class="mono fname">{x.name}</div>
                        <div class="sub">{x.error ? <span class="warn-text">{x.error}</span> : `${x.target || "not sniffer firmware"} ${x.version || ""}`} · {f.ago(x.mtime)}</div></td>
                      <td class="num"><button type="button" class="btn small" onClick={() => inspect({ file: x.name })}>Check</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {check && (
            <div class="fw-check">
              {check.busy ? <Loading>Checking…</Loading> : check.err ? <p class="note warn"><Icon name="alert" size={16} /> {check.err}</p> : r && (
                <>
                  <KV rows={[
                    ["Image", <>{i.project} <b>{i.version}</b></>],
                    ["For", `${i.chip || ""}${r.target ? ` · the ${r.target}` : ""}`],
                    ["Built", `${i.built || ""} · ${i.idf || ""}`],
                    ["Size", f.bytes(f.num(i.size))],
                    ...(r.running ? [["Running now", <span class="mono">{r.running}</span>] as [string, preact.ComponentChildren]] : []),
                  ]} />
                  {problems.length > 0 && <p class="note warn"><Icon name="alert" size={16} /><span>{problems.map((p, k) => <>{k > 0 && <br />}{p}</>)}</span></p>}
                  {r.target && (
                    <div class="toolbar">
                      <button type="button" class="btn primary" disabled={!ok || sending} onClick={flash}>Update the {r.target} to {i.version}</button>
                      {!ok && <span class="muted small">{problems.length ? "fix the problems above first" : "needs update_token in the Configuration"}</span>}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

/** Listen on another channel (every sniffer), or go back to the configured one. */
function Channel({ d, refresh }: { d: any; refresh: () => void }) {
  const C = d.channel || {}, cur = f.num(C.current), conf = f.num(C.configured);
  const [choice, setChoice] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const ch = choice ?? cur ?? conf ?? 11;
  const send = async (target: number | null, okText: string) => {
    setBusy(true);
    try {
      await post("api/channel", { channel: target });
      toast(okText);
      setChoice(null);
      refresh();
    } catch (e: any) { toast(e?.message || String(e), "error", 7000); } finally { setBusy(false); }
  };
  const listen = async () => {
    if (ch === cur) { toast(`Already listening on channel ${ch}`, "info"); setChoice(null); return; }
    if (ch !== conf && !await confirmIt({
      title: `Every sniffer to channel ${ch}?`, confirm: `Listen on ${ch}`, danger: true,
      body: `On another channel the sniffers don't hear your network (Zigbee2MQTT stays on ${conf ?? "its channel"}). The choice applies to every sniffer and is kept across reconnects and restarts until you go back.`,
    })) return;
    send(ch, ch === conf ? `Back on channel ${ch}` : `Listening on channel ${ch}: your network (channel ${conf}) isn't heard until you go back`);
  };
  return (
    <Card title="Channel">
      <div class="toolbar">
        <span>Listening on <b>{cur ?? "—"}</b>{cur !== null && conf !== null && cur !== conf && <> <Chip tone="warn">not the configured {conf}</Chip></>}</span>
        <select class="select" value={String(ch)} aria-label="Channel to listen on" onChange={(e) => setChoice(+(e.target as HTMLSelectElement).value)}>
          {Array.from({ length: 16 }, (_, k) => <option>{11 + k}</option>)}
        </select>
        <button type="button" class="btn small" disabled={busy} onClick={listen}>Listen</button>
        {cur !== null && conf !== null && cur !== conf && <button type="button" class="btn small" disabled={busy} onClick={() => send(null, "Back on the configured channel")}>Back to {conf}</button>}
      </div>
      <p class="muted small">On another channel the sniffers don't hear your network (Zigbee2MQTT stays on {conf ?? "its channel"}). The choice applies to every sniffer and is kept across reconnects and restarts until you go back.</p>
    </Card>
  );
}

function HomeAssistant({ d }: { d: any }) {
  const H = d.ha || {};
  const [copied, setCopied] = useState("");
  const copy = async () => {
    setCopied((await copyText(HA_EXAMPLE)) ? "Copied" : "Select the text and copy it");
  };
  return (
    <Card title="Home Assistant">
      <div class="sevline">{H.connected ? <><SevIcon sev="good" /> Publishing over MQTT</> : <><SevIcon sev={H.enabled ? "warn" : "info"} /> {H.error || "not connected"}</>}</div>
      <p class="muted small">A <b>Zigbee Sniffer</b> device with sensors (connected, Wi-Fi signal, problems, firmware…){H.device_sensors ? <>, and a <b>Zigbee health</b> sensor on each Zigbee2MQTT device</> : ""}. Leaves, rejoins, route errors and sniffer outages fire <span class="mono">zigbee_sniffer_event</span>. For example, a notification:</p>
      <pre class="hex">{HA_EXAMPLE}</pre>
      <button type="button" class="btn small" onClick={copy}><Icon name="copy" size={14} /> {copied || "Copy"}</button>
    </Card>
  );
}
