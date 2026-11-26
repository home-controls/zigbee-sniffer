// The shell: tabs, the time range and the connection on the right, banners for trouble that
// matters on every page, then the page. Pages are picked from the hash (#/device/0x072f, …).

import { Shell, Splash, Pill } from "./kit/shell";
import { initTheme } from "./kit/theme";
import { useFamily } from "./kit/family";
import { Seg } from "./kit/ui";
import { Icon } from "./kit/icons";
import { RANGES, range, setRange, several, status, statusDown, where } from "./store";
import { FrameDrawer } from "./frames";
import { Overview } from "./pages/Overview";
import { Devices } from "./pages/Devices";
import { Device } from "./pages/Device";
import { Mesh } from "./pages/Mesh";
import { MapPage } from "./pages/Map";
import { Live } from "./pages/Live";
import { Captures } from "./pages/Captures";
import { SnifferPage } from "./pages/Sniffer";

const { embedded } = initTheme("zbs.theme");

const NAV = [
  { id: "overview", label: "Overview", icon: "home" },
  { id: "devices", label: "Devices", icon: "list" },
  { id: "mesh", label: "Mesh", icon: "mesh" },
  { id: "map", label: "Map", icon: "map" },
  { id: "live", label: "Live", icon: "frames" },
  { id: "captures", label: "Captures", icon: "clock" },
  { id: "sniffer", label: "Sniffer", icon: "antenna" },
];
const PAGES = new Set([...NAV.map((n) => n.id), "device"]);
const RANGED = new Set(["overview", "devices", "device", "mesh", "sniffer", "map"]);

export function App() {
  // the other Zigbee apps for the menu (found through Home Assistant); before any early return
  const family = useFamily();
  const s = status.value;
  if (!s && !statusDown.value) return <Splash>Connecting…</Splash>;
  if (!s) return <Splash>Can't reach the Zigbee Sniffer app, retrying…</Splash>;
  const r = where.value;
  const page = PAGES.has(r.page) ? r.page : "overview";
  // a new key per route: each visit starts fresh (its own polling, nothing left over)
  const key = location.hash;
  return (
    <Shell app="sniffer" version={s.version} nav={NAV} page={page === "device" ? "devices" : page} embedded={embedded} links={family}
      right={<TopRight ranged={RANGED.has(page)} />} banner={<Banners />}>
      {page === "overview" && <Overview key={key} />}
      {page === "devices" && <Devices key={key} filter={r.q.get("f")} />}
      {page === "device" && <Device key={key} addr={r.arg.toLowerCase()} />}
      {page === "mesh" && <Mesh key={key} />}
      {page === "map" && <MapPage key={key} />}
      {page === "live" && <Live key={key} addr={(r.q.get("addr") || "").toLowerCase()} />}
      {page === "captures" && <Captures key={key} q={r.q} />}
      {page === "sniffer" && <SnifferPage key={key} />}
      <FrameDrawer />
    </Shell>
  );
}

function TopRight({ ranged }: { ranged: boolean }) {
  const s = status.value;
  const down = statusDown.value;
  const sn: any[] = Array.isArray(s?.sniffers) ? s.sniffers : [];
  const mw = s?.merge?.waiting_for_name ? ` · waiting for ${s.merge.waiting_for_name}'s frames (${s.merge.behind_s} s behind)` : "";
  const text = down ? "App not responding"
    : s?.connected ? `Live${sn.length > 1 ? ` · ${sn.filter((x) => x.connected).length}/${sn.length} sniffers` : ""} · ch ${s.channel} · ${s.fps} frames/s${mw}`
      : s?.last_error || "Not connected";
  const tone = down || !s?.connected ? "bad" : sn.every((x) => x.connected) ? "ok" : "warn";
  return (
    <>
      {ranged && <Seg label="Time range" value={range.value} onChange={setRange} options={RANGES} />}
      <Pill tone={tone} label={text} title={text} />
    </>
  );
}

/** Trouble that matters on every page: the app itself, the sniffers, the capture disk, tshark. */
function Banners() {
  const s = status.value;
  if (statusDown.value) return <div class="banner bad"><Icon name="alert" size={16} /> The Zigbee Sniffer app isn't answering; retrying. What's shown may be stale.</div>;
  if (!s) return null;
  const out: preact.JSX.Element[] = [];
  const line = (tone: "bad" | "warn", body: preact.ComponentChildren) => out.push(<div class={`banner ${tone}`}><Icon name="alert" size={16} /><span>{body}</span></div>);
  if (s.disk_error) line("bad", <>Storage: {s.disk_error}</>);
  if (!s.host) line("bad", <>Set <b>sniffer_host</b> in this app's Configuration tab to the bridge's IP address.</>);
  else if (!s.connected) line("bad", <>Not connected to the sniffer: {s.last_error || "connecting"}</>);
  if (s.bridge && s.bridge.radio_link_ok === false) line("bad", "The bridge isn't hearing the radio board: check the 3 UART wires.");
  if (several.value) for (const x of s.sniffers) if (!x.connected && x.host) line("warn", <>Sniffer <b>{x.name}</b> isn't connected: {x.last_error || "connecting"}</>);
  if (s.tshark_error) line("warn", <>tshark: {s.tshark_error}</>);
  return out.length ? <div class="banners">{out}</div> : null;
}
