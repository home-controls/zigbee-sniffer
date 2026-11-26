// App-wide state: the app's status (polled every 5 s while the page is visible), the time range,
// the current route, and small remembered choices (localStorage, "zbs." like the old page).

import { computed, signal } from "@preact/signals";
import { route as kitRoute, setDefaultPage } from "./kit/route";
import { api } from "./api";
import { parseHash, type Route } from "./logic";

export const pref = {
  get: (k: string, d: string): string => { try { return localStorage.getItem("zbs." + k) ?? d; } catch { return d; } },
  set: (k: string, v: string | number | boolean): void => { try { localStorage.setItem("zbs." + k, String(v)); } catch { /* private window */ } },
  flag: (k: string, d: boolean): boolean => pref.get(k, d ? "1" : "0") === "1",
  setFlag: (k: string, v: boolean): void => pref.set(k, v ? "1" : "0"),
};

export type Range = "1h" | "6h" | "24h" | "7d";
export const RANGES: { v: Range; label: string }[] = [
  { v: "1h", label: "1 h" }, { v: "6h", label: "6 h" }, { v: "24h", label: "24 h" }, { v: "7d", label: "7 days" },
];
const savedRange = pref.get("range", "24h") as Range;
export const range = signal<Range>(RANGES.some((r) => r.v === savedRange) ? savedRange : "24h");
export function setRange(r: Range): void {
  range.value = r;
  pref.set("range", r);
}

// The kit's hash route says when the hash changed; the query part ("?t=…&addr=…") is read here.
setDefaultPage("overview");
export const where = computed<Route>(() => {
  kitRoute.value;
  return parseHash(location.hash);
});

export const status = signal<any | null>(null);
/** The status request failed: the app (its backend) isn't answering. */
export const statusDown = signal(false);
let statusAt = 0;

export async function loadStatus(): Promise<void> {
  statusAt = Date.now();
  try {
    status.value = await api("api/status");
    statusDown.value = false;
  } catch {
    statusDown.value = true;
  }
}

export function startStatus(): void {
  loadStatus();
  setInterval(() => { if (!document.hidden && Date.now() - statusAt > 4000) loadStatus(); }, 5000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - statusAt > 4000) loadStatus(); });
}

/** More than one sniffer is configured: signals name their sniffer, device charts get a line per sniffer. */
export const several = computed(() => (Array.isArray(status.value?.sniffers) ? status.value.sniffers.length : 0) > 1);
