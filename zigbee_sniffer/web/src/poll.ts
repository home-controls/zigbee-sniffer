// usePoll: load now and every `ms` while the page is visible (and again when it becomes visible).
// The last answer stays on screen while the next one loads; an error is kept until a load works.
// An answer that arrives after a newer load started, or after the page went away, is dropped.

import { useEffect, useRef, useState } from "preact/hooks";

export function usePoll<T>(ms: number, load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const seq = useRef(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  const run = useRef<(force?: boolean) => Promise<void>>(async () => {});
  useEffect(() => {
    let alive = true;
    setData(null);
    setErr(null);
    run.current = async (force = false) => {
      if (!alive || (document.hidden && !force)) return;
      const my = ++seq.current;
      try {
        const d = await loadRef.current();
        if (alive && my === seq.current) { setData(d); setErr(null); }
      } catch (e: any) {
        if (alive && my === seq.current) setErr(e?.message || String(e));
      }
    };
    run.current(true);
    const t = ms > 0 ? window.setInterval(() => run.current(false), ms) : undefined;
    const vis = () => { if (!document.hidden) run.current(true); };
    document.addEventListener("visibilitychange", vis);
    return () => {
      alive = false;
      clearInterval(t);
      document.removeEventListener("visibilitychange", vis);
    };
  }, deps);
  return { data, err, refresh: () => run.current(true), setData };
}

/** A function that stays the same across renders but always calls the latest `fn`. */
export function useLatest<F extends (...a: any[]) => any>(fn: F): F {
  const ref = useRef(fn);
  ref.current = fn;
  return useRef(((...a: any[]) => ref.current(...a)) as F).current;
}
