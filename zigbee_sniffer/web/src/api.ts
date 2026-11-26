// The app's own API, always by relative path: the page sits under Home Assistant's ingress path.

async function check(r: Response): Promise<Response> {
  if (!r.ok) throw new Error((await r.text()) || r.statusText || `HTTP ${r.status}`);
  return r;
}

export async function api<T = any>(path: string): Promise<T> {
  return (await check(await fetch(path, { cache: "no-store" }))).json();
}

/** POST JSON (the default) or raw bytes with their content type. */
export async function post<T = any>(path: string, body?: unknown, type = "application/json"): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    body: type === "application/json" ? JSON.stringify(body ?? {}) : (body as BodyInit | null),
    headers: { "Content-Type": type },
  });
  return (await check(r)).json();
}

export async function del<T = any>(path: string): Promise<T> {
  const r = await check(await fetch(path, { method: "DELETE" }));
  return r.json().catch(() => ({}) as T);
}

export const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

export function downloadText(name: string, text: string, type = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

