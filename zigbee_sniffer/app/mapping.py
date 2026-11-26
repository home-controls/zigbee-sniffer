"""Floor plans, where devices and sniffers are on them, and an estimate of Zigbee coverage.

Floors: an uploaded image (PNG, JPG, SVG, WebP) or a blank grid of a given size in metres,
with a level (0 = ground floor, 1 = the floor above...). An image floor gets its scale from two
points a known distance apart. Positions are fractions of the floor's width and height, keyed
by IEEE address (devices) or "sniffer:<id>". All of it lives in /data/map.json and /data/maps/.

Coverage: every placed sniffer measures every placed device's signal (RSSI). Those pairs fit a
log-distance path-loss model,

    rssi = A_device - 10 n log10(distance / 1 m) - L * floors between + G_sniffer,

where A is the device's own strength at 1 m (transmit power and antenna), n how fast signal
falls with distance in this house (2 in free space, 3-4 through walls), L the loss per floor
(fitted when sniffers hear devices on other floors of aligned plans), and G each sniffer's antenna
gain against the first sniffer's (a better antenna hears everything louder, which says nothing
about the house or the devices; the devices two sniffers both hear pin it down). Strengths and
the map are as the first sniffer's antenna would hear them. With it, the strength a
device at any point would see from each router can be estimated: the coverage map. It is an
estimate - walls are only in the average n - and the fit's typical error is reported with it.
"""

import json
import math
import statistics
import time
import uuid
from pathlib import Path

IMAGE_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/svg+xml": "svg", "image/webp": "webp", "image/gif": "gif"}
DEFAULT_FLOOR_HEIGHT_M = 3.0
DEFAULT_FLOOR_LOSS = 15.0  # dB per floor until the data says otherwise
DEFAULT_N10 = 30.0  # 10 * n
MIN_SAMPLES = 4
MIN_GAIN_SAMPLES = 3  # measurements a sniffer needs before its antenna gain is fitted


class FloorMaps:
    def __init__(self, data_dir: Path) -> None:
        self.file = data_dir / "map.json"
        self.img_dir = data_dir / "maps"
        self.img_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.data = json.loads(self.file.read_text())
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("floors", [])
        self.data.setdefault("positions", {})
        self.data.setdefault("floor_height_m", DEFAULT_FLOOR_HEIGHT_M)

    def save(self) -> None:
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1))
        tmp.replace(self.file)

    @property
    def floors(self) -> list[dict]:
        return sorted(self.data["floors"], key=lambda f: (f.get("level", 0), f.get("name", "")))

    def floor(self, fid: str) -> dict:
        for f in self.data["floors"]:
            if f["id"] == fid:
                return f
        raise KeyError(f"no floor {fid}")

    def add_floor(self, name: str, level: int, width_m: float | None, height_m: float | None) -> dict:
        f = {"id": uuid.uuid4().hex[:8], "name": name or "Floor", "level": int(level), "image": None,
             "img_w": None, "img_h": None, "scale": None, "created": time.time()}
        if width_m and height_m:
            f["width_m"], f["height_m"] = float(width_m), float(height_m)
        self.data["floors"].append(f)
        self.save()
        return f

    def update_floor(self, fid: str, changes: dict) -> dict:
        f = self.floor(fid)
        if "name" in changes:
            f["name"] = str(changes["name"])[:60] or f["name"]
        if "level" in changes:
            f["level"] = int(changes["level"])
        if "scale" in changes:  # image pixels per metre
            f["scale"] = float(changes["scale"]) if changes["scale"] else None
        if "width_m" in changes and "height_m" in changes and not f.get("image"):
            f["width_m"], f["height_m"] = float(changes["width_m"]), float(changes["height_m"])
        self.save()
        return f

    def delete_floor(self, fid: str) -> None:
        f = self.floor(fid)
        self.data["floors"].remove(f)
        self.data["positions"] = {k: v for k, v in self.data["positions"].items() if v.get("floor") != fid}
        if f.get("image"):
            (self.img_dir / f["image"]).unlink(missing_ok=True)
        self.save()

    def set_image(self, fid: str, data: bytes, content_type: str, width: int, height: int) -> dict:
        ext = IMAGE_TYPES.get(content_type.split(";")[0].strip().lower())
        if not ext:
            raise ValueError("use a PNG, JPG, SVG, WebP or GIF image")
        f = self.floor(fid)
        if f.get("image"):
            (self.img_dir / f["image"]).unlink(missing_ok=True)
        name = f"{fid}-{int(time.time())}.{ext}"
        (self.img_dir / name).write_bytes(data)
        f.update(image=name, img_w=int(width), img_h=int(height), scale=None)
        f.pop("width_m", None)
        f.pop("height_m", None)
        self.save()
        return f

    def image_path(self, fid: str) -> Path | None:
        f = self.floor(fid)
        return self.img_dir / f["image"] if f.get("image") else None

    def set_positions(self, put: dict, clear: list) -> None:
        floors = {f["id"] for f in self.data["floors"]}
        for key, pos in (put or {}).items():
            if pos.get("floor") not in floors:
                raise ValueError(f"no floor {pos.get('floor')}")
            self.data["positions"][str(key)] = {"floor": pos["floor"], "x": min(1.0, max(0.0, float(pos["x"]))),
                                                "y": min(1.0, max(0.0, float(pos["y"])))}
        for key in clear or []:
            self.data["positions"].pop(str(key), None)
        self.save()

    # ------------------------------------------------------------ geometry

    def size_m(self, f: dict) -> tuple[float, float] | None:
        """A floor's width and height in metres, if known (a blank floor, or an image with a scale)."""
        if f.get("width_m") and f.get("height_m"):
            return f["width_m"], f["height_m"]
        if f.get("img_w") and f.get("img_h") and f.get("scale"):
            return f["img_w"] / f["scale"], f["img_h"] / f["scale"]
        return None

    def point_m(self, pos: dict) -> tuple[float, float, int] | None:
        """(x m, y m, level) of a position, if its floor has a scale."""
        try:
            f = self.floor(pos["floor"])
        except KeyError:
            return None
        size = self.size_m(f)
        if not size:
            return None
        return pos["x"] * size[0], pos["y"] * size[1], f.get("level", 0)

    def distance(self, a: tuple, b: tuple) -> tuple[float, int]:
        """(metres, floors between) of two points from point_m. Plans of different floors are taken as
        drawn on the same grid (same origin and scale), so they line up."""
        floors = abs(a[2] - b[2])
        dz = floors * self.data["floor_height_m"]
        return max(0.5, math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + dz * dz)), floors


def _solve(rows: list[list[float]], ys: list[float], ws: list[float] | None = None) -> list[float] | None:
    """(Weighted) least squares by the normal equations (a handful of unknowns), Gaussian elimination."""
    k = len(rows[0])
    ws = ws or [1.0] * len(rows)
    a = [[sum(w * r[i] * r[j] for r, w in zip(rows, ws)) for j in range(k)] for i in range(k)]
    v = [sum(w * r[i] * y for r, y, w in zip(rows, ys, ws)) for i in range(k)]
    for i in range(k):
        p = max(range(i, k), key=lambda r: abs(a[r][i]))
        if abs(a[p][i]) < 1e-9:
            return None
        a[i], a[p], v[i], v[p] = a[p], a[i], v[p], v[i]
        for r in range(i + 1, k):
            f = a[r][i] / a[i][i]
            for c in range(i, k):
                a[r][c] -= f * a[i][c]
            v[r] -= f * v[i]
    x = [0.0] * k
    for i in range(k - 1, -1, -1):
        x[i] = (v[i] - sum(a[i][c] * x[c] for c in range(i + 1, k))) / a[i][i]
    return x


def _wmean(vals: list[tuple[float, float]]) -> float:
    """Weighted mean of (value, weight)."""
    tw = sum(w for _, w in vals)
    return sum(v * w for v, w in vals) / tw if tw else 0.0


def _house(samples: list[dict], ys: list[float], ws: list[float], cross: bool, gain_ids: list[str]):
    """The shared part of the model for measurements ys (already corrected for device offsets):
    (A, n10, L, {sniffer: gain}, n fixed?, L fitted?). Falls back step by step: without the floor
    term if its loss comes out negative (noise), with a typical n if n is out of physical range,
    without antenna gains if they can't be told apart (each sniffer hearing its own devices only)."""

    def attempt(use_n: bool, use_floors: bool, use_gains: bool, y: list[float]):
        rows = []
        for sm in samples:
            row = [1.0]
            if use_n:
                row.append(-math.log10(sm["d"]))
            if use_floors:
                row.append(-float(sm["floors"]))
            if use_gains:
                row += [1.0 if sm.get("sniffer") == g else 0.0 for g in gain_ids]
            rows.append(row)
        x = _solve(rows, y, ws)
        if x is None:
            return None
        i, n10, loss = 1, None, None
        if use_n:
            n10, i = x[i], i + 1
        if use_floors:
            loss, i = x[i], i + 1
        return x[0], n10, loss, ({g: x[i + k] for k, g in enumerate(gain_ids)} if use_gains else {})

    for use_gains in ((True, False) if gain_ids else (False,)):
        use_floors = cross
        r = attempt(True, use_floors, use_gains, ys)
        if r and use_floors and r[2] < 0:  # a negative floor loss is noise: fit without it
            use_floors = False
            r = attempt(True, False, use_gains, ys)
        if r is None:
            continue
        a, n10, loss, gains = r
        if 15 <= n10 <= 50:
            return a, n10, (loss if use_floors else (0.0 if cross else DEFAULT_FLOOR_LOSS)), gains, False, use_floors
        # out of physical range: keep a typical n, fit the rest
        ys2 = [y + DEFAULT_N10 * math.log10(sm["d"]) for y, sm in zip(ys, samples)]
        r2 = attempt(False, cross, use_gains, ys2)
        if r2 is None:
            continue
        a2, _, loss2, gains2 = r2
        return a2, DEFAULT_N10, (max(0.0, loss2) if cross else DEFAULT_FLOOR_LOSS), gains2, True, cross
    ys2 = [y + DEFAULT_N10 * math.log10(sm["d"]) for y, sm in zip(ys, samples)]
    return statistics.mean(ys2), DEFAULT_N10, DEFAULT_FLOOR_LOSS, {}, True, False


def fit(samples: list[dict], ref: str | None = None) -> dict:
    """samples: [{"device", "sniffer", "d" (m), "floors", "rssi", "n" (frames)}] -> the path-loss model.

    First the house: one A, n and floor loss L shared by every device, and each sniffer's antenna
    gain against the reference sniffer `ref`, weighted by how many frames each measurement averages
    (capped, so one chatty device doesn't decide it). Then each device's own A, but only for devices
    two or more placed sniffers hear: with one measurement a device's strength can't be told apart
    from the walls between it and the sniffer, and fitting it anyway hides that error (the old
    fit's reported error was about half the real one). The reported error is leave-one-out: each
    measurement predicted without itself."""
    if len(samples) < MIN_SAMPLES:
        return {"ok": False, "samples": len(samples),
                "why": f"needs at least {MIN_SAMPLES} measurements (a placed sniffer hearing a placed device, "
                       f"both on floors with a scale); there are {len(samples)}"}
    ws = [min(10.0, math.sqrt(max(1, s.get("n") or 1))) for s in samples]
    cross = any(s["floors"] for s in samples)
    per_sniffer: dict = {}
    for s in samples:
        per_sniffer[s.get("sniffer")] = per_sniffer.get(s.get("sniffer"), 0) + 1
    if ref not in per_sniffer:
        ref = max(per_sniffer, key=lambda k: per_sniffer[k])
    gain_ids = sorted(g for g, c in per_sniffer.items() if g is not None and g != ref and c >= MIN_GAIN_SAMPLES)

    ys = [s["rssi"] for s in samples]
    a0, n10, loss, gains, n10_fixed, loss_fitted = _house(samples, ys, ws, cross, gain_ids)

    def predict(s, a):
        return a - n10 * math.log10(s["d"]) - loss * s["floors"] + gains.get(s.get("sniffer"), 0.0)

    count = {}
    for s in samples:
        count[s["device"]] = count.get(s["device"], 0) + 1
    several = {d for d, c in count.items() if c >= 2}
    # Alternate: each such device's offset from the house, then the house again from the
    # offset-corrected measurements, so n, L and the gains come from how one device sounds at
    # different sniffers.
    offsets: dict[str, float] = {}
    for _ in range(12 if several else 1):
        per: dict[str, list[tuple[float, float]]] = {}
        for s, w in zip(samples, ws):
            if s["device"] in several:
                per.setdefault(s["device"], []).append((s["rssi"] - predict(s, a0), w))
        offsets = {d: _wmean(r) for d, r in per.items()}
        if (n10_fixed and not gain_ids) or not several:
            break
        a0, n10, loss, gains, n10_fixed, loss_fitted = _house(
            samples, [s["rssi"] - offsets.get(s["device"], 0.0) for s in samples], ws, cross, gain_ids)
    # leave-one-out: a device's offset from its *other* measurements, shrunk toward the house
    resid = []
    for s in samples:
        others = [(s2["rssi"] - predict(s2, a0), w2) for s2, w2 in zip(samples, ws)
                  if s2["device"] == s["device"] and s2 is not s] if s["device"] in several else []
        off = _wmean(others) * len(others) / (len(others) + 1.0) if others else 0.0
        resid.append(s["rssi"] - predict(s, a0 + off))
    rmse = math.sqrt(sum(r * r for r in resid) / len(resid))
    offsets = {d: v * count[d] / (count[d] + 1.0) for d, v in offsets.items()}
    gain_rows = ([{"sniffer": ref, "db": 0.0, "ref": True, "samples": per_sniffer.get(ref, 0)}] if gain_ids else []) + [
        {"sniffer": g, "db": round(gains[g], 1), "ref": False, "samples": per_sniffer[g]} for g in gain_ids if g in gains]
    return {"ok": True, "samples": len(samples), "devices": len(count), "a0": round(a0, 1), "n": round(n10 / 10, 2),
            "n10": n10, "n_fixed": n10_fixed, "floor_loss": round(loss, 1), "floor_loss_fitted": loss_fitted,
            "rmse": round(rmse, 1), "devices_with_strength": len(offsets), "offsets": offsets,
            "gains": gain_rows, "gain_ref": ref}
