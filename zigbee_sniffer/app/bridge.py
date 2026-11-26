"""The sniffer hardware, through the bridge's own web server (bridge 0.2+ on port 80).

`GET /` is the bridge's status: firmware of both boards (version and trial state), Wi-Fi, its
frame buffer, the UART. `POST /update/bridge` and `POST /update/radio` take an ESP-IDF app image
with the `X-Update-Token` header; each call returns when the update is done (the radio's is
relayed over the UART by the bridge) or has failed, with a line of text saying which.
"""

import asyncio
import hashlib
import logging
import time

import aiohttp

log = logging.getLogger("bridge")

PROJECTS = {"radio": "zigbee_sniffer_radio", "bridge": "zigbee_sniffer_bridge"}
CHIPS = {0: "ESP32", 2: "ESP32-S2", 5: "ESP32-C3", 9: "ESP32-S3", 12: "ESP32-C2", 13: "ESP32-C6", 16: "ESP32-H2",
         23: "ESP32-C5"}
TARGET_CHIP = {"radio": "ESP32-C6", "bridge": "ESP32-S3"}
APP_DESC_MAGIC = 0xABCD5432


def board_of(version: str) -> str:
    """The bridge board a version is built for: "0.3.2+devkitc" -> devkitc; no suffix = supermini."""
    return version.split("+", 1)[1] if "+" in version else "supermini"


def image_info(data: bytes) -> dict:
    """What an ESP-IDF app image says about itself: project, version, chip, build date."""
    if len(data) < 256 or data[0] != 0xE9:
        raise ValueError("not an ESP-IDF app image (it should start with 0xE9)")
    if int.from_bytes(data[32:36], "little") != APP_DESC_MAGIC:
        raise ValueError("no app description in the image (is this the app .bin, not the bootloader or a merged image?)")
    text = lambda a, b: data[a:b].split(b"\0")[0].decode(errors="replace")
    chip_id = int.from_bytes(data[12:14], "little")
    project = text(80, 112)
    return {
        "project": project, "version": text(48, 80), "chip": CHIPS.get(chip_id, f"chip {chip_id}"),
        "built": f"{text(128, 144)} {text(112, 128)}".strip(), "idf": text(144, 176), "size": len(data),
        "target": next((t for t, p in PROJECTS.items() if p == project), None),
        "sha256": verify_hash(data),
    }


def verify_hash(data: bytes) -> bool | None:
    """The SHA-256 ESP-IDF appends to an app image: True if it matches, False if the image is damaged,
    None when the image carries none. Layout: 24-byte header (segment count at 1, hash-appended flag
    at 23), segments of (load address, length, data), padding so that the checksum byte ends on a
    16-byte boundary, then the 32-byte hash of everything before it."""
    if len(data) < 24 or data[23] != 1:
        return None
    pos = 24
    for _ in range(data[1]):
        if pos + 8 > len(data):
            return False
        pos += 8 + int.from_bytes(data[pos + 4 : pos + 8], "little")
    pos += 15 - (pos % 16)  # padding, then the checksum byte
    end = pos + 1
    if end + 32 > len(data):
        return False
    return hashlib.sha256(data[:end]).digest() == data[end : end + 32]


def check_image(info: dict, target: str, status: dict) -> list[str]:
    """Reasons not to flash this image to that board (empty: fine)."""
    problems = []
    if info["project"] != PROJECTS[target]:
        problems.append(f"this is {info['project'] or 'an unknown project'}, not the {target} firmware ({PROJECTS[target]})")
    # A radio on USB says which chip it is (radio 0.3+, "radio_chip"); a bridge's radio is a C6.
    chip = status.get(f"{target}_chip", TARGET_CHIP[target])
    if chip is None:
        problems.append(f"the {target} hasn't said which chip it is yet (it does every 30 s), so the image can't be "
                        "checked; try again in a minute")
    elif info["chip"] != chip:
        problems.append(f"built for {info['chip']}, the {target} is an {chip}")
    if info.get("sha256") is False:
        problems.append("the image is damaged: its SHA-256 doesn't match (download or copy it again)")
    running = status.get(target)
    if target == "bridge":
        if not running:
            problems.append("the bridge's running version is unknown (its status page didn't answer), so its board "
                            "can't be checked; try again when the Sniffer page shows the bridge firmware")
        elif board_of(info["version"]) != board_of(running):
            problems.append(f"built for the {board_of(info['version'])} board; this bridge is a {board_of(running)}")
    return problems


class Bridge:
    """Polls the bridge's status page and passes firmware updates to it."""

    def __init__(self, host: str, http_port: int = 80) -> None:
        self.host = host
        self.base = f"http://{host}" if http_port == 80 else f"http://{host}:{http_port}"
        self.status: dict = {}
        self.at = 0.0  # when `status` was read
        self.error = ""
        self.updating: dict | None = None  # {"target", "version", "started", ...} while an update runs
        self.last_result: dict | None = None
        self._session: aiohttp.ClientSession | None = None

    def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def poll(self) -> dict:
        if not self.host:
            return {}
        try:
            async with self.session().get(f"{self.base}/", timeout=aiohttp.ClientTimeout(total=8)) as r:
                self.status = await r.json(content_type=None)
                self.at, self.error = time.time(), ""
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            self.error = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        return self.status

    async def run(self, every_s: float = 30) -> None:
        while True:
            await self.poll()
            await asyncio.sleep(5 if self.updating else every_s)

    async def update(self, target: str, data: bytes, token: str) -> dict:
        """Send an image to the bridge; returns {"ok", "message", "seconds"}."""
        started = time.time()
        version = "?"
        result: dict = {"ok": False, "message": "the update didn't start"}
        try:
            info = image_info(data)
            version = info["version"]
            self.updating = {"target": target, "version": version, "size": len(data), "started": started}
            async with self.session().post(
                f"{self.base}/update/{target}", data=data,
                headers={"X-Update-Token": token, "Content-Type": "application/octet-stream"},
                timeout=aiohttp.ClientTimeout(total=300),
            ) as r:
                text = (await r.text()).strip()
                result = {"ok": r.status == 200, "message": text or f"HTTP {r.status}", "status": r.status}
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            result = {"ok": False, "message": f"the bridge didn't answer: {type(e).__name__} {e}".strip()}
        except Exception as e:  # noqa: BLE001 - whatever happens, the update must not stay "running"
            log.exception("Firmware update of the %s failed", target)
            result = {"ok": False, "message": f"the update failed: {type(e).__name__} {e}".strip()}
        finally:
            result.update(target=target, version=version, seconds=round(time.time() - started), finished=time.time())
            self.last_result, self.updating = result, None
        log.info("Firmware update of the %s to %s: %s", target, version, result["message"])
        asyncio.get_running_loop().call_later(3, lambda: asyncio.ensure_future(self.poll()))
        return result
