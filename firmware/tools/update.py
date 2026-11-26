"""Update the sniffer's firmware over Wi-Fi, through the bridge.

    python tools/update.py status          --host HOST
    python tools/update.py radio  [FILE]   --host HOST     # C6, relayed over the UART
    python tools/update.py bridge [FILE]   --host HOST     # the S3 itself

FILE defaults to the board's last build: c6-radio/build/zigbee_sniffer_radio.bin, and for the
bridge the build for the board it says it is (s3-bridge/build/ for the Super Mini,
s3-bridge/build-<board>/ otherwise, e.g. build-devkitc/). The token comes from
$SNIFFER_UPDATE_TOKEN, else CONFIG_BRIDGE_UPDATE_TOKEN in s3-bridge/sdkconfig.secrets. Standard
library only.

Each board boots a new image on trial and keeps it only if it works (the bridge: Wi-Fi up for
30 s; the radio: the two boards hear each other); otherwise it rolls back by itself.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = {"radio": "zigbee_sniffer_radio", "bridge": "zigbee_sniffer_bridge"}


def board_of(version: str) -> str:
    """The bridge board a version is built for: "0.3.2+devkitc" -> devkitc; no suffix = supermini."""
    return version.split("+", 1)[1] if "+" in version else "supermini"


def default_build(target: str, running: str) -> Path:
    if target == "radio":
        return ROOT / "c6-radio" / "build" / "zigbee_sniffer_radio.bin"
    board = board_of(running)
    folder = "build" if board == "supermini" else f"build-{board}"
    return ROOT / "s3-bridge" / folder / "zigbee_sniffer_bridge.bin"


def token() -> str:
    tok = os.environ.get("SNIFFER_UPDATE_TOKEN", "")
    if tok:
        return tok
    secrets = ROOT / "s3-bridge" / "sdkconfig.secrets"
    if secrets.exists():
        for line in secrets.read_text().splitlines():
            m = re.match(r'^CONFIG_BRIDGE_UPDATE_TOKEN="(.*)"\s*$', line)
            if m:
                return m.group(1)
    sys.exit("No update token: set SNIFFER_UPDATE_TOKEN or CONFIG_BRIDGE_UPDATE_TOKEN in s3-bridge/sdkconfig.secrets")


def image_info(data: bytes) -> tuple[str, str]:
    """(project name, version) from the app description after the image and segment headers."""
    if len(data) < 112 or data[0] != 0xE9 or int.from_bytes(data[32:36], "little") != 0xABCD5432:
        sys.exit("Not an ESP-IDF app image")
    version = data[48:80].split(b"\0")[0].decode()
    project = data[80:112].split(b"\0")[0].decode()
    return project, version


def status(host: str) -> dict:
    with urllib.request.urlopen(f"http://{host}/", timeout=10) as r:
        return json.load(r)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=["status", "radio", "bridge"])
    ap.add_argument("file", nargs="?", type=Path)
    # Each bridge is zigbee-sniffer-<last 4 hex of its MAC>.local (0.3.6+); an IP is steadier.
    host = os.environ.get("SNIFFER_HOST")
    ap.add_argument("--host", default=host, required=host is None, help="bridge IP or mDNS name")
    args = ap.parse_args()

    if args.target == "status":
        print(json.dumps(status(args.host), indent=2))
        return

    before = status(args.host)
    path = args.file or default_build(args.target, before["bridge"])
    data = path.read_bytes()
    project, version = image_info(data)
    if project != PROJECTS[args.target]:
        sys.exit(f"{path} is {project}, not {PROJECTS[args.target]}")
    if args.target == "bridge" and board_of(version) != board_of(before["bridge"]):
        sys.exit(f"{path} is for the {board_of(version)} board; this bridge is a {board_of(before['bridge'])}")
    print(f"{args.target}: {before[args.target]} -> {version} ({len(data)} bytes from {path})")

    req = urllib.request.Request(
        f"http://{args.host}/update/{args.target}",
        data=data,
        method="POST",
        headers={"X-Update-Token": token(), "Content-Type": "application/octet-stream"},
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        sys.exit(f"Failed ({e.code}): {e.read().decode().strip()}")
    print(f"({time.time() - started:.0f} s)")

    if args.target == "bridge":
        # The bridge restarts on trial; wait for it to come back and keep the new image.
        print("Waiting for the bridge to restart and confirm (about 40 s)...")
        deadline = time.time() + 240
        while time.time() < deadline:
            time.sleep(5)
            try:
                st = status(args.host)
            except OSError:
                continue
            if st["bridge"] == version and st["bridge_firmware"] in ("confirmed", "running"):
                print(f"bridge {version} confirmed on {st['bridge_partition']}")
                return
            if st["bridge_firmware"] == "rolled_back":
                sys.exit(f"bridge {version} failed its trial; back on {st['bridge']}")
        sys.exit("bridge did not confirm within 4 minutes; check its log")


if __name__ == "__main__":
    main()
