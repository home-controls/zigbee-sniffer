# Local development: fake sniffer bridges

Two simulators let you run the Zigbee Sniffer app on a PC without any hardware.
Each one sets up a folder (`--root`) with everything the app reads:

| Path | What it is |
| --- | --- |
| `<root>/data/options.json` | the add-on options the app reads (`SNIFFER_DATA` points here) |
| `<root>/z2m/configuration.yaml`, `database.db` | a Zigbee2MQTT setup: PAN 0x852C, channel 25, device names (`Z2M_DIR` points here) |
| `<root>/captures/` | capture files written by `--backfill` (`SNIFFER_CAPTURES` points here) |
| `<root>/positions.json` | `devsim2.py` only: where each device and sniffer sits, for placing them on the map |

The simulated house uses fixed test values:

- The network key in `configuration.yaml` is Zigbee2MQTT's public example key.
- `update_token` is `devtoken`.
- NWK commands and ZDO are sent without NWK security, so tshark can dissect them even without the key.

## `devsim.py`: one bridge

This is a fake bridge 0.3 on `127.0.0.1:<--port>` (default 6638). Its status page and firmware update endpoints run on `127.0.0.1:8080`.

How the bridge behaves:

- **Connections.** It sends a HELLO first. An app that answers with CLIENT_HELLO gets its backlog and then live frames as FRAME_AT. An app that doesn't answer gets plain FRAMEs.
- **Status.** It sends radio and bridge status every 5 s.
- **Firmware updates.** `POST /update/radio|bridge` with `X-Update-Token: devtoken` takes about 4 s. The board then reports the new version on trial.
- **Wi-Fi drops.** With `--drop-every N`, the bridge drops its Wi-Fi every N seconds for `--down` seconds (default 20). It buffers frames meanwhile.

The simulated house:

- **Devices.** 31 devices, routers and end devices, each with its own RSSI at the sniffer and a parent route.
- **Regular traffic.** Link Status every 15 s, polls from end devices, and reports routed hop by hop with MAC retries and ACKs (a few ACKs are "missed"). There is also a many-to-one route request every 2 minutes and coordinator commands.
- **Route errors.** When a hop gives up, the router sends a Network Status (link failure).
- **Neighbours.** A neighbour's Zigbee network (PAN 0x551B), Thread-like frames (PAN 0x7962) and occasional beacon requests.
- **Problems to find:**
  - "Accent 2" leaves and rejoins every 15-30 min.
  - "Closet Door" goes silent 40 minutes before the simulator starts.
  - Zigbee2MQTT knows two devices that are never heard: "Garage Sensor" and "Spare Switch".

Options: `--root DIR` (required), `--backfill HOURS` (captures written before serving, default 0), `--port`, `--drop-every SECONDS`, `--down SECONDS`.

## `devsim2.py`: two bridges in one house (several sniffers, the map)

This simulates the same devices spread over two floors of a 20 x 12 m house.

- **Signal.** Each bridge hears a frame at `rssi = A_device - 27 log10(distance) - 13 dB per floor + gain + noise` (n = 2.7; gain is 0 for Main and `--up-gain` for Upstairs). It doesn't hear the frame at all below -100 dBm.
- **"Main" bridge.** Ground floor, `127.0.0.1:6638`, status page on 8080. Always connected. Its bridge clock starts 10 s after boot.
- **"Upstairs" bridge.** Upper floor, `127.0.0.1:6639`, status page on 8081. Its bridge clock starts 77 s after boot. With `--drop-every N` it drops its Wi-Fi every N seconds for `--down` seconds, then delivers its backlog. That exercises merging of copies, clock-skew correction and backlog matching.
- **Options.** `options.json` gets `more_sniffers: [{"name": "Upstairs", "port": 6639, "http_port": 8081}]`.
- **Backfill.** Frames written with `--backfill` are the ones "Main" would have heard.
- **Map.** `positions.json` holds `size_m` and `floor_height_m`. It also gives each device (by IEEE) and each sniffer (by id) a position: `level` plus `x`/`y` as fractions of the floor. Create two floors of 20 x 12 m on the app's Map page, then place everything at those positions. The coverage model should then come out near n = 2.7 and a floor loss near 13 dB.

Options: `--root DIR` (required), `--backfill HOURS`, `--drop-every SECONDS` (upstairs only), `--down SECONDS`, `--up-gain DB` (the upstairs antenna hears this much louder, like a better antenna; the map should fit it back as that sniffer's gain), `--jitter-ms MS` (each bridge's frames reach the app up to this late, independently, so either sniffer's copy can come in first, as over real Wi-Fi), `--hear-dbm DBM` (a bridge hears nothing weaker than this; at -100 both hear the whole house, around -80 each hears ~80 % and some frames, MAC retries included, only one does).

To exercise merging the way the real house does (some frames heard by one sniffer only, copies in either order), run `--jitter-ms 30 --hear-dbm -80 --drop-every 90`. Then every frame should be written once: in the captures' `.sniffers` files no transmission is written twice (look for the same ACK, or the same frame less than 1 ms apart, on two lines, one per sniffer).

MAC retries come 2-5 ms after their original, as on air (macAckWaitDuration, backoff, CCA, turnaround); until 0.5.8 the simulator spaced them 14-24 ms apart, which hid merging mistakes between a frame and its retry.

## Running the app against a simulator

Run these from the `zigbee_sniffer` folder.

**1. Start the simulator.** It writes `options.json` and the Zigbee2MQTT files before it starts serving:

```powershell
$env:UV_LINK_MODE = "copy"
uv run --python 3.12 python dev/devsim.py --root $env:TEMP\zbs-sim --backfill 0.5 --drop-every 300
# or, for two sniffers:
uv run --python 3.12 python dev/devsim2.py --root $env:TEMP\zbs-sim2 --backfill 0.3 --drop-every 120
```

**2. Start the app in a second terminal**, pointed at the same root:

```powershell
$root = "$env:TEMP\zbs-sim"                       # or zbs-sim2
$env:UV_LINK_MODE = "copy"
$env:SNIFFER_DATA = "$root\data"                  # options.json, history.db, map.json, tshark key table
$env:SNIFFER_CAPTURES = "$root\captures"          # hourly .pcap files
$env:Z2M_DIR = "$root\z2m"                        # names, PAN ID and network key
$env:SNIFFER_WEB_PORT = "8098"                    # the web page: http://127.0.0.1:8098/
$env:SNIFFER_LIVE_PORT = "17761"                  # live Wireshark stream (TCP@127.0.0.1:17761)
$env:SNIFFER_BIND = "127.0.0.1"                   # don't listen on the LAN
$env:SNIFFER_BRIDGE_HTTP_PORT = "8080"            # the main fake bridge's status page (the second one's comes from options.json)
$env:TSHARK = "C:\Program Files\Wireshark\tshark.exe"  # leave unset if tshark is on PATH
uv run --python 3.12 --with-requirements requirements.txt python app/main.py
```

The same commands in bash:

```bash
root=/tmp/zbs-sim
python dev/devsim.py --root "$root" --backfill 0.5 --drop-every 300 &
SNIFFER_DATA="$root/data" SNIFFER_CAPTURES="$root/captures" Z2M_DIR="$root/z2m" \
SNIFFER_WEB_PORT=8098 SNIFFER_LIVE_PORT=17761 SNIFFER_BIND=127.0.0.1 SNIFFER_BRIDGE_HTTP_PORT=8080 \
TSHARK=tshark python app/main.py
```

Notes:

- Requests from 127.0.0.1 are allowed by default (`SNIFFER_ALLOW`, default `172.30.32.2,127.0.0.1,::1`), so a local browser can open the page without Home Assistant's ingress.
- Outside Home Assistant there is no Supervisor token, so publishing to Home Assistant and MQTT stays off ("not running as a Home Assistant add-on").
- On Windows, `TZ` and `time.tzset` aren't available. Capture files are named by the PC's local time, and the log says "Time zone UTC".
- To start over, stop both programs and delete the root folder.
- The fake bridges always use ports 6638/6639 (frames) and 8080/8081 (status). Stop anything else on those ports first.

## Tests

The unit tests in `../tests` don't need tshark, MQTT or a network:

```powershell
$env:UV_LINK_MODE = "copy"
uv run --python 3.12 --with pytest --with aiohttp --with pyyaml python -m pytest -q tests
```
