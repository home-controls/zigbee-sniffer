# Zigbee sniffer (XIAO ESP32C6 + ESP32-S3 bridge → Home Assistant)

A passive Zigbee listener to put where the network is weak. It never transmits.

```
XIAO ESP32C6 (radio)  --UART-->  ESP32-S3 bridge (Wi-Fi)  <--TCP 6638--  HA app "Zigbee Sniffer"
listens on your channel          buffers + serves frames                  hourly .pcap + sidebar page
```

Bridge boards (one build profile each, `s3-bridge/sdkconfig.board.<board>`):

| Board | Profile | Flash / PSRAM | Frame buffer | Wi-Fi at the desk |
| --- | --- | --- | --- | --- |
| ESP32-S3-DevKitC-1-N16R8 (recommended) | `devkitc` | 16 MB / 8 MB octal | 6 MB, ~50 min | -30 to -55 dBm |
| ESP32-S3 Super Mini (ESP32-S3FH4R2; weak antenna) | `supermini` | 4 MB / 2 MB quad | ~1.75 MB, ~15 min | -82 to -92 dBm |

| Folder | What |
| --- | --- |
| `protocol/` | Shared framing (`sniffer_proto.h`), mirrored in the app's `proto.py` |
| `c6-radio/` | Promiscuous 802.15.4 receive → frames with RSSI/LQI/timestamp over UART (to the bridge) or USB (straight into HA, radio 0.3+) |
| `s3-bridge/` | UART → TCP server for HA (HA connects to it, like it does to ESPHome devices) |
| HA app | `zigbee_sniffer/` at this repository's root; the repository is its add-on store |

## Wiring (3 wires + power)

TX goes to RX both ways. Both bridge boards use their pins labelled TX / RX.

| XIAO ESP32C6 | | ESP32-S3 bridge (Super Mini or DevKitC-1) |
| --- | --- | --- |
| D6 / TX (GPIO16) | → | RX (GPIO44) |
| D7 / RX (GPIO17) | ← | TX (GPIO43) |
| GND | — | GND |
| 5V | — | 5V (powers the C6 from the S3's USB) |

Power the pair from the S3's USB only, and don't plug both boards into USB while their 5V pins
are joined. The C6's LED flashes on traffic, with a slow heartbeat when quiet. Both S3 boards'
LEDs are RGB, which the bridge doesn't drive. Its log and status page show its state.

**DevKitC-1:** use the port labelled **USB** (native USB: power, logs, and resets for flashing).
Its TX/RX header pins are also wired to the board's USB-to-UART chip behind the port labelled
**UART**, so leave that port unplugged while the C6 is wired. GPIO17 / GPIO18 are the clean
alternative: move the wires and set `CONFIG_BRIDGE_UART_TX_GPIO=17` / `CONFIG_BRIDGE_UART_RX_GPIO=18`.
Its factory firmware doesn't reset into flashing mode by itself: for the first flash, hold BOOT,
tap RST, release BOOT. After the flash, if it doesn't start, tap RST.

## Build and flash

ESP-IDF v5.5.6: load its environment first (`export.ps1` on Windows, `. ./export.sh` elsewhere, from
your ESP-IDF install).

**S3 bridge**: copy `s3-bridge/sdkconfig.secrets.example` to `s3-bridge/sdkconfig.secrets`
(git-ignored), fill in the Wi-Fi name and password and an update token (any long random
string), then:

```powershell
cd firmware/s3-bridge
# DevKitC-1 (its own build folder and sdkconfig):
idf.py -B build-devkitc -D SNIFFER_BOARD=devkitc -D SDKCONFIG=sdkconfig.devkitc -p COMx flash monitor
# Super Mini (the default profile):
idf.py set-target esp32s3   # first time; recreates sdkconfig so the secrets are picked up
idf.py -p COMx flash monitor
```

A board's firmware carries its profile in the version (`0.3.5+devkitc`; no suffix = Super Mini),
and the bridge refuses an update built for the other board.

It logs its IP and name (`Wi-Fi up: 192.168.1.x (zigbee-sniffer-c2e4.local)`). Since 0.3.6 each
bridge's DHCP and mDNS name ends in the last 4 hex digits of its Wi-Fi MAC, so several bridges can
share a network. Put the IP in the HA app's `sniffer_host` option, or for another sniffer, add it
to `more_sniffers` with a name (a DHCP reservation keeps the IP fixed).

A new pair needs one USB flash each. Flash the bridge first; its log then says `No status from
the radio board` until the C6 has its firmware. To flash the C6, unplug the S3 and plug in the
C6's own USB (the 5V wire then powers the S3 from it); afterwards put the S3 back on USB.

**C6 radio**:

```powershell
cd firmware/c6-radio
idf.py -p COMx flash monitor
```

Flash over USB one board at a time if their 5V pins are joined. After this first USB flash (0.2.x
or later on both), updates go over Wi-Fi.

## A radio on USB, no bridge (radio 0.3+)

The same radio firmware can send its frames out of the chip's own USB port instead of the UART,
so the board plugs straight into the Home Assistant box (`CONFIG_SNIFF_LINK_USB`). The HA app
plays the bridge's part (channel, pings, updates over the cable): add the board under its
`usb_sniffers` option. The console log moves to UART0 (pads D6/D7), so the USB carries only
framed messages. Radio 0.3 also reports the chip it was built for (in `SNIFF_T_RADIO_BOOT`, after
the 4 bytes older bridges read), so an image for the wrong chip is refused.

Tested on a **Seeed XIAO ESP32C5**. It has no antenna switch: keep an antenna on its U.FL socket.
Its LED is GPIO27.

```powershell
cd firmware/c6-radio
idf.py -B build-c5usb -D SDKCONFIG=sdkconfig.c5usb -D SDKCONFIG_DEFAULTS=sdkconfig.defaults.c5usb set-target esp32c5   # first time
idf.py -B build-c5usb -D SDKCONFIG=sdkconfig.c5usb -D SDKCONFIG_DEFAULTS=sdkconfig.defaults.c5usb -p COMx flash
```

After that first flash, updates go through the HA app's Sniffer page for that sniffer (pick
`build-c5usb/zigbee_sniffer_radio.bin`). A C6 can run the USB build too: use the defaults above
with `CONFIG_IDF_TARGET="esp32c6"` and `CONFIG_SNIFF_XIAO_RF_SWITCH=y`.

## Updates over Wi-Fi

Build as usual (`idf.py build` in either folder), then from `firmware/`:

```powershell
python tools/update.py status --host 192.168.1.61
python tools/update.py radio  --host 192.168.1.61   # the C6, relayed by the bridge over the UART
python tools/update.py bridge --host 192.168.1.61   # the S3 itself
```

(`python` is the ESP-IDF one after `export.ps1` / `export.sh`. The script
takes the token from `s3-bridge/sdkconfig.secrets`, and an image path as an optional argument.)

How it works:

- The bridge serves HTTP on port 80: `GET /` (status JSON), `POST /update/bridge`,
  `POST /update/radio`. Both updates need the `X-Update-Token` header to match
  `CONFIG_BRIDGE_UPDATE_TOKEN`; with no token set, updates are off.
- Each endpoint checks the image's chip and project name first, so a file for the other board,
  or another project built for the same C6, is refused before anything is written.
- **Bridge**: written to its spare app slot (`ota_0`/`ota_1`), then it restarts on trial. It
  keeps the image once Wi-Fi has been up 30 s, and rolls back by itself after 3 minutes
  otherwise. About a minute end to end.
- **Radio**: the upload is staged in the bridge's `radio_img` partition first, so a slow or
  stalling Wi-Fi link only makes it take longer while the radio keeps listening. Then the
  bridge sends it over the UART in 480-byte acked chunks (`SNIFF_T_UPDATE_*` in
  `protocol/sniffer_proto.h`). The radio stops listening for those few seconds, writes its
  spare slot, checks the image's SHA-256 and reboots into it on trial. It keeps the image once
  the bridge's ping says both directions of the UART work, and rolls back after 60 s otherwise.
  About 30 s end to end.
- `radio_firmware` / `bridge_firmware` in the status: `running` (flashed over USB), `trial`,
  `confirmed`, or `rolled_back` (a newer image failed its trial; shown until the next good
  update).

Tested 2026-11-06: radio and bridge updates over Wi-Fi, and a radio image built with the wrong
UART baud rolling back on its own. The bridge's own rollback path (Wi-Fi never comes up) has not
been tried.

The bridge scans every channel and joins the strongest access point of its network (the default
joins the first one it hears). The status shows `wifi_rssi`, `wifi_channel` and `wifi_ap`.

## Frame buffer (bridge 0.3+)

A weak Wi-Fi link costs time, not frames. Every frame goes into a buffer on the bridge, stamped
with the bridge's clock. The buffer takes most of the PSRAM (up to 6 MB): 6 MB on the DevKitC-1,
about 50 minutes of channel 25, and ~1.75 MB on the Super Mini, about 15 minutes. A frame stays
there until the app has it, whether HA is disconnected or the link is just slow. On a board
without working PSRAM the buffer is 48 KB of internal RAM (about 20-30 seconds).

- On each connection the bridge sends a HELLO with its clock (`bridge_us`) before anything else.
  An app that answers with CLIENT_HELLO (flag `SNIFF_CLIENT_FRAME_AT`) gets the backlog, oldest
  first, then live frames, all as FRAME_AT. It times each one as HELLO wall time +
  (frame `bridge_us` - HELLO `bridge_us`). An older app that sends no CLIENT_HELLO gets plain
  live frames as before, and the buffered ones are skipped. See "Buffered frames" in
  `protocol/sniffer_proto.h`.
- A message whose send fails stays in hand for the next connection: at worst one frame arrives
  twice.
- Frame times are the radio's microsecond timestamps moved onto the bridge's clock. The bridge
  tracks the offset from the frames that cross the UART fastest, follows crystal drift, and
  starts over when the radio restarts.
- Status: `client` (`buffered`, `live_only`, `connecting`, `none`), `buffer_bytes`,
  `backlog_bytes`, `buffer_full_drops` (lost: buffer full) and `live_only_skips` (buffered
  frames an older app couldn't take). `Bridge dropped` in the app is the sum of the two.
- The buffer is in RAM: a bridge restart (or update) loses whatever it held.

## Notes

- The radio checks each frame's checksum in hardware and only passes good frames, with RSSI and
  LQI in place of the checksum. Frames are stored without FCS (pcap link type 283, 802.15.4 TAP).
- The C6 sets its own addresses to values no Zigbee frame uses and runs promiscuous, so it never
  acknowledges anything on another device's behalf.
- Frames that arrive while HA isn't connected wait in the bridge's buffer (above). They are lost
  only when it fills, or when the app doesn't take buffered frames (`Bridge dropped`).
