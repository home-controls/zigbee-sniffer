# Zigbee Sniffer — how it works

The user guide is [DOCS.md](DOCS.md) (it is what Home Assistant shows on the add-on's
Documentation tab). This file is the reference for the code: what each part does, the data it
keeps, the API the page uses, and how to run and ship it.

## What it is

A Home Assistant add-on that listens to the Zigbee network through one or more ESP32 sniffers
(an ESP32-C6 radio in promiscuous mode behind an ESP32-S3 Wi-Fi bridge; firmware in this
repository's `firmware/`). It

- writes every frame it hears to hourly pcap files (`/share/zigbee_captures`),
- keeps a per-minute history per device and for the network in SQLite (`/data/history.db`),
- decrypts frames with tshark and Zigbee2MQTT's network key for events, mesh link costs and
  full decodes,
- judges each device (findings with a severity) and the network,
- shows it all in an ingress page (Overview, Devices, a page per device, Mesh, Map, Live,
  Captures, Sniffer),
- publishes sensors and `zigbee_sniffer_event` events to Home Assistant,
- updates the sniffer's own firmware and changes its channel.

## Architecture

```
 ESP32-C6 radio --UART--> ESP32-S3 bridge --TCP 6638--> Sniffer (sniffers.py)  one per bridge
                                          \--HTTP 80---> Bridge (bridge.py): status, OTA upload
                                                              |
                                                 frames with the time heard
                                                              v
                                                     Merger (merge.py)  copies of one transmission
                                                              |          from several sniffers -> one
                                                              v
                                                   emit() (main.py)
                              +-------------------+-----------+------------+------------------+
                              v                   v                        v                  v
                     RotatingPcap (pcap.py)  Analyzer (analysis.py)   live ring (3000)   Wireshark stream
                     hourly .pcap files      per-minute counters      for the Live page  (port 17760)
                              |                   |
                              |             flush() every 30 s
                              |                   v
                              +--------->  Store (store.py)  SQLite /data/history.db
                    tshark pass every 60 s  (events, NWK commands, link costs from decrypted frames)
                                                  |
                                     Report (report.py): devices, findings, mesh, overview
                                                  |
                        aiohttp API (main.py) ----+---- HomeAssistant (hass.py): MQTT discovery, events
                                  |
                        static/ (the page, built from web/)
```

Everything runs in one asyncio process (`main.py`). Blocking work (SQLite, pcap scans, tshark)
goes to threads or subprocesses: `asyncio.to_thread` for the store, `asyncio.create_subprocess_exec`
for tshark, with separate concurrency limits for the background pass and for page requests.

### Modules

| File | Role |
| --- | --- |
| `main.py` | Options, wiring, the frame path (`emit`), background tasks (ticker, flusher, decoder, housekeeping, HA publisher, catch-up), the HTTP API and the Wireshark stream |
| `proto.py` | The bridge's wire protocol: framing, message types, structs, CRC |
| `sniffers.py` | One bridge link: connect/reconnect, CLIENT_HELLO, clock pairing, status, per-minute health, sniffer events |
| `usb.py` | A radio on USB (`usb_sniffers`): raw serial port, `UsbSniffer` (the app plays the bridge: SET_CHANNEL, PING, radio clock timing) and `UsbRadio` (the bridge's status + firmware updates over the cable) |
| `bridge.py` | The bridge's HTTP side: status JSON, firmware image parsing and checks, OTA upload |
| `merge.py` | Merging copies of one transmission heard by several sniffers |
| `mac.py` | 802.15.4 MAC / Zigbee NWK header parsing (addresses, PAN, sequence, frame kind) |
| `analysis.py` | Live per-minute counters per device and network, retries, ACK matching, hops, IEEE learning |
| `store.py` | SQLite schema, writes, queries, pruning |
| `pcap.py` | Hourly pcap files (TAP link type 283): writing, scanning, reading records, copying ranges |
| `tshark.py` / `decode.py` | Running tshark (key table, field extraction, summaries, full decodes); turning fields into events, NWK command counts and link costs |
| `names.py` | Device names, types and models from Zigbee2MQTT; our PAN ID; the network key for tshark |
| `report.py` | Devices table, per-device findings and severity, mesh graph, routes, overview |
| `hass.py` | MQTT discovery entities, per-device health sensors, `zigbee_sniffer_event`, Zigbee2MQTT reads for Ping |
| `mapping.py` | Floors, plan images, positions, distances, the path-loss model fit |
| `static/` | The page as built from `web/` (Preact on the Zigbee UI kit): `index.html`, one JS and one CSS file, the logo |

## The sniffer protocol

Mirror of `firmware/protocol/sniffer_proto.h`. Every message:

```
0xA5 0x5A | type u8 | length u16 LE | payload (<= 512) | CRC-16/CCITT-FALSE u16 LE over type..payload
```

| Type | Dir | Payload |
| --- | --- | --- |
| `0x01` FRAME | bridge -> app | `<QBbBB` radio timestamp µs, channel, RSSI dBm, LQI, flags; then the PSDU (802.15.4 frame without FCS) |
| `0x02` RADIO_STATUS | bridge -> app | `<IIIB3B` uptime s, frames, dropped, channel, version x.y.z |
| `0x03` HELLO | bridge -> app | JSON: `bridge` (version), `bridge_us` (its clock now), `backlog_bytes` (buffered frames waiting) |
| `0x04` BRIDGE_STATUS | bridge -> app | `<IIIIbB` uptime s, UART frames, UART CRC errors, TCP drops, Wi-Fi RSSI, radio link ok |
| `0x06` FRAME_AT | bridge -> app | `<Q` bridge µs when the radio heard it, then a FRAME payload (used for buffered frames) |
| `0x10` SET_CHANNEL | app -> bridge | channel u8 |
| `0x12` CLIENT_HELLO | app -> bridge | `<I` flags; `0x01` = send FRAME_AT and the buffered backlog |

**A radio on USB** (radio 0.3+ built with `CONFIG_SNIFF_LINK_USB`) speaks the radio's side of the
same framing on its USB Serial/JTAG port, and the app speaks the bridge's: SET_CHANNEL on open,
`0x11` PING every second (`0x01` = a radio status arrived in the last 3 s, which is what lets a
radio on trial keep a new image), and the update messages `0x20`-`0x24` (BEGIN u32 size, DATA u32
offset + up to 480 bytes, END, ABORT; each answered by UPDATE_ACK `<BIi` stage, bytes held,
esp_err_t), stop-and-wait. The radio sends plain FRAME, RADIO_STATUS and `0x05` RADIO_BOOT (`<3BB`
version, fw state 0 running / 1 trial / 2 confirmed / 3 rolled back, then `<H` the image chip id:
13 = ESP32-C6, 23 = ESP32-C5). Its frames are timed on the radio's clock, followed like a
bridge's; the first second of frames after the port opens is held and the clock paired from the
freshest of them (the radio's USB buffer can hold a minute of frames from while the port was
closed: 0.6.0-0.6.1 paired from the oldest, 53 s off, and nothing merged), the older ones then go
out at their own time as late frames; a radio clock that starts over (a
restart without the cable dropping) re-pairs and tells the merger, as a bridge restart does. Before opening, `device_problem` reads the device's USB vendor from sysfs and refuses anything but
Espressif's 303a (the device list also offers the Zigbee/Thread dongles, 10c4); the port is then
held with TIOCEXCL and opened raw without HUPCL; the console log goes to the radio's UART0, so nothing but framed
messages comes out (boot ROM text is skipped by the decoder).

On connect the bridge sends HELLO; the app answers CLIENT_HELLO then SET_CHANNEL. A bridge 0.3+
then sends its backlog (frames buffered while no client was connected, in PSRAM) as FRAME_AT,
followed by live frames. The decoder resynchronises on the sync bytes after a bad CRC.

The bridge's HTTP server (port 80) serves `GET /` (status JSON: versions, firmware trial state,
Wi-Fi, buffer, counters) and `POST /update/radio` / `POST /update/bridge` with the image as the
body and `X-Update-Token` (the bridge's `CONFIG_BRIDGE_UPDATE_TOKEN`, the add-on's
`update_token`).

### Frame times

- **FRAME** (live, bridges before 0.3): the radio's microsecond clock gives the spacing; it is
  anchored to the arrival time and re-anchored whenever the two drift more than 1 s apart.
- **FRAME_AT** (bridge 0.3+ sends every frame this way, live and buffered): wall time = bridge
  time + offset. HELLO gives the first offset; after that the offset follows the smallest
  "arrival − bridge time" seen (delivery can only add delay), allowed to creep up by 50 µs per
  second for a bridge clock that runs slow. A single pairing per connection drifted 10-20 ppm:
  past the 5 s "late" limit within days, and past the merge window between two sniffers within
  hours. `clock_offset_ms` in the sniffer summary is how far the bridge's clock drifted since it
  connected. Every move of the offset (the creep, or a step down) is reported to the merger
  (`on_offset`), which moves its correction for that sniffer by as much, and so is the jump when
  a new connection pairs the clocks afresh (from where the last connection's offset ended: a
  bridge's drift over a long connection adds up to seconds a day, and a correction left that far
  off would split every copy after a reconnect).
- Frames that arrive together (one TCP read) are timed after one step of the offset to the
  burst's smallest "arrival − bridge time" (`prime`); stepping frame by frame pressed every later
  frame of a burst onto its arrival time, tens of ms off. The first read, which holds the HELLO,
  is left to the HELLO's pairing.
- A frame that arrives more than 5 s after it was heard counts as **late** (buffered): Live
  marks it, the sniffer's health counts it, and it goes into its own hour's capture file.

## Several sniffers: merging

`merge.py`. With one sniffer frames go straight through. With several, each copy is hashed
(blake2b of the bytes) and

1. matched to a transmission still waiting with the same bytes, within the match window,
   **that this sniffer hasn't already heard** (a MAC retry has identical bytes but is a second
   copy at the same sniffer, so it stays a transmission of its own); the nearest one wins, so
   when one sniffer heard only a retry its copy goes to the retry;
2. else matched the same way against transmissions already emitted in the last `MEMORY_S` =
   1500 s; the extra copy only adds that sniffer's signal (`late_copy`: `dev_sniffer_min`, the
   capture's `.sniffers` line, the coverage counters);
3. else, for a frame that asks for an ACK, it is checked against a mix-up (`_repair`): if a
   waiting transmission at this copy's time already holds a copy from this sniffer that sits at
   least `RETRY_GAP_S` = 1.5 ms away from it, that earlier copy was an original matched to the
   MAC retry another sniffer heard alone (whose copy came in first). The new copy takes its
   place, and the original becomes a transmission of its own at its own time
   (`status()["repaired"]` counts these);
4. else it starts a new transmission.

The emitted transmission carries all copies (and `at`: each sniffer's copy time); the strongest copy's RSSI/LQI stands for it in the
capture file and in `dev_min`, and every copy's RSSI goes into `dev_sniffer_min` and the
capture's `.sniffers` file. Its bytes are dropped after it is emitted (matching needs only the
hash and the time).

**When a transmission goes out (the watermark).** Each bridge sends its frames in the order it
heard them, its buffer first. The ticker (every 0.1 s) releases, in time order, every waiting
transmission up to a cutoff: `now - HOLD_S` (0.4 s, how late a live sniffer's copies can be),
lowered to `mark - 50 ms` (the newest frame time it delivered) for any sniffer that

- is delivering its buffer (its latest frame arrived more than `CATCHUP_S` = 1 s after it was heard),
- is connected but has sent nothing at all, frames or status, for `STALL_S` = 1.5 s (a stall),
- or dropped its connection less than `WAIT_S` = 30 s ago,

for at most `WAIT_S`, and nothing waits more than `MAX_HOLD_S` = 60 s after it arrived. Only
sniffers whose connection the app reports (`link()`, from `Sniffer.on_link`) are waited for.
`status()["waiting_for"]` names the sniffer holding the others back (the header bar shows it).
This puts the frames of a Wi-Fi drop, a stall or a bridge update in time order, next to their
ACKs, merged with the others' copies, instead of seconds out of order.

**After a restart** (`seed`): before the sniffers connect, the app reads the last `MEMORY_S` of
the current and previous hour's captures into the merger's memory (keys and times only, ACKs
keyed to the frame before them the same way). A backlog of frames from before the restart then
matches them instead of being written again. Which sniffers heard them isn't known, so any
sniffer's copy matches.

**Timing:**

- **Skew**: every match tells how far apart two sniffers' clocks still are; each sniffer's times
  are corrected toward the first sniffer's (an exponential average, `skew_ms` per sniffer), learned
  only from copies within the window in use (a wrong match under the wide window, two identical
  frames tens of ms apart, would knock it off by a few ms; a real jump widens the window first,
  through the wide-window matches' differences, and is then learned). Each
  sniffer's own clock pairing (sniffers.py) moves too, a few ms at a time, independently of the
  other's; `offset_moved()` moves the correction by the same amount (the reference sniffer's move
  carries all the others), so the copies stay lined up between the averages' updates.
- **Match window**: `WINDOW_S` = 0.25 s until the timing is known; once at least 30 matched copies
  in the last 10 s have been measured, 3 × their 99th percentile + 0.5 ms (`WINDOW_SLACK_S`), at
  least 1 ms (`WINDOW_MIN_S`) (`window()`, recomputed every second). Only frames that ask for an
  ACK use it: they are the ones a MAC retry can follow, at the earliest ~1.7 ms later (the
  frame's airtime, macAckWaitDuration 864 µs, CCA, turnaround), which a narrow window keeps apart
  from the first try another sniffer heard. With copies lined up within 0.3 ms the window is
  ~1.4 ms; until 0.5.8 it was at least 3 ms (3 × p99 + 1 ms), wide enough to merge an original
  with a quick retry (about 600 a day with two real sniffers). Frames that ask for no ACK are never resent, so they keep the wide window.
  A connection opening, or a clock-pairing move over 1 ms (`STEP_S`: frames already waiting are
  on the old timeline for a moment), clears the measurements, so the window starts wide again. `match_stats()` gives each sniffer's median and 95th-percentile difference.
- **ACKs**: a 3-byte ACK holds only a sequence number, so unrelated ACKs share bytes, and the
  other sniffer's copy of an ACK can arrive before the frame it answers. An ACK is paired with the
  frame that asked for it in the same sniffer's stream (same sequence, within 50 ms), timed from
  that frame's transmission, and keyed to it, so it merges with ACKs paired to the same
  transmission. An ACK no frame of that sniffer asked for (it heard the ACK but not the frame)
  is matched by its bytes to any ACK transmission, paired or not, within 10 ms or the narrow
  window, whichever is narrower (`_acks`, all ACKs by their bytes, pending and remembered); a
  paired copy that finds no transmission under its key looks there too. Until 0.5.8 those copies
  only matched other unpaired ACKs, so an ACK one sniffer paired and the other couldn't was
  written twice: a fifth of all ACKs with the two real sniffers.

**What each sniffer adds** (`count_coverage` in main.py): for each of our network's non-ACK
transmissions, every connected sniffer's `sniffer_health` row counts `total`, and `heard` /
`solo` if it heard it / only it did; a late copy moves the transmission from the first sniffer's
`solo` to shared. The Sniffer page's `coverage` adds the devices only it hears and its median
RSSI difference from each other sniffer over the devices both hear (`dev_sniffer_min`, ≥ 3
frames each).

## Map and coverage model

`mapping.py` keeps `/data/map.json` (floors, positions, floor height) and plan images in
`/data/maps/`. A floor has a name, a level, an optional image with its pixel size, and a scale
(pixels per metre) or, for a blank grid, a size in metres. Positions are fractions (0-1) of
the floor's width and depth, keyed by `ieee` (or `addr:<short>` before the IEEE is known) for
devices and `sniffer:<id>` for sniffers. Distances are 3D: floors apart × floor height.

The coverage endpoint pairs every placed sniffer with every placed device it heard (≥ 3 frames
in the range) and fits

```
rssi = A_device - n10 · log10(d) - L · floors_between + G_sniffer
```

by weighted least squares (weight √frames, capped at 10): first one A, n10 and L for the house
and a gain G per sniffer against the first one (`ref`, G = 0; fitted for a sniffer with at least 3
measurements; sniffers' antennas differ by many dB, which says nothing about the house or the
devices), with fallbacks: a negative L is refitted without the floor term (L only when some pair
crosses floors, else 15 dB); n10 is kept to 15-50, else 30 is assumed and the rest fitted; the
gains are dropped if they can't be told apart. Then each device's own A from its residuals —
only for devices two or more placed sniffers hear, since with one measurement a device's
strength can't be told from the walls between it and the sniffer — alternating with the house
fit (12 rounds) so loud and quiet devices don't bias n and the gains come from devices both
sniffers hear. Strengths and the map are at the reference sniffer's gain; `gains` lists each
sniffer's (the page says "Sniffer 2 hears 17 dB louder than Main"). The reported error is leave-one-out
(each measurement predicted without itself). It needs at least 4 measurements. Routers without
their own strength take the average of measured devices of the same model, else the house's A.

The page computes the layers itself on a grid: **Coverage** = the best predicted router (or
coordinator) signal at each cell, **Backup** = the second best, **Heard by <sniffer>** =
inverse-distance-weighted measured RSSI of the devices that sniffer hears.

## Background tasks

| Task | Every | Does |
| --- | --- | --- |
| `Sniffer.run` (one per bridge) | connection | read TCP, decode messages, time frames, hand them to the merger; reconnect with backoff 2-60 s |
| `ticker` | 0.1 s | release merged transmissions; every 5 s (by the clock) the sniffers' health tick (offline after 120 s) |
| `flusher` | 30 s | flush pcap buffers, move the analyzer's counters, sniffer health, Zigbee2MQTT's events and new incidents into SQLite; batches that fail to write are retried (up to 20 min); HA events are queued |
| `decoder` | 60 s | the tshark pass over each capture file's not-yet-decoded stretch (≤ 48 MB per run, 4 runs per file per pass): events, NWK command counts, link costs, OTA blocks; a failed run is retried, not marked done |
| `housekeeping` | 600 s | reload Zigbee2MQTT names, base topic and the network key, enforce retention |
| `ha_publisher` | 60 s | MQTT discovery and states |
| `HA.run_events` | queue | send `zigbee_sniffer_event`s to Core (so a slow Core never holds up the history) |
| `catch_up` | startup | count frames in the captures beyond what the history has (the current and previous hour before the sniffers connect, with each frame's sniffers from the `.sniffers` file); realign bookkeeping that is ahead of a file cut short by a hard reset; then seed the merger from the end of the captures and let the sniffers connect |

Every task runs under `supervise()`: an exception is logged and the task restarted (backoff
2-60 s), so one bug can't end the app or leave it running without that part. At startup capture
files are renamed to their local hour if needed, and their bookkeeping goes with them.

## What the analyzer counts

`analysis.py` turns each transmission into per-minute counters (moved to SQLite every 30 s):

- per device (`dev_min`): frames sent (`tx`), RSSI sum/min/max and LQI sum of what the sniffer
  heard from it, ACK-requested unicast sent (`uni`) and how many were MAC retries (`retry`: the
  same source, destination and sequence number again within 1 s), frames it relayed for others
  (`relay`), data polls (`poll`), its own NWK messages counted once however many hops carried
  them (`msgs`), unicast frames sent to it (`rx`) and those whose ACK the sniffer didn't hear
  (`noack`), airtime (`air`);
- per sniffer per device (`dev_sniffer_min`): frames and RSSI as each sniffer heard them;
- for the network (`net_min`): our frames, other networks' frames, frames naming no network,
  airtime ours and total (channel busy), unicast/retries/no-ACK, broadcasts, beacon requests
  (scans), frames the radio or bridge dropped;
- the hops (`hops`, per hour): MAC source/destination against NWK source/destination, which is
  how routes and "who relays for whom" are shown;
- per link (`link_tx`, per hour): unicast frames, resends and missing ACKs from each MAC sender
  to each receiver, so a device's resends can be pinned on one neighbour;
- the last time each device's own NWK message was heard at any hop (`seen.msg_ts`), so a device
  heard only through relays isn't taken for silent;
- addresses: the short-address ↔ IEEE map learned from frames carrying the 64-bit NWK source
  (confirmed after 3 frames), with `address_change` / `address_reused` events, and association /
  orphan events from MAC commands.

The tshark pass adds what needs the decrypted NWK/APS layers: Network Status (route errors;
status 0x0C many-to-one route failure is stored as `route_failure_up` on the *reporting* router,
0x0D as `address_conflict`, 0x11 as `bad_frame_counter`), Leave, Rejoin request/response, Device
Announce, Network Report/Update, End Device Timeout (`events`); NWK command counts per device
(`cmd_min`, e.g. route requests); Link Status costs both ways per router and neighbour (`links`,
per hour); and the OTA Upgrade cluster: image blocks sent to each device per minute with the
highest file offset and the image size on offer (`ota_min`), plus `ota_start`, `ota_offer`,
`ota_done` and `ota_failed` events. A message relayed by several routers is counted once (NWK
source + sequence).

Zigbee2MQTT's bridge topics (over the same MQTT connection as the entities) add `z2m_online`,
`z2m_offline`, `z2m_restart`, `device_joined`, `device_interview`, `device_leave`,
`device_announce` and its own `ota_done`/`ota_failed` (stored with `other = 'z2m'`, on the device
when it is named). Those, firmware-update events, channel changes and sniffer disconnects are the
charts' **marks**.

## Storage

### SQLite `/data/history.db` (WAL)

| Table | Key | Columns |
| --- | --- | --- |
| `dev_min` | minute, addr | tx, rssi_sum/min/max, lqi_sum, uni, retry, relay, poll, msgs, rx, noack, air |
| `dev_sniffer_min` | minute, addr, sniffer | n, rssi_sum/min/max |
| `net_min` | minute | ours, others, unnamed, air_ours, air_all, uni, retry, noack, bcast, scans, dropped |
| `hops` | hour, mac_src, mac_dst, nwk_src, nwk_dst | n, rssi_sum (non-retry frames of our network) |
| `seen` | addr | ts, rssi, lqi (last heard directly), msg_ts (its last own message, any hop) |
| `link_tx` | hour, src, dst | uni, retry, noack (per MAC link) |
| `ota_min` | minute, addr | blocks, offset_min (lowest block offset, 0.5.4), offset_max, size (firmware download progress) |
| `ieee` | addr, ieee | first, last |
| `events` | id | ts, kind, addr, other, ieee, detail, file, n (file + frame number point into the captures) |
| `cmd_min` | minute, addr, cmd | n |
| `links` | hour, router, neighbor | n, in_sum, out_sum, last_ts, last_in, last_out |
| `sniffer_health` | sniffer, minute | up_s, disconnects, rssi_sum/n/min/max (bridge Wi-Fi), buffered, backlog_max, crc, heard/solo/total (our transmissions it heard, only it heard, all while it was connected; 0.5.3) |
| `files` | rel | offset, frames (counted into the history), ev_offset, ev_frames (decoded by tshark) |

Sniffer events are stored with `addr = 'sniffer'` and `other = <sniffer id>`; channel changes
with `other = 'app'`; Zigbee2MQTT's with `other = 'z2m'`; incidents fire as events with
`addr = 'network'` (not stored). Every 10 minutes rows older than `retention_days` are deleted
from all tables (no VACUUM). Pages read through a second, read-only connection (WAL), so a long
query never holds up writing. A database SQLite can't open is moved aside
(`history.db.damaged-<time>`) and the history is rebuilt from the captures.

### Capture files

`/share/zigbee_captures/YYYY-MM-DD/zigbee_YYYY-MM-DD_HH.pcap`, one per local hour (only the
date folders count: `pcap.capture_files`; keep backups outside the folder all the same) (when the
clocks go back, the repeated hour shares a file). Classic pcap, µs timestamps, link type 283
(IEEE 802.15.4 TAP) with TLVs for FCS type, RSS, channel and LQI; every network's frames. Up to
3 hour files are open at once (buffered frames from an earlier hour). Retention deletes files
older than `retention_days`, then the oldest until the total is under `max_storage_mb` (never
the current one). The live Wireshark stream on TCP 17760 sends the same format.

With several sniffers each capture has a `<file>.pcap.sniffers` text file beside it: one line per
frame number, `n sniffer:rssi sniffer:rssi`, and a further line for a copy that came after the
frame was written (`pcap.read_copies` merges them, reading on from where it stopped). A capture
cut back to its last whole record after a crash drops the lines about the frames it lost.
Retention deletes it with its capture and counts it toward `max_storage_mb`.

### Other files in `/data`

`options.json` (Supervisor), `channel.json` (a channel chosen on the Sniffer page),
`sniffers_known.json` (sniffers that have connected before: a new one fires `sniffer_added`;
seeded from the history the first time),
`map.json` + `maps/` (floors, positions, plan images), `tshark-home/` (tshark's profile with
the network key table), `ha_devices.json` (which devices have a health sensor in HA, so removed
ones can be taken out).

## Findings

`report.py` judges each device over the selected range. Severity `high` = problem, `warn` =
warning, `info` = note (the HA health sensor uses those words).

Answers are cached until the history is next written (`history_written()`, after every
history write; at most `STALE_S` = 90 s), or for their own TTL if shorter-lived data needs it
(baselines 30 min, after decoded data `invalidate()`).

A device's signal (`rssi_avg`, min, max, the sparkline) is the sniffer that hears it best
(highest average among those with ≥ 3 frames and ≥ 2 % of the most any sniffer has), named in
`rssi_sniffer` / `rssi_sniffer_name`, from `dev_sniffer_min`; `signal` lists every sniffer's.
Without per-sniffer rows (history before 0.5.0) it falls back to `dev_min`'s best copy. The
baseline keeps `rssi_by_sniffer` (each sniffer's 7-day average, ≥ 20 frames), and the row's
`baseline.rssi_avg` is the shown sniffer's; each `signal` entry also has `normal` (that
sniffer's 7-day average for the device) and `change` (now minus normal, ≥ 5 frames). A
sniffer's normals only use its rows since it was last moved (`sniffer_moves`, from
`/data/sniffer_moves.json`, set by POST `/api/sniffer/moved?sniffer=`) and only once it has
`SNIFFER_NORMAL_HOURS` = 12 distinct hours of them; the Sniffer page's `normals` says how far
it is, and its findings suggest a move when half the devices at it changed by 5 dB or more (or
30 % by 8). A device's
page adds `signal_series`: per sniffer the buckets plus `ref` and `ref_kind` ("normal", or
"range": its average over the range when it has no normal yet), which the page's "vs normal"
chart subtracts.

**Firmware** (`ota()`): `ota_min` rows (minute, device: blocks, lowest and highest block offset,
image size) are split into downloads at gaps over 10 min (looking 3 h back so one that began
before the range is whole). Per download: `started`, `last_ts`, `duration`, `from` (lowest
offset / size: where a resumed download picked up), `progress`, `bytes`, `rate` (B/s), `eta`
(while updating), `state` (updating if a block came in the last 3 min, else done / failed from
the first `ota_done` / `ota_failed` after it began, preferring Zigbee2MQTT's which has the
versions, else stalled), `result` and `restarted` (a Zigbee2MQTT announce / interview within 15
min of the result). The latest stands for the device, earlier ones under `sessions`.
`firmware()` adds Zigbee2MQTT's status per device (`names.load_z2m_updates()`: state.json's
`update` — state, installed and latest version, release notes — read again when the file
changes) and lists the devices with an update available. "Need attention" counts devices
at warn or above.

Each finding has `sev`, `code`, `text`, and optionally `detail` (the numbers behind it) and
`context`: `"incident"` (it happened during network-wide trouble) or `"ota"` (during the
device's firmware download). A finding with a context counts one level lower (high → warn →
info), except leave, silent, not heard, unreachable and the OTA state itself.

| Finding | Condition | Severity |
| --- | --- | --- |
| `not_heard` | a known device with no frames or messages in the range (only while a sniffer is connected) | router heard before: high; router never heard: warn; end device: info |
| `silent` | quiet (directly or through relays) longer than max(6 × its usual interval, 5 min router / 15 min end device), measured up to the last frame any sniffer heard | router high, end device warn |
| `unreachable` | ≥ 20 unicast to it, none acknowledged, nothing sent by it | high |
| `retries` | resent ≥ max(8 %, 2 × network-wide, 2 × its 7-day normal), ≥ 20 frames | info; warn from max(15 %, limit + 5) with ≥ 40 frames; high from max(30 %, limit + 15) with ≥ 100; the detail names the neighbour most resends go to |
| `no_ack` | ≥ 20 unicast to it and ≥ 20 % without a heard ACK, split into real losses (`rx_lost`: frames to it its neighbours sent again, the MAC retries on the links into it in `link_tx`, capped at the missing ACKs) and ACKs the sniffers missed (`noack_missed`: the sender carried on) | losses ≥ 10 % of what was sent to it: info, warn from 30 % with ≥ 40 frames ("Lost N%"); under 10 %: info, or nothing when ≥ 80 % of the missing ACKs were the sniffers' |
| `leave` | left the network | high |
| `rejoin` | rejoin request or response | warn |
| `orphan` | orphan notification | warn |
| `announce` | Device Announce (joined, rejoined or power-cycled) | 1 info, ≥ 2 warn |
| `address` | short address changed or reused | warn |
| `address_conflict` | Network Status 0x0D about it | warn |
| `frame_counter` | Network Status 0x11 (stale security frame counter) about it | warn |
| `uplink_errors` | it reported many-to-one route failures (couldn't forward toward the coordinator) in ≥ 3 distinct minutes and ≥ 1 per 4 h | warn; info with context `incident` when fewer than that fall outside incidents |
| `route_errors` | it reported other route errors in ≥ 3 distinct minutes (same rate rule) | as above |
| `route_errors_to` | routers couldn't reach it, ≥ 3 distinct minutes (same rate rule) | as above |
| `route_discovery` | ≥ 6 route requests (not many-to-one) and ≥ 3 per hour | warn |
| `weak_mesh` | best Link Status cost ≥ 5 | warn |
| `few_neighbors` | ≤ 2 neighbours in its own table | info |
| `lopsided` | a neighbour link at cost ≤ 3 one way and ≥ 5 the other | info |
| `parent_changes` | an end device that sent to ≥ 2 parents (each ≥ 10 % of its frames) | warn |
| `unusual_traffic` | ≥ 4 × its normal frames per hour and ≥ 120/h (not during its OTA) | info |
| `weaker` | every sniffer that heard it ≥ 20 frames, now and in its normal, hears it ≥ 8 dB below that normal (each against its own) | info |
| `relays_less` | a router relaying < 20 % of its normal (normal ≥ 60/h) | info |
| `ota` | downloading firmware (info), stalled or failed (warn) | |
| `faint` | average RSSI at the best sniffer ≤ -88 dBm (≥ 5 frames) | info |
| `relayed_only` | its messages arrive, but only through relays | info |

"Normal" is the device's own rate over the 7 days before the range (needs 12 hours of history).

Network findings on the Overview: incidents (below), no sniffer connected (warn), radio/bridge
drops (≥ 1 % info, ≥ 5 % warn), channel busy ≥ 25 % (warn), other networks ≥ 30 % of frames
(info), ≥ 5 % of unicast resent network-wide (warn), ≥ 20 beacon requests (info), Network Report
(PAN ID conflict, warn), Network Update (warn), no network key (info).

### Incidents

`report._incidents` looks at every minute of the range: a minute is bad when traffic is ≥ 3 × the
normal (the median per minute, over the day before for short ranges) and ≥ 200 frames, or ≥ 5
devices had route failures in the 5 minutes up to it, or ≥ 3 devices received OTA blocks, or
≥ 10 % of ≥ 100 unicast frames were resent. Bad minutes less than 6 minutes apart form one
incident; one shorter than 2 minutes counts only with ≥ 8 devices or an OTA. Each incident has
`start`, `end` (null while it lasts), `sev` (high with ≥ 15 devices or a channel ≥ 30 % busy),
`title`, `detail`, `cause` (firmware updates of N devices, N failed; Zigbee2MQTT restarted at
HH:MM), `devices` and `evidence` {traffic_x, busy_pct, retry_pct, route_failures, devices_n,
ota_n}. A new incident fires a `zigbee_sniffer_event` of kind `incident`.

### One row per device

A device that changed its short address appears under both in the history. Rows are folded by
IEEE (the names' current pair, else the history's `ieee` table) into the current address,
summing the counters; an offline device's row is built from its IEEE, and an address that now
belongs to another device doesn't lend its old owner's name.

Sniffer findings (`sniffer_findings` in `main.py`, per sniffer): no host or not connected
(high), radio link down (high), status page not answering (info), a board rolled back (warn) or
on trial (info), bridge Wi-Fi below -75 dBm (warn), ≥ 3 disconnects in the range (warn), buffer
overflow drops (warn), board restarts (info; ≥ 3 warn), ≥ 10 UART CRC errors (info), updates
off or no `update_token` (info), listening off the configured channel (info), HA publishing
error (info).

## The page

`web/` is the page's source: Preact + `@preact/signals` on the shared **Zigbee UI** kit (the same
shell, components and logo as Zigbee Studio and Zigbee Bridge), copied into `web/src/kit/` and checked
at build (`node src/kit/check.mjs` fails on a hand-edited copy; change the kit, then
`node <zigbee-ui>/tools/sync.mjs web/src/kit`). Vite builds it flat into `app/static/` (committed:
the Supervisor doesn't run npm), with every URL relative because the page sits under Home Assistant's
ingress path.

```
cd web && npm ci && npm run build   # -> app/static
npm test                            # the page's pure logic (web/tests)
```

Hash routes: `#/overview`, `#/devices`, `#/device/<addr>`, `#/mesh`, `#/map`, `#/live`,
`#/captures`, `#/sniffer` (Zigbee Studio links to `#/device/<nwk>`). Each page polls while it is open
(Overview and device page 10 s, Devices 15 s, Mesh 30 s, Map 60 s and not while editing, Live 2 s,
Sniffer 5 s); the connection pill every 5 s. The charts are the Sniffer's own (incident bands, event
marks, labelled reference lines, a click on a bucket opens Captures there), drawn in the kit's style
with its table view. Any frame row opens the decode drawer (tshark tree, hex, copy; Esc closes).
Actions ask first in the kit's dialog; deleting a floor needs its name typed. Settings remembered in
`localStorage` under `zbs.*`: time range, device filter and sort, Mesh options, Map
floor/layer/opacity/toggles, Live options, chosen sniffer. Live keeps the latest 600 frames and shows 400.

## HTTP API

All under the ingress path; `range` is `1h`, `6h`, `24h` (default) or `7d`. GET unless noted.
Requests are answered only from Home Assistant's ingress proxy (172.30.32.2) and localhost
(`SNIFFER_ALLOW` overrides the list); anything else gets 403.

Zigbee Studio (the Zigbee2MQTT page in `../zigbee_studio`) may also GET `status`, `overview`,
`devices`, `device/{addr}`, `mesh`, `live`, `map`, `map/coverage` and a floor's image, and set up
the floor maps (POST `map/floors`, `map/floors/{id}`, `map/floors/{id}/image`, `map/positions`;
DELETE `map/floors/{id}`), with the header `X-Zigbee-Studio-Key` (`studio.py`). The key is made
once into `/share/zigbee_sniffer/studio.key` (Studio maps `/share` read-only) and removed when the
option `zigbee_studio` is off. Nothing else that changes anything (channel, firmware, pings, the
sniffers), decodes stored captures, downloads them or traces a device is on that list.

| Route | Returns |
| --- | --- |
| `/`, `/static/{name}` | the page |
| `/api/status` | sniffers (link, fps, frames, firmware, clock drift), PAN, counters, key loaded, `tshark_error`, `disk_error`, `history_recovered`, `history_unwritten`, history size, merged copies, `merge` {waiting_for(_name), behind_s, window_ms, pending, seeded, repaired} |
| `/api/overview?range` | totals, series, counts, attention list (≤ 80), events (≤ 60), `incidents`, `ota` {active, devices (downloads, each with `z2m` versions), available, known}, `marks`, other networks |
| `/api/devices?range` | device rows with findings, severity, `baseline`, `ota`, `parents`, `signal` (per sniffer, with `normal` and `change`), `rssi_sniffer(_name)`, `fw_update` (Zigbee2MQTT's update state); `sniffers` [{id, name}] |
| `/api/device/{addr}?range` | one device: row, series, talks-to/relays, routes, neighbours and link history, `next_hops` (resends per neighbour), `baseline`, `ota`, `incidents`, `marks` (with sniffers added / offline / back), events, recent frames, `signal_series` (signal per sniffer with `ref`), `firmware` (Zigbee2MQTT's version and update state) |
| `/api/device/{addr}/hours?range` | `hours`: [{file, start, frames}] the hours it was heard in, newest first |
| `/api/mesh?range` | nodes, Link Status edges, end-device parents, traffic |
| `/api/networks` | other PANs heard since start |
| `/api/live?after&others=1&addr&decode=1` | up to 300 frames newer than `after` |
| `/api/captures` | {files: [{file, size, side_size, mtime, current, frames, start}], oldest, storage_mb (with the `.sniffers` files), limit_mb, retention_days} |
| `/api/decode?file&t&q&addr&others&retries=1&n&limit&offset` | a page of a capture file, decoded: {total, offset, rows, focus, file}; `t` (unix time) alone picks the hour's file and the page holding that moment; with several sniffers each row has `heard_by` |
| `/api/frame?live=<id>&file&n` | one frame: tshark's full tree and hex (keys hidden); falls back to file + n when the live buffer no longer has it |
| `/download/{rel}`, `/decoded/{rel}?format=json\|text&addr` | the pcap; tshark's decode streamed (keys hidden) |
| POST `/api/channel` `{channel \| null}` | listen on another channel (every sniffer), or the configured one |
| `/api/sniffer?sniffer&range` | one sniffer's health, history (series rows end with heard, solo, total), findings, events (with channel changes), `marks`, bridge status, firmware; `sniffers[]` with `clock_offset_ms`, `skew_ms` and `match` {n, p50_ms, p95_ms}; `coverage` {heard_pct, solo_pct, devices, solo_devices, vs: [{name, median_db, devices}]}; `merge` |
| POST `/api/sniffer/moved?sniffer` | the sniffer was moved: its signal normals start again from now (event `sniffer_moved`, marked on device charts) |
| POST `/api/firmware/inspect?sniffer&file` (or image body) | image info, target, problems |
| POST `/api/firmware/{radio\|bridge}?sniffer&file` (or image body) | start an update (202) |
| POST `/api/ping/{addr}` | ask Zigbee2MQTT to read genBasic zclVersion; the device's frames (and the ACK after each) are kept apart for 60 s for the trace |
| `/api/trace/{addr}?since` | the ping's frames: hops, tries, ACKs, polls, round-trip time |
| `/api/map` | floors, positions, items that can be placed |
| POST `/api/map/floors`; POST/DELETE `/api/map/floors/{fid}` | add, change (name, level, scale, size, floor height), delete a floor |
| POST/GET `/api/map/floors/{fid}/image?w&h` | upload (PNG, JPEG, SVG, WebP, GIF, ≤ 24 MB) / fetch a plan |
| POST `/api/map/positions` `{set, clear}` | place / remove items |
| `/api/map/coverage?range` | the fitted model (with `gains` per sniffer and `gain_ref`), placed items with signal and strength, mesh links between them |

## Home Assistant

Over MQTT discovery (the Supervisor's MQTT service; availability topic `zigbee_sniffer/status`
with a last will):

- **Zigbee Sniffer** device (the first sniffer): Connected, Radio link problem, Zigbee devices
  with problems (list in attributes), Frames per minute, Channel busy, Frames resent, Bridge
  Wi-Fi signal, Bridge disconnects (24 h), Frames delivered late, Radio firmware, Bridge
  firmware, Zigbee channel.
- **Zigbee Sniffer <name>** per extra sniffer (via the first): Connected, Radio link problem,
  Wi-Fi signal, Disconnects, Frames delivered late, both firmwares.
- **Zigbee health** on each Zigbee2MQTT device (`zigbee2mqtt_<ieee>`): ok / note / warning /
  problem / not heard over the last hour, with findings, short address, signal, resent %, no-ACK
  %, best link cost, neighbours, next hop, messages in the last hour, last heard.

Health sensors of devices removed from Zigbee2MQTT (or all of them, when `device_sensors` is
turned off) are removed with an empty retained config; at most half of them at once, so an
unreadable Zigbee2MQTT database can't wipe them all.

Events `zigbee_sniffer_event` (POSTed to Core through the Supervisor API by a queue of their own)
with kind, device, address, ieee, detail, time; kinds: leave, rejoin, rejoin_response, announce,
network_status, orphan, address_change, address_reused, address_conflict, bad_frame_counter,
association, association_response, incident, ota_done, ota_failed, sniffer_offline, sniffer_back, sniffer_added,
bridge_reboot, radio_reboot, firmware_update. At most one per (kind, address, and sniffer for
sniffer events) per minute; events older than 10 minutes are not fired.

The MQTT client also subscribes to `<base>/bridge/state`, `<base>/bridge/event` and
`<base>/bridge/response/device/ota_update/update` (`<base>` from Zigbee2MQTT's `mqtt.base_topic`)
for the timeline marks; retained messages (old news on subscribing) are ignored, and offline then
online within 10 minutes is a `z2m_restart`.

Ping publishes `{"read": {"cluster": "genBasic", "attributes": ["zclVersion"]}}` to
`zigbee2mqtt/<friendly name>/set` and traces the frames that follow.

## Firmware checks

Before an image goes to a bridge: at least 256 bytes, ESP image magic `0xE9`, app description
magic `0xABCD5432` at offset 32; project `zigbee_sniffer_radio` (radio) or
`zigbee_sniffer_bridge` (bridge); chip id ESP32-C6 for the radio, ESP32-S3 for the bridge; the
SHA-256 ESP-IDF appends must match (when the image carries one); for the bridge, the `+board`
suffix of the version must match the running one, and the update is refused while the running
version is unknown. It needs `update_token`, one update per sniffer at a time (taken before the
upload is read, so a double click can't start two), and is sent with `X-Update-Token` (300 s
timeout); whatever happens, the update doesn't stay "running". The bridge verifies the image itself and rolls back
if the new firmware doesn't confirm. Images can also be picked from
`/share/zigbee_sniffer/firmware/*.bin` (newest 20).

## Configuration

Options (`/data/options.json`, see `config.yaml`; default when missing): `sniffer_host`,
`sniffer_port` 6638, `sniffer_name` Main, `more_sniffers` [] (`name`, `host`, `port`), `usb_sniffers` []
(`name`, `device`; the add-on has `uart: true` so serial devices are mapped in), `channel`
25 (overridden by `channel.json`), `retention_days` 7, `max_storage_mb` 2000, `decode` true,
`update_token` "", `publish_to_ha` true, `device_sensors` true.

Environment variables (for running outside the add-on):

| Variable | Default |
| --- | --- |
| `SNIFFER_DATA` | `/data` |
| `SNIFFER_CAPTURES` | `/share/zigbee_captures` |
| `Z2M_DIR` | `/homeassistant/zigbee2mqtt` |
| `SNIFFER_WEB_PORT` | 8099 |
| `SNIFFER_BIND` | 0.0.0.0 |
| `SNIFFER_LIVE_PORT` | 17760 |
| `SNIFFER_BRIDGE_HTTP_PORT` | 80 (first sniffer) |
| `TSHARK` | `tshark` (run with `HOME=/data/tshark-home`) |
| `SNIFFER_ALLOW` | `172.30.32.2,127.0.0.1,::1` (who may use the web port) |
| `SNIFFER_STUDIO_KEY` | `/share/zigbee_sniffer/studio.key` (Zigbee Studio's key) |
| `TZ` | else `time_zone` from `/homeassistant/.storage/core.config` |
| `SUPERVISOR_TOKEN` | else s6's `/run/s6/container_environment` |

## Security

- The network key is only in tshark's key table in `/data`. tshark prints the key it used and the
  key in Transport Key commands; `tshark.redact()` replaces every form of it (text, JSON, the
  decrypted hex of Transport Key frames) before anything leaves the app.
- Only the ingress proxy is answered (see the API section), plus Zigbee Studio's read-only GETs
  and floor-map changes with its key.
- Floor plans are served with `Content-Security-Policy: sandbox` and `nosniff`.
- The capture files themselves are encrypted as heard; a join's Transport Key in them can be
  decrypted with the public ZigBeeAlliance09 key, as with any Zigbee capture.

## Tests and the simulator

`tests/` (pytest; no tshark, MQTT or network needed) and `dev/` (fake bridges that speak the
protocol, one or two in a simulated two-floor house); `dev/README.md` has the commands.

## Running it locally

The app runs on Windows or Linux with Python 3.12+, `aiohttp`, `pyyaml`, `paho-mqtt` and
(optionally) Wireshark's tshark. Environment variables point it away from the add-on paths:

```bash
cd zigbee_sniffer/app
SNIFFER_DATA=/tmp/zs/data SNIFFER_CAPTURES=/tmp/zs/captures Z2M_DIR=/tmp/zs/z2m \
SNIFFER_WEB_PORT=8098 SNIFFER_LIVE_PORT=17761 SNIFFER_BIND=127.0.0.1 \
TSHARK="C:/Program Files/Wireshark/tshark.exe" \
uv run --python 3.12 --with aiohttp --with pyyaml --with paho-mqtt python main.py
```

`/tmp/zs/data/options.json` holds the add-on options (same keys as `config.yaml`). Without a
real bridge, point `sniffer_host` at a simulator that speaks the protocol above.

## Shipping it

The add-on is built by the Supervisor from the zigbee-sniffer repository, an add-on store of its
own (its add-on ID is `<hash of the store URL>_zigbee_sniffer`; Zigbee Studio finds it by that pattern). To release: change the code, rebuild the page if `web/` changed, bump `version` in `config.yaml`,
`VERSION` in `main.py` and `web/package.json`, add a `CHANGELOG.md` entry, update `DOCS.md` for anything a user sees,
commit on `main` as "Zigbee Sniffer X.Y.Z: ...", push, then reload the add-on store in Home
Assistant and update (auto-update is on, so it also arrives by itself).
