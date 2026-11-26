# Changelog

## 0.7.2

- **Ready-made images**: releases are built on GitHub, so installing or updating downloads a finished
  image instead of building it on your Home Assistant machine. Faster, and the same for everyone.
- **Radio firmware comes with the app**: the Sniffer page's Firmware card lists the radio images built
  with this release (ESP32-C6 for a radio wired to a Wi-Fi bridge, ESP32-C5 plugged in over USB),
  ready to check and send. They are also attached to each GitHub release. The Wi-Fi bridge (ESP32-S3)
  still needs your own build: its Wi-Fi name and password are built into it.

## 0.7.1

- The name in the top bar opens the app menu, like Zigbee Studio's: Zigbee Studio and the Zigbee
  Bridge, found through Home Assistant (the bridge's address comes from Zigbee Studio).

## 0.7.0

- **Its own repository**: the add-on and its firmware (`firmware/`: the radio, the Wi-Fi bridge and
  the shared protocol) in one add-on repository.
- **Carry-over**: moving an install from another store, put the old install's `/data` in
  `/share/zigbee_sniffer/carry-over/` and the new one takes it over on its first start (the history,
  floor maps and positions, the channel picked on the Sniffer page, known sniffers and their moves).
  It never overwrites and runs once.
- **One look for the Zigbee apps**: the page is rebuilt on the shared Zigbee UI kit, the same as
  Zigbee Studio and Zigbee Bridge, with the same Zigbee logo.

## 0.6.5

- Only the date folders in `/share/zigbee_captures` (`YYYY-MM-DD/`) hold captures. Every scan
  of the folder took any `*/…pcap` for one, hidden folders included: at startup a copy of an
  hour kept in a backup folder there was taken for a misnamed capture and appended to that hour's
  live file (the history then counted that hour twice), and retention could have deleted files
  from `.analysis` or a folder set aside by hand.

## 0.6.4

- A USB sniffer no longer takes a frame with a stale timestamp for a radio restart. ESP-IDF's
  802.15.4 driver stamps a receive slot when a frame starts; when the radio is busy (draining its
  USB backlog right after the port opens) a frame can finish in a slot that wasn't stamped for it
  and carry the time the slot was last used, seconds or minutes earlier. 0.6.2-0.6.3 re-paired the
  clock on such frames a few times after each start ("the bridge restarted" in the log). Now a
  clock going backwards is a restart only when the radio is fresh from a boot (under 30 s); a stale
  stamp gets the previous frame's time and is logged.

## 0.6.3

- A sniffer's timing correction is only moved once it has been learned from matched copies.
  When a sniffer's clock pairing stepped before any of its copies had matched, the merger made
  the step its correction. The USB sniffer on the HA box hit this at every start: the app's
  startup holds up its first reads for a second or two, the pairing comes out that late, the
  next live frame steps it back, and the made-up -1.6 s correction then kept every copy it heard
  from matching (each written as one more transmission that only it heard). Bridges pair at their
  HELLO, so they rarely hit it.

## 0.6.2

- A USB sniffer's clock is paired right when its port opens. While nobody has the port open the
  radio keeps writing frames into its USB buffer, and those (up to a minute old) come first.
  0.6.0-0.6.1 paired the clock from the first of them, 53 s off on the HA box; the next live
  frame corrected it, but the merger took that for clock drift and kept it as the sniffer's
  offset, so none of its frames merged with the other sniffers' copies (each was written as one
  more transmission that only it heard). Now the first second of frames is held and the clock is
  paired from the freshest; the old frames come out at their own time, as late frames.

## 0.6.1

- A USB sniffer opens only an ESP32's own USB port (USB vendor 303a, read from sysfs), and
  refuses anything else before touching it. The device list also offers the Zigbee2MQTT and
  Thread border router dongles (Sonoff MG24, vendor 10c4), and a USB sniffer pointed at one of
  them by mistake would have sent its channel and ping messages into it. The Sniffer page says
  why ("Won't open ...: USB vendor 10c4 ... pick the usb-Espressif_USB_JTAG_serial_debug_unit
  device").
- The port is held exclusively while the app has it open (TIOCEXCL), so nothing else opens it
  meanwhile.

## 0.6.0

**A sniffer on USB.** A sniffer radio can plug straight into the Home Assistant box instead of
sitting behind a Wi-Fi bridge: a XIAO ESP32C5 (or C6) with radio firmware 0.3, built for USB.
- New option `usb_sniffers` (`name`, `device`); the add-on now maps the box's serial devices
  (`uart: true`). Pick the `/dev/serial/by-id/...` device, which survives replugging.
- The app plays the bridge's part over the cable: it sets the channel, pings the radio, and times
  its frames on the radio's own clock (a radio restart re-pairs the clock, as a bridge restart
  does). It merges with the Wi-Fi sniffers like any other.
- Radio firmware updates over the cable from its Sniffer page, with no update token. The radio
  restarts into the image on trial and keeps it once it hears the app again. Images for the
  wrong chip are refused: radio 0.3 reports the chip it was built for (ESP32-C5 is known now).
- The Sniffer page shows "USB link" and "Plugged into this box" for it, with no bridge, Wi-Fi or
  buffer, and findings that fit (a USB port that sends nothing, damaged messages on the cable).

## 0.5.13

- Zigbee Studio can set up the floor maps too (add, rename and delete floors, upload a plan, set
  its scale, place devices and sniffers), with the same key. Nothing else it may change: the
  channel, firmware, pings and the sniffers' own settings stay on this page.

## 0.5.12

- Zigbee Studio (the Zigbee2MQTT page beside this one) can show the Sniffer's findings: it may
  read devices, a device's history, health, the mesh, the maps and live frames, with a key the
  Sniffer keeps in `/share/zigbee_sniffer/studio.key`. Only reading: changing the channel,
  firmware, maps, pings, traces, decoding stored captures and downloads stay on this page. The
  new option `zigbee_studio` (on) turns it off and removes the key.

## 0.5.11

- Capture files can be counted into the history again from scratch: list them in
  `recount.json` in the captures folder and restart the app. Their old counts come out first
  (that hour's counters, hops and links, the files' events, who heard what), then they are
  counted like frames written while the app was down, which sniffer heard each frame included.
  The sniffers' own health, the bridges' dropped frames and Zigbee2MQTT's events stay. Used once
  to put back the 33 hours of Sniffer 2's frames that 0.5.3-0.5.9 filed 38.7 h early after its
  bridge restarted (the files were repaired outside the app).

## 0.5.10

- A sniffer whose bridge restarted is timed right again. A restart starts the bridge's clock over,
  and 0.5.3-0.5.9 moved the merger's correction by the leap in the clock pairing, the bridge's
  whole previous uptime: after Sniffer 2's bridge restarted on 11-11 at 10:48 (38.7 h up), every
  frame it heard was filed 38.7 h early, none merged with Main's copies, and the merger held the
  live view back by its full minute. Now a restart starts that sniffer's correction afresh.
- A timing correction past 5 minutes between two sniffers is dropped and learned again, with a
  warning in the log, whatever caused it.

## 0.5.9

- The app reports the version it runs (0.5.8 still said 0.5.7 on its status, header and Home
  Assistant device); a test keeps `main.py`'s version in step with the add-on's.

## 0.5.8

From a review of 24 hours of the two real sniffers' captures (every unicast followed to its
destination: messages do arrive; these were the app's own mistakes).

**Merging two sniffers' copies**
- An ACK one sniffer heard together with its frame and the other heard alone is written once.
  The lone copy had nothing to pair with, so it never merged with the other: a fifth of all ACKs
  (about 7 % of every frame in the captures) were written twice, and each such ACK counted as
  "only it heard" at both sniffers.
- An original no longer merges with the MAC retry another sniffer heard alone. Once copies line
  up, the match window is 3 × their spread + 0.5 ms, at least 1 ms (it was at least 3 ms, longer
  than the ~1.7 ms before a quick retry); and when the mix-up happens anyway (wide window after a
  reconnect, copies in the wrong order), the sniffer that heard both swaps them back as soon as
  its retry comes in. About 600 a day had come out as two copies of one frame under 1 ms apart.
- The simulator spaces MAC retries as on air (2-5 ms; they were 14-24 ms) and can deliver each
  bridge's frames with jitter and hear only part of the house (`devsim2.py --jitter-ms`,
  `--hear-dbm`), which shows both mistakes; with the fixes it writes every frame once.

**No ACK, lost or missed**
- Frames sent to a device with no ACK heard are split into lost (its neighbour sent the frame
  again) and ACKs the sniffers missed (the sender carried on, so it got one; about a third of
  them). The finding says how much was lost ("Lost 33% of the frames sent to it") and is judged
  on that; a device whose missing ACKs are nearly all the sniffers' no longer gets one. The
  device page shows both, and the Home Assistant health sensor gets `lost_pct`.

**Log**
- A dropped connection says why: a timeout logged "Connection lost: " (and "Can't reach …: ")
  with nothing after it, because a timeout has no text of its own. Now: "no data for 30 s",
  "no answer in 10 s", or the error's name.
- "Loaded N device names" is logged at startup and when names change (with what changed), not
  every 10 minutes.

## 0.5.7

- The Sniffer page's "Its normals" counts the same hours the normals rest on (0.5.6 counted from
  counters that only began with 0.5.3, so a sniffer with days of normals read "learning").

## 0.5.6

- The Sniffer page's "Its normals" counts the hours the sniffer has heard our devices since it was
  placed (it showed whichever time range was last worked out, often 0).

## 0.5.5

- A sniffer's signal normals only count once it has 12 hours of history where it is: Sniffer 2's
  "normal" had been learned from its first two hours (mostly at a desk), which put ▼ on 15 devices
  at it after it was moved.
- "Moved it" on the Sniffer page (What it adds): the sniffer's normals start again from there, and
  the move is marked on every device's charts. The page suggests it when most devices sound
  different at one sniffer at once.
- Firmware downloads stored before 0.5.4 (no lowest offset) no longer claim to have started at 0 %
  with the whole image in a minute: where they began and how much came show as unknown.

## 0.5.4

**Signal per sniffer you can read**
- Devices has a signal column per sniffer (with 2-3 sniffers): each sniffer's dBm with a bar, the
  one that hears the device best in bold, and ▼ / ▲ when it is 8 dB or more off its normal there.
  Sorting and the CSV export work per sniffer.
- A device's page has one Signal card: a table of each sniffer's signal, its 7-day normal for the
  device and the change, and a chart that shows each sniffer against its own normal (0 is normal,
  below is weaker), so the lines lie on top of each other while all is well, whatever the
  antennas. "dBm" switches to the raw levels. A device heard now and then reads as one dashed line
  instead of scattered pieces.

**Firmware updates**
- Each download is a session: when it started and ended, how much came and how fast, an ETA
  while it runs, where it picked up when an earlier download had been cut off (shaded in the
  bar: "picked up at 97%"), how it ended, and when the device restarted with the new image.
- Versions: the image's version from the frames on air, and Zigbee2MQTT's installed and latest
  version per device (from its state.json). The Overview lists the updates Zigbee2MQTT has
  available; Devices tags devices with "update available" or "updating 45%"; a device's page has
  a Firmware card with its version and downloads.
- A firmware incident no longer repeats its title as the cause, says how many downloads finished
  or failed, and ends when the downloads do instead of staying "ongoing" for a few minutes.

**Faster**
- Pages' answers are kept until the history is next written (every 30 s) instead of 8 s: the
  24-hour and 7-day Overview, which take a second to compute, are no longer recomputed on every
  poll.
- The device table reads each sniffer's signal in one pass instead of two; a device's page no
  longer queries the per-sniffer signal separately.

## 0.5.3

Everything from the two-sniffer review (`docs/2026-11-09-zigbee-sniffer-two-sniffers.md`).

**Signal per sniffer**
- A device's signal is the sniffer that hears it best, named ("at Sniffer 2"), not the loudest
  copy from whichever sniffer: two sniffers' antennas differed by 17 dB, so every device's chart
  jumped when the second one joined and would have dropped whenever it went offline.
- "Weaker than usual" compares each sniffer with its own 7-day normal and fires only when every
  sniffer that can tell agrees; "faint" names the best sniffer. A device's signal chart has a line
  per sniffer. The Home Assistant health sensor gets `heard_best_by`.
- The coverage model fits each sniffer's antenna gain from the devices two sniffers both hear
  (in a test house, ±2.4 dB error with it against ±11 dB without); the map says "Sniffer 2 hears
  17 dB louder than Main" and is drawn as the first sniffer would hear.

**Merging copies**
- Transmissions go out in time order once every sniffer has caught up: a sniffer whose Wi-Fi
  drops, stalls or is sending its buffer holds the others back (up to 30 s), so frames from a
  drop or a bridge update no longer land seconds out of order, away from their ACKs, and their
  ACKs aren't written twice. The header bar says who the app is waiting for.
- After a restart the app remembers the last 25 minutes of captures, so a bridge's backlog from
  before the restart isn't written again (about 860 frames were, when the second sniffer was
  added).
- Each sniffer's clock pairing moves on its own; the correction between sniffers now moves with
  it, so copies line up to well under a millisecond. The match window then narrows from 250 ms
  to a few ms for frames that ask for an ACK, so a MAC retry one sniffer heard isn't merged into
  the first try another heard. The Sniffer page shows how closely copies line up.
- Frames that reach the app together keep their spacing: the clock pairing used to step frame
  by frame through a burst, pressing its later frames onto the arrival time (up to tens of ms
  off), which split copies between sniffers.

**What each sniffer adds**
- Which sniffers heard each frame, and how loud, is kept next to each capture
  (`<hour>.pcap.sniffers`): Captures shows it like Live does, and frames counted into the
  history after a restart keep their per-sniffer signal.
- The Sniffer page's new "What it adds" card: the share of our transmissions it heard and that
  only it heard, the devices only it hears, and its signal against each other sniffer.
- A sniffer connecting for the first time is an event (`sniffer_added`), and sniffers being
  added, going offline or coming back are marked on every device's charts.
- Live and Captures name the sniffer of a frame only one sniffer heard.
- Damaged UART messages while a bridge updates or restarts (it stops reading the UART while it
  writes its flash) are reported apart, not as a UART problem.

## 0.5.2

- Route errors stored before 0.5.1 are re-filed the 0.5.1 way when the app starts: many-to-one
  route failures move to the router that reported them, address conflicts and stale frame
  counters get their own kinds, so the last 30 days' findings stop blaming the wrong devices.
- The incident card no longer prints its evidence twice.

## 0.5.1

Everything from the 0.5.0 review (`docs/2026-11-07-zigbee-sniffer-review.md`).

**Security**
- The network key no longer shows anywhere: tshark's "[Key: ...]" and "[Key Label: ...]" lines,
  the key inside Transport Key commands (and their decrypted bytes), and the same fields in the
  JSON download are replaced by "hidden".
- The web port answers only Home Assistant's ingress proxy (which checks the login), not every
  container on HA's internal network.
- Uploaded floor plans are served so that an SVG can't run script if opened on its own.

**Findings you can trust**
- Many-to-one route failures are pinned on the router that couldn't forward toward the
  coordinator ("Couldn't forward traffic toward the coordinator"), not on the device whose frame
  it was; route errors count distinct minutes, not every resent status frame. Address conflicts
  and stale security frame counters get findings of their own.
- **Incidents**: when the whole mesh is in trouble at once (traffic several times normal, route
  failures on many routers in the same minutes, firmware updates flooding the channel), the
  Overview shows one incident with its span, evidence and likely cause, the charts shade it, and
  Home Assistant gets an `incident` event. Device findings inside it are marked and count one
  level lower.
- Resends are judged against the network's rate and the device's own last 7 days, need enough
  frames for a warning or problem, and say "27 of 80" and which neighbour most of them go to.
- Silence counts relayed messages too, is measured up to the last frame any sniffer heard, and
  isn't judged while no sniffer is connected; a router that stays away stays a problem.
- One row per device after a short-address change (no more second "silent" copy, no more
  flapping health sensor); an offline device no longer takes the name of whoever reuses its
  address.
- New findings: unreachable (frames to it never acknowledged, nothing from it), lopsided links,
  end devices switching parents, traffic far above its normal, weaker than usual at the sniffer,
  a router relaying much less than usual, PAN ID conflict reports and network updates.

**New**
- **Firmware updates on air**: OTA image blocks are read from the captures, so the Overview shows
  "N devices updating firmware" with each one's progress, and a stalled or failed download is a
  finding.
- **Zigbee2MQTT on the timeline**: its restarts, device joins, interviews, leaves and OTA results
  (from MQTT) are markers on every chart.
- **Where the resends go**: resends and missing ACKs per link, on each device's page.
- A device's normal (last 7 days) next to its numbers.
- From a chart to the frames: click a bar to open Captures at that moment; a device's page lists
  the hours it was heard in; Ping ×5; LQI in the tables; search in Mesh; CSV export of Devices; a
  light/dark switch; keyboard and screen-reader access; a phone-friendly header.

**Robustness**
- Each bridge's clock is followed frame by frame (it drifted: frames would all have counted as
  "late" after a few days, and two sniffers' copies would have stopped merging after hours).
- With several sniffers, clock skew between them is measured from matched copies, and ACKs are
  paired with their frame inside each sniffer's stream before merging.
- The analyzer's bookkeeping no longer slows down per frame on a busy channel (it scanned its
  whole table for every frame once it held 8192 entries).
- Captures decode in the background and only what was added since the last look; opening one
  frame no longer reads the whole file.
- A failed tshark run is retried instead of being marked done (its events were lost); a missing
  tshark binary no longer breaks pages; long backlogs are decoded in parts.
- Disk full: frames are still counted and shown, with a banner; history that couldn't be written
  is retried. A damaged history database is moved aside and rebuilt from the captures. Capture
  bookkeeping is realigned after a hard reset or a rename. Every background task restarts itself
  if it fails.
- Home Assistant: health sensors of devices removed from Zigbee2MQTT are removed; events are sent
  without holding up the history, and several sniffers' events no longer share a rate limit.
- Firmware updates: one at a time even on a double click, the image's SHA-256 is checked, a
  bridge image is refused when the bridge's board can't be checked, and a failure never leaves
  the update "running".
- Zigbee2MQTT's split configuration (`devices: devices.yaml`) is read.
- The coverage model fits a device's own strength only where two sniffers hear it, weighs
  measurements by frames, and reports an honest (leave-one-out) error.
- The history is written every 30 s instead of 10 (a third of the disk writes), uses its own read
  connection, and CRCs are computed in C.
- A simulator and tests are in the repository (`dev/`, `tests/`).

## 0.5.0

- **Several sniffers**: list more bridges under the new `more_sniffers` option (name, address,
  port) and name the first with `sniffer_name`. A transmission heard by several sniffers is
  counted once (same bytes within a quarter of a second) and stored once, with the strongest
  copy; each sniffer's signal is kept per device. Frames a sniffer buffered during a Wi-Fi drop
  still merge with the copies the others heard live.
- The Sniffer page has a chip per sniffer (health and firmware updates act on the chosen one; a
  channel change moves them all); the status pill shows how many are connected, and a banner names any that
  aren't. A device's page shows how well each sniffer hears it; Live shows how many sniffers
  heard a frame (hover for each one's signal). Each extra sniffer gets its own Home Assistant
  device (connected, radio link, Wi-Fi, disconnects, late frames, firmware), and events name
  the sniffer.
- **Map** tab: floors drawn from an uploaded plan (PNG, JPG, SVG) or a blank grid of a given
  size; set the scale by marking two points a known distance apart; place the sniffers and the
  devices by clicking, drag to move. On top, a **coverage heat map**: the app fits a path-loss
  model (signal per tenfold distance, loss per floor, each device's own strength) to what the
  placed sniffers measure, then shows the strongest router signal estimated at every spot
  (or the second strongest, to see where there is no backup). Also each sniffer's measured
  signal, interpolated between the devices it hears; mesh links between placed routers; end
  devices; device names. Hover anything for the details.
- Capture files: up to three hour files stay open, so buffered frames from an earlier hour no
  longer reopen files over and over.

## 0.4.2

- Fewer false alarms (seen on the live network, where 18 devices were flagged): resent frames
  are a note from 8%, a warning from 15% and a problem from 30%; "no ACK heard" stays a note
  (usually ACKs the sniffer missed) unless it passes 50% on a device the sniffer hears well.
- The example automation on the Sniffer page notifies on events only.

## 0.4.1

- Home Assistant entities and events actually start: the Supervisor token is read from s6's
  container environment (the app runs with a clean environment under the image's init).

## 0.4.0

- **Sniffer page** for the hardware: the link to the bridge, the bridge's Wi-Fi, its frame
  buffer, both boards' firmware and trial state (a rolled-back radio shows up as a finding),
  restarts, UART errors; with history charts (connected time, Wi-Fi signal, disconnects, late
  and lost frames) and an events list. The app now reads the bridge's own status page.
- **Firmware updates from Home Assistant**: choose a `.bin` (or one in
  `/share/zigbee_sniffer/firmware`); the app checks the project, chip and board before anything is
  sent, then updates the radio or the bridge through the bridge and shows the outcome. Needs
  the new `update_token` option (the bridge's CONFIG_BRIDGE_UPDATE_TOKEN).
- **Channel** can be changed on the Sniffer page; the choice is kept across reconnects and
  restarts until you go back to the configured one.
- **Home Assistant entities** over MQTT discovery (needs the Mosquitto add-on): a Zigbee Sniffer
  device (connected, radio link, Wi-Fi signal, frames per minute, channel busy, resent, devices
  with problems, disconnects, firmware of both boards, channel), and a **Zigbee health** sensor
  on every Zigbee2MQTT device (ok / note / warning / problem / not heard, findings as attributes).
  Options `publish_to_ha` and `device_sensors`.
- **Events** `zigbee_sniffer_event` on Home Assistant's bus for leaves, rejoins, announcements,
  route errors, orphans, address changes, joins, the sniffer going offline (2 min) and coming
  back, board restarts and firmware updates. The Sniffer page shows an example automation.
- **Ping** on a device's page: Zigbee2MQTT reads the device's ZCL version and the sniffer traces
  the request and the reply hop by hop (signal, resends, ACKs) with the round-trip time.

## 0.3.2

- Takes the frames the bridge buffers (bridge 0.3+): on connecting the app asks for them
  (CLIENT_HELLO), and each frame then comes with the time the radio heard it (FRAME_AT), so a
  Wi-Fi drop costs time, not frames. The backlog arrives first, oldest first, and lands in its
  own hour's capture file and minute of the history. In Live such frames carry a "buffered"
  badge; the Overview's Sniffer panel counts them. Older bridges keep working as before.
- At start-up the last two hours of captures are counted before frames are taken, so a backlog
  that reaches into the previous hour isn't counted twice.

## 0.3.1

- Installed from an add-on repository instead of as a local add-on.
- A short address change (or a short address taken over by another device) is only believed
  once 3 frames agree: a single frame with a flipped bit no longer raises "its short address
  changed".
- A Link Status cost of 0 means the router doesn't know the cost yet; it is shown as "–" and
  no longer counts as a perfect link in the mesh findings and the map.

## 0.3.0

A troubleshooting tool rather than a counter: history, a page per device, the mesh, and every
frame decoded in full.

- **History.** Per-minute counters for every device and the whole network are kept in
  `/data/history.db` (SQLite) for as long as the captures (`retention_days`), and survive
  restarts. Frames written while the app was down (or by 0.2.0) are counted from the capture
  files at start-up, so the history has no holes where captures exist.
- **Device pages.** Click any device: signal at the sniffer over time (average with the
  min–max band), traffic it sent and relayed, delivery (resent frames, missing ACKs), the mesh
  commands it sent, its mesh neighbours with link costs both ways, how its messages travel
  (the hops the sniffer heard), who it sends to and hears from, its events, and its recent
  frames. Time range 1 h / 6 h / 24 h / 7 days.
- **Findings.** Each device gets plain-language findings, ranked: silent devices (against how
  often it usually talks), retries, missing ACKs, leaves, rejoins, announces, address changes,
  route errors, route discovery, weak mesh links, and devices heard only through relays.
  Network-wide: sniffer drops, a busy channel, neighbours' share, beacon storms. The Overview
  leads with them.
- **Decrypted events and mesh links.** A tshark pass reads the encrypted NWK commands with
  the network key: Leave, Rejoin, Network Status (route errors), Device Announce, route
  requests, and the routers' Link Status (each router's neighbour table with incoming and
  outgoing cost, every 15 s).
- **Mesh map.** A live map of who hears whom from Link Status, coloured by link cost, with end
  devices on their parents. Drag to rearrange; weakest links and fragile routers listed below.
- **Full frame decode.** Click any frame (Live, Captures, a device's recent frames) for
  tshark's full protocol tree, MAC to ZCL/ZDO, decrypted, with raw and decrypted hex.
  Live shows tshark's decoded summary for every frame; ACKs show who acknowledged whom.
- **Devices table.** Sortable, searchable, with filters (need attention, routers, end
  devices, faint, not heard), a signal meter, trend sparkline, mesh link costs, next hop,
  resent and no-ACK rates, and Zigbee2MQTT devices the sniffer hasn't heard at all.
- Captures: filter by device or resent frames only; links from events open the exact frame.
- The `.pcap` files are unchanged and stay compatible with Wireshark.

## 0.2.0

- The pages show our network only: frames are told apart by PAN ID (Zigbee2MQTT's), so
  neighbours' Zigbee and Thread networks on the same channel no longer appear as weak devices
  of ours or under our devices' names. The Overview counts them separately and lists them in
  their own table; Live and Captures can show them with "Other networks". An ACK takes the
  network of the frame it answers; ACKs of frames not heard count as naming no network. The `.pcap` files
  and the live Wireshark stream still carry every frame heard.
- Capture files are named by local hour, as documented: the image now has time-zone data, so
  the app follows Home Assistant's time zone (0.1.0 used UTC). Files from 0.1.0 are renamed
  to their local hour at start-up.

## 0.1.0

- First version: connects to the sniffer bridge, hourly pcap files (IEEE 802.15.4 TAP with
  RSSI/LQI/channel), retention, live Wireshark stream, sidebar page with overview, live view,
  and decoded/searchable captures (network key read from Zigbee2MQTT).
