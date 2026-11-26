# Zigbee Sniffer

A Zigbee troubleshooting tool built on ESP32 sniffers (firmware in `firmware/`
of this repository): an ESP32-C6 radio behind a Wi-Fi bridge, or a radio plugged straight
into this box's USB. The app listens through them, writes everything it hears to hourly capture
files, keeps a history per device, and shows it all in the sidebar.

## Configuration

| Option | Meaning |
| --- | --- |
| `sniffer_host` | The bridge's IP address (it prints it at boot; a DHCP reservation keeps it fixed) |
| `sniffer_port` | Bridge TCP port, 6638 |
| `sniffer_name` | What to call this sniffer when there are several (Main) |
| `more_sniffers` | Other bridges to listen through as well: `name`, `host`, optional `port` |
| `usb_sniffers` | Radios plugged into this box's USB: `name` (optional) and `device` (pick the `/dev/serial/by-id/...` one). See below |
| `channel` | Zigbee channel to listen on (Zigbee2MQTT uses 25) |
| `retention_days` | Delete captures and history older than this |
| `max_storage_mb` | Also delete the oldest captures past this total |
| `decode` | Decrypt frames with tshark: summaries, full frame decode, events and mesh links |
| `update_token` | The bridge's `CONFIG_BRIDGE_UPDATE_TOKEN` (in `s3-bridge/sdkconfig.secrets`): lets the Sniffer page update firmware |
| `publish_to_ha` | Sensors over MQTT and `zigbee_sniffer_event` events in Home Assistant |
| `device_sensors` | A "Zigbee health" sensor on each Zigbee2MQTT device |
| `zigbee_studio` | Let the Zigbee Studio add-on show the Sniffer's findings, charts, live frames and maps, and set up the floor maps (floors, plans, where devices are), with a key kept in `/share/zigbee_sniffer`. Nothing else: the channel, firmware and sniffers stay on this page. Off: only this page gets answers |

## The pages

The time range (1 h, 6 h, 24 h, 7 days) at the top applies to Overview, Devices, a device's
page and Mesh.

- **Overview**: incidents first (network-wide trouble, see below), devices downloading firmware,
  then what needs attention, recent events (joins, leaves, rejoins, route errors), traffic, how
  busy the channel is, delivery (resent frames, missing ACKs), route discovery, and the other
  networks sharing the channel. Click a bar on any chart to open the captured frames of that moment.
- **Devices**: every device heard, plus Zigbee2MQTT's devices the sniffer hasn't heard.
  Sort by any column; filter to the ones that need attention. Click one for its page.
- **A device's page**: the incidents it was part of, its findings, signal at the sniffer over
  time, traffic it sent and relayed, delivery, where its resends go (per neighbour), the mesh
  commands it sent, its mesh neighbours and their link costs, how its messages travel, who it
  talks to over the air, its events and its recent frames. Its normal (the 7 days before the
  range) is shown under its numbers. "Watch live" shows only its frames; "Search captures" lists
  the hours it was heard in.
- **Mesh**: a map of who hears whom from the routers' Link Status, coloured by link cost, end
  devices next to their parents. Drag devices to rearrange; click one to open it.
- **Map**: your floors with the sniffers and devices where they really are, and a coverage
  heat map (see below).
- **Live**: the latest frames with tshark's decoded summary. "Over the air" is the hop the
  sniffer heard; "Network layer" is the real origin and destination, which differ when a router
  relays a message. ACKs show who acknowledged whom.
- **Captures**: any stored hour, decoded and searchable (a device name, `Leave`, `Rejoin`,
  `Route`, `Report Attributes`...), filtered by device or to resent frames. It says how far back
  the captures go and how much of the storage limit they use (on a busy channel the limit, not
  `retention_days`, decides).

- **Sniffer**: the hardware. The link to the bridge, its Wi-Fi, its buffer, both boards' firmware
  and trial state, restarts and UART errors, with history charts and an events list. Update
  firmware and change the channel here.

On a device's page, **Ping** asks Zigbee2MQTT to read the device's ZCL version and traces the
round trip on air: each hop of the request and of the reply, the sender's signal at the sniffer,
how many tries it took and whether an ACK came back, and the total time. A sleepy end device
only answers after its next poll, so give it a few seconds. **Ping ×5** does it five times and
shows how many came back and the median and longest round trip.

Charts carry markers for what Zigbee2MQTT did (restarted, a device joined, was interviewed, left,
finished or failed a firmware update), for channel changes and sniffer disconnects: hover one for
what it was. Incidents are shaded.

Click any frame, on any page, for the full decode: tshark's protocol tree from the radio
header to ZCL/ZDO, decrypted, with the raw and decrypted bytes.

## Several sniffers

One sniffer only hears what reaches its corner of the house. Add more bridges under
`more_sniffers`, for example:

```yaml
sniffer_name: Main
more_sniffers:
  - name: Upstairs
    host: 192.168.1.61
```

A radio plugged into this box counts as one more sniffer (see "A sniffer on USB").

All of them listen on the same channel. A transmission several sniffers heard is counted once,
kept with the strongest copy, and each sniffer's signal goes into the history:

- **Matching.** Copies with the same bytes, heard at the same moment by different sniffers, are
  one transmission. Each bridge has its own clock; the app learns how they line up from the
  copies that match (usually to well under a millisecond, shown on the Sniffer page as "Its
  timing"). A MAC retry has the same bytes as the first try, but a sniffer that already heard the
  first try makes it a new transmission, and once the clocks line up closely a retry one sniffer
  heard is kept apart from the first try another heard, so retries still count.
- **Order.** A transmission goes out (to the capture, the history, Live) once every sniffer has
  delivered its frames up to that moment. A sniffer whose Wi-Fi drops, stalls or that is sending
  what it buffered holds the others back until it has caught up (at most 30 s, never more than a
  minute after a frame arrived). Live then says "waiting for <sniffer>'s frames" in the header
  bar. That way frames from a Wi-Fi drop or a bridge update are written in time order next to
  their ACKs, and merged rather than counted twice.
- **Restarts.** When the app starts it remembers what the last 25 minutes of captures hold, so
  a bridge's backlog of frames from before the restart isn't written a second time.
- **Which sniffers heard each frame** is kept beside each capture, in `<hour>.pcap.sniffers`.
  Live and Captures show "×2" after a frame's signal (hover for each sniffer's), or the name of
  the one sniffer that heard it.

**Signal with several sniffers.** Sniffers can differ by 10-20 dB just from their antennas and
where they sit, so one sniffer's dBm can't be compared with another's. How to read it:

- **Devices** has a column per sniffer ("Signal at Main", "Signal at Sniffer 2"): how loud each
  hears the device. Bold is the sniffer that hears it best; ▼9 means 9 dB weaker than its normal
  at that sniffer (▲ stronger). Compare a device with itself, at the same sniffer, over time.
- **A device's page**, Signal card: a row per sniffer with its signal now, its normal (the 7-day
  average at that sniffer) and the change. The chart's **vs normal** view puts each sniffer's line
  against its own normal, so the lines lie together at 0 while all is well and dip together when
  the device really got weaker (moved, something in the way, failing). **dBm** shows the raw
  levels. A sniffer without 7 days of history yet is drawn against its average over the range.
- The device's headline signal, the Home Assistant attribute (`heard_best_by` says which) and
  "faint" use the sniffer that hears it best. "Weaker than usual" compares each sniffer with its
  own normal and only fires when every sniffer that heard the device then and now agrees.
- A sniffer's normals need **12 hours** of history where it is now; until then its column has no
  ▼ / ▲ and it plays no part in "weaker than usual" (the Sniffer page shows how far it is). After
  moving a sniffer (or changing its antenna) press **Moved it** on its Sniffer page, in What it
  adds: its normals start again from there, and the move is marked on every device's charts. The
  page suggests it when most devices sound different at that sniffer at once. A sniffer going offline
or moving therefore doesn't make the whole network look weaker. When a sniffer is added, goes
offline or comes back, a marker goes on every device's charts, since what is heard of a device
changes with it.

The Sniffer page shows one sniffer at a time (pick it with the chips at the top); firmware
updates act on that one. Its **What it adds** card says what share of our network's
transmissions it heard, how many only it heard, which devices only it hears, and how much louder
or quieter it hears the devices it shares with each other sniffer (antenna and place). The
channel is the network's, so changing it moves every sniffer. A device's page lists how well
each sniffer hears it. In Home Assistant the first sniffer is the Zigbee Sniffer device; each
other one gets a "Zigbee Sniffer <name>" device of its own, and its events name it. A sniffer
connecting for the first time is a `sniffer_added` event.


## A sniffer on USB

A sniffer radio can also plug straight into the Home Assistant box, with no bridge and no
Wi-Fi: a XIAO ESP32C5 (or ESP32C6) running the radio firmware 0.3+ built for USB
(`sdkconfig.defaults.c5usb` in `firmware/c6-radio`). Add it under `usb_sniffers`:

```yaml
usb_sniffers:
  - name: HA box
    device: /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_10:BD:A3:CD:BA:2C-if00
```

- **Only an ESP32's own USB port.** The device list also shows the Zigbee and Thread dongles; the
  app refuses anything that isn't an Espressif USB device (vendor 303a) before opening it, and
  says so on the Sniffer page.
- **The app plays the bridge.** It sets the channel, pings the radio every second and reads its
  frames, statuses and firmware state over the cable. The Sniffer page shows "USB link" and
  "Plugged into this box" instead of the bridge's Wi-Fi and buffer.
- **Updates go over the cable.** Pick a radio image on its Sniffer page (no `update_token`
  needed). The radio writes it, restarts into it, and keeps it once it hears the app again
  (otherwise it rolls back). The app refuses an image built for the other chip.
- **Where it hears.** Beside the coordinator it hears about what Zigbee2MQTT hears: useful for
  checking deliveries, less so for weak corners of the house. Put it on a short USB extension
  cable, away from the Zigbee and Thread dongles and the box's USB 3 ports.
- **Nothing is buffered.** The cable doesn't drop like Wi-Fi, but frames heard while the app is
  stopped (an update, a restart) are lost: the radio counts them as dropped.
## Map and coverage

On the Map tab, add a floor: upload its plan (PNG, JPG or SVG) or start from a blank grid of a
given size in metres. Draw every floor on the same grid (same corner, same scale) so the levels
line up, and give each a level (0 ground, 1 upstairs, -1 basement). Then **Edit layout**:

1. **Set scale**: click two points on the plan a known distance apart and type the distance (m
   or ft). A blank grid already has one.
2. **Place**: click a sniffer or device in the list, then click where it is; drag to move it.
   Place at least your sniffers and the routers.
3. Set the height between floors if it isn't about 3 m.

The coverage layers:

- **Coverage** is the strongest signal any router (or the coordinator) is estimated to deliver at
  each spot; **Backup coverage** is the second strongest, which shows where a device would have
  nowhere to go if its router failed. Green is strong; yellow from about -80 dBm, orange -88,
  red -98 (Zigbee's floor is around -100).
- The estimate comes from what the placed sniffers measure: each device's signal at each sniffer
  against the distance and floors between them. From that the app fits how fast signal falls
  with distance (n, typically 2-3.5 indoors), how much a floor costs (often 10-20 dB), and each
  device's own strength (a mains router with a good antenna is louder than a bulb). The floor
  loss is only fitted when some sniffer hears devices on another floor; until then it is taken
  as 15 dB. Each sniffer's antenna is fitted too, from the devices two sniffers both hear (a
  better antenna hears everything louder, which says nothing about the house): strengths and
  the map are as the first sniffer would hear them. Below the map it says what was fitted,
  including "Sniffer 2 hears 17 dB louder than Main", and the typical error in dB. Walls only
  count on average, so read it as a guide: it shows where coverage is thin, not the exact dBm.
- **Heard by <sniffer>** is measured, not estimated: that sniffer's signal from each placed
  device, spread between them. It shows what the sniffer can hear, not what the devices hear.

Mesh links between placed routers (coloured by link cost), end devices and names can be
toggled on top. Hover anything for its details; click a device to open its page.

## Firmware updates

Set `update_token` to the bridge's `CONFIG_BRIDGE_UPDATE_TOKEN`. On the Sniffer page choose a
`.bin` (the app image from `idf.py build`: `c6-radio/build/zigbee_sniffer_radio.bin` or the
bridge's), or put images in `/share/zigbee_sniffer/firmware` and press Check. The app reads the
image's project, chip and version and refuses one meant for the other board (or for the other
bridge board) before anything is sent. Confirm, and it goes to the bridge: a bridge update
restarts the bridge, which keeps the image once its Wi-Fi has been up 30 s; a radio update is
relayed over the UART (the radio stops listening for about 30 s) and kept once the boards hear
each other. Either rolls back by itself otherwise, and the page shows which.

## Home Assistant

With the Mosquitto add-on running, the app publishes over MQTT discovery:

- a **Zigbee Sniffer** device: Connected, Radio link problem, Zigbee devices with problems (the
  list as attributes), Frames per minute, Channel busy, Frames resent, Bridge Wi-Fi signal,
  Bridge disconnects (24 h), Frames delivered late, Radio firmware, Bridge firmware, Zigbee channel;
- on every Zigbee2MQTT device, a **Zigbee health** sensor: `ok`, `note`, `warning`, `problem` or
  `not heard` (over the last hour), with the findings, signal at the sniffer (and with several,
  `heard_best_by`: which one), resent and no-ACK rates, best mesh link cost, next hop and last
  heard as attributes.

It also fires `zigbee_sniffer_event` with `kind`, `device`, `address`, `ieee`, `detail` and `time`
for: `leave`, `rejoin`, `rejoin_response`, `announce`, `network_status` (route error), `orphan`,
`address_change`, `address_reused`, `address_conflict`, `bad_frame_counter`, `association`,
`association_response`, `incident` (network-wide trouble started), `ota_done`, `ota_failed`,
`sniffer_offline` (no connection for 2 minutes), `sniffer_back`, `sniffer_added`, `bridge_reboot`,
`radio_reboot`, `firmware_update`. The same kind for the same device (or sniffer) is fired at most
once a minute. Health sensors of devices removed from Zigbee2MQTT are removed again. For example:

```yaml
alias: Zigbee trouble
triggers:
  - trigger: event
    event_type: zigbee_sniffer_event
    event_data: { kind: leave }
  - trigger: event
    event_type: zigbee_sniffer_event
    event_data: { kind: sniffer_offline }
actions:
  - action: notify.notify
    data:
      title: Zigbee
      message: "{{ trigger.event.data.device }}: {{ trigger.event.data.detail }}"
```

## When the bridge's Wi-Fi drops

Bridge firmware 0.3 and later keeps every frame while the app isn't connected (about 10-15
minutes in its 1.5 MB buffer) and sends them when the app reconnects, each with the time the
radio heard it. They go into their own hour's capture file and the history as if they had come
live; Live marks them "buffered". With an older bridge, frames heard while disconnected are lost.

## Reading the numbers

- **Signal at the sniffer** (RSSI) is how well the *sniffer* hears a device. It depends on
  where the sniffer sits and on its antenna, so a faint device is only a hint. With several
  sniffers it is the one that hears the device best.
- **Mesh link cost** is what the routers themselves report in their Link Status, every 15 s,
  for each neighbour: incoming (how well it hears the neighbour) and outgoing (how well the
  neighbour hears it). 1 is excellent, 3 is fine, 5 is poor, 7 is barely usable. This is the
  best measure of the mesh itself.
- **Resent**: unicast frames the device sent again because no ACK came back in time (MAC
  retries). A few percent is normal; from 8% it is noted, from 15% it is a warning: a poor link
  to its next hop.
- **No ACK**: frames sent to the device whose ACK the sniffer didn't hear. Either the device
  didn't get them - then the sender sends the frame again, and the app counts it as **lost** - or
  the sniffers missed its ACK (it is faint, or the ACK collided) and the sender carried on. The
  finding is judged on the lost ones: from 10% of what was sent to it it is noted, from 30% it is
  a warning; when nearly all missing ACKs are the sniffers', there is no finding. A device's page
  shows both numbers.
- **Messages** are the device's own network-layer messages, counted once however many routers
  relay them, so devices the sniffer can't hear directly still show activity.
- **Relayed**: frames a router forwarded for other devices.
- **Route errors** (Network Status) are a router saying it couldn't deliver toward a device. The
  most common kind, a *many-to-one route failure*, means the reporting router couldn't pass a
  frame up toward the coordinator: that is shown on the reporting router ("couldn't forward
  traffic toward the coordinator"), because its route up the mesh is what broke. Route errors are
  counted in distinct minutes (a router repeats its status for every frame it can't pass).
  **Route requests** from a device mean it is looking for new routes because old ones broke.
- **Silent** compares how long a device has been quiet (heard directly or through relays) with
  how often it usually talks, up to the last frame any sniffer heard; nothing is judged silent
  while no sniffer is connected.
- **Where its resends go**: resends and missing ACKs per neighbour. One bad neighbour among good
  ones points at that link (distance, interference, that router overloaded).
- **Normal** is the device's own average over the 7 days before the range. Resends are judged
  against the larger of 8 %, twice the network's rate and twice its normal; a warning needs at
  least 40 frames, a problem 100.

## Incidents

When the whole mesh is in trouble at the same time, the per-device findings would all say the
same thing. Instead the Overview shows an **incident**: a stretch where traffic was several times
its normal, or five or more devices had route failures within a few minutes, or several devices
were downloading firmware, or a tenth of unicast frames had to be resent. It lists the evidence
(traffic ×, channel busy, resent %, devices involved) and a likely cause: firmware updates (read
from the OTA frames on air) or Zigbee2MQTT restarting (from its MQTT state). Findings of the
devices involved that fall inside it are marked "during incident" and count one level lower; a
device that also has trouble outside the incident keeps its warning.

## Firmware updates of Zigbee devices

Zigbee2MQTT sends firmware to a device block by block over the mesh, and the decode pass reads
those frames (the OTA Upgrade cluster). Each download shows as a session, on the Overview, in
Devices ("updating 45%") and on the device's page:

- **Progress, speed and ETA** from the blocks' file offsets; **picked up at 97%** when the device
  resumed a download that had been cut off (the bar shades the part it already had).
- **How it ended**: the device's Upgrade End (success, or why it gave up), or Zigbee2MQTT's
  result with the versions ("updated from 1.0.42.0 to 1.0.43.0"), and **restarted** when the
  device announced itself afterwards (it installs the image and reboots).
- **Versions**: Zigbee2MQTT's installed and latest version per device, read from its state.json
  (rewritten every few minutes), so the Overview also lists the updates **available** that
  haven't started. A device's page has a Firmware card with its version and downloads.

Downloading fills the channel (each block is a frame, relayed hop by hop), so an update of many
devices at once shows as an incident, which ends when the downloads do.

## Where things are stored

- Captures: `/share/zigbee_captures/YYYY-MM-DD/zigbee_YYYY-MM-DD_HH.pcap`, one file per hour
  in Home Assistant's time zone, with RSSI, LQI and channel per frame (pcap link type 283,
  IEEE 802.15.4 TAP). They hold every frame the radio heard, other networks' included.
  Download them from Captures and open them in Wireshark; to decrypt there, add the network
  key under Preferences → Protocols → ZigBee → Security Keys. With several sniffers, the
  frame's RSSI is the strongest copy's, and `<hour>.pcap.sniffers` next to it lists every
  sniffer that heard each frame (by frame number) with its signal. It counts toward
  `max_storage_mb` and is deleted with its capture.
- History: `/data/history.db` (SQLite), per-minute counters per device and for the network,
  the hops between devices, events and Link Status costs, pruned with `retention_days`. If the
  app was stopped, it counts the frames in the captures it hasn't seen yet when it starts.
- Counting captures again: after capture files were changed by hand (repaired), list them in
  `/share/zigbee_captures/recount.json` as `{"files": ["YYYY-MM-DD/zigbee_YYYY-MM-DD_HH.pcap", ...],
  "reason": "why"}` and restart the app. It takes those hours out of the history and counts the
  files again from scratch (the log says when it's done, and the request file goes away).

## Decryption

The app reads the network key from Zigbee2MQTT's `configuration.yaml` (or its `secret.yaml`)
on this HA host and writes it only to tshark's key table in the app's private `/data` folder.
It is never shown, logged, or sent anywhere: where tshark prints the key it used (or a key a
frame carries, as in a Transport Key command), the page and the downloads say "hidden". The
saved `.pcap` files stay encrypted, as captured. Without the key the history still has signal,
traffic, retries, ACKs and hops (they are in clear headers), but no events, mesh links or
decoded summaries.

The page answers only through Home Assistant (the sidebar, which checks your login). Other
add-ons can reach the app's port on Home Assistant's internal network, but get nothing.

## Live in Wireshark (optional)

Set a host port for `17760/tcp` in the app's Network settings, then in Wireshark capture from
the interface `TCP@<HA address>:17760`.

## Our network and the others

The sniffer hears every network on its channel: neighbours' Zigbee, Thread (Matter) networks.
Frames name their network by PAN ID, so the app shows only ours, the PAN ID in Zigbee2MQTT's
`configuration.yaml` (`advanced.pan_id`, else its coordinator backup). Other networks share
the airtime, so the Overview counts them, but their devices are left out of the tables and
never get our devices' names (each network reuses the same short addresses). An ACK names no
network, so it takes the network of the frame it answers; ACKs whose frame the sniffer didn't
hear are counted as "naming no network".
