/*
 * Zigbee sniffer wire protocol, shared by the C6 radio, the S3 bridge and (in Python) the HA app.
 *
 * The same framing runs on the UART between the boards and on the TCP stream from the bridge
 * to Home Assistant, and on a radio's own USB port when it is plugged straight into the Home
 * Assistant box (radio 0.3+, CONFIG_SNIFF_LINK_USB): there the app speaks the bridge's side of the
 * radio messages (SET_CHANNEL, PING, UPDATE_*) and gets plain SNIFF_T_FRAME:
 *
 *   0xA5 0x5A | type (u8) | length (u16 LE) | payload[length] | crc16 (u16 LE)
 *
 * crc16 is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over type, length and payload.
 * All multi-byte fields are little-endian.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define SNIFF_SYNC0 0xA5
#define SNIFF_SYNC1 0x5A

#define SNIFF_HEADER_LEN  5 /* sync(2) + type(1) + length(2) */
#define SNIFF_TRAILER_LEN 2 /* crc16 */
#define SNIFF_MAX_PAYLOAD 512

enum {
    /* radio -> bridge -> app */
    SNIFF_T_FRAME        = 0x01, /* one received 802.15.4 frame, see sniff_frame_hdr_t */
    SNIFF_T_RADIO_STATUS = 0x02, /* once a second, see sniff_radio_status_t */
    /* bridge -> app */
    SNIFF_T_HELLO         = 0x03, /* first on every connection: JSON, see "Buffered frames" below */
    SNIFF_T_BRIDGE_STATUS = 0x04, /* every 5 s, see sniff_bridge_status_t */
    SNIFF_T_FRAME_AT      = 0x06, /* a frame with its time on the bridge's clock, see below */
    /* app -> bridge -> radio */
    SNIFF_T_SET_CHANNEL = 0x10, /* payload: u8 channel (11..26) */
    /* app -> bridge */
    SNIFF_T_CLIENT_HELLO = 0x12, /* right after connecting: u32 flags (SNIFF_CLIENT_*) */

    /* Between the boards only (the bridge never forwards these to the app). */
    SNIFF_T_RADIO_BOOT = 0x05, /* radio -> bridge: see sniff_radio_boot_t; at boot, every 30 s, on a passed trial */
    SNIFF_T_PING       = 0x11, /* bridge -> radio, every second: u8 flags (SNIFF_PING_*) */

    /* Radio firmware update over the UART, bridge -> radio. Stop-and-wait: one message, one ack. */
    SNIFF_T_UPDATE_BEGIN = 0x20, /* u32 image size */
    SNIFF_T_UPDATE_DATA  = 0x21, /* u32 offset, then 1..SNIFF_UPDATE_CHUNK image bytes */
    SNIFF_T_UPDATE_END   = 0x22, /* empty: check the image and reboot into it on trial */
    SNIFF_T_UPDATE_ABORT = 0x23, /* empty */
    SNIFF_T_UPDATE_ACK   = 0x24, /* radio -> bridge: see sniff_update_ack_t */
};

#define SNIFF_PING_RADIO_HEARD 0x01 /* the bridge got a radio status in the last 3 s */

/*
 * Buffered frames (bridge 0.3+). The bridge keeps every frame while no app is connected, or while
 * the link is slow, and delivers it later, so a weak Wi-Fi link costs time, not frames.
 *
 *   HELLO (bridge -> app, sent before anything else): {"bridge":"x.y.z","bridge_us":N,
 *     "backlog_bytes":M}. bridge_us is the bridge's clock (microseconds since it booted) at the
 *     moment it sends the HELLO: the app pairs it with its own wall time on arrival.
 *   CLIENT_HELLO (app -> bridge): u32 flags. SNIFF_CLIENT_FRAME_AT = the app takes SNIFF_T_FRAME_AT
 *     and the backlog. An app that sends no CLIENT_HELLO within 3 s (older apps) gets what it always
 *     got: plain SNIFF_T_FRAME, live only (frames buffered before it connected are dropped).
 *   FRAME_AT (bridge -> app): u64 bridge_us, then a SNIFF_T_FRAME payload (sniff_frame_hdr_t +
 *     PSDU). bridge_us is when the radio heard the frame, on the bridge's clock: the radio
 *     timestamp plus the radio-to-bridge clock offset, so spacing keeps the radio's microsecond
 *     precision. Wall time = HELLO wall time + (bridge_us - HELLO bridge_us) / 1e6, for live and
 *     backlog frames alike. Frames come oldest first; a backlog can run hours into the past.
 */
#define SNIFF_CLIENT_FRAME_AT 0x01

#define SNIFF_UPDATE_CHUNK 480 /* image bytes per SNIFF_T_UPDATE_DATA (fits SNIFF_MAX_PAYLOAD) */

/* Firmware state, as each board reports its own. */
enum {
    SNIFF_FW_RUNNING     = 0, /* not on trial (flashed over USB, or a trial that passed long ago) */
    SNIFF_FW_TRIAL       = 1, /* a new image on its first run: rolls back unless it passes its check */
    SNIFF_FW_CONFIRMED   = 2, /* this run's trial passed: the image is kept */
    SNIFF_FW_ROLLED_BACK = 3, /* a newer image failed its trial; the board came back to this one */
};

typedef struct __attribute__((packed)) {
    uint8_t version[3]; /* radio firmware major, minor, patch */
    uint8_t state;      /* SNIFF_FW_* */
} sniff_radio_boot_t;

/* What radio 0.3+ sends as SNIFF_T_RADIO_BOOT: the 4 bytes above (all an older bridge reads), then
 * the ESP-IDF image chip id it was built for (13 = ESP32-C6, 23 = ESP32-C5), so whoever updates it
 * can refuse an image for the other chip. */
typedef struct __attribute__((packed)) {
    sniff_radio_boot_t boot;
    uint16_t           chip_id;
} sniff_radio_boot_ext_t;

typedef struct __attribute__((packed)) {
    uint8_t  stage;  /* the SNIFF_T_UPDATE_* message this answers */
    uint32_t offset; /* image bytes the radio holds after it */
    int32_t  err;    /* esp_err_t, 0 = ok */
} sniff_update_ack_t;

/* SNIFF_T_FRAME payload: this header, then the PSDU without FCS (MAC header + MAC payload). */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us; /* radio timestamp of the SFD, microseconds since radio boot */
    uint8_t  channel;
    int8_t   rssi; /* dBm */
    uint8_t  lqi;
    uint8_t  flags; /* bit 0: frame was acked with frame-pending set */
} sniff_frame_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t uptime_s;
    uint32_t frames;  /* frames received since boot */
    uint32_t dropped; /* frames lost because the UART queue was full */
    uint8_t  channel;
    uint8_t  version[3]; /* radio firmware major, minor, patch */
} sniff_radio_status_t;

typedef struct __attribute__((packed)) {
    uint32_t uptime_s;
    uint32_t uart_frames;    /* valid frames from the radio */
    uint32_t uart_crc_errors;
    uint32_t tcp_dropped;    /* frames lost: the buffer was full, or (older app) sent before it connected */
    int8_t   wifi_rssi;
    uint8_t  radio_link_ok;  /* a radio status arrived in the last 3 s */
} sniff_bridge_status_t;

static inline uint16_t sniff_crc16(const uint8_t *data, size_t len, uint16_t crc)
{
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/**
 * Build one framed message into out (which needs payload_len + 7 bytes).
 * @return total bytes written
 */
static inline size_t sniff_encode(uint8_t *out, uint8_t type, const void *payload, uint16_t payload_len)
{
    out[0] = SNIFF_SYNC0;
    out[1] = SNIFF_SYNC1;
    out[2] = type;
    out[3] = (uint8_t)(payload_len & 0xFF);
    out[4] = (uint8_t)(payload_len >> 8);
    const uint8_t *p = (const uint8_t *)payload;
    for (uint16_t i = 0; i < payload_len; i++) {
        out[SNIFF_HEADER_LEN + i] = p[i];
    }
    const uint16_t crc = sniff_crc16(&out[2], 3u + payload_len, 0xFFFF);
    out[SNIFF_HEADER_LEN + payload_len]     = (uint8_t)(crc & 0xFF);
    out[SNIFF_HEADER_LEN + payload_len + 1] = (uint8_t)(crc >> 8);
    return SNIFF_HEADER_LEN + payload_len + SNIFF_TRAILER_LEN;
}

/* Incremental decoder: feed bytes one at a time; returns 1 when a valid message is complete. */
typedef struct {
    uint8_t  state;
    uint8_t  type;
    uint16_t length;
    uint16_t got;
    uint8_t  buf[3 + SNIFF_MAX_PAYLOAD + 2]; /* type, length(2), payload, crc(2) */
    uint32_t crc_errors;
} sniff_decoder_t;

static inline int sniff_decode_byte(sniff_decoder_t *d, uint8_t byte)
{
    switch (d->state) {
    case 0:
        d->state = (byte == SNIFF_SYNC0) ? 1 : 0;
        return 0;
    case 1:
        d->state = (byte == SNIFF_SYNC1) ? 2 : (byte == SNIFF_SYNC0 ? 1 : 0);
        d->got   = 0;
        return 0;
    case 2: /* type + length */
        d->buf[d->got++] = byte;
        if (d->got == 3) {
            d->type   = d->buf[0];
            d->length = (uint16_t)(d->buf[1] | (d->buf[2] << 8));
            if (d->length > SNIFF_MAX_PAYLOAD) {
                d->state = 0;
                d->crc_errors++;
                return 0;
            }
            d->state = 3;
        }
        return 0;
    case 3: /* payload + crc */
        d->buf[d->got++] = byte;
        if (d->got == 3u + d->length + 2u) {
            d->state             = 0;
            const uint16_t want  = sniff_crc16(d->buf, 3u + d->length, 0xFFFF);
            const uint16_t have  = (uint16_t)(d->buf[3 + d->length] | (d->buf[4 + d->length] << 8));
            if (want != have) {
                d->crc_errors++;
                return 0;
            }
            return 1;
        }
        return 0;
    default:
        d->state = 0;
        return 0;
    }
}

/* After sniff_decode_byte() returned 1: */
static inline const uint8_t *sniff_payload(const sniff_decoder_t *d)
{
    return &d->buf[3];
}
