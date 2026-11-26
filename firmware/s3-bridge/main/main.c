/*
 * Zigbee sniffer, Wi-Fi half (ESP32-S3 Super Mini or ESP32-S3-DevKitC-1-N16R8; see the
 * sdkconfig.board.* files).
 *
 * Reads framed messages from the radio board over UART, checks them, and serves them to one TCP
 * client: the Home Assistant "Zigbee Sniffer" app, which connects here (the same direction HA
 * uses to reach ESPHome devices). Channel changes from the app go back down to the radio.
 *
 * Every frame goes into a buffer (PSRAM: ~15 min on a Super Mini, ~50 on a DevKitC) stamped with the bridge's
 * clock, and stays there until the app has it: while HA is disconnected or the Wi-Fi link is
 * slow, frames wait instead of being lost. An app that asks for buffered frames (CLIENT_HELLO)
 * gets the backlog as FRAME_AT, timed by the HELLO's clock anchor; an older app gets plain live
 * FRAMEs as before. See "Buffered frames" in sniffer_proto.h.
 *
 * Firmware updates over Wi-Fi (HTTP on port 80, header X-Update-Token):
 *   GET  /               status as JSON
 *   POST /update/bridge  this board's new image: written to the spare slot, booted on trial
 *   POST /update/radio   the radio's new image: taken into the radio_img partition first (the
 *                        radio keeps listening while Wi-Fi delivers it), then sent over the UART
 *                        in acked chunks; the radio writes its spare slot and boots it on trial
 * A board on trial keeps the new image only once it passes its check (the bridge: Wi-Fi up for
 * 30 s; the radio: it hears the bridge, which hears it). Otherwise it rolls back by itself.
 *
 * LED: slow blink = no Wi-Fi, fast blink = Wi-Fi but no HA connection, mostly on = streaming
 * (flickers off on traffic).
 */

#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mdns.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "sniffer_proto.h"

static const char *TAG = "bridge";

#define UART_PORT UART_NUM_1

/* The frame buffer: most of the PSRAM when the board has it (Super Mini 2 MB -> ~1.75 MB, ~15 min;
 * DevKitC-1-N16R8 8 MB -> 6 MB, ~50 min), else a small one in internal RAM (~20-30 s). Channel 25
 * carries roughly 2 KB of frames a second. */
#define BACKLOG_PSRAM_MAX      (6 * 1024 * 1024)
#define BACKLOG_PSRAM_MIN      (512 * 1024)
#define BACKLOG_PSRAM_SPARE    (256 * 1024) /* left for anything else that asks for PSRAM */
#define BACKLOG_INTERNAL_BYTES (48 * 1024)
/* An app that hasn't said within this long that it takes buffered frames is an older one. */
#define CLIENT_HELLO_WAIT_US (3 * 1000000LL)

/* Keep a new image only after Wi-Fi has been up this long; give up on it after TRIAL_LIMIT. */
#define TRIAL_PASS_US  (30 * 1000000LL)
#define TRIAL_LIMIT_US (180 * 1000000LL)

enum { CLIENT_NONE, CLIENT_PENDING, CLIENT_LEGACY, CLIENT_FRAME_AT };

static RingbufHandle_t   s_ring; /* encoded messages, oldest first: frames always, statuses while connected */
static size_t            s_ring_bytes;
static size_t            s_psram_bytes;
static volatile int      s_client = -1;
static volatile uint8_t  s_client_mode = CLIENT_NONE;
static volatile int64_t  s_client_since_us;
static volatile bool     s_wifi_up;
static volatile int64_t  s_wifi_up_since_us;
static volatile int64_t  s_last_radio_status_us;
static volatile bool     s_traffic;
static volatile uint32_t s_uart_frames;
static volatile uint32_t s_full_drops;   /* frames that found the buffer full (uart_rx_task only) */
static volatile uint32_t s_legacy_skips; /* buffered frames an older app couldn't take (tcp_tx_task only) */
static sniff_decoder_t   s_uart_dec;

/* Radio clock -> bridge clock: bridge_us - radio_us for the frame that crossed the UART fastest. */
static int64_t s_rb_off;
static int64_t s_rb_last_us;
static bool    s_rb_valid;

/* The board a firmware version was built for: "0.3.2+devkitc" -> "devkitc"; no suffix = Super Mini. */
static const char *board_of(const char *version)
{
    const char *plus = strchr(version, '+');
    return plus ? plus + 1 : "supermini";
}

static uint32_t tcp_dropped(void)
{
    return s_full_drops + s_legacy_skips;
}

static const char *client_name(uint8_t mode)
{
    switch (mode) {
    case CLIENT_PENDING:
        return "connecting";
    case CLIENT_LEGACY:
        return "live_only";
    case CLIENT_FRAME_AT:
        return "buffered";
    default:
        return "none";
    }
}

/* Firmware state of both boards */
static volatile uint8_t s_bridge_fw = SNIFF_FW_RUNNING;
static volatile uint8_t s_radio_version[3];
static volatile uint8_t s_radio_fw = 0xFF; /* unknown until a SNIFF_T_RADIO_BOOT arrives */
static volatile int64_t s_radio_boot_us;
static volatile bool    s_radio_updating;
static QueueHandle_t    s_ack_q; /* SNIFF_T_UPDATE_ACK from the radio */
static char             s_last_update[128] = "none since boot";

static const char *fw_name(uint8_t state)
{
    switch (state) {
    case SNIFF_FW_RUNNING:
        return "running";
    case SNIFF_FW_TRIAL:
        return "trial";
    case SNIFF_FW_CONFIRMED:
        return "confirmed";
    case SNIFF_FW_ROLLED_BACK:
        return "rolled_back";
    default:
        return "unknown";
    }
}

static bool radio_heard(void)
{
    return (esp_timer_get_time() - s_last_radio_status_us) < 3000000;
}

/* ---------------------------------------------------------------- Wi-Fi */

/* "zigbee-sniffer-c2e4": the end of the board's Wi-Fi MAC, so several bridges on one network each
 * keep their own DHCP and mDNS name. */
static char s_hostname[24] = "zigbee-sniffer";

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        s_wifi_up = false;
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = data;
        ESP_LOGI(TAG, "Wi-Fi up: " IPSTR " (%s.local), HA connects to port %d", IP2STR(&ev->ip_info.ip),
                 s_hostname, CONFIG_BRIDGE_TCP_PORT);
        s_wifi_up_since_us = esp_timer_get_time();
        s_wifi_up          = true;
    }
}

static void wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    uint8_t      mac[6];
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
        snprintf(s_hostname, sizeof(s_hostname), "zigbee-sniffer-%02x%02x", mac[4], mac[5]);
    }
    esp_netif_set_hostname(netif, s_hostname);

    const wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL));

    wifi_config_t wc = {0};
    strlcpy((char *)wc.sta.ssid, CONFIG_BRIDGE_WIFI_SSID, sizeof(wc.sta.ssid));
    strlcpy((char *)wc.sta.password, CONFIG_BRIDGE_WIFI_PASSWORD, sizeof(wc.sta.password));
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    /* With several access points on the same network, the default fast scan joins the first one it
     * hears, however weak. Scan every channel and join the strongest. */
    wc.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wc.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE); /* steady low latency beats saving a few mA on USB power */

    if (mdns_init() == ESP_OK) {
        mdns_hostname_set(s_hostname);
        mdns_instance_name_set(s_hostname);
        mdns_service_add(NULL, "_zigbee-sniffer", "_tcp", CONFIG_BRIDGE_TCP_PORT, NULL, 0);
        mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    }
}

/* ---------------------------------------------------------------- queue to the client */

/* Frames always go in (that is the buffer); status messages only while an app is connected, since
 * an old status is worth nothing. Called from several tasks: the buffer stays on the stack. */
static void enqueue(uint8_t type, const void *payload, uint16_t len)
{
    uint8_t out[SNIFF_HEADER_LEN + SNIFF_MAX_PAYLOAD + SNIFF_TRAILER_LEN];
    if (type != SNIFF_T_FRAME_AT && s_client_mode < CLIENT_LEGACY) {
        return;
    }
    const size_t n = sniff_encode(out, type, payload, len);
    if (xRingbufferSend(s_ring, out, n, 0) != pdTRUE && type == SNIFF_T_FRAME_AT) {
        s_full_drops++;
    }
}

/*
 * When the radio heard a frame, on the bridge's clock. A frame reaches the bridge a little after
 * the radio heard it (UART queueing), so the offset tracks the fastest crossing: it takes any
 * smaller sample at once, creeps up by 50 ppm otherwise (the two boards' crystals drift), and
 * starts over on a jump of more than a second (the radio restarted and its clock began again).
 */
static int64_t frame_bridge_us(uint64_t radio_us, int64_t rx_us)
{
    const int64_t sample = rx_us - (int64_t)radio_us;
    if (!s_rb_valid || sample > s_rb_off + 1000000 || sample < s_rb_off - 1000000) {
        s_rb_off   = sample;
        s_rb_valid = true;
    } else {
        const int64_t crept = s_rb_off + (rx_us - s_rb_last_us) / 20000;
        s_rb_off            = sample < crept ? sample : crept;
    }
    s_rb_last_us = rx_us;
    return (int64_t)radio_us + s_rb_off;
}

/* ---------------------------------------------------------------- UART with the radio */

static void uart_rx_task(void *arg)
{
    uint8_t buf[256];
    for (;;) {
        /* Take whatever has arrived (at least one byte, or 50 ms of silence): asking for a full
         * buffer would hold a short message, like an update ack, until the timeout. */
        size_t avail = 0;
        uart_get_buffered_data_len(UART_PORT, &avail);
        const size_t want = avail == 0 ? 1 : (avail < sizeof(buf) ? avail : sizeof(buf));
        const int    n    = uart_read_bytes(UART_PORT, buf, want, pdMS_TO_TICKS(50));
        for (int i = 0; i < n; i++) {
            if (!sniff_decode_byte(&s_uart_dec, buf[i])) {
                continue;
            }
            const uint8_t *p = sniff_payload(&s_uart_dec);
            switch (s_uart_dec.type) {
            case SNIFF_T_FRAME:
                s_uart_frames++;
                s_traffic = true;
                if (s_uart_dec.length >= sizeof(sniff_frame_hdr_t) && s_uart_dec.length <= SNIFF_MAX_PAYLOAD - 8) {
                    /* Stored as FRAME_AT: the frame stamped with the bridge's clock. */
                    uint8_t                  at[SNIFF_MAX_PAYLOAD];
                    const sniff_frame_hdr_t *h = (const sniff_frame_hdr_t *)p;
                    const int64_t            t = frame_bridge_us(h->timestamp_us, esp_timer_get_time());
                    memcpy(at, &t, 8);
                    memcpy(at + 8, p, s_uart_dec.length);
                    enqueue(SNIFF_T_FRAME_AT, at, (uint16_t)(8 + s_uart_dec.length));
                }
                break;
            case SNIFF_T_RADIO_STATUS:
                s_last_radio_status_us = esp_timer_get_time();
                if (s_uart_dec.length >= sizeof(sniff_radio_status_t)) {
                    const sniff_radio_status_t *st = (const sniff_radio_status_t *)p;
                    memcpy((void *)s_radio_version, st->version, 3);
                }
                enqueue(SNIFF_T_RADIO_STATUS, p, s_uart_dec.length);
                break;
            case SNIFF_T_RADIO_BOOT:
                if (s_uart_dec.length >= sizeof(sniff_radio_boot_t)) {
                    const sniff_radio_boot_t *b = (const sniff_radio_boot_t *)p;
                    memcpy((void *)s_radio_version, b->version, 3);
                    if (b->state != s_radio_fw) {
                        ESP_LOGI(TAG, "Radio %u.%u.%u firmware: %s", b->version[0], b->version[1], b->version[2],
                                 fw_name(b->state));
                    }
                    s_radio_fw      = b->state;
                    s_radio_boot_us = esp_timer_get_time();
                }
                break;
            case SNIFF_T_UPDATE_ACK:
                if (s_uart_dec.length >= sizeof(sniff_update_ack_t)) {
                    sniff_update_ack_t ack;
                    memcpy(&ack, p, sizeof(ack));
                    xQueueSend(s_ack_q, &ack, 0);
                }
                break;
            default:
                break;
            }
        }
    }
}

/* Called from several tasks: the buffer stays on the caller's stack, and one uart_write_bytes call
 * sends a whole message, so messages from different tasks never interleave. */
static void uart_send(uint8_t type, const void *payload, uint16_t len)
{
    uint8_t      out[SNIFF_HEADER_LEN + SNIFF_MAX_PAYLOAD + SNIFF_TRAILER_LEN];
    const size_t n = sniff_encode(out, type, payload, len);
    uart_write_bytes(UART_PORT, out, n);
}

/* ---------------------------------------------------------------- TCP */

static bool send_all(int sock, const uint8_t *data, size_t len)
{
    while (len) {
        const int n = send(sock, data, len, 0);
        if (n <= 0) {
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

/* Bytes waiting in the buffer: from its free (oldest unreleased) to its write position. (The ring's
 * "free size" is only the largest contiguous gap, about half the buffer once it has wrapped.) */
static size_t backlog_bytes(void)
{
    UBaseType_t free_pos, read_pos, write_pos, acquire_pos, items;
    vRingbufferGetInfo(s_ring, &free_pos, &read_pos, &write_pos, &acquire_pos, &items);
    if (write_pos == free_pos) {
        return items ? s_ring_bytes : 0; /* full, or empty */
    }
    return (write_pos + s_ring_bytes - free_pos) % s_ring_bytes;
}

/*
 * Drains the buffer to the app, oldest first, once it has said what it takes. A message whose send
 * fails stays in hand for the next connection, so a dropped link loses nothing (at worst the app
 * gets one frame twice). An older app gets plain FRAMEs, live ones only.
 */
static void tcp_tx_task(void *arg)
{
    static uint8_t conv[SNIFF_HEADER_LEN + SNIFF_MAX_PAYLOAD + SNIFF_TRAILER_LEN];
    uint8_t       *item = NULL;
    size_t         size = 0;
    for (;;) {
        const int     sock = s_client;
        const uint8_t mode = s_client_mode;
        if (sock < 0 || mode < CLIENT_LEGACY) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        if (!item) {
            item = xRingbufferReceive(s_ring, &size, pdMS_TO_TICKS(500));
            if (!item) {
                continue;
            }
        }
        const uint8_t *out = item;
        size_t         n   = size;
        if (item[2] == SNIFF_T_FRAME_AT && mode == CLIENT_LEGACY) {
            const uint16_t len = (uint16_t)(item[3] | (item[4] << 8));
            int64_t        at;
            memcpy(&at, item + SNIFF_HEADER_LEN, 8);
            if (at < s_client_since_us) { /* buffered before it connected: it can't place it in time */
                s_legacy_skips++;
                vRingbufferReturnItem(s_ring, item);
                item = NULL;
                continue;
            }
            n   = sniff_encode(conv, SNIFF_T_FRAME, item + SNIFF_HEADER_LEN + 8, (uint16_t)(len - 8));
            out = conv;
        }
        if (!send_all(sock, out, n)) {
            ESP_LOGW(TAG, "Client too slow or gone; closing (%u bytes buffered)", (unsigned)backlog_bytes());
            shutdown(sock, SHUT_RDWR);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue; /* keep the message for the next connection */
        }
        vRingbufferReturnItem(s_ring, item);
        item = NULL;
    }
}

static void serve_client(int sock)
{
    const int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    const struct timeval snd = {.tv_sec = 15, .tv_usec = 0}; /* ride out a stalling Wi-Fi link */
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof(snd));
    const struct timeval rcv = {.tv_sec = 0, .tv_usec = 250000}; /* to notice an app that says nothing */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof(rcv));

    /* The HELLO goes out before anything else: its bridge_us anchors FRAME_AT times to wall time. */
    uint8_t   enc[SNIFF_HEADER_LEN + 160 + SNIFF_TRAILER_LEN];
    char      hello[160];
    const int hl = snprintf(hello, sizeof(hello), "{\"bridge\":\"%s\",\"bridge_us\":%lld,\"backlog_bytes\":%u}",
                            BRIDGE_VERSION, (long long)esp_timer_get_time(), (unsigned)backlog_bytes());
    s_client_since_us = esp_timer_get_time();
    s_client_mode     = CLIENT_PENDING;
    if (!send_all(sock, enc, sniff_encode(enc, SNIFF_T_HELLO, hello, (uint16_t)hl))) {
        s_client_mode = CLIENT_NONE;
        close(sock);
        return;
    }
    s_client = sock;

    sniff_decoder_t dec = {0};
    uint8_t         buf[64];
    for (;;) {
        const int n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (s_client_mode == CLIENT_PENDING && esp_timer_get_time() - s_client_since_us > CLIENT_HELLO_WAIT_US) {
                s_client_mode = CLIENT_LEGACY;
                ESP_LOGI(TAG, "Client sent no CLIENT_HELLO: live frames only, as before");
            }
            continue;
        }
        if (n <= 0) {
            break;
        }
        for (int i = 0; i < n; i++) {
            if (!sniff_decode_byte(&dec, buf[i])) {
                continue;
            }
            const uint8_t *p = sniff_payload(&dec);
            if (dec.type == SNIFF_T_CLIENT_HELLO && dec.length >= 4) {
                uint32_t flags;
                memcpy(&flags, p, 4);
                s_client_mode = (flags & SNIFF_CLIENT_FRAME_AT) ? CLIENT_FRAME_AT : CLIENT_LEGACY;
                ESP_LOGI(TAG, "Client takes %s (%u bytes buffered)",
                         s_client_mode == CLIENT_FRAME_AT ? "buffered frames" : "live frames only",
                         (unsigned)backlog_bytes());
            } else if (dec.type == SNIFF_T_SET_CHANNEL && dec.length >= 1) {
                if (s_radio_updating) {
                    ESP_LOGW(TAG, "HA asked for channel %u during a radio update: ignored", p[0]);
                    continue;
                }
                ESP_LOGI(TAG, "HA asked for channel %u", p[0]);
                uart_send(SNIFF_T_SET_CHANNEL, p, 1);
            }
        }
    }
    s_client_mode = CLIENT_NONE;
    s_client = -1;
    close(sock);
}

static void tcp_server_task(void *arg)
{
    for (;;) {
        while (!s_wifi_up) {
            vTaskDelay(pdMS_TO_TICKS(500));
        }
        const int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        const int one      = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr = {
            .sin_family      = AF_INET,
            .sin_port        = htons(CONFIG_BRIDGE_TCP_PORT),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };
        if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 1) != 0) {
            ESP_LOGE(TAG, "Cannot listen on port %d", CONFIG_BRIDGE_TCP_PORT);
            close(listener);
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        for (;;) {
            struct sockaddr_in peer;
            socklen_t          plen = sizeof(peer);
            const int          sock = accept(listener, (struct sockaddr *)&peer, &plen);
            if (sock < 0) {
                break;
            }
            char ip[16];
            inet_ntoa_r(peer.sin_addr, ip, sizeof(ip));
            ESP_LOGI(TAG, "Client connected from %s", ip);
            serve_client(sock); /* one client at a time */
            ESP_LOGI(TAG, "Client %s disconnected", ip);
        }
        close(listener);
    }
}

/* ---------------------------------------------------------------- firmware images */

/*
 * An ESP-IDF app image starts with a 24-byte image header and an 8-byte segment header, then the
 * app description (esp_app_desc_t). Checked before anything is written, so a file for the other
 * board, or for another project on the same C6, is refused up front.
 */
#define IMG_MAGIC            0xE9
#define IMG_CHIP_ID_OFF      12
#define APP_DESC_OFF         32
#define APP_DESC_MAGIC       0xABCD5432u
#define APP_DESC_VERSION_OFF (APP_DESC_OFF + 16)
#define APP_DESC_PROJECT_OFF (APP_DESC_OFF + 48)
#define IMG_HEAD_LEN         (APP_DESC_PROJECT_OFF + 32)
#define CHIP_ID_ESP32S3      0x0009
#define CHIP_ID_ESP32C6      0x000D
#define RADIO_SLOT_SIZE      (1600 * 1024) /* ota_0 / ota_1 in c6-radio/partitions.csv */

static bool check_image(const uint8_t *head, uint16_t chip, const char *project, char *version, size_t vlen, char *why,
                        size_t wlen)
{
    uint32_t magic;
    memcpy(&magic, head + APP_DESC_OFF, 4);
    const uint16_t img_chip = (uint16_t)(head[IMG_CHIP_ID_OFF] | (head[IMG_CHIP_ID_OFF + 1] << 8));
    char           name[33] = {0};
    memcpy(name, head + APP_DESC_PROJECT_OFF, 32);
    snprintf(version, vlen, "%.32s", (const char *)(head + APP_DESC_VERSION_OFF));
    if (head[0] != IMG_MAGIC || magic != APP_DESC_MAGIC) {
        snprintf(why, wlen, "not an ESP-IDF app image (send build/<project>.bin)");
        return false;
    }
    if (img_chip != chip || strcmp(name, project) != 0) {
        snprintf(why, wlen, "image is %s for chip id %u; this endpoint takes %s", name, img_chip, project);
        return false;
    }
    return true;
}

/* Read exactly len body bytes (fewer only at the end of the body). -1 on error. A weak Wi-Fi link
 * can stall a TCP stream for many seconds while it retransmits, so ride out up to a minute. */
static int recv_exact(httpd_req_t *req, uint8_t *buf, size_t len)
{
    size_t got      = 0;
    int    timeouts = 0;
    while (got < len) {
        const int n = httpd_req_recv(req, (char *)buf + got, len - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts < 6) {
            ESP_LOGW(TAG, "Upload stalled %d0 s at %u of %u bytes", timeouts, (unsigned)got, (unsigned)len);
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return (int)got;
}

static bool authorized(httpd_req_t *req)
{
    const char *want = CONFIG_BRIDGE_UPDATE_TOKEN;
    if (want[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                            "Updates are off: set CONFIG_BRIDGE_UPDATE_TOKEN in sdkconfig.secrets and flash once over USB");
        return false;
    }
    char got[80] = {0};
    if (httpd_req_get_hdr_value_str(req, "X-Update-Token", got, sizeof(got)) != ESP_OK) {
        got[0] = '\0';
    }
    /* Compare every byte, so the time taken says nothing about how much matched. */
    const size_t wl   = strlen(want);
    uint8_t      diff = (uint8_t)(strlen(got) != wl);
    for (size_t i = 0; i < wl; i++) {
        diff |= (uint8_t)(want[i] ^ got[i < sizeof(got) ? i : 0]);
    }
    if (diff) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Wrong or missing X-Update-Token");
        return false;
    }
    return true;
}

static void finish(httpd_req_t *req, bool ok, const char *msg)
{
    strlcpy(s_last_update, msg, sizeof(s_last_update));
    ESP_LOGI(TAG, "Update: %s", msg);
    if (ok) {
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_sendstr(req, msg);
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
    }
}

static void restart_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(1000)); /* let the HTTP reply go out */
    esp_restart();
}

static esp_err_t update_bridge_handler(httpd_req_t *req)
{
    if (!authorized(req)) {
        return ESP_OK;
    }
    static uint8_t         buf[4096];
    char                   version[33], why[96], msg[128];
    const esp_partition_t *next  = esp_ota_get_next_update_partition(NULL);
    const size_t           total = req->content_len;
    if (!next || total < IMG_HEAD_LEN || total > next->size) {
        snprintf(msg, sizeof(msg), "bridge image size %u does not fit the %u-byte slot", (unsigned)total,
                 next ? (unsigned)next->size : 0u);
        finish(req, false, msg);
        return ESP_OK;
    }
    int n = recv_exact(req, buf, total < sizeof(buf) ? total : sizeof(buf));
    if (n < IMG_HEAD_LEN) {
        finish(req, false, "bridge image upload broke off");
        return ESP_OK;
    }
    if (!check_image(buf, CHIP_ID_ESP32S3, "zigbee_sniffer_bridge", version, sizeof(version), why, sizeof(why))) {
        snprintf(msg, sizeof(msg), "refused: %s", why);
        finish(req, false, msg);
        return ESP_OK;
    }
    /* Same chip, different board: flash size, PSRAM type and UART pins differ, so refuse it. */
    const char *running = esp_app_get_description()->version;
    if (strcmp(board_of(version), board_of(running)) != 0) {
        snprintf(msg, sizeof(msg), "refused: image %s is for the %s board; this bridge is a %s", version,
                 board_of(version), board_of(running));
        finish(req, false, msg);
        return ESP_OK;
    }
    esp_ota_handle_t h;
    esp_err_t        err = esp_ota_begin(next, OTA_WITH_SEQUENTIAL_WRITES, &h);
    size_t           done = 0;
    while (err == ESP_OK) {
        err = esp_ota_write(h, buf, (size_t)n);
        done += (size_t)n;
        if (err != ESP_OK || done >= total) {
            break;
        }
        const size_t want = total - done < sizeof(buf) ? total - done : sizeof(buf);
        n                 = recv_exact(req, buf, want);
        if (n <= 0) {
            err = ESP_ERR_TIMEOUT;
        }
    }
    if (err != ESP_OK) {
        esp_ota_abort(h);
        snprintf(msg, sizeof(msg), "bridge update failed at byte %u: %s", (unsigned)done, esp_err_to_name(err));
        finish(req, false, msg);
        return ESP_OK;
    }
    err = esp_ota_end(h); /* checks the whole image, including its SHA-256 */
    if (err == ESP_OK) {
        err = esp_ota_set_boot_partition(next);
    }
    if (err != ESP_OK) {
        snprintf(msg, sizeof(msg), "bridge image rejected: %s", esp_err_to_name(err));
        finish(req, false, msg);
        return ESP_OK;
    }
    snprintf(msg, sizeof(msg), "bridge %s written to %s; restarting on trial (kept once Wi-Fi is up 30 s)", version,
             next->label);
    finish(req, true, msg);
    xTaskCreate(restart_task, "restart", 2048, NULL, 3, NULL);
    return ESP_OK;
}

/* Send one update message to the radio and wait for its ack (retried on silence). */
static bool radio_cmd(uint8_t type, const void *payload, uint16_t len, int timeout_ms, sniff_update_ack_t *ack)
{
    for (int attempt = 0; attempt < 5; attempt++) {
        xQueueReset(s_ack_q);
        uart_send(type, payload, len);
        const TickType_t until = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
        for (;;) {
            const TickType_t now = xTaskGetTickCount();
            if ((int32_t)(until - now) <= 0 || xQueueReceive(s_ack_q, ack, until - now) != pdTRUE) {
                break;
            }
            if (ack->stage == type) {
                return true;
            }
        }
    }
    return false;
}

static esp_err_t update_radio_handler(httpd_req_t *req)
{
    if (!authorized(req)) {
        return ESP_OK;
    }
    static uint8_t         buf[4096];
    static uint8_t         data[4 + SNIFF_UPDATE_CHUNK];
    uint8_t               *chunk = data + 4;
    char                   version[33], why[96], msg[128];
    sniff_update_ack_t     ack   = {0};
    const size_t           total = req->content_len;
    const esp_partition_t *stage =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "radio_img");
    if (!stage) {
        finish(req, false, "no radio_img partition: flash the bridge once over USB");
        return ESP_OK;
    }
    const size_t limit = stage->size < RADIO_SLOT_SIZE ? stage->size : RADIO_SLOT_SIZE;
    if (total < IMG_HEAD_LEN || total > limit) {
        snprintf(msg, sizeof(msg), "radio image size %u does not fit (up to %u bytes)", (unsigned)total,
                 (unsigned)limit);
        finish(req, false, msg);
        return ESP_OK;
    }

    /* 1. Take the whole upload into radio_img first. Wi-Fi can be slow and stall; the radio keeps
     *    listening meanwhile, and the UART transfer below never waits on the network. */
    int n = recv_exact(req, buf, total < sizeof(buf) ? total : sizeof(buf));
    if (n < IMG_HEAD_LEN) {
        finish(req, false, "radio image upload broke off");
        return ESP_OK;
    }
    if (!check_image(buf, CHIP_ID_ESP32C6, "zigbee_sniffer_radio", version, sizeof(version), why, sizeof(why))) {
        snprintf(msg, sizeof(msg), "refused: %s", why);
        finish(req, false, msg);
        return ESP_OK;
    }
    esp_err_t err = esp_partition_erase_range(stage, 0, (total + 4095) & ~(size_t)4095);
    size_t    got = 0;
    while (err == ESP_OK) {
        err = esp_partition_write(stage, got, buf, (size_t)n);
        got += (size_t)n;
        if (err != ESP_OK || got >= total) {
            break;
        }
        n = recv_exact(req, buf, total - got < sizeof(buf) ? total - got : sizeof(buf));
        if (n <= 0) {
            snprintf(msg, sizeof(msg), "radio image upload broke off at byte %u", (unsigned)got);
            finish(req, false, msg);
            return ESP_OK;
        }
    }
    if (err != ESP_OK) {
        snprintf(msg, sizeof(msg), "staging the radio image failed: %s", esp_err_to_name(err));
        finish(req, false, msg);
        return ESP_OK;
    }

    /* 2. Relay it to the radio over the UART, one acked chunk at a time. */
    if (!radio_heard()) {
        finish(req, false, "the radio isn't sending its status: check the UART wiring");
        return ESP_OK;
    }
    const uint8_t old[3] = {s_radio_version[0], s_radio_version[1], s_radio_version[2]};
    s_radio_updating     = true;
    ESP_LOGI(TAG, "Radio update to %s: %u bytes staged, sending", version, (unsigned)total);

    const uint32_t size32 = (uint32_t)total;
    if (!radio_cmd(SNIFF_T_UPDATE_BEGIN, &size32, sizeof(size32), 5000, &ack) || ack.err != ESP_OK) {
        snprintf(msg, sizeof(msg), "radio did not start the update: %s",
                 ack.stage == SNIFF_T_UPDATE_BEGIN ? esp_err_to_name(ack.err) : "no answer (radio firmware 0.1.x has no updates; flash it once over USB)");
        goto fail;
    }
    uint32_t off = 0;
    while (off < total) {
        const size_t len = total - off < SNIFF_UPDATE_CHUNK ? total - off : SNIFF_UPDATE_CHUNK;
        if (esp_partition_read(stage, off, chunk, len) != ESP_OK) {
            snprintf(msg, sizeof(msg), "reading the staged image failed at byte %" PRIu32, off);
            goto fail;
        }
        memcpy(data, &off, 4);
        if (!radio_cmd(SNIFF_T_UPDATE_DATA, data, (uint16_t)(4 + len), 1000, &ack)) {
            snprintf(msg, sizeof(msg), "radio stopped answering at byte %" PRIu32, off);
            goto fail;
        }
        if (ack.err != ESP_OK || ack.offset != off + (uint32_t)len) {
            snprintf(msg, sizeof(msg), "radio refused bytes at %" PRIu32 " (holds %" PRIu32 "): %s", off, ack.offset,
                     esp_err_to_name(ack.err));
            goto fail;
        }
        off += (uint32_t)len;
    }
    if (!radio_cmd(SNIFF_T_UPDATE_END, NULL, 0, 15000, &ack) || ack.err != ESP_OK) {
        snprintf(msg, sizeof(msg), "radio rejected the image: %s",
                 ack.stage == SNIFF_T_UPDATE_END ? esp_err_to_name(ack.err) : "no answer");
        goto fail;
    }

    /* It reboots into the new image on trial, then reports whether it kept it. */
    const int64_t sent_us = esp_timer_get_time();
    s_radio_fw            = 0xFF;
    while (esp_timer_get_time() - sent_us < 90 * 1000000LL) { /* a failed trial takes 60 s to roll back */
        vTaskDelay(pdMS_TO_TICKS(200));
        const uint8_t st = s_radio_fw;
        if (s_radio_boot_us > sent_us && (st == SNIFF_FW_CONFIRMED || st == SNIFF_FW_ROLLED_BACK)) {
            break;
        }
    }
    s_radio_updating = false;
    if (s_radio_fw == SNIFF_FW_CONFIRMED) {
        snprintf(msg, sizeof(msg), "radio updated %u.%u.%u -> %u.%u.%u and confirmed", old[0], old[1], old[2],
                 s_radio_version[0], s_radio_version[1], s_radio_version[2]);
        finish(req, true, msg);
    } else if (s_radio_fw == SNIFF_FW_ROLLED_BACK) {
        snprintf(msg, sizeof(msg), "radio %s failed its trial and rolled back to %u.%u.%u", version,
                 s_radio_version[0], s_radio_version[1], s_radio_version[2]);
        finish(req, false, msg);
    } else {
        snprintf(msg, sizeof(msg), "radio %s written, but it has not confirmed it within 90 s (now: %s)", version,
                 fw_name(s_radio_fw));
        finish(req, false, msg);
    }
    return ESP_OK;

fail:
    uart_send(SNIFF_T_UPDATE_ABORT, NULL, 0);
    s_radio_updating = false;
    finish(req, false, msg);
    return ESP_OK;
}

static esp_err_t status_handler(httpd_req_t *req)
{
    wifi_ap_record_t ap   = {0};
    const bool       ok   = s_wifi_up && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    char             json[1024];
    snprintf(json, sizeof(json),
             "{\"bridge\":\"%s\",\"hostname\":\"%s\",\"bridge_firmware\":\"%s\",\"bridge_partition\":\"%s\","
             "\"radio\":\"%u.%u.%u\",\"radio_firmware\":\"%s\",\"radio_link\":%s,\"radio_updating\":%s,"
             "\"wifi_rssi\":%d,\"wifi_channel\":%u,\"wifi_ap\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
             "\"uptime_s\":%" PRIu32 ",\"ha_connected\":%s,\"client\":\"%s\",\"psram_bytes\":%u,"
             "\"buffer_bytes\":%u,\"backlog_bytes\":%u,\"buffer_full_drops\":%" PRIu32 ","
             "\"live_only_skips\":%" PRIu32 ",\"uart_tx_gpio\":%d,\"uart_rx_gpio\":%d,\"uart_frames\":%" PRIu32 ","
             "\"uart_crc_errors\":%" PRIu32 ",\"updates\":%s,\"last_update\":\"%s\"}",
             esp_app_get_description()->version, s_hostname, fw_name(s_bridge_fw),
             esp_ota_get_running_partition()->label,
             s_radio_version[0], s_radio_version[1], s_radio_version[2], fw_name(s_radio_fw),
             radio_heard() ? "true" : "false", s_radio_updating ? "true" : "false", ok ? ap.rssi : 0,
             ok ? ap.primary : 0, ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
             (uint32_t)(esp_timer_get_time() / 1000000), s_client >= 0 ? "true" : "false",
             client_name(s_client_mode), (unsigned)s_psram_bytes, (unsigned)s_ring_bytes, (unsigned)backlog_bytes(),
             s_full_drops, s_legacy_skips, CONFIG_BRIDGE_UART_TX_GPIO, CONFIG_BRIDGE_UART_RX_GPIO, s_uart_frames,
             s_uart_dec.crc_errors, CONFIG_BRIDGE_UPDATE_TOKEN[0] ? "true" : "false", s_last_update);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static void http_init(void)
{
    httpd_config_t cfg    = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size        = 8192;
    cfg.recv_wait_timeout = 10;
    cfg.send_wait_timeout = 10;
    cfg.max_open_sockets  = 3;
    cfg.lru_purge_enable  = true;
    httpd_handle_t srv    = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "HTTP server did not start: no updates over Wi-Fi");
        return;
    }
    const httpd_uri_t uris[] = {
        {.uri = "/", .method = HTTP_GET, .handler = status_handler},
        {.uri = "/update/bridge", .method = HTTP_POST, .handler = update_bridge_handler},
        {.uri = "/update/radio", .method = HTTP_POST, .handler = update_radio_handler},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(srv, &uris[i]);
    }
    if (!CONFIG_BRIDGE_UPDATE_TOKEN[0]) {
        ESP_LOGW(TAG, "No CONFIG_BRIDGE_UPDATE_TOKEN: updates over Wi-Fi are off");
    }
}

/* A new image runs on trial: keep it once Wi-Fi has been up a while, else go back to the old one. */
static void bridge_fw_init(void)
{
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK &&
        st == ESP_OTA_IMG_PENDING_VERIFY) {
        s_bridge_fw = SNIFF_FW_TRIAL;
        ESP_LOGW(TAG, "New firmware on trial: kept once Wi-Fi is up %d s", (int)(TRIAL_PASS_US / 1000000));
    } else if (esp_ota_get_last_invalid_partition() != NULL) {
        s_bridge_fw = SNIFF_FW_ROLLED_BACK;
        ESP_LOGW(TAG, "A newer firmware failed its trial; running the previous one");
    }
}

static void bridge_fw_check(int64_t now_us)
{
    if (s_bridge_fw != SNIFF_FW_TRIAL) {
        return;
    }
    if (s_wifi_up && now_us - s_wifi_up_since_us >= TRIAL_PASS_US) {
        esp_ota_mark_app_valid_cancel_rollback();
        s_bridge_fw = SNIFF_FW_CONFIRMED;
        ESP_LOGI(TAG, "New firmware confirmed");
    } else if (now_us >= TRIAL_LIMIT_US) {
        ESP_LOGE(TAG, "New firmware never got Wi-Fi up for long: rolling back");
        esp_ota_mark_app_invalid_rollback_and_reboot();
    }
}

/* ---------------------------------------------------------------- status + LED */

static void led_write(bool lit)
{
#if CONFIG_BRIDGE_LED_GPIO >= 0
    gpio_set_level(CONFIG_BRIDGE_LED_GPIO, lit ? 0 : 1);
#endif
}

static void status_task(void *arg)
{
    int64_t last_status = 0;
    int64_t last_ping   = 0;
    for (;;) {
        const int64_t now_us = esp_timer_get_time();
        const int64_t ms     = now_us / 1000;
        if (!s_wifi_up) {
            led_write((ms % 2000) < 1000);
        } else if (s_client < 0) {
            led_write((ms % 400) < 200);
        } else {
            const bool flicker = s_traffic;
            s_traffic          = false;
            led_write(!flicker);
        }

        if (now_us - last_ping >= 1000000) {
            /* Tells the radio both directions of the UART work (it ends a radio trial). */
            last_ping           = now_us;
            const uint8_t flags = radio_heard() ? SNIFF_PING_RADIO_HEARD : 0;
            uart_send(SNIFF_T_PING, &flags, 1);
            bridge_fw_check(now_us);
        }

        if (now_us - last_status >= 5000000) {
            last_status         = now_us;
            wifi_ap_record_t ap = {0};
            const bool       ok = s_wifi_up && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
            const sniff_bridge_status_t st = {
                .uptime_s        = (uint32_t)(now_us / 1000000),
                .uart_frames     = s_uart_frames,
                .uart_crc_errors = s_uart_dec.crc_errors,
                .tcp_dropped     = tcp_dropped(),
                .wifi_rssi       = ok ? ap.rssi : 0,
                .radio_link_ok   = radio_heard(),
            };
            enqueue(SNIFF_T_BRIDGE_STATUS, &st, sizeof(st));
            if (!st.radio_link_ok && !s_radio_updating) {
                ESP_LOGW(TAG, "No status from the radio board: check the UART wiring");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(40));
    }
}

/* ---------------------------------------------------------------- init */

void app_main(void)
{
    ESP_LOGI(TAG, "Zigbee sniffer bridge " BRIDGE_VERSION " (%s)", esp_ota_get_running_partition()->label);
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    bridge_fw_init();

#if CONFIG_BRIDGE_LED_GPIO >= 0
    const gpio_config_t led = {.pin_bit_mask = 1ULL << CONFIG_BRIDGE_LED_GPIO, .mode = GPIO_MODE_OUTPUT};
    ESP_ERROR_CHECK(gpio_config(&led));
    led_write(false);
#endif

    const uart_config_t ucfg = {
        .baud_rate  = CONFIG_BRIDGE_UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, 16384, 2048, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &ucfg));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, CONFIG_BRIDGE_UART_TX_GPIO, CONFIG_BRIDGE_UART_RX_GPIO,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    /* The frame buffer: most of the PSRAM if the board has it (and it came up), else internal RAM. */
    static StaticRingbuffer_t ring_ctl;
    uint8_t                  *storage  = NULL;
    bool                      in_psram = false;
    s_psram_bytes                      = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    const size_t largest               = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if (largest >= BACKLOG_PSRAM_MIN + BACKLOG_PSRAM_SPARE) {
        size_t want = largest - BACKLOG_PSRAM_SPARE;
        want        = (want > BACKLOG_PSRAM_MAX ? BACKLOG_PSRAM_MAX : want) & ~(size_t)3;
        storage     = heap_caps_malloc(want, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (storage) {
            s_ring_bytes = want;
            in_psram     = true;
        }
    }
    if (!storage) {
        storage      = heap_caps_malloc(BACKLOG_INTERNAL_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        s_ring_bytes = BACKLOG_INTERNAL_BYTES;
    }
    configASSERT(storage);
    s_ring  = xRingbufferCreateStatic(s_ring_bytes, RINGBUF_TYPE_NOSPLIT, storage, &ring_ctl);
    s_ack_q = xQueueCreate(8, sizeof(sniff_update_ack_t));
    configASSERT(s_ring && s_ack_q);
    ESP_LOGI(TAG, "Board %s; frame buffer %u KB in %s (PSRAM %u KB)", board_of(BRIDGE_VERSION),
             (unsigned)(s_ring_bytes / 1024), in_psram ? "PSRAM" : "internal RAM", (unsigned)(s_psram_bytes / 1024));

    if (strlen(CONFIG_BRIDGE_WIFI_SSID) == 0) {
        ESP_LOGE(TAG, "No Wi-Fi name set: copy sdkconfig.secrets.example to sdkconfig.secrets and rebuild");
    }
    wifi_init();

    xTaskCreate(uart_rx_task, "uart_rx", 6144, NULL, 7, NULL);
    xTaskCreate(tcp_tx_task, "tcp_tx", 4096, NULL, 6, NULL);
    xTaskCreate(tcp_server_task, "tcp_srv", 4096, NULL, 5, NULL);
    xTaskCreate(status_task, "status", 4096, NULL, 4, NULL);
    http_init();
}
