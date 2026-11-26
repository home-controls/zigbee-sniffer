/*
 * Zigbee sniffer, radio half (Seeed XIAO ESP32C6, or ESP32C5 on USB).
 *
 * Puts the 802.15.4 radio in promiscuous receive on one channel and streams every frame, with
 * its RSSI, LQI and radio timestamp, over its link (protocol: sniffer_proto.h). The link is either
 * the UART to the Wi-Fi bridge (CONFIG_SNIFF_LINK_UART) or the chip's own USB port, plugged straight
 * into the Home Assistant box (CONFIG_SNIFF_LINK_USB): then the HA app plays the bridge's part
 * (pings, channel, updates) and the console log goes to UART0 so the USB carries frames only.
 * It never transmits: no Zigbee stack, no ACKs (its own addresses are set to values no Zigbee
 * frame uses), so it can't disturb the network it is watching.
 *
 * Received frames arrive in the radio ISR; they are copied into a ring buffer and the radio
 * buffer is released at once. A task drains the ring buffer to the UART.
 *
 * Firmware updates come from the bridge (or the app, on USB) over the same link (SNIFF_T_UPDATE_*): the radio stops
 * listening, writes the image to its spare slot, checks it and reboots into it on trial. The new
 * image is kept once the bridge's ping says it hears this radio (both directions of the UART
 * work); without that within TRIAL_LIMIT it rolls back to the previous image.
 */

#include <inttypes.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#if CONFIG_SNIFF_LINK_USB
#include "driver/usb_serial_jtag.h"
#endif
#include "esp_attr.h"
#include "esp_ieee802154.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "sniffer_proto.h"

static const char *TAG = "radio";

#define UART_PORT        UART_NUM_1
#define RING_BYTES       (24 * 1024)
#define LINK_WRITE_MS    50 /* a link nobody reads (USB with the port closed) drops messages, never blocks */
#define XIAO_RF_POWER    3  /* low = RF switch powered */
#define XIAO_RF_ANTENNA  14 /* low = on-board, high = U.FL */
#define MAX_PSDU         127

/* An update the bridge stops feeding for this long is dropped and listening resumes. */
#define UPDATE_IDLE_US (15 * 1000000LL)
/* A new image is kept on the bridge's say-so, but not before this: the bridge still counts the
 * old image's last status as "heard" for 3 s after the reboot. */
#define TRIAL_MIN_US   (5 * 1000000LL)
#define TRIAL_LIMIT_US (60 * 1000000LL)

typedef struct __attribute__((packed)) {
    sniff_frame_hdr_t hdr;
    uint8_t           psdu[MAX_PSDU];
} rx_item_t;

static RingbufHandle_t   s_ring;
static volatile uint32_t s_frames;
static volatile uint32_t s_dropped;
static volatile uint8_t  s_channel = CONFIG_SNIFF_CHANNEL;
static volatile bool     s_led_kick;

/* Firmware state; the update itself is only touched by rx_task. */
static volatile uint8_t       s_fw = SNIFF_FW_RUNNING;
static volatile bool          s_updating;
static esp_ota_handle_t       s_ota;
static const esp_partition_t *s_ota_part; /* non-NULL while an update is open */
static uint32_t               s_ota_size;
static uint32_t               s_ota_have;
static int64_t                s_ota_last_us;

/* ---------------------------------------------------------------- radio (ISR side) */

void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    /* frame[0] = length incl. the 2-byte FCS slot, which the driver replaces with RSSI/LQI. */
    const uint8_t len = frame[0];
    if (len >= 2 && len <= MAX_PSDU + 2) {
        rx_item_t item;
        const uint8_t psdu_len    = len - 2;
        item.hdr.timestamp_us     = info->timestamp;
        item.hdr.channel          = info->channel;
        item.hdr.rssi             = info->rssi;
        item.hdr.lqi              = info->lqi;
        item.hdr.flags            = info->pending ? 1 : 0;
        memcpy(item.psdu, &frame[1], psdu_len);
        BaseType_t woken = pdFALSE;
        if (xRingbufferSendFromISR(s_ring, &item, sizeof(item.hdr) + psdu_len, &woken) == pdTRUE) {
            s_frames++;
        } else {
            s_dropped++;
        }
        s_led_kick = true;
        portYIELD_FROM_ISR(woken);
    }
    esp_ieee802154_receive_handle_done(frame);
}

static void radio_start(uint8_t channel)
{
    esp_ieee802154_set_channel(channel);
    esp_ieee802154_receive();
    s_channel = channel;
    ESP_LOGI(TAG, "Listening on channel %u", channel);
}

static void radio_init(void)
{
    ESP_ERROR_CHECK(esp_ieee802154_enable());
    /* Addresses no real frame targets, so the hardware never auto-ACKs on anyone's behalf. */
    uint8_t ext[8];
    esp_fill_random(ext, sizeof(ext));
    ext[0] |= 0x02; /* locally administered */
    esp_ieee802154_set_extended_address(ext);
    esp_ieee802154_set_short_address(0xFFFE);
    esp_ieee802154_set_panid(0xFFFF);
    esp_ieee802154_set_coordinator(false);
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);
    radio_start(CONFIG_SNIFF_CHANNEL);
}

/* ---------------------------------------------------------------- link (UART or USB) */

/* One call writes one whole message, so messages from different tasks never interleave (both
 * drivers copy a write into their TX buffer in one piece). Returns false if it was dropped. */
static bool link_write(const uint8_t *data, size_t n)
{
#if CONFIG_SNIFF_LINK_USB
    /* All or nothing: with the port closed the host takes nothing, and blocking here would stall
     * the status task (and its trial rollback) for good. */
    return usb_serial_jtag_write_bytes(data, n, pdMS_TO_TICKS(LINK_WRITE_MS)) == (int)n;
#else
    return uart_write_bytes(UART_PORT, data, n) == (int)n;
#endif
}

/* Whatever has arrived, up to max bytes: returns as soon as there is at least one byte, or after
 * timeout_ms of silence (0 bytes). */
static int link_read(uint8_t *buf, size_t max, uint32_t timeout_ms)
{
#if CONFIG_SNIFF_LINK_USB
    return usb_serial_jtag_read_bytes(buf, max, pdMS_TO_TICKS(timeout_ms));
#else
    size_t avail = 0;
    uart_get_buffered_data_len(UART_PORT, &avail);
    const size_t want = avail == 0 ? 1 : (avail < max ? avail : max);
    return uart_read_bytes(UART_PORT, buf, want, pdMS_TO_TICKS(timeout_ms));
#endif
}

static void link_flush(void)
{
#if CONFIG_SNIFF_LINK_USB
    vTaskDelay(pdMS_TO_TICKS(200)); /* the host polls the USB every millisecond or so */
#else
    uart_wait_tx_done(UART_PORT, pdMS_TO_TICKS(200));
#endif
}

/* Called from several tasks: the buffer stays on the caller's stack. */
static bool link_send(uint8_t type, const void *payload, uint16_t len)
{
    uint8_t      out[SNIFF_HEADER_LEN + SNIFF_MAX_PAYLOAD + SNIFF_TRAILER_LEN];
    const size_t n = sniff_encode(out, type, payload, len);
    return link_write(out, n);
}

static void tx_task(void *arg)
{
    for (;;) {
        size_t size = 0;
        void  *item = xRingbufferReceive(s_ring, &size, pdMS_TO_TICKS(1000));
        if (item) {
            if (!link_send(SNIFF_T_FRAME, item, (uint16_t)size)) {
                s_dropped++;
            }
            vRingbufferReturnItem(s_ring, item);
        }
    }
}

/* ---------------------------------------------------------------- firmware state */

static void send_boot(void)
{
    const sniff_radio_boot_ext_t b = {
        .boot    = {.version = {RADIO_VERSION_MAJOR, RADIO_VERSION_MINOR, RADIO_VERSION_PATCH}, .state = s_fw},
        .chip_id = CONFIG_IDF_FIRMWARE_CHIP_ID,
    };
    link_send(SNIFF_T_RADIO_BOOT, &b, sizeof(b));
}

static void fw_init(void)
{
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK &&
        st == ESP_OTA_IMG_PENDING_VERIFY) {
        s_fw = SNIFF_FW_TRIAL;
        ESP_LOGW(TAG, "New firmware on trial: kept once the bridge hears this radio");
    } else if (esp_ota_get_last_invalid_partition() != NULL) {
        s_fw = SNIFF_FW_ROLLED_BACK;
        ESP_LOGW(TAG, "A newer firmware failed its trial; running the previous one");
    }
}

/* The bridge's ping says it hears this radio: both directions of the link work. */
static void trial_pass(void)
{
    if (s_fw != SNIFF_FW_TRIAL || esp_timer_get_time() < TRIAL_MIN_US) {
        return;
    }
    esp_ota_mark_app_valid_cancel_rollback();
    s_fw = SNIFF_FW_CONFIRMED;
    ESP_LOGI(TAG, "New firmware confirmed");
    send_boot();
}

/* ---------------------------------------------------------------- update over the link */

static void update_ack(uint8_t stage, esp_err_t err)
{
    const sniff_update_ack_t ack = {.stage = stage, .offset = s_ota_have, .err = err};
    link_send(SNIFF_T_UPDATE_ACK, &ack, sizeof(ack));
}

static void update_stop(const char *why)
{
    if (s_ota_part) {
        esp_ota_abort(s_ota);
        s_ota_part = NULL;
    }
    if (s_updating) {
        s_updating = false;
        ESP_LOGW(TAG, "Update stopped: %s", why);
        radio_start(s_channel);
    }
}

static void update_begin(const uint8_t *p, uint16_t len)
{
    update_stop("a new update started");
    s_ota_have                  = 0;
    uint32_t               size = 0;
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (len >= 4) {
        memcpy(&size, p, 4);
    }
    if (!part || size == 0 || size > part->size) {
        update_ack(SNIFF_T_UPDATE_BEGIN, ESP_ERR_INVALID_SIZE);
        return;
    }
    s_updating = true;
    esp_ieee802154_sleep(); /* no frames (or radio interrupts) while the flash is written */
    const esp_err_t err = esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &s_ota);
    if (err == ESP_OK) {
        s_ota_part    = part;
        s_ota_size    = size;
        s_ota_last_us = esp_timer_get_time();
        ESP_LOGI(TAG, "Update: receiving %" PRIu32 " bytes into %s", size, part->label);
    }
    update_ack(SNIFF_T_UPDATE_BEGIN, err);
    if (err != ESP_OK) {
        update_stop(esp_err_to_name(err));
    }
}

static void update_data(const uint8_t *p, uint16_t len)
{
    if (!s_ota_part || len < 5) {
        update_ack(SNIFF_T_UPDATE_DATA, ESP_ERR_INVALID_STATE);
        return;
    }
    uint32_t off;
    memcpy(&off, p, 4);
    const uint32_t n = len - 4u;
    s_ota_last_us    = esp_timer_get_time();
    if (off + n <= s_ota_have) {
        update_ack(SNIFF_T_UPDATE_DATA, ESP_OK); /* a resend after a lost ack: already written */
        return;
    }
    if (off != s_ota_have || s_ota_have + n > s_ota_size) {
        update_ack(SNIFF_T_UPDATE_DATA, ESP_ERR_INVALID_STATE);
        return;
    }
    const esp_err_t err = esp_ota_write(s_ota, p + 4, n);
    if (err == ESP_OK) {
        s_ota_have += n;
    }
    update_ack(SNIFF_T_UPDATE_DATA, err);
    if (err != ESP_OK) {
        update_stop(esp_err_to_name(err));
    }
}

static void update_end(void)
{
    if (!s_ota_part || s_ota_have != s_ota_size) {
        update_ack(SNIFF_T_UPDATE_END, ESP_ERR_INVALID_SIZE);
        update_stop("image incomplete");
        return;
    }
    const esp_partition_t *part = s_ota_part;
    s_ota_part                  = NULL;    /* esp_ota_end frees the handle whatever it returns */
    esp_err_t err               = esp_ota_end(s_ota); /* checks the whole image, including its SHA-256 */
    if (err == ESP_OK) {
        err = esp_ota_set_boot_partition(part);
    }
    update_ack(SNIFF_T_UPDATE_END, err);
    if (err != ESP_OK) {
        update_stop(esp_err_to_name(err));
        return;
    }
    ESP_LOGI(TAG, "Update: image good, restarting into %s on trial", part->label);
    link_flush();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

static void rx_task(void *arg)
{
    static sniff_decoder_t dec;
    uint8_t                buf[256];
    for (;;) {
        /* Take whatever has arrived (at least one byte, or 100 ms of silence): asking for a full
         * buffer would sit out the timeout after every message, and updates are stop-and-wait. */
        const int n = link_read(buf, sizeof(buf), 100);
        for (int i = 0; i < n; i++) {
            if (!sniff_decode_byte(&dec, buf[i])) {
                continue;
            }
            const uint8_t *p = sniff_payload(&dec);
            switch (dec.type) {
            case SNIFF_T_SET_CHANNEL:
                if (!s_updating && dec.length >= 1 && p[0] >= 11 && p[0] <= 26 && p[0] != s_channel) {
                    radio_start(p[0]);
                }
                break;
            case SNIFF_T_PING:
                if (dec.length >= 1 && (p[0] & SNIFF_PING_RADIO_HEARD)) {
                    trial_pass();
                }
                break;
            case SNIFF_T_UPDATE_BEGIN:
                update_begin(p, dec.length);
                break;
            case SNIFF_T_UPDATE_DATA:
                update_data(p, dec.length);
                break;
            case SNIFF_T_UPDATE_END:
                update_end();
                break;
            case SNIFF_T_UPDATE_ABORT:
                update_stop("the bridge cancelled it");
                break;
            default:
                break;
            }
        }
        if (s_updating && esp_timer_get_time() - s_ota_last_us > UPDATE_IDLE_US) {
            update_stop("the bridge went quiet");
        }
    }
}

/* ---------------------------------------------------------------- status + LED */

static void led_write(bool lit)
{
#if CONFIG_SNIFF_LED_GPIO >= 0
    gpio_set_level(CONFIG_SNIFF_LED_GPIO, lit ? 0 : 1); /* XIAO LEDs are active low */
#endif
}

static void status_task(void *arg)
{
    TickType_t last_status = xTaskGetTickCount();
    TickType_t last_log    = xTaskGetTickCount();
    TickType_t last_boot   = xTaskGetTickCount();
    uint32_t   logged      = 0;
    for (;;) {
        /* Short flash per burst of traffic; a slow heartbeat when the air is quiet; steady while updating. */
        const bool kicked = s_led_kick;
        s_led_kick        = false;
        const bool beat   = ((esp_timer_get_time() / 1000) % 2000) < 30;
        led_write(s_updating || kicked || beat);

        if (xTaskGetTickCount() - last_status >= pdMS_TO_TICKS(1000)) {
            last_status = xTaskGetTickCount();
            if (!s_updating && esp_ieee802154_get_state() == ESP_IEEE802154_RADIO_IDLE) {
                esp_ieee802154_receive(); /* re-arm if the radio ever stopped */
            }
            const sniff_radio_status_t st = {
                .uptime_s = (uint32_t)(esp_timer_get_time() / 1000000),
                .frames   = s_frames,
                .dropped  = s_dropped,
                .channel  = s_channel,
                .version  = {RADIO_VERSION_MAJOR, RADIO_VERSION_MINOR, RADIO_VERSION_PATCH},
            };
            link_send(SNIFF_T_RADIO_STATUS, &st, sizeof(st));
            if (s_fw == SNIFF_FW_TRIAL && esp_timer_get_time() >= TRIAL_LIMIT_US) {
                ESP_LOGE(TAG, "New firmware never heard from the bridge: rolling back");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
        if (xTaskGetTickCount() - last_boot >= pdMS_TO_TICKS(30000)) {
            last_boot = xTaskGetTickCount();
            send_boot();
        }
        if (xTaskGetTickCount() - last_log >= pdMS_TO_TICKS(10000)) {
            last_log         = xTaskGetTickCount();
            const uint32_t f = s_frames;
            ESP_LOGI(TAG, "channel %u: %" PRIu32 " frames (+%" PRIu32 " in 10 s), %" PRIu32 " dropped", s_channel, f,
                     f - logged, (uint32_t)s_dropped);
            logged = f;
        }
        vTaskDelay(pdMS_TO_TICKS(40));
    }
}

/* ---------------------------------------------------------------- init */

static void board_init(void)
{
#if CONFIG_SNIFF_XIAO_RF_SWITCH
    const gpio_config_t rf = {
        .pin_bit_mask = (1ULL << XIAO_RF_POWER) | (1ULL << XIAO_RF_ANTENNA),
        .mode         = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&rf));
    gpio_set_level(XIAO_RF_POWER, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
#if CONFIG_SNIFF_EXTERNAL_ANTENNA
    gpio_set_level(XIAO_RF_ANTENNA, 1);
#else
    gpio_set_level(XIAO_RF_ANTENNA, 0);
#endif
#endif
#if CONFIG_SNIFF_LED_GPIO >= 0
    const gpio_config_t led = {.pin_bit_mask = 1ULL << CONFIG_SNIFF_LED_GPIO, .mode = GPIO_MODE_OUTPUT};
    ESP_ERROR_CHECK(gpio_config(&led));
    led_write(false);
#endif
}

static void link_init(void)
{
#if CONFIG_SNIFF_LINK_USB
    usb_serial_jtag_driver_config_t cfg = {.tx_buffer_size = 16384, .rx_buffer_size = 2048};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));
#else
    const uart_config_t cfg = {
        .baud_rate  = CONFIG_SNIFF_UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, 2048, 8192, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, CONFIG_SNIFF_UART_TX_GPIO, CONFIG_SNIFF_UART_RX_GPIO, UART_PIN_NO_CHANGE,
                                 UART_PIN_NO_CHANGE));
#endif
}

void app_main(void)
{
    ESP_LOGI(TAG, "Zigbee sniffer radio %d.%d.%d (%s)", RADIO_VERSION_MAJOR, RADIO_VERSION_MINOR, RADIO_VERSION_PATCH,
             esp_ota_get_running_partition()->label);
    fw_init();
    board_init();
    link_init();
    s_ring = xRingbufferCreate(RING_BYTES, RINGBUF_TYPE_NOSPLIT);
    configASSERT(s_ring);

    xTaskCreate(tx_task, "link_tx", 4096, NULL, 6, NULL);
    xTaskCreate(rx_task, "link_rx", 6144, NULL, 5, NULL);
    xTaskCreate(status_task, "status", 4096, NULL, 4, NULL);

    radio_init();
    send_boot();
#if CONFIG_SNIFF_LINK_USB
    ESP_LOGI(TAG, "Frames go out the USB port (this log is on UART0 only)");
#else
    ESP_LOGI(TAG, "UART %d baud on TX GPIO%d / RX GPIO%d", CONFIG_SNIFF_UART_BAUD, CONFIG_SNIFF_UART_TX_GPIO,
             CONFIG_SNIFF_UART_RX_GPIO);
#endif
}
