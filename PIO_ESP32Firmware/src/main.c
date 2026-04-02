#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG "ESP_FMDN"
#define EID_LEN_BYTES 20
#define ROTATION_PERIOD_SECONDS 1024

#if defined(CONFIG_IDF_TARGET_ESP32C3)
#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

#elif defined(CONFIG_IDF_TARGET_ESP32)
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"

#else
#error "Unsupported target"
#endif

#include "secret.h"

// MAC address rotation variable, the MAC address will be derived from the key and thus will appear random
static esp_bd_addr_t mac_addr = {0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

// Find My Device Network (FMDN) advertisement
// Octet 	Value 	        Description
// 0 	    0x02 	        Length
// 1 	    0x01 	        Flags data type value
// 2 	    0x06 	        Flags data
// 3 	    0x18 or 0x19 	Length
// 4 	    0x16 	        Service data data type value
// 5 	    0xAA 	        16-bit service UUID
// 6 	    0xFE 	        16-bit service UUID
// 7 	    0x40 or 0x41 	FMDN frame type with unwanted tracking protection mode indication
// 8..27 	Random          20-byte ephemeral identifier
// 28 		Hashed flags

uint8_t adv_raw_data[31] = {
    0x02,   // Length
    0x01,   // Flags data type value
    0x06,   // Flags data
    0x19,   // Length
    0x16,   // Service data data type value
    0xAA,   // 16-bit service UUID
    0xFE,   // 16-bit service UUID
    0x41,   // FMDN frame type with unwanted tracking protection mode indication
            // 20-byte ephemeral identifier (inserted below)
            // Hashed flags (implicitly initialized to 0)
};

static uint8_t *g_eid_bank = NULL;
static uint16_t g_eid_key_count = 0;
static bool g_ble_ready = false;


static int hex_char_to_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}


static bool parse_eid_bank(const char *hex_keys, uint16_t key_count)
{
    size_t expected_hex_len = (size_t)key_count * EID_LEN_BYTES * 2;
    size_t actual_hex_len = strlen(hex_keys);

    if (actual_hex_len != expected_hex_len) {
        ESP_LOGE(TAG, "Invalid key string length. Expected %u, got %u", (unsigned)expected_hex_len, (unsigned)actual_hex_len);
        return false;
    }

    g_eid_bank = (uint8_t *)malloc((size_t)key_count * EID_LEN_BYTES);
    if (g_eid_bank == NULL) {
        ESP_LOGE(TAG, "Failed to allocate EID bank buffer");
        return false;
    }

    for (size_t i = 0; i < (size_t)key_count * EID_LEN_BYTES; i++) {
        int high = hex_char_to_value(hex_keys[i * 2]);
        int low = hex_char_to_value(hex_keys[i * 2 + 1]);
        if (high < 0 || low < 0) {
            ESP_LOGE(TAG, "Invalid hex in EID key string at byte index %u", (unsigned)i);
            free(g_eid_bank);
            g_eid_bank = NULL;
            return false;
        }
        g_eid_bank[i] = (uint8_t)((high << 4) | low);
    }

    g_eid_key_count = key_count;
    return true;
}

static void set_mac_address_from_key(uint16_t index)
{
    uint8_t *key_ptr = &g_eid_bank[(size_t)index * EID_LEN_BYTES];
    uint8_t mac_rng[6] = {0};
    esp_fill_random(mac_rng, sizeof(mac_rng));
    
    // Derive MAC address from the first 6 bytes of the key and XOR with random bytes form the HW RNG of the ESP32
    for (int i = 0; i < 6; i++) {
        mac_addr[i] = key_ptr[i] ^ mac_rng[i];
    }

    // static random bits per: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html
    mac_addr[0] = mac_addr[0] | 0b11000000;

#if defined(CONFIG_IDF_TARGET_ESP32C3)
    ble_hs_id_set_pub(mac_addr);
#elif defined(CONFIG_IDF_TARGET_ESP32)
    esp_ble_gap_set_device_name("ESP32-FMDN");
    esp_ble_gap_set_rand_addr(mac_addr);
#endif
    ESP_LOGI(TAG, "Set MAC address to %02X:%02X:%02X:%02X:%02X:%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

static void set_advertisement_key_by_index(uint16_t index)
{
    uint8_t *key_ptr = &g_eid_bank[(size_t)index * EID_LEN_BYTES];
    memcpy(&adv_raw_data[8], key_ptr, EID_LEN_BYTES);
}


#if defined(CONFIG_IDF_TARGET_ESP32C3)
static int ble_advertise_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
        case BLE_GAP_EVENT_ADV_COMPLETE:
            ESP_LOGI(TAG, "Advertising completed");
            break;
        default:
            break;
    }
    return 0;
}


static void ble_start_advertising(void)
{
    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0x20,
        .itvl_max = 0x20,
    };

    ble_gap_adv_stop();
    ble_gap_adv_set_addr(mac_addr);
    ble_gap_adv_set_data(adv_raw_data, sizeof(adv_raw_data));
    ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, &adv_params, ble_advertise_cb, NULL);
}


static void ble_host_task(void *param)
{
    ESP_LOGI(TAG, "BLE Host Task Started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}


static void on_sync(void)
{
    ble_svc_gap_device_name_set("ESP32-C3-BLE");
    g_ble_ready = true;
    ble_start_advertising();
}
#endif


#if defined(CONFIG_IDF_TARGET_ESP32)
static esp_ble_adv_params_t g_adv_params = {
    .adv_int_min = 0x20,                                    // 20ms
    .adv_int_max = 0x20,                                    // 20ms
    .adv_type = ADV_TYPE_NONCONN_IND,                       // Non-connectable undirected advertising
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,                  // Will be set to the rotated MAC address
    .channel_map = ADV_CHNL_ALL,                            // Advertise on all channels
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY, // Allow scan and connection requests from any device
};


static void ble_start_advertising(void)
{
    esp_ble_gap_stop_advertising();
    ESP_ERROR_CHECK(esp_ble_gap_set_rand_addr(mac_addr));
    ESP_ERROR_CHECK(esp_ble_gap_config_adv_data_raw(adv_raw_data, sizeof(adv_raw_data)));
    ESP_ERROR_CHECK(esp_ble_gap_start_advertising(&g_adv_params));
}
#endif


static void key_rotation_task(void *param)
{
    int last_slot = -1;

    while (true) {
        if (g_ble_ready && g_eid_key_count > 0) {
            uint64_t now_seconds = esp_timer_get_time() / 1000000ULL;
            int slot = (int)((now_seconds / ROTATION_PERIOD_SECONDS) % g_eid_key_count);

            if (slot != last_slot) {
                set_advertisement_key_by_index((uint16_t)slot);
                set_mac_address_from_key((uint16_t)slot);
                ble_start_advertising();
                last_slot = slot;
                ESP_LOGI(TAG, "Rotated advertisement key to index %d", slot);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(500));
    }
}


void app_main()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    if (!parse_eid_bank(eid_keys_hex, eid_key_count)) {
        ESP_LOGE(TAG, "Failed to parse EID key bank. Aborting.");
        return;
    }

    ESP_LOGI(TAG, "Loaded %u rotating advertisement keys", g_eid_key_count);

    uint64_t now_seconds = esp_timer_get_time() / 1000000ULL;
    uint16_t initial_slot = (uint16_t)((now_seconds / ROTATION_PERIOD_SECONDS) % g_eid_key_count);
    set_advertisement_key_by_index(initial_slot);

#if defined(CONFIG_IDF_TARGET_ESP32C3)
    ESP_LOGI(TAG, "Initializing BLE");
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = on_sync;
    ble_svc_gap_init();
    nimble_port_freertos_init(ble_host_task);

#elif defined(CONFIG_IDF_TARGET_ESP32)
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9));
    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9));
    ESP_LOGI(TAG, "Set BLE TX Power to 9 dBm");

    ble_start_advertising();
    g_ble_ready = true;
    ESP_LOGI(TAG, "BLE advertising started.");
#endif

    xTaskCreate(key_rotation_task, "key_rotation_task", 4096, NULL, 5, NULL);
}
