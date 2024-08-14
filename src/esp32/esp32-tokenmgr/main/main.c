#include <errno.h>

#include "config.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "tokenmgr.h"

#define TAG "token_mgr"

#define WIFI_MAX_ENTRY 3
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

token_store_t token_store = {0};
const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};
static esp_netif_t *netif;

static void event_handler(void *arg, esp_event_base_t event_base,
						  int32_t event_id, void *event_data) {
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
		esp_wifi_connect();
	else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (s_retry_num < WIFI_MAX_ENTRY) {
			esp_wifi_connect();
			s_retry_num++;
			ESP_LOGI(TAG, "retry to connect to the AP");
		} else
			xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);

		ESP_LOGI(TAG, "connect to the AP fail");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		s_retry_num = 0;
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

esp_netif_t *wifi_init_sta(void) {
	s_wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	esp_netif_t *netif = esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id, instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

	wifi_config_t wifi_config = {
		.sta =
			{
				.ssid = WIFI_SSID, .password = WIFI_PASS,
				// .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
				// .sae_pwe_h2e = ESP_WIFI_SAE_MODE,
				// .sae_h2e_identifier = EXAMPLE_H2E_IDENTIFIER,
			},
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGI(TAG, "esp_wifi_start finished.");

	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
										   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	if (bits & WIFI_CONNECTED_BIT)
		ESP_LOGI(TAG, "connected to ap SSID:%s", WIFI_SSID);
	else if (bits & WIFI_FAIL_BIT)
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", WIFI_SSID);
	else
		ESP_LOGE(TAG, "UNEXPECTED EVENT");

	return netif;
}

static void app_init(void) {
	// Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	netif = wifi_init_sta();

	reset_nvs_storage();
}

static void app_deinit(void) {
	if (netif != NULL)
		esp_netif_destroy(netif);
}

void app_main(void) {
	printf("App started\n");

	app_init();

	fetch_request_t fetch_req = {
		.num_tokens = 8,
		.access_type = ACCESS_PUBSUB,
	};
	const char *topic = "/sample/topic/pub";

	uint8_t timestamp[TIMESTAMP_LEN], random_bytes[RANDOM_BYTES_LEN];

	do {
		esp_err_t ret = get_token(topic, fetch_req, timestamp, random_bytes);

		if (ret == ESP_OK) {
			char timestamp_cstr[TIMESTAMP_LEN * 2 + 1] = {0}, random_bytes_cstr[RANDOM_BYTES_LEN * 2 + 1] = {0};
			char first, second;
			for (int i = 0; i < TIMESTAMP_LEN; i++) {
				first = (timestamp[i] >> 4) & 0xF;
				second = timestamp[i] & 0xF;
				timestamp_cstr[2 * i] = first < 0xA ? first + '0' : first - 0xA + 'A';
				timestamp_cstr[2 * i + 1] = second < 0xA ? second + '0' : second - 0xA + 'A';
			}
			for (int i = 0; i < RANDOM_BYTES_LEN; i++) {
				first = (random_bytes[i] >> 4) & 0xF;
				second = random_bytes[i] & 0xF;
				random_bytes_cstr[2 * i] = first < 0xA ? first + '0' : first - 0xA + 'A';
				random_bytes_cstr[2 * i + 1] = second < 0xA ? second + '0' : second - 0xA + 'A';
			}
			ESP_LOGI(TAG, "Successfully fetched token: %s:%s", timestamp_cstr, random_bytes_cstr);
		} else {
			ESP_LOGE(TAG, "Failed to fetch token");
		}
		sleep(2);
	} while (true);

	app_deinit();
}
