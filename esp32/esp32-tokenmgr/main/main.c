#include <errno.h>

#include "config.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "tokenmgr.h"

static const char *TAG = "tokenmgr_app";

token_store_t token_store = {0};
const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};
const esp_mqtt5_connection_property_config_t mqtt_connect_property = {
	.session_expiry_interval = 10,
	.maximum_packet_size = 1024,
};
static esp_netif_t *netif;

static void app_init(void) {
	netif = comp_init();
}

static void app_deinit(void) {
	comp_deinit(netif);
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
