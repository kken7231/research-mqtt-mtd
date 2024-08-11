#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#define TIMESTAMP_LEN 6
#define RANDOM_BYTES_LEN 6
#define TOKEN_SIZE (TIMESTAMP_LEN + RANDOM_BYTES_LEN)
#define TIME_REVOCATION (7 * 24 * 60 * 60)	// 1 week in seconds

typedef enum {
	ACCESS_PUB = 1,
	ACCESS_SUB = 2,
	ACCESS_PUBSUB = 3
} access_type_t;

typedef struct {
	uint8_t num_tokens;
	access_type_t access_type;
} fetch_request_t;

typedef struct {
	uint8_t timestamp[TIMESTAMP_LEN];
	uint8_t *random_bytes;
	uint8_t token_count;
} token_store_t;

#define TAG "token_mgr"

extern const uint8_t client_crt_start[] asm("_binary_client1_pem_start");
extern const uint8_t client_crt_end[] asm("_binary_client1_pem_end");
extern const uint8_t client_key_start[] asm("_binary_client1_key_start");
extern const uint8_t client_key_end[] asm("_binary_client1_key_end");

static token_store_t token_store = {0};

#define WIFI_MAX_ENTRY 3
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;
static const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};
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

static esp_err_t save_token_store_to_nvs() {
	nvs_handle_t nvs_handle;
	ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs_handle));

	esp_err_t err = ESP_OK;

	err = nvs_set_blob(nvs_handle, "timestamp", token_store.timestamp, TIMESTAMP_LEN);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save timestamp: %s", esp_err_to_name(err));
		goto err_save_token_store_to_nvs_withclose;
	}

	err = nvs_set_blob(nvs_handle, "random_bytes", token_store.random_bytes, token_store.token_count * RANDOM_BYTES_LEN);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save random bytes: %s", esp_err_to_name(err));
		goto err_save_token_store_to_nvs_withclose;
	}

	err = nvs_set_u8(nvs_handle, "token_count", token_store.token_count);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save token count: %s", esp_err_to_name(err));
		goto err_save_token_store_to_nvs_withclose;
	}

	err = nvs_commit(nvs_handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
		goto err_save_token_store_to_nvs_withclose;
	}
	ESP_LOGI(TAG, "save_token_store_to_nvs: success");

err_save_token_store_to_nvs_withclose:
	nvs_close(nvs_handle);
	return err;
}

static esp_err_t load_token_store_from_nvs() {
	nvs_handle_t nvs_handle;
	esp_err_t err = ESP_OK;

	err = nvs_open("storage", NVS_READONLY, &nvs_handle);
	if (err == ESP_ERR_NVS_NOT_FOUND) {
		token_store.token_count = 0;
		return ESP_OK;
	} else if (err != ESP_OK) {
		ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
		token_store.token_count = 0;
		return err;
	}

	uint8_t token_count = 0;
	err = nvs_get_u8(nvs_handle, "token_count", &token_count);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to load token count: %s", esp_err_to_name(err));
		goto err_load_token_store_from_nvs_withreset;
	} else if (token_count == 0)
		goto success_load_token_store_from_nvs;

	size_t timestamp_size = TIMESTAMP_LEN;
	err = nvs_get_blob(nvs_handle, "timestamp", token_store.timestamp, &timestamp_size);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to load timestamp: %s", esp_err_to_name(err));
		goto err_load_token_store_from_nvs_withreset;
	}

	size_t random_bytes_size = 0;
	err = nvs_get_blob(nvs_handle, "random_bytes", NULL, &random_bytes_size);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to get size of random bytes: %s", esp_err_to_name(err));
		goto err_load_token_store_from_nvs_withreset;
	}

	token_store.random_bytes = malloc(random_bytes_size);
	if (!token_store.random_bytes) {
		ESP_LOGE(TAG, "Failed to allocate memory for random bytes");
		goto err_load_token_store_from_nvs_withreset;
	}

	err = nvs_get_blob(nvs_handle, "random_bytes", token_store.random_bytes, &random_bytes_size);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to load random bytes: %s", esp_err_to_name(err));
		goto err_load_token_store_from_nvs_withreset;
	}

success_load_token_store_from_nvs:
	token_store.token_count = token_count;
	ESP_LOGI(TAG, "load_token_store_from_nvs: success");
	nvs_close(nvs_handle);
	return err;

err_load_token_store_from_nvs_withreset:
	token_store.token_count = 0;
	if (token_store.random_bytes != NULL) {
		free(token_store.random_bytes);
		token_store.random_bytes = NULL;
	}
	nvs_close(nvs_handle);
	save_token_store_to_nvs();
	return err;
}

static esp_err_t reset_nvs_storage() {
	nvs_handle_t nvs_handle;
	esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
	if (err == ESP_ERR_NVS_NOT_FOUND)
		return ESP_OK;

	err = nvs_set_blob(nvs_handle, "timestamp", token_store.timestamp, TIMESTAMP_LEN);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save timestamp: %s", esp_err_to_name(err));
		goto err_reset_nvs_storage_withclose;
	}

	err = nvs_set_blob(nvs_handle, "random_bytes", NULL, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save random bytes: %s", esp_err_to_name(err));
		goto err_reset_nvs_storage_withclose;
	}

	err = nvs_set_u8(nvs_handle, "token_count", 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to save token count: %s", esp_err_to_name(err));
		goto err_reset_nvs_storage_withclose;
	}

	err = nvs_commit(nvs_handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
		goto err_reset_nvs_storage_withclose;
	}
	ESP_LOGI(TAG, "reset_nvs_storage: success");

err_reset_nvs_storage_withclose:
	nvs_close(nvs_handle);
	return err;
}

static esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
	size_t read_len = 0;
	while (read_len < len) {
		int ret = esp_tls_conn_read(tls, dst + read_len, len - read_len);
		if (ret < 0) {
			ESP_LOGE(TAG, "Connection read error: %d", ret);
			return ESP_FAIL;
		}
		read_len += ret;
	}
	return ESP_OK;
}

static esp_err_t conn_write(esp_tls_t *tls, const uint8_t *data, size_t len, uint32_t timeout_ms) {
	size_t written_len = 0;
	while (written_len < len) {
		int ret = esp_tls_conn_write(tls, data + written_len, len - written_len);
		if (ret < 0) {
			ESP_LOGE(TAG, "Connection write error: %d", ret);
			return ESP_FAIL;
		}
		written_len += ret;
	}
	return ESP_OK;
}

static esp_err_t fetch_tokens(fetch_request_t req, const char *topic, size_t topic_len) {
	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		return ESP_ERR_INVALID_ARG;
	}

	esp_tls_cfg_t cfg = {
		.crt_bundle_attach = esp_crt_bundle_attach,
		.clientcert_buf = client_crt_start,
		.clientcert_bytes = client_crt_end - client_crt_start,
		.clientkey_buf = client_key_start,
		.clientkey_bytes = client_key_end - client_key_start,
		.tls_version = ESP_TLS_VER_TLS_1_2,
		.ciphersuites_list = CIPHERSUITES_LIST,
		.common_name = "server",
	};
	// if (cfg.cacert_buf == NULL || cfg.clientcert_buf == NULL || cfg.clientkey_buf == NULL) {
	if (cfg.clientcert_buf == NULL || cfg.clientkey_buf == NULL) {
		ESP_LOGE(TAG, "Certificate or key buffer is NULL");
		return ESP_FAIL;
	}
	// if (cfg.cacert_bytes == 0 || cfg.clientcert_bytes == 0 || cfg.clientkey_bytes == 0) {
	if (cfg.clientcert_bytes == 0 || cfg.clientkey_bytes == 0) {
		ESP_LOGE(TAG, "Certificate or key buffer length is 0 [%d, %d, %d]", cfg.cacert_bytes, cfg.clientcert_bytes, cfg.clientkey_bytes);
		return ESP_FAIL;
	}
	esp_tls_t *tls = esp_tls_init();
	if (tls == NULL) {
		ESP_LOGE(TAG, "Failed to allocate esp_tls_t");
		return ESP_FAIL;
	}
	if (esp_tls_conn_new_sync(ISSUER_HOST, strlen(ISSUER_HOST), ISSUER_PORT, &cfg, tls) < 0) {
		ESP_LOGE(TAG, "Failed to open TLS connection");
		return ESP_FAIL;
	}

	uint8_t info[2] = {req.num_tokens / 4, topic_len};
	if (req.access_type & ACCESS_PUB) info[0] |= 0x80;
	if (req.access_type & ACCESS_SUB) info[0] |= 0x40;

	esp_err_t err = conn_write(tls, info, sizeof(info), 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write info");
		goto err_fetch_tokens_destroytls;
	}
	ESP_LOGI(TAG, "conn_write info success");

	err = conn_write(tls, (const uint8_t *)topic, topic_len, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write topic");
		goto err_fetch_tokens_destroytls;
	}
	ESP_LOGI(TAG, "conn_write topic success");

	uint8_t ts[TIMESTAMP_LEN];
	err = conn_read(tls, ts, TIMESTAMP_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read timestamp");
		goto err_fetch_tokens_destroytls;
	}
	ESP_LOGI(TAG, "conn_read timestamp success");

	memcpy(token_store.timestamp, ts, TIMESTAMP_LEN);
	token_store.random_bytes = realloc(token_store.random_bytes, req.num_tokens * RANDOM_BYTES_LEN);
	token_store.token_count = req.num_tokens;

	uint8_t rb[RANDOM_BYTES_LEN];
	for (int i = 0; i < req.num_tokens; ++i) {
		err = conn_read(tls, rb, RANDOM_BYTES_LEN, 0);
		if (err != ESP_OK) {
			ESP_LOGE(TAG, "Failed to conn_read random bytes");
			goto err_fetch_tokens_destroytls;
		}
		ESP_LOGI(TAG, "conn_read random bytes success");
		memcpy(&token_store.random_bytes[i * RANDOM_BYTES_LEN], rb, RANDOM_BYTES_LEN);
	}
	save_token_store_to_nvs();	// Save the token store to NVS after fetching tokens

err_fetch_tokens_destroytls:
	if (tls != NULL)
		esp_tls_conn_destroy(tls);
	return err;
}

static esp_err_t get_token_internal(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
	if (fetch_req.num_tokens < 4 || fetch_req.num_tokens > 0x3F * 4 || fetch_req.num_tokens % 4 != 0) {
		ESP_LOGE(TAG, "Invalid number of tokens. Must be between [4, 0x3F*4] and multiples of 4");
		return ESP_ERR_INVALID_ARG;
	}

	size_t topic_len = strlen(topic);
	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		return ESP_ERR_INVALID_ARG;
	}

	if (token_store.token_count == 0) {
		ESP_LOGI(TAG, "No token in the token store");
		if (fetch_tokens(fetch_req, topic, topic_len) != ESP_OK) {
			return ESP_FAIL;
		}
	}

	memcpy(timestamp, token_store.timestamp, TIMESTAMP_LEN);
	memcpy(random_bytes, token_store.random_bytes, RANDOM_BYTES_LEN);
	memmove(token_store.random_bytes, token_store.random_bytes + RANDOM_BYTES_LEN, (token_store.token_count - 1) * RANDOM_BYTES_LEN);
	token_store.token_count--;
	return save_token_store_to_nvs();
}

static void get_token_init(void) {
	load_token_store_from_nvs();  // Load token store from NVS at startup
}

static void get_token_deinit(void) {
	// reset_nvs_storage();
	if (token_store.random_bytes != NULL) {
		free(token_store.random_bytes);
		token_store.random_bytes = NULL;
	}
}

static esp_err_t get_token(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
	get_token_init();
	esp_err_t ret = get_token_internal(topic, fetch_req, timestamp, random_bytes);
	get_token_deinit();
	return ret;
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
		// sleep(2);
	} while (true);

	app_deinit();
}
