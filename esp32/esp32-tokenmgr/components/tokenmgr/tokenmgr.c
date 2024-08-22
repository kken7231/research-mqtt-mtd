#include "tokenmgr.h"

static EventGroupHandle_t wifi_event_group, mqtt_plain_event_group, mqtt_tls_event_group;
static esp_mqtt_client_handle_t plain_mqtt_client, tls_mqtt_client;
static int wifi_retry_num = 0;
static const char *TAG = "tokenmgr";
static esp_netif_t *netif;
static tokenmgr_state_t current_state = TOKENMGR_STATE_BEFORE_ONETIME_INIT;
int permit_time_logging = 0;

#define CHECK_CURSTATE_IF_OPERATIONAL(err, goto_label)           \
	if (current_state != TOKENMGR_STATE_OPERTATIONAL) {          \
		ESP_LOGE(TAG, "tokenmgr needs to be initialized first"); \
		err = ESP_FAIL;                                          \
		goto goto_label;                                         \
	}

#ifdef COMPILEROPT_INCLUDE_TIME_LOG

typedef enum {
	TIME_RECORD_TYPE_UNDEFINED,
	TIME_RECORD_TYPE_FUNC_STARTED,
	TIME_RECORD_TYPE_FUNC_ENDED,
} time_record_type_t;
typedef struct {
	time_record_type_t record_type;
	struct timeval timestamp;  // Real-world time in microseconds
	const char *label;		   // Label associated with the time log
} time_record_t;

#define TIME_RECORD_STORE_MAX 1024
static time_record_t time_record_store[TIME_RECORD_STORE_MAX];
static int time_record_store_count = 0;
#define HIER_INDENT 4

static void log_time(time_record_type_t record_type, const char *label) {
	if (current_state != TOKENMGR_STATE_OPERTATIONAL || permit_time_logging == 0) return;
	if (time_record_store_count < TIME_RECORD_STORE_MAX) {
		time_record_store[time_record_store_count].record_type = record_type;
		gettimeofday(&time_record_store[time_record_store_count].timestamp, NULL);
		time_record_store[time_record_store_count].label = strdup(label);
		if (time_record_store[time_record_store_count].label == NULL) {
			fprintf(stderr, "Memory allocation failed\n");
			exit(1);
		}
		time_record_store_count++;
	} else {
		fprintf(stderr, "Time logging failed due to insufficient space in time_record_store\n");
	}
}

#define LOG_TIME(LABEL) log_time(TIME_RECORD_TYPE_UNDEFINED, LABEL)
#define LOG_TIME_FUNC_START()                              \
	if (current_state == TOKENMGR_STATE_OPERTATIONAL) {    \
		log_time(TIME_RECORD_TYPE_FUNC_STARTED, __func__); \
	}

#define LOG_TIME_FUNC_END()                              \
	if (current_state == TOKENMGR_STATE_OPERTATIONAL) {  \
		log_time(TIME_RECORD_TYPE_FUNC_ENDED, __func__); \
	}

void print_time_record_summary(void) {
	printf("Time Record Summary:\n");
	printf("====================\n");
	char time_string[26];
	int hier_prefix_len = 0;
	const int hier_prefix_indent = 4;
	time_t ts_sec;
	long ts_usec;
	struct tm *tm_info;
	for (int i = 0; i < time_record_store_count; i++) {
		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED && hier_prefix_len > 0) {
			hier_prefix_len -= hier_prefix_indent;
		}
		ts_sec = time_record_store[i].timestamp.tv_sec;
		ts_usec = time_record_store[i].timestamp.tv_usec;

		tm_info = localtime(&ts_sec);
		strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", tm_info);

		const char *suffix = "";
		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_STARTED) {
			suffix = " started";
		} else if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED) {
			suffix = " ended";
		}

		int indent_len = time_record_store[i].record_type == TIME_RECORD_TYPE_UNDEFINED ? 0 : hier_prefix_len;
		printf("%s.%06ld %*s%s%s",
			   time_string, ts_usec,
			   indent_len, "",
			   time_record_store[i].label, suffix);

		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED) {
			for (int j = i - 1; j >= 0; j--) {
				if (time_record_store[j].record_type == TIME_RECORD_TYPE_FUNC_STARTED &&
					strcmp(time_record_store[j].label, time_record_store[i].label) == 0) {
					long elapsed_sec = time_record_store[i].timestamp.tv_sec - time_record_store[j].timestamp.tv_sec;
					long elapsed_usec = time_record_store[i].timestamp.tv_usec - time_record_store[j].timestamp.tv_usec;
					if (elapsed_usec < 0) {
						elapsed_sec -= 1;
						elapsed_usec += 1000000;
					}
					printf(" (%ld.%06ld seconds)", elapsed_sec, elapsed_usec);
					break;
				}
			}
		}
		printf("\n");

		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_STARTED) {
			hier_prefix_len += hier_prefix_indent;
		}
	}
	printf("====================\n");
}

void reset_time_record_store(void) {
	for (int i = 0; i < time_record_store_count; i++) {
		if (time_record_store[i].label) {
			free((void *)time_record_store[i].label);
			time_record_store[i].label = NULL;
		}
	}
	time_record_store_count = 0;
}
#else
#define LOG_TIME(LABEL)
#define LOG_TIME_FUNC_START()
#define LOG_TIME_FUNC_END()
void print_time_record_summary(void) {};
void reset_time_record_store(void) {};
#endif

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
		esp_wifi_connect();
	else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (wifi_retry_num < WIFI_MAX_RETRY) {
			esp_wifi_connect();
			wifi_retry_num++;
			ESP_LOGI(TAG, "retry to connect to the AP");
		} else
			xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
		ESP_LOGI(TAG, "Failed to connect to the AP");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ESP_LOGI(TAG, "IP address assigned:" IPSTR, IP2STR(&((ip_event_got_ip_t *)event_data)->ip_info.ip));
		wifi_retry_num = 0;
		xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

static esp_netif_t *wifi_init_sta(void) {
	LOG_TIME_FUNC_START();
	wifi_event_group = xEventGroupCreate();
	esp_netif_t *netif = esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id, instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = wifi_sta_config,
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGI(TAG, "esp_wifi_start triggered");

	EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
										   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));

	if (bits & WIFI_CONNECTED_BIT)
		ESP_LOGI(TAG, "connected to ap SSID:%s", wifi_sta_config.ssid);
	else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", wifi_sta_config.ssid);
		goto wifi_init_sta_err;
	} else {
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
		goto wifi_init_sta_err;
	}

	ESP_ERROR_CHECK(mdns_init());
	ESP_ERROR_CHECK(mdns_hostname_set("client"));
	ESP_LOGI(TAG, "mdns hostname set to client");

	esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
	config.start = false;
	config.server_from_dhcp = true;
	config.index_of_first_server = 1;
	config.ip_event_to_renew = IP_EVENT_STA_GOT_IP;
	ESP_ERROR_CHECK(esp_netif_sntp_init(&config));
	ESP_ERROR_CHECK(esp_netif_sntp_start());
	ESP_LOGI(TAG, "esp_netif_sntp_start triggered");
	int sntp_retry = 0;
	while (esp_netif_sntp_sync_wait(1000 / portTICK_PERIOD_MS) == ESP_ERR_TIMEOUT && ++sntp_retry < SNTP_MAX_RETRY) {
		ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", sntp_retry, SNTP_MAX_RETRY);
	}
	sntp_sync_status_t sntp_status = sntp_get_sync_status();
	if (sntp_status == SNTP_SYNC_STATUS_COMPLETED) {
		ESP_LOGI(TAG, "time fixed with SNTP");
		LOG_TIME("Time fixed with SNTP");
		goto wifi_init_sta_finish;
	} else {
		ESP_LOGE(TAG, "time didn't fixed with SNTP");
		goto wifi_init_sta_err;
	}

wifi_init_sta_err:
	if (netif) {
		esp_wifi_stop();
		esp_wifi_deinit();
		esp_netif_destroy(netif);
	}
wifi_init_sta_finish:
	LOG_TIME_FUNC_END();
	return netif;
}

static esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
	// LOG_TIME_FUNC_START();
	size_t read_len = 0;
	while (read_len < len) {
		int ret = esp_tls_conn_read(tls, dst + read_len, len - read_len);
		if (ret < 0) {
			ESP_LOGE(TAG, "Connection read error: %d", ret);
			LOG_TIME_FUNC_END();
			return ESP_FAIL;
		}
		read_len += ret;
	}
	// LOG_TIME_FUNC_END();
	return ESP_OK;
}

static esp_err_t conn_write(esp_tls_t *tls, const uint8_t *data, size_t len, uint32_t timeout_ms) {
	// LOG_TIME_FUNC_START();
	size_t written_len = 0;
	while (written_len < len) {
		int ret = esp_tls_conn_write(tls, data + written_len, len - written_len);
		if (ret < 0) {
			ESP_LOGE(TAG, "Connection write error: %d", ret);
			LOG_TIME_FUNC_END();
			return ESP_FAIL;
		}
		written_len += ret;
	}
	// LOG_TIME_FUNC_END();
	return ESP_OK;
}

static esp_err_t fetch_tokens(fetch_request_t req, const char *topic, size_t topic_len) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		err = ESP_ERR_INVALID_ARG;
		goto fetch_tokens_finish;
	}

	esp_tls_cfg_t cfg = {
		.crt_bundle_attach = esp_crt_bundle_attach,
		.clientcert_buf = client_crt_start,
		.clientcert_bytes = client_crt_end - client_crt_start,
		.clientkey_buf = client_key_start,
		.clientkey_bytes = client_key_end - client_key_start,
		.tls_version = ESP_TLS_VER_TLS_1_3,
		.ciphersuites_list = CIPHERSUITES_LIST,
	};
	// if (cfg.cacert_buf == NULL || cfg.clientcert_buf == NULL || cfg.clientkey_buf == NULL) {
	if (cfg.clientcert_buf == NULL || cfg.clientkey_buf == NULL) {
		ESP_LOGE(TAG, "Certificate or key buffer is NULL");
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	// if (cfg.cacert_bytes == 0 || cfg.clientcert_bytes == 0 || cfg.clientkey_bytes == 0) {
	if (cfg.clientcert_bytes == 0 || cfg.clientkey_bytes == 0) {
		ESP_LOGE(TAG, "Certificate or key buffer length is 0 [%d, %d, %d]", cfg.cacert_bytes, cfg.clientcert_bytes, cfg.clientkey_bytes);
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	esp_tls_t *tls = esp_tls_init();
	if (tls == NULL) {
		ESP_LOGE(TAG, "Failed to allocate esp_tls_t");
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	if (esp_tls_conn_new_sync(ISSUER_HOST, strlen(ISSUER_HOST), ISSUER_PORT, &cfg, tls) < 0) {
		ESP_LOGE(TAG, "Failed to open TLS connection");
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}

	uint8_t *req_data = (uint8_t *)malloc(2 + topic_len);
	req_data[0] = req.num_tokens / 4;
	req_data[1] = topic_len;
	if (req.access_type & ACCESS_PUB) req_data[0] |= 0x80;
	if (req.access_type & ACCESS_SUB) req_data[0] |= 0x40;
	memcpy(req_data + 2, topic, topic_len);

	err = conn_write(tls, req_data, 2 + topic_len, 0);
	free((void *)req_data);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write info+topic");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_write info+topic success");

	err = conn_read(tls, token_store.timestamp, TIMESTAMP_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read timestamp");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_read timestamp success");

	// Allocate memory for random bytes in heap
	token_store.random_bytes = malloc(req.num_tokens * RANDOM_BYTES_LEN);
	if (!token_store.random_bytes) {
		ESP_LOGE(TAG, "Failed to allocate memory for random bytes");
		goto fetch_tokens_finish_destroytls;
	}
	err = conn_read(tls, token_store.random_bytes, req.num_tokens * RANDOM_BYTES_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read random bytes");
		free((void *)token_store.random_bytes);
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_read random bytes success");

	token_store.token_count = req.num_tokens;

fetch_tokens_finish_destroytls:
	if (tls != NULL)
		esp_tls_conn_destroy(tls);
fetch_tokens_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t get_token_internal(const char *topic, fetch_request_t fetch_req, uint8_t timestamp[TIMESTAMP_LEN], uint8_t random_bytes[RANDOM_BYTES_LEN]) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	if (fetch_req.num_tokens < 4 || fetch_req.num_tokens > 0x3F * 4 || fetch_req.num_tokens % 4 != 0) {
		ESP_LOGE(TAG, "Invalid number of tokens. Must be between [4, 0x3F*4] and multiples of 4");
		err = ESP_ERR_INVALID_ARG;
		goto get_token_internal_finish;
	}

	size_t topic_len = strlen(topic);
	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		err = ESP_ERR_INVALID_ARG;
		goto get_token_internal_finish;
	}

	if (token_store.token_count == 0) {
		ESP_LOGI(TAG, "No token in the token store");
		err = fetch_tokens(fetch_req, topic, topic_len);
		if (err != ESP_OK)
			goto get_token_internal_finish;
	}

	memcpy(timestamp, token_store.timestamp, TIMESTAMP_LEN);
	memcpy(random_bytes, token_store.random_bytes, RANDOM_BYTES_LEN);
	memmove(token_store.random_bytes, token_store.random_bytes + RANDOM_BYTES_LEN, (token_store.token_count - 1) * RANDOM_BYTES_LEN);
	token_store.token_count--;

get_token_internal_finish:
	LOG_TIME_FUNC_END();
	return err;
}

void tokenmgr_app_init(void) {
	LOG_TIME_FUNC_START();
	if (current_state == TOKENMGR_STATE_BEFORE_ONETIME_INIT) {
		ESP_ERROR_CHECK(esp_netif_init());
		ESP_ERROR_CHECK(esp_event_loop_create_default());
		current_state = TOKENMGR_STATE_UNINITIALIZED;
	}
	LOG_TIME_FUNC_END();
}

void tokenmgr_init(void) {
	LOG_TIME_FUNC_START();
	if (current_state == TOKENMGR_STATE_BEFORE_ONETIME_INIT) {
		ESP_LOGE(TAG, "Call tokenmgr_app_init() before calling this function");
	} else if (current_state == TOKENMGR_STATE_UNINITIALIZED) {
		esp_err_t ret = nvs_flash_init();
		if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
			ESP_ERROR_CHECK(nvs_flash_erase());
			ret = nvs_flash_init();
		}
		ESP_ERROR_CHECK(ret);

		esp_log_level_set("wifi", ESP_LOG_WARN);

		netif = wifi_init_sta();

		current_state = TOKENMGR_STATE_OPERTATIONAL;
		ESP_LOGI(TAG, "tokenmgr initialized");
	} else {
		ESP_LOGE(TAG, "tokenmgr is already initialized");
	}
	LOG_TIME_FUNC_END();
}

void tokenmgr_deinit() {
	LOG_TIME_FUNC_START();
	if (current_state == TOKENMGR_STATE_OPERTATIONAL) {
		if (plain_mqtt_client != NULL) {
			esp_mqtt_client_destroy(plain_mqtt_client);
		}
		if (tls_mqtt_client != NULL) {
			esp_mqtt_client_destroy(tls_mqtt_client);
		}
		if (netif != NULL) {
			mdns_free();
			esp_netif_sntp_deinit();
			esp_wifi_stop();
			esp_wifi_deinit();
			esp_netif_destroy(netif);
		}

		current_state = TOKENMGR_STATE_UNINITIALIZED;
		ESP_LOGI(TAG, "tokenmgr deinitialized");
	}
	LOG_TIME_FUNC_END();
}

esp_err_t get_token(const char *topic, fetch_request_t fetch_req, uint8_t timestamp[TIMESTAMP_LEN], uint8_t random_bytes[RANDOM_BYTES_LEN]) {
	LOG_TIME_FUNC_START();
	esp_err_t ret = ESP_OK;
	CHECK_CURSTATE_IF_OPERATIONAL(ret, get_token_finish);
	ret = get_token_internal(topic, fetch_req, timestamp, random_bytes);
get_token_finish:
	LOG_TIME_FUNC_END();
	return ret;
}

esp_err_t b64encode_token(const uint8_t timestamp[TIMESTAMP_LEN], const uint8_t random_bytes[RANDOM_BYTES_LEN], uint8_t encoded_token[BASE64_ENCODED_TOKEN_SIZE]) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	CHECK_CURSTATE_IF_OPERATIONAL(err, b64encode_token_finish);
	if (!timestamp || !random_bytes || !encoded_token) {
		err = ESP_ERR_INVALID_ARG;
		goto b64encode_token_finish;
	}

	uint8_t token[TOKEN_SIZE];
	memcpy(token, timestamp, TIMESTAMP_LEN);
	memcpy(token + TIMESTAMP_LEN, random_bytes, RANDOM_BYTES_LEN);

	size_t output_len;
	int ret = mbedtls_base64_encode((unsigned char *)encoded_token, BASE64_ENCODED_TOKEN_SIZE, &output_len, (const unsigned char *)token, TOKEN_SIZE);
	if (ret != 0 || output_len != BASE64_ENCODED_TOKEN_SIZE - 1) {
		err = ESP_FAIL;
		goto b64encode_token_finish;
	}
	encoded_token[BASE64_ENCODED_TOKEN_SIZE - 1] = '\0';

b64encode_token_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static void mqtt_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	mqtt_client_type_t *client_type = (mqtt_client_type_t *)arg;
	const char *client_type_label = (*client_type == MQTT_CLIENT_PLAIN) ? "plain" : "tls";
	const EventGroupHandle_t client_group = (*client_type == MQTT_CLIENT_PLAIN) ? mqtt_plain_event_group : mqtt_tls_event_group;
	if ((esp_mqtt_event_id_t)event_id == MQTT_EVENT_CONNECTED) {
		ESP_LOGI(TAG, "Event MQTT_EVENT_CONNECTED (%s)", client_type_label);
		xEventGroupSetBits(client_group, MQTT_CONNECTED_BIT);
	} else if ((esp_mqtt_event_id_t)event_id == MQTT_EVENT_ERROR) {
		ESP_LOGE(TAG, "Event MQTT_EVENT_ERROR (%s)", client_type_label);
		xEventGroupSetBits(client_group, MQTT_FAIL_BIT);
	} else if ((esp_mqtt_event_id_t)event_id != MQTT_EVENT_BEFORE_CONNECT) {
		ESP_LOGE(TAG, "MQTT (%s) event other than MQTT_EVENT_CONNECTED: %ld", client_type_label, event_id);
		xEventGroupSetBits(client_group, MQTT_FAIL_BIT);
	}
}

static esp_mqtt_client_handle_t mqtt_client_start(esp_mqtt_client_config_t *p_cfg, mqtt_client_type_t *p_client_type) {
	EventGroupHandle_t *p_event_group;
	esp_mqtt_client_handle_t mqtt_client;
	const char *mqtt_client_label;

	if (*p_client_type == MQTT_CLIENT_PLAIN) {
		p_event_group = &mqtt_plain_event_group;
		mqtt_client_label = "plain";
	} else {
		p_event_group = &mqtt_tls_event_group;
		mqtt_client_label = "tls";
	}
	*p_event_group = xEventGroupCreate();
	mqtt_client = esp_mqtt_client_init(p_cfg);
	if (mqtt_client == NULL) {
		ESP_LOGE(TAG, "MQTT (%s) client initialization failed", mqtt_client_label);
		return NULL;
	}
	ESP_ERROR_CHECK(esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void *)p_client_type));
	ESP_ERROR_CHECK(esp_mqtt_client_start(mqtt_client));
	ESP_LOGI(TAG, "esp_mqtt_client_start triggered (%s)", mqtt_client_label);

	EventBits_t bits = xEventGroupWaitBits(*p_event_group,
										   MQTT_CONNECTED_BIT | MQTT_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	ESP_ERROR_CHECK(esp_mqtt_client_unregister_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler));
	if (bits & MQTT_CONNECTED_BIT)
		ESP_LOGI(TAG, "MQTT (%s) connected", mqtt_client_label);
	else {
		if (bits & MQTT_FAIL_BIT)
			ESP_LOGE(TAG, "MQTT (%s) connection failed", mqtt_client_label);
		else
			ESP_LOGE(TAG, "UNEXPECTED EVENT");
		if (mqtt_client != NULL)
			esp_mqtt_client_destroy(mqtt_client);
		return NULL;
	}
	return mqtt_client;
}

esp_err_t mqtt_publish_qos0(mqtt_client_type_t client_type, const char *topic, const char *data, int len_data) {
	LOG_TIME_FUNC_START();
	esp_err_t ret = ESP_OK;
	esp_mqtt_client_handle_t mqtt_client = NULL;
	CHECK_CURSTATE_IF_OPERATIONAL(ret, mqtt_publish_qos0_finish);
	const char *mqtt_client_label;

	if (client_type == MQTT_CLIENT_PLAIN) {
		esp_mqtt_client_config_t plain_cfg = {
			.broker.address.uri = PLAIN_BROKER_URI,
			.credentials.client_id = "esp32-plain-cli",
			.session.protocol_ver = MQTT_PROTOCOL_V_5,
			.network.disable_auto_reconnect = true,
		};
		mqtt_client_type_t plain_client_type = MQTT_CLIENT_PLAIN;
		mqtt_client_label = "plain";
		mqtt_client = mqtt_client_start(&plain_cfg, &plain_client_type);
	} else {
		esp_mqtt_client_config_t tls_cfg = {
			.broker = {
				.address.uri = TLS_BROKER_URI,
				.verification.crt_bundle_attach = esp_crt_bundle_attach,
			},
			.credentials = {
				.client_id = "esp32-tls-cli",
				.authentication = {
					.certificate = (const char *)client_crt_start,
					.key = (const char *)client_key_start,
				},
			},
			.session.protocol_ver = MQTT_PROTOCOL_V_5,
			.network.disable_auto_reconnect = true,
		};
		mqtt_client_type_t tls_client_type = MQTT_CLIENT_TLS;
		mqtt_client_label = "tls";
		mqtt_client = mqtt_client_start(&tls_cfg, &tls_client_type);
	}

	if (mqtt_client == NULL)
		goto mqtt_publish_qos0_finish;

	if (esp_mqtt_client_publish(mqtt_client, topic, data, len_data, 0, 0) != 0) {
		ESP_LOGE(TAG, "MQTT Publish (%s) failed", mqtt_client_label);
		ret = ESP_FAIL;
	} else {
		ESP_LOGI(TAG, "MQTT Publish (%s) success", mqtt_client_label);
	}
mqtt_publish_qos0_finish:
	if (mqtt_client) {
		esp_mqtt_client_disconnect(mqtt_client);
		esp_mqtt_client_destroy(mqtt_client);
	}

	LOG_TIME_FUNC_END();
	return ret;
}