#include "tokenmgr.h"

static EventGroupHandle_t wifi_event_group, mqtt_plain_event_group, mqtt_tls_event_group;
static esp_mqtt_client_handle_t plain_mqtt_client, tls_mqtt_client;
static int wifi_retry_num = 0;
static const char *TAG = "tokenmgr";

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

#define TIME_RECORD_STORE_MAX 100
static time_record_t time_record_store[TIME_RECORD_STORE_MAX];
static int time_record_store_count = 0;
#define HIER_INDENT 4

static void log_time(time_record_type_t record_type, const char *label) {
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

#define LOG_TIME_FUNC_START()                                        \
	do {                                                             \
		const char *suffix = " started";                             \
		size_t buffer_size = strlen(__func__) + strlen(suffix) + 1;  \
		char log_buffer[buffer_size];                                \
		snprintf(log_buffer, buffer_size, "%s%s", __func__, suffix); \
		log_time(TIME_RECORD_TYPE_FUNC_STARTED, log_buffer);         \
	} while (0)

#define LOG_TIME_FUNC_END()                                          \
	do {                                                             \
		const char *suffix = " ended";                               \
		size_t buffer_size = strlen(__func__) + strlen(suffix) + 1;  \
		char log_buffer[buffer_size];                                \
		snprintf(log_buffer, buffer_size, "%s%s", __func__, suffix); \
		log_time(TIME_RECORD_TYPE_FUNC_ENDED, log_buffer);           \
	} while (0)

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
		if (time_record_store[i].record_type == TIME_RECORD_TYPE_FUNC_ENDED) {
			hier_prefix_len -= hier_prefix_indent;
		}
		ts_sec = time_record_store[i].timestamp.tv_sec;
		ts_usec = time_record_store[i].timestamp.tv_usec;

		tm_info = localtime(&ts_sec);
		strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", tm_info);

		int indent_len = time_record_store[i].record_type == TIME_RECORD_TYPE_UNDEFINED ? 0 : hier_prefix_len;
		printf("%s.%06ld %*s%s\n",
			   time_string, ts_usec,
			   indent_len, "",
			   time_record_store[i].label);
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
	LOG_TIME_FUNC_START();
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
	LOG_TIME_FUNC_END();
}

static esp_netif_t *wifi_init_sta(void) {
	LOG_TIME_FUNC_START();
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

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
	if (netif)
		esp_netif_destroy(netif);
wifi_init_sta_finish:
	LOG_TIME_FUNC_END();
	return netif;
}

static void mqttplain_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	LOG_TIME_FUNC_START();
	if (event_id == MQTT_EVENT_CONNECTED) {
		ESP_LOGI(TAG, "MQTT (plain) connected");
		xEventGroupSetBits(mqtt_plain_event_group, MQTT_CONNECTED_BIT);
	} else if (event_id != MQTT_EVENT_BEFORE_CONNECT) {
		ESP_LOGE(TAG, "MQTT (plain) event other than connected:  %ld", event_id);
		xEventGroupSetBits(mqtt_plain_event_group, MQTT_FAIL_BIT);
	}
	LOG_TIME_FUNC_END();
}

static void mqtttls_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	LOG_TIME_FUNC_START();
	if (event_id == MQTT_EVENT_CONNECTED) {
		ESP_LOGI(TAG, "MQTT (tls) connected");
		xEventGroupSetBits(mqtt_tls_event_group, MQTT_CONNECTED_BIT);
	} else if (event_id != MQTT_EVENT_BEFORE_CONNECT) {
		ESP_LOGE(TAG, "MQTT (tls) event other than connected: %ld", event_id);
		xEventGroupSetBits(mqtt_tls_event_group, MQTT_FAIL_BIT);
	}
	LOG_TIME_FUNC_END();
}

static esp_err_t mqtt_init(void) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;

	// plain connection
	esp_mqtt_client_config_t mqtt5_plain_cfg = {
		.broker.address.uri = PLAIN_BROKER_URI,
		.credentials.client_id = "esp32-plain-cli",
		.session.protocol_ver = MQTT_PROTOCOL_V_5,
		.network.disable_auto_reconnect = true,
	};
	mqtt_plain_event_group = xEventGroupCreate();
	plain_mqtt_client = esp_mqtt_client_init(&mqtt5_plain_cfg);
	ESP_ERROR_CHECK(esp_mqtt5_client_set_connect_property(plain_mqtt_client, &mqtt_connect_property));
	ESP_ERROR_CHECK(esp_mqtt_client_register_event(plain_mqtt_client, ESP_EVENT_ANY_ID, mqttplain_event_handler, NULL));
	ESP_ERROR_CHECK(esp_mqtt_client_start(plain_mqtt_client));
	ESP_LOGI(TAG, "esp_mqtt_client_start triggered (plain).");

	EventBits_t bits = xEventGroupWaitBits(mqtt_plain_event_group,
										   MQTT_CONNECTED_BIT | MQTT_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	if (bits & MQTT_CONNECTED_BIT)
		ESP_LOGI(TAG, "MQTTv5 (plain) connected");
	else {
		err = ESP_FAIL;
		if (bits & MQTT_FAIL_BIT)
			ESP_LOGE(TAG, "MQTTv5 (plain) connection failed");
		else
			ESP_LOGE(TAG, "UNEXPECTED EVENT");
		goto mqtt_init_finish;
	}

	// tls connection
	esp_mqtt_client_config_t mqtt5_tls_cfg = {
		.broker = {
			.address.uri = TLS_BROKER_URI,
			.verification = {
				.crt_bundle_attach = esp_crt_bundle_attach,
			},
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
	mqtt_tls_event_group = xEventGroupCreate();
	tls_mqtt_client = esp_mqtt_client_init(&mqtt5_tls_cfg);
	ESP_ERROR_CHECK(esp_mqtt5_client_set_connect_property(tls_mqtt_client, &mqtt_connect_property));
	ESP_ERROR_CHECK(esp_mqtt_client_register_event(tls_mqtt_client, ESP_EVENT_ANY_ID, mqtttls_event_handler, NULL));
	esp_mqtt_client_start(tls_mqtt_client);
	ESP_LOGI(TAG, "esp_mqtt_client_start triggered (tls).");

	bits = xEventGroupWaitBits(mqtt_tls_event_group,
							   MQTT_CONNECTED_BIT | MQTT_FAIL_BIT,
							   pdFALSE, pdFALSE, portMAX_DELAY);
	if (bits & MQTT_CONNECTED_BIT)
		ESP_LOGI(TAG, "MQTTv5 (tls) connected");
	else {
		err = ESP_FAIL;
		if (bits & MQTT_FAIL_BIT)
			ESP_LOGE(TAG, "MQTTv5 (tls) connection failed");
		else
			ESP_LOGE(TAG, "UNEXPECTED EVENT");

		if (plain_mqtt_client != NULL)
			esp_mqtt_client_destroy(plain_mqtt_client);
		goto mqtt_init_finish;
	}

mqtt_init_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t save_token_store_to_nvs() {
	LOG_TIME_FUNC_START();
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
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t load_token_store_from_nvs() {
	LOG_TIME_FUNC_START();
	nvs_handle_t nvs_handle;
	esp_err_t err = ESP_OK;

	err = nvs_open("storage", NVS_READONLY, &nvs_handle);
	if (err == ESP_ERR_NVS_NOT_FOUND) {
		token_store.token_count = 0;
		LOG_TIME_FUNC_END();
		return ESP_OK;
	} else if (err != ESP_OK) {
		ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
		token_store.token_count = 0;
		LOG_TIME_FUNC_END();
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
	LOG_TIME_FUNC_END();
	return err;

err_load_token_store_from_nvs_withreset:
	token_store.token_count = 0;
	if (token_store.random_bytes != NULL) {
		free(token_store.random_bytes);
		token_store.random_bytes = NULL;
	}
	nvs_close(nvs_handle);
	save_token_store_to_nvs();
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t reset_nvs_storage() {
	LOG_TIME_FUNC_START();
	nvs_handle_t nvs_handle;
	esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
	if (err == ESP_ERR_NVS_NOT_FOUND) {
		LOG_TIME_FUNC_END();
		return ESP_OK;
	}

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
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
	LOG_TIME_FUNC_START();
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
	LOG_TIME_FUNC_END();
	return ESP_OK;
}

static esp_err_t conn_write(esp_tls_t *tls, const uint8_t *data, size_t len, uint32_t timeout_ms) {
	LOG_TIME_FUNC_START();
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
	LOG_TIME_FUNC_END();
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

	uint8_t info[2] = {req.num_tokens / 4, topic_len};
	if (req.access_type & ACCESS_PUB) info[0] |= 0x80;
	if (req.access_type & ACCESS_SUB) info[0] |= 0x40;

	err = conn_write(tls, info, sizeof(info), 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write info");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_write info success");

	err = conn_write(tls, (const uint8_t *)topic, topic_len, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write topic");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_write topic success");

	uint8_t ts[TIMESTAMP_LEN];
	err = conn_read(tls, ts, TIMESTAMP_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read timestamp");
		goto fetch_tokens_finish_destroytls;
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
			goto fetch_tokens_finish_destroytls;
		}
		memcpy(&token_store.random_bytes[i * RANDOM_BYTES_LEN], rb, RANDOM_BYTES_LEN);
	}
	ESP_LOGI(TAG, "conn_read random bytes success");
	save_token_store_to_nvs();	// Save the token store to NVS after fetching tokens

fetch_tokens_finish_destroytls:
	if (tls != NULL)
		esp_tls_conn_destroy(tls);
fetch_tokens_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t get_token_internal(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
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
	err = save_token_store_to_nvs();

get_token_internal_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static void get_token_init(void) {
	LOG_TIME_FUNC_START();
	load_token_store_from_nvs();  // Load token store from NVS at startup
	LOG_TIME_FUNC_END();
}

static void get_token_deinit(void) {
	LOG_TIME_FUNC_START();
	// reset_nvs_storage();
	if (token_store.random_bytes != NULL) {
		free(token_store.random_bytes);
		token_store.random_bytes = NULL;
	}
	LOG_TIME_FUNC_END();
}

esp_netif_t *comp_init(void) {
	LOG_TIME_FUNC_START();

	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	esp_log_level_set("wifi", ESP_LOG_WARN);

	esp_netif_t *netif = wifi_init_sta();

	ret = mqtt_init();
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Mqtt initialization failed");
		goto comp_initialize_finish;
	}

	reset_nvs_storage();
comp_initialize_finish:
	LOG_TIME_FUNC_END();
	return netif;
}

void comp_deinit(esp_netif_t *netif) {
	LOG_TIME_FUNC_START();
	if (netif != NULL) {
		esp_netif_sntp_deinit();
		esp_netif_destroy(netif);
	}
	mdns_free();
	LOG_TIME_FUNC_END();
}
esp_err_t get_token(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
	LOG_TIME_FUNC_START();
	get_token_init();
	esp_err_t ret = get_token_internal(topic, fetch_req, timestamp, random_bytes);
	get_token_deinit();
	LOG_TIME_FUNC_END();
	return ret;
}
