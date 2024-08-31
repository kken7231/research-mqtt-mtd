#include "tokenmgr.h"

static const char *TAG = "tokenmgr";
static esp_netif_t *netif;
tokenmgr_state_t current_state = TOKENMGR_STATE_BEFORE_ONETIME_INIT;
static esp_mqtt_client_handle_t plain_mqtt_client, tls_mqtt_client;

static token_store_t token_store_instance = {.head = NULL, .tail = NULL};
static token_store_t *token_store = &token_store_instance;

static esp_err_t fetch_tokens(issuer_request_t req, const char *topic, const uint16_t topic_len) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	// request
	uint8_t req_data[4 + topic_len];
	memset(req_data, 0, 4 + topic_len);

	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		err = ESP_ERR_INVALID_ARG;
		goto fetch_tokens_finish;
	}
	if (req.num_tokens_divided_by_multiplier < 1 || req.num_tokens_divided_by_multiplier > 0x1F) {
		ESP_LOGE(TAG, "field NumberOfTokens is not in the range of [1, 0x1F]");
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
	if (!cfg.clientcert_buf || !cfg.clientkey_buf) {
		ESP_LOGE(TAG, "Certificate or key buffer is NULL");
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	if (cfg.clientcert_bytes == 0 || cfg.clientkey_bytes == 0) {
		ESP_LOGE(TAG, "Certificate or key buffer length is 0 [%d, %d, %d]", cfg.cacert_bytes, cfg.clientcert_bytes, cfg.clientkey_bytes);
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	esp_tls_t *tls = esp_tls_init();
	if (!tls) {
		ESP_LOGE(TAG, "Failed to allocate esp_tls_t");
		err = ESP_FAIL;
		goto fetch_tokens_finish;
	}
	if (esp_tls_conn_new_sync(ISSUER_HOST, strlen(ISSUER_HOST), ISSUER_PORT, &cfg, tls) < 0) {
		ESP_LOGE(TAG, "Failed to open TLS connection");
		err = ESP_FAIL;
		goto fetch_tokens_finish_destroytls;
	}

	// Send a request
	// uint8_t *req_data = (uint8_t *)malloc(4 + topic_len);
	// if (!req_data) {
	// 	ESP_LOGE(TAG, "Failed to allocate memory for req_data");
	// 	err = ESP_ERR_NO_MEM;
	// 	goto fetch_tokens_finish_destroytls;
	// }
	int offset = 0;
	req_data[offset] = req.num_tokens_divided_by_multiplier;
	if (req.access_type_is_pub) req_data[offset] |= 0x80;
	if (is_encryption_enabled(req.payload_aead_type)) req_data[offset] |= 0x40;
	offset++;
	if (is_encryption_enabled(req.payload_aead_type)) req_data[offset++] = req.payload_aead_type;
	req_data[offset++] = (uint8_t)((topic_len >> 8) & 0xFF);
	req_data[offset++] = (uint8_t)(topic_len & 0xFF);
	memcpy(req_data + offset, topic, topic_len);
	offset += topic_len;
	err = conn_write(tls, req_data, offset, 0);
	// free((void *)req_data);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_write issuer_request");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_write issuer_request success");

	// Check the store
	token_store_entry_t *entry = token_store_search(token_store, topic, req.access_type_is_pub);
	if (entry) {
		// found
		if (entry->all_random_data)
			free((void *)(entry->all_random_data));
		entry->cur_random_data = NULL;
		entry->token_count = 0;
		entry->cur_token_idx = 0;

		entry->payload_aead_type = req.payload_aead_type;
		if (entry->payload_encryption_key)
			free((void *)(entry->payload_encryption_key));
	} else {
		// not found
		token_store_entry_t *new_token_store = token_store_entry_init(topic, req.access_type_is_pub);
		if (!new_token_store) {
			err = ESP_ERR_NO_MEM;
			goto fetch_tokens_finish_destroytls;
		}
		new_token_store->payload_aead_type = req.payload_aead_type;
		token_store_append(token_store, new_token_store);
		entry = new_token_store;
	}

	if (is_encryption_enabled(entry->payload_aead_type)) {
		entry->payload_encryption_key = malloc(get_keylen(entry->payload_aead_type));
		// uint8_t enc_key[get_keylen(entry->payload_aead_type)];
		// entry->payload_encryption_key = enc_key;
		err = conn_read(tls, entry->payload_encryption_key, get_keylen(entry->payload_aead_type), 0);
		if (err != ESP_OK) {
			ESP_LOGE(TAG, "Failed to conn_read encryption key");
			goto fetch_tokens_finish_destroytls;
		}
		ESP_LOGI(TAG, "conn_read encryption key success");
	}

	err = conn_read(tls, entry->timestamp, TIMESTAMP_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read timestamp");
		goto fetch_tokens_finish_destroytls;
	}
	ESP_LOGI(TAG, "conn_read timestamp success");

	// Allocate memory for random bytes in heap
	entry->all_random_data = (uint8_t *)malloc(req.num_tokens_divided_by_multiplier * TOKEN_NUM_MULTIPIER * RANDOM_BYTES_LEN);
	// uint8_t random_data[req.num_tokens_divided_by_multiplier * TOKEN_NUM_MULTIPIER * RANDOM_BYTES_LEN];
	// entry->all_random_data = random_data;
	if (!entry->all_random_data) {
		ESP_LOGE(TAG, "Failed to allocate memory for random bytes");
		err = ESP_ERR_NO_MEM;
		goto fetch_tokens_finish_destroytls;
	}
	err = conn_read(tls, entry->all_random_data, req.num_tokens_divided_by_multiplier * TOKEN_NUM_MULTIPIER * RANDOM_BYTES_LEN, 0);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to conn_read random bytes");
		free((void *)entry->all_random_data);
		goto fetch_tokens_finish_destroytls;
	}
	entry->cur_random_data = entry->all_random_data;
	ESP_LOGI(TAG, "conn_read random bytes success");

	entry->token_count = req.num_tokens_divided_by_multiplier * TOKEN_NUM_MULTIPIER;
	entry->cur_token_idx = 0;

fetch_tokens_finish_destroytls:
	if (tls)
		esp_tls_conn_destroy(tls);
fetch_tokens_finish:
	LOG_TIME_FUNC_END();
	return err;
}

static esp_err_t get_token_internal(const char *topic, issuer_request_t req, uint8_t token[TOKEN_SIZE], uint8_t *encryption_key, uint16_t *cur_token_idx) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	if (req.num_tokens_divided_by_multiplier < 1 || req.num_tokens_divided_by_multiplier > 0x1F) {
		ESP_LOGE(TAG, "field NumberOfTokens is not in the range of [1, 0x1F]");
		err = ESP_ERR_INVALID_ARG;
		goto get_token_internal_finish;
	}

	size_t topic_len = strlen(topic);
	if (topic_len > 0x7F) {
		ESP_LOGE(TAG, "Topic must be less than 0x7F letters");
		err = ESP_ERR_INVALID_ARG;
		goto get_token_internal_finish;
	}

	token_store_entry_t *entry = token_store_search(token_store, topic, req.access_type_is_pub);
	if (!entry || (entry->token_count <= entry->cur_token_idx)) {
		ESP_LOGI(TAG, "No token in the token store");
		err = fetch_tokens(req, topic, topic_len);
		if (err != ESP_OK)
			goto get_token_internal_finish;

		if (!entry) {
			entry = token_store->tail;
		}
	}
	memcpy(token, entry->timestamp, TIMESTAMP_LEN);
	memcpy(token + TIMESTAMP_LEN, entry->cur_random_data, RANDOM_BYTES_LEN);
	if (is_encryption_enabled(entry->payload_aead_type)) {
		if (encryption_key) {
			memcpy(encryption_key, entry->payload_encryption_key, get_keylen(entry->payload_aead_type));
		}
		if (cur_token_idx) {
			*cur_token_idx = entry->cur_token_idx;
		}
	}
	entry->cur_random_data += RANDOM_BYTES_LEN;
	entry->cur_token_idx++;

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
		if (plain_mqtt_client) {
			esp_mqtt_client_destroy(plain_mqtt_client);
		}
		if (tls_mqtt_client) {
			esp_mqtt_client_destroy(tls_mqtt_client);
		}
		if (netif) {
			mdns_free();
			esp_netif_sntp_deinit();
			esp_wifi_stop();
			esp_wifi_deinit();
			esp_netif_destroy(netif);
		}

		reset_token_store();

		current_state = TOKENMGR_STATE_UNINITIALIZED;
		ESP_LOGI(TAG, "tokenmgr deinitialized");
	}
	LOG_TIME_FUNC_END();
}

void reset_token_store() {
	reset_token_store_entries(token_store);
	token_store->head = NULL;
	token_store->tail = NULL;
}

esp_err_t get_token(const char *topic, issuer_request_t fetch_req, uint8_t token[TOKEN_SIZE], uint8_t *encryption_key, uint16_t *cur_token_idx) {
	LOG_TIME_FUNC_START();
	esp_err_t ret = ESP_OK;
	CHECK_CURSTATE_IF_OPERATIONAL(ret, get_token_finish);
	ret = get_token_internal(topic, fetch_req, token, encryption_key, cur_token_idx);
get_token_finish:
	LOG_TIME_FUNC_END();
	return ret;
}
