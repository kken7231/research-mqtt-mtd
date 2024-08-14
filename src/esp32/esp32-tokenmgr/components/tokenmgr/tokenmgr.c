#include "tokenmgr.h"

#include "esp_log.h"
#include "nvs_flash.h"

#define ISSUER_HOST "192.168.11.6"
#define ISSUER_PORT 18883

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

esp_err_t reset_nvs_storage() {
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

esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
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

esp_err_t conn_write(esp_tls_t *tls, const uint8_t *data, size_t len, uint32_t timeout_ms) {
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

esp_err_t fetch_tokens(fetch_request_t req, const char *topic, size_t topic_len) {
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

esp_err_t get_token_internal(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
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

esp_err_t get_token(const char *topic, fetch_request_t fetch_req, uint8_t *timestamp, uint8_t *random_bytes) {
	get_token_init();
	esp_err_t ret = get_token_internal(topic, fetch_req, timestamp, random_bytes);
	get_token_deinit();
	return ret;
}
