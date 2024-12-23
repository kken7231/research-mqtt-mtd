#include "tokenmgr.h"

static const char *TAG = "tokenmgr_util";

esp_err_t b64encode_token(const uint8_t token[TOKEN_SIZE], uint8_t encoded_token[BASE64_ENCODED_TOKEN_SIZE]) {
	LOG_TIME_FUNC_START();
	esp_err_t err = ESP_OK;
	CHECK_CURSTATE_IF_OPERATIONAL(err, b64encode_token_finish);
	if (!token || !encoded_token) {
		err = ESP_ERR_INVALID_ARG;
		goto b64encode_token_finish;
	}

	size_t output_len;
	int ret = mbedtls_base64_encode((unsigned char *)encoded_token, BASE64_ENCODED_TOKEN_SIZE, &output_len, (const unsigned char *)token, TOKEN_SIZE);
	if (ret != 0 || output_len != BASE64_ENCODED_TOKEN_SIZE - 1) {
		err = ESP_FAIL;
		goto b64encode_token_finish;
	}
	// Replace '+' with '-' and '/' with '_'
	for (size_t i = 0; i < output_len; i++) {
		if (encoded_token[i] == '+') {
			encoded_token[i] = '-';
		} else if (encoded_token[i] == '/') {
			encoded_token[i] = '_';
		}
	}
	encoded_token[BASE64_ENCODED_TOKEN_SIZE - 1] = '\0';

b64encode_token_finish:
	LOG_TIME_FUNC_END();
	return err;
}

esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
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

esp_err_t conn_write(esp_tls_t *tls, const uint8_t *data, size_t len, uint32_t timeout_ms) {
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
