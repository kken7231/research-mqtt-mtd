#include "tokenmgr.h"

static const char *TAG = "tokenmgr_token_store";
bool is_encryption_enabled(payload_aead_type_t type) {
	return type == PAYLOAD_AEAD_AES_128_GCM ||
		   type == PAYLOAD_AEAD_AES_256_GCM ||
		   type == PAYLOAD_AEAD_CHACHA20_POLY1305;
}

int get_keylen(payload_aead_type_t type) {
	switch (type) {
		case PAYLOAD_AEAD_AES_128_GCM:
			return 16;
		case PAYLOAD_AEAD_AES_256_GCM:
		case PAYLOAD_AEAD_CHACHA20_POLY1305:
			return 32;
		default:
			return 0;
	}
}

int get_noncelen(payload_aead_type_t type) {
	switch (type) {
		case PAYLOAD_AEAD_AES_128_GCM:
		case PAYLOAD_AEAD_AES_256_GCM:
		case PAYLOAD_AEAD_CHACHA20_POLY1305:
			return 12;
		default:
			return 0;
	}
}

esp_err_t seal_message(payload_aead_type_t type, const char *plaintext, const size_t plaintext_len, const uint8_t *encKey, uint64_t nonceSpice, uint8_t **sealed, size_t *sealed_len) {
	LOG_TIME_FUNC_START();
	if (!encKey || !plaintext) {
		ESP_LOGE(TAG, "encKey or plaintext is NULL");
		return ESP_ERR_INVALID_ARG;
	}

	esp_err_t err = ESP_OK;

	uint8_t nonce[get_noncelen(type)];	// 12 bytes nonce for GCM and ChaCha20-Poly1305
	memset(nonce, 0, sizeof(nonce));
	uint64_t nonce_uint = NONCE_BASE + nonceSpice;
	for (int i = 0; i < 8; i++) {
		nonce[i] = (uint8_t)((nonce_uint >> (56 - 8 * i)) & 0xFF);
	}

	switch (type) {
		case PAYLOAD_AEAD_AES_128_GCM:
		case PAYLOAD_AEAD_AES_256_GCM: {
			mbedtls_gcm_context gcm;
			mbedtls_gcm_init(&gcm);
			mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

			int ret = mbedtls_gcm_setkey(&gcm, cipher, encKey, get_keylen(type) * 8);
			if (ret != 0) {
				mbedtls_gcm_free(&gcm);
				err = ESP_FAIL;
				goto seal_message_finish;
			}

			*sealed_len = plaintext_len + 16;  // GCM adds a 16-byte tag
			*sealed = (uint8_t *)malloc(*sealed_len);
			if (*sealed == NULL) {
				mbedtls_gcm_free(&gcm);
				err = ESP_ERR_NO_MEM;
				goto seal_message_finish;
			}

			ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, nonce, sizeof(nonce), NULL, 0, (const unsigned char *)plaintext, (unsigned char *)*sealed, 16, (unsigned char *)(*sealed + plaintext_len));
			mbedtls_gcm_free(&gcm);

			if (ret != 0) {
				free((void *)*sealed);
				err = ESP_FAIL;
				goto seal_message_finish;
			}
			break;
		}
		case PAYLOAD_AEAD_CHACHA20_POLY1305: {
			mbedtls_chachapoly_context chachapoly;
			mbedtls_chachapoly_init(&chachapoly);

			int ret = mbedtls_chachapoly_setkey(&chachapoly, encKey);
			if (ret != 0) {
				mbedtls_chachapoly_free(&chachapoly);
				err = ESP_FAIL;
				goto seal_message_finish;
			}

			*sealed_len = plaintext_len + 16;  // ChaCha20-Poly1305 adds a 16-byte tag
			*sealed = (uint8_t *)malloc(*sealed_len);

			ret = mbedtls_chachapoly_encrypt_and_tag(&chachapoly, plaintext_len, nonce, NULL, 0, (const unsigned char *)plaintext, (unsigned char *)*sealed, (unsigned char *)(*sealed + plaintext_len));
			mbedtls_chachapoly_free(&chachapoly);

			if (ret != 0) {
				free((void *)*sealed);
				err = ESP_FAIL;
				goto seal_message_finish;
			}
			break;
		}
		default:
			err = ESP_ERR_INVALID_ARG;
			goto seal_message_finish;
	}

seal_message_finish:
	LOG_TIME_FUNC_END();
	return err;
}
