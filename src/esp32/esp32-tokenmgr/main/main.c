#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"

#define ISSUER_PORT 11883
#define MQTTBROKER_PORT 1883
#define TIMESTAMP_LEN 6
#define RANDOM_BYTES_LEN 6
#define TOKEN_SIZE (TIMESTAMP_LEN + RANDOM_BYTES_LEN)
#define TIME_REVOCATION (7 * 24 * 60 * 60) // 1 week in seconds

#define LOGPRINTE(tag, format, ...) \
    ESP_LOGE(tag, format, ##__VA_ARGS__); \
    printf(format, ##__VA_ARGS__); \
    printf("\n");

#define LOGPRINTI(tag, format, ...) \
    ESP_LOGI(tag, format, ##__VA_ARGS__); \
    printf(format, ##__VA_ARGS__); \
    printf("\n");


typedef enum {
    ACCESS_PUB = 1,
    ACCESS_SUB = 2,
    ACCESS_PUBSUB = 3
} access_type_t;

typedef struct {
    uint8_t num_tokens;
    access_type_t access_type;
    const char *ca_crt;
    const char *client_crt;
    const char *client_key;
} fetch_request_t;

typedef struct {
    uint8_t timestamp[TIMESTAMP_LEN];
    uint8_t *random_bytes;
    uint8_t token_count;
} token_store_t;

static const char *TAG = "token_mgr";
static const char *ISSUER_HOST = "server";
// static const char *MQTTBROKER_HOST = "server";
static token_store_t token_store = {0};


static esp_err_t save_token_store_to_nvs() {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        LOGPRINTE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(nvs_handle, "timestamp", token_store.timestamp, TIMESTAMP_LEN);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to save timestamp: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(nvs_handle, "random_bytes", token_store.random_bytes, token_store.token_count * RANDOM_BYTES_LEN);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to save random bytes: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_u32(nvs_handle, "token_count", token_store.token_count);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to save token count: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
        return err;
    }

    nvs_close(nvs_handle);
    return ESP_OK;
}

static esp_err_t load_token_store_from_nvs() {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        LOGPRINTE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return err;
    }

    size_t timestamp_size = TIMESTAMP_LEN;
    err = nvs_get_blob(nvs_handle, "timestamp", token_store.timestamp, &timestamp_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        LOGPRINTI(TAG, "No token store found in NVS");
        nvs_close(nvs_handle);
        return ESP_ERR_NOT_FOUND;
    } else if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to load timestamp: %s", esp_err_to_name(err));
        return err;
    }

    size_t random_bytes_size = 0;
    err = nvs_get_blob(nvs_handle, "random_bytes", NULL, &random_bytes_size);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to get size of random bytes: %s", esp_err_to_name(err));
        return err;
    }

    token_store.random_bytes = malloc(random_bytes_size);
    if (!token_store.random_bytes) {
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to allocate memory for random bytes");
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_blob(nvs_handle, "random_bytes", token_store.random_bytes, &random_bytes_size);
    if (err != ESP_OK) {
        free(token_store.random_bytes);
        token_store.random_bytes = NULL;
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to load random bytes: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_get_u8(nvs_handle, "token_count", &token_store.token_count);
    if (err != ESP_OK) {
        free(token_store.random_bytes);
        token_store.random_bytes = NULL;
        nvs_close(nvs_handle);
        LOGPRINTE(TAG, "Failed to load token count: %s", esp_err_to_name(err));
        return err;
    }

    nvs_close(nvs_handle);
    return ESP_OK;
}

static esp_err_t conn_read(esp_tls_t *tls, uint8_t *dst, size_t len, uint32_t timeout_ms) {
    size_t read_len = 0;
    while (read_len < len) {
        int ret = esp_tls_conn_read(tls, dst + read_len, len - read_len);
        if (ret < 0) {
            LOGPRINTE(TAG, "Connection read error: %d", ret);
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
            LOGPRINTE(TAG, "Connection write error: %d", ret);
            return ESP_FAIL;
        }
        written_len += ret;
    }
    return ESP_OK;
}

static esp_err_t fetch_tokens(fetch_request_t req, const uint8_t *topic, size_t topic_len) {
    if (topic_len > 0x7F) {
        LOGPRINTE(TAG, "Topic must be less than 0x7F letters");
        return ESP_ERR_INVALID_ARG;
    }

    esp_tls_cfg_t cfg = {
        .cacert_pem_buf = (const unsigned char *)req.ca_crt,
        .cacert_pem_bytes = strlen(req.ca_crt) + 1,
        .clientcert_pem_buf = (const unsigned char *)req.client_crt,
        .clientcert_pem_bytes = strlen(req.client_crt) + 1,
        .clientkey_pem_buf = (const unsigned char *)req.client_key,
        .clientkey_pem_bytes = strlen(req.client_key) + 1,
    };
    esp_tls_t *tls = esp_tls_init();
    if (esp_tls_conn_new_sync(ISSUER_HOST, strlen(ISSUER_HOST), ISSUER_PORT, &cfg, tls) < 0) {
        LOGPRINTE(TAG, "Failed to open TLS connection");
        return ESP_FAIL;
    }

    uint8_t info[2] = {req.num_tokens / 4, topic_len};
    if (req.access_type & ACCESS_PUB) {
        info[0] |= 0x80;
    }
    if (req.access_type & ACCESS_SUB) {
        info[0] |= 0x40;
    }

    if (conn_write(tls, info, sizeof(info), 0) != ESP_OK ||
        conn_write(tls, topic, topic_len, 0) != ESP_OK) {
        esp_tls_conn_destroy(tls);
        return ESP_FAIL;
    }

    uint8_t ts[TIMESTAMP_LEN];
    if (conn_read(tls, ts, TIMESTAMP_LEN, 0) != ESP_OK) {
        esp_tls_conn_destroy(tls);
        return ESP_FAIL;
    }

    memcpy(token_store.timestamp, ts, TIMESTAMP_LEN);
    token_store.random_bytes = realloc(token_store.random_bytes, req.num_tokens * RANDOM_BYTES_LEN);
    token_store.token_count = req.num_tokens;

    for (int i = 0; i < req.num_tokens; ++i) {
        uint8_t rb[RANDOM_BYTES_LEN];
        if (conn_read(tls, rb, RANDOM_BYTES_LEN, 0) != ESP_OK) {
            esp_tls_conn_destroy(tls);
            return ESP_FAIL;
        }
        memcpy(&token_store.random_bytes[i * RANDOM_BYTES_LEN], rb, RANDOM_BYTES_LEN);
    }

    esp_tls_conn_destroy(tls);
    save_token_store_to_nvs(); // Save the token store to NVS after fetching tokens
    return ESP_OK;
}

static esp_err_t get_token(const char *topic, fetch_request_t fetch_req, uint8_t **timestamp, uint8_t **token) {
    if (fetch_req.num_tokens < 4 || fetch_req.num_tokens > 0x3F * 4 || fetch_req.num_tokens % 4 != 0) {
        LOGPRINTE(TAG, "Invalid number of tokens. Must be between [4, 0x3F*4] and multiples of 4");
        return ESP_ERR_INVALID_ARG;
    }

    size_t topic_len = strlen(topic);
    if (topic_len > 0x7F) {
        LOGPRINTE(TAG, "Topic must be less than 0x7F letters");
        return ESP_ERR_INVALID_ARG;
    }

    if (token_store.token_count == 0) {
        if (fetch_tokens(fetch_req, (const uint8_t *)topic, topic_len) != ESP_OK) {
            return ESP_FAIL;
        }
    }

    *timestamp = malloc(TIMESTAMP_LEN);
    memcpy(*timestamp, token_store.timestamp, TIMESTAMP_LEN);

    *token = malloc(RANDOM_BYTES_LEN);
    memcpy(*token, token_store.random_bytes, RANDOM_BYTES_LEN);

    memmove(token_store.random_bytes, token_store.random_bytes + RANDOM_BYTES_LEN, (token_store.token_count - 1) * RANDOM_BYTES_LEN);
    token_store.token_count--;

    save_token_store_to_nvs(); // Save the token store to NVS after updating it
    return ESP_OK;
}

void app_main(void) {
    printf("App started\n");
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    load_token_store_from_nvs(); // Load token store from NVS at startup

    fetch_request_t fetch_req = {
        .num_tokens = 8,
        .access_type = ACCESS_PUBSUB,
        .ca_crt = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
        .client_crt = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
        .client_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
    };

    uint8_t *timestamp = NULL;
    uint8_t *token = NULL;
    ret = get_token("/sample/topic/pub", fetch_req, &timestamp, &token);
    if (ret == ESP_OK) {
        LOGPRINTI(TAG, "Successfully fetched token");
        // Do something with the token
    } else {
        LOGPRINTE(TAG, "Failed to fetch token");
    }

    if (timestamp) free(timestamp);
    if (token) free(token);
    if (token_store.random_bytes) free(token_store.random_bytes);
}
