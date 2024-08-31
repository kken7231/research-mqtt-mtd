#ifndef TOKENMGR_H
#define TOKENMGR_H

#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_tls.h"
#include "esp_wifi.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/gcm.h"
#include "mbedtls/poly1305.h"
#include "mdns.h"
#include "mqtt_client.h"
#include "nvs_flash.h"

/*
	MQTT-MTD Parameters
*/
#define TIMESTAMP_LEN 6
#define RANDOM_BYTES_LEN 6
#define TOKEN_SIZE (TIMESTAMP_LEN + RANDOM_BYTES_LEN)
#define BASE64_ENCODED_TOKEN_SIZE ((TOKEN_SIZE + 2) / 3 * 4) + 1
#define TIME_REVOCATION (7 * 24 * 60 * 60)	// 1 week in seconds
#define TOKEN_NUM_MULTIPIER 16
#define NONCE_BASE 123456
// Definition expected in config.h
extern const char *ISSUER_HOST;
// Definition expected in config.h
extern const int ISSUER_PORT;

typedef enum {
	PAYLOAD_AEAD_NONE = 0x0,
	// Referred to TLSv1.3 cipher suites. Only AEAD.

	PAYLOAD_AEAD_AES_128_GCM = 0x1,
	PAYLOAD_AEAD_AES_256_GCM = 0x2,
	PAYLOAD_AEAD_CHACHA20_POLY1305 = 0x3,
} payload_aead_type_t;

bool is_encryption_enabled(payload_aead_type_t);
int get_keylen(payload_aead_type_t);
int get_noncelen(payload_aead_type_t);
esp_err_t seal_message(payload_aead_type_t, const char *, const size_t, const uint8_t *, uint64_t, uint8_t *, size_t *);

typedef struct {
	uint16_t num_tokens_divided_by_multiplier;
	bool access_type_is_pub;
	payload_aead_type_t payload_aead_type;
} issuer_request_t;

typedef struct {
	const char *topic;
	bool access_type_is_pub;

	uint8_t timestamp[TIMESTAMP_LEN];
	uint8_t *all_random_data;
	uint8_t *cur_random_data;
	uint16_t token_count;
	uint16_t cur_token_idx;

	payload_aead_type_t payload_aead_type;
	uint8_t *payload_encryption_key;

	struct token_store_entry_t *prev;
	struct token_store_entry_t *next;
} token_store_entry_t;

typedef struct {
	token_store_entry_t *head;
	token_store_entry_t *tail;
} token_store_t;

token_store_entry_t *token_store_entry_init(const char *, bool);
void token_store_append(token_store_t *, token_store_entry_t *);
token_store_entry_t *token_store_search(token_store_t *, const char *, bool);
void reset_token_store_entries(token_store_t *store);
void reset_token_store();

typedef enum {
	TOKENMGR_STATE_BEFORE_ONETIME_INIT,
	TOKENMGR_STATE_UNINITIALIZED,
	TOKENMGR_STATE_OPERTATIONAL,
} tokenmgr_state_t;

extern tokenmgr_state_t current_state;

#define CHECK_CURSTATE_IF_OPERATIONAL(err, goto_label)                    \
	if (current_state != TOKENMGR_STATE_OPERTATIONAL) {                   \
		ESP_LOGE("tokenmgr.h", "tokenmgr needs to be initialized first"); \
		err = ESP_FAIL;                                                   \
		goto goto_label;                                                  \
	}

/*
	Embedded client certificate and key
*/
extern const uint8_t client_crt_start[] asm("_binary_client_pem_start");
extern const uint8_t client_crt_end[] asm("_binary_client_pem_end");
extern const uint8_t client_key_start[] asm("_binary_client_key_start");
extern const uint8_t client_key_end[] asm("_binary_client_key_end");

/*
	Definition expected in the App
*/
extern const int CIPHERSUITES_LIST[];

/*
	Wifi Parameters
*/
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
// Definition expected in config.h
extern const wifi_sta_config_t wifi_sta_config;
#define WIFI_MAX_RETRY 3
#define SNTP_MAX_RETRY 15

esp_netif_t *wifi_init_sta(void);

/*
	MQTT Parameters
*/
#define MQTT_CONNECTED_BIT BIT0
#define MQTT_FAIL_BIT BIT1
// Definition expected in config.h
extern const char *PLAIN_BROKER_URI;
// Definition expected in config.h
extern const char *TLS_BROKER_URI;
// Definition expected in the app
typedef enum {
	MQTT_CLIENT_PLAIN,
	MQTT_CLIENT_TLS
} mqtt_client_type_t;

esp_mqtt_client_handle_t mqtt_client_start(esp_mqtt_client_config_t *, mqtt_client_type_t *);
esp_err_t mqtt_publish_qos0(mqtt_client_type_t, const char *, const char *, int);

/*
	Logger Declarations
*/
void print_time_record_summary(void);
void reset_time_record_store(void);
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

void log_time(time_record_type_t, const char *);

#define LOG_TIME(LABEL) log_time(TIME_RECORD_TYPE_UNDEFINED, LABEL)
#define LOG_TIME_FUNC_START()                              \
	if (current_state == TOKENMGR_STATE_OPERTATIONAL) {    \
		log_time(TIME_RECORD_TYPE_FUNC_STARTED, __func__); \
	}

#define LOG_TIME_FUNC_END()                              \
	if (current_state == TOKENMGR_STATE_OPERTATIONAL) {  \
		log_time(TIME_RECORD_TYPE_FUNC_ENDED, __func__); \
	}
#else
#define LOG_TIME(LABEL)
#define LOG_TIME_FUNC_START()
#define LOG_TIME_FUNC_END()
#endif

/*
	Util Funcions
*/
esp_err_t b64encode_token(const uint8_t[TOKEN_SIZE], uint8_t[BASE64_ENCODED_TOKEN_SIZE]);
esp_err_t conn_read(esp_tls_t *, uint8_t *, size_t, uint32_t);
esp_err_t conn_write(esp_tls_t *, const uint8_t *, size_t, uint32_t);

/*
	Function Declarations
*/
void tokenmgr_app_init(void);
void tokenmgr_init(void);
void tokenmgr_deinit(void);

esp_err_t get_token(const char *, issuer_request_t, uint8_t[TOKEN_SIZE], uint8_t *, uint16_t *);
#endif