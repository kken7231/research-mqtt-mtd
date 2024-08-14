#ifndef TOKENMGR_H
#define TOKENMGR_H
#include <string.h>
#include <unistd.h>

#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_tls.h"

#ifndef TAG
#define TAG "token_mgr"
#endif

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

extern const uint8_t client_crt_start[] asm("_binary_client1_pem_start");
extern const uint8_t client_crt_end[] asm("_binary_client1_pem_end");
extern const uint8_t client_key_start[] asm("_binary_client1_key_start");
extern const uint8_t client_key_end[] asm("_binary_client1_key_end");

extern token_store_t token_store;
extern const int CIPHERSUITES_LIST[];

esp_err_t reset_nvs_storage(void);
esp_err_t conn_read(esp_tls_t *, uint8_t *, size_t, uint32_t);
esp_err_t conn_write(esp_tls_t *, const uint8_t *, size_t, uint32_t);
esp_err_t fetch_tokens(fetch_request_t, const char *, size_t);
esp_err_t get_token(const char *, fetch_request_t, uint8_t *, uint8_t *);

#endif