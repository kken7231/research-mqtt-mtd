#ifndef TOKENMGR_H
#define TOKENMGR_H

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
#include "mdns.h"
#include "mqtt_client.h"
#include "nvs_flash.h"

/*
	MQTT-MTD Parameters
*/
#define TIMESTAMP_LEN 6
#define RANDOM_BYTES_LEN 6
#define TOKEN_SIZE (TIMESTAMP_LEN + RANDOM_BYTES_LEN)
#define TIME_REVOCATION (7 * 24 * 60 * 60)	// 1 week in seconds
// Definition expected in config.h
extern const char *ISSUER_HOST;
// Definition expected in config.h
extern const int ISSUER_PORT;

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
extern token_store_t token_store;
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
extern const esp_mqtt5_connection_property_config_t mqtt_connect_property;

/*
	Function Declarations
*/
esp_netif_t *comp_init(void);
void comp_deinit(esp_netif_t *);
void print_time_record_summary(void);
void reset_time_record_store(void);

esp_err_t get_token(const char *, fetch_request_t, uint8_t *, uint8_t *);

#endif