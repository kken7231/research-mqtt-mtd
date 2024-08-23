/* Example test application for testable component.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "config.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "nvs_flash.h"
#include "tokenmgr.h"

static const char *TAG = "tokenmgr_benchmarkapp";

#define TOPIC_PUB "/sample/topic/pub"

extern int permit_time_logging;
const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};


static struct timeval start_tv, end_tv;
void setUp(void) {
	tokenmgr_init();
}

void tearDown(void) {
	tokenmgr_deinit();
}

esp_err_t publish_plain(const uint16_t ntokens, const char *data, long *elapsed_sec, long *elapsed_usec) {
	fetch_request_t fetch_req = {
		.num_tokens = ntokens,
		.access_type = ACCESS_PUB,
		.enchash_enabled = false,
	};
	const char* topic = TOPIC_PUB;
	uint8_t timestamp[TIMESTAMP_LEN] , random_bytes[RANDOM_BYTES_LEN], encoded_token[BASE64_ENCODED_TOKEN_SIZE];
	esp_err_t err = ESP_OK;
	err = get_token(topic, fetch_req, timestamp, random_bytes);
	if(err != ESP_OK) return err;
	err = b64encode_token(timestamp, random_bytes, encoded_token);
	if(err != ESP_OK) return err;
	return mqtt_publish_qos0(MQTT_CLIENT_PLAIN, topic, data, 0);
}

esp_err_t publish_plain_withenchash(const uint16_t ntokens, const char *data, long *elapsed_sec, long *elapsed_usec) {
	fetch_request_t fetch_req = {
		.num_tokens = ntokens,
		.access_type = ACCESS_PUB,
		.enchash_enabled = true,
	};
	const char* topic = TOPIC_PUB;
	uint8_t timestamp[TIMESTAMP_LEN] , random_bytes[RANDOM_BYTES_LEN], encoded_token[BASE64_ENCODED_TOKEN_SIZE];
	esp_err_t err = ESP_OK;
	err = get_token(topic, fetch_req, timestamp, random_bytes);
	if(err != ESP_OK) return err;
	err = b64encode_token(timestamp, random_bytes, encoded_token);
	if(err != ESP_OK) return err;
	return mqtt_publish_qos0(MQTT_CLIENT_PLAIN, topic, data, 0);
}


esp_err_t publish_tls(const char *data, long *elapsed_sec, long *elapsed_usec) {
	return mqtt_publish_qos0(MQTT_CLIENT_TLS, TOPIC_PUB, data, 0);
}

esp_err_t run_benchmark(esp_err_t (*func)(const char *, long *, long *), const char *data, long *elapsed_sec, long *elapsed_usec) {
	setUp();
	esp_err_t err = ESP_OK;
	gettimeofday(&start_tv, NULL);
	err = func(data, elapsed_sec, elapsed_usec);
	gettimeofday(&end_tv, NULL);
	*elapsed_sec = end_tv.tv_sec - start_tv.tv_sec;
	*elapsed_usec = end_tv.tv_usec - start_tv.tv_usec;
	if (*elapsed_usec < 0) {
		*elapsed_sec--;
		*elapsed_usec += 1000000;
	}
	tearDown();
	return err;
}

void app_main(void) {
	tokenmgr_app_init();
}
