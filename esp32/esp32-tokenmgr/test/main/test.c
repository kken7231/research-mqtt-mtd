/* Example test application for testable component.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "tokenmgr.h"
#include "unity.h"
#include "esp_netif_sntp.h"
#include <time.h>
#include <sys/time.h>

static const char *TAG = "tokenmgr_testapp";


token_store_t token_store = {0};
extern int permit_time_logging;
const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};
const esp_mqtt5_connection_property_config_t mqtt_connect_property = {
	.session_expiry_interval = 10,
	.maximum_packet_size = 1024,
};

void setUp(void) {
	tokenmgr_init();
}

void tearDown(void) {
	tokenmgr_deinit();
}

static void print_banner(const char *text);

void app_main(void) {
	tokenmgr_app_init();

	// permit_time_logging = 1;

	// UNITY_BEGIN();
	// unity_run_test_by_name("Get a publish token");
	// UNITY_END();
	// print_time_record_summary();
	// reset_time_record_store();

	// UNITY_BEGIN();
	// unity_run_test_by_name("Base64 Encode of the token");
	// UNITY_END();
	// print_time_record_summary();
	// reset_time_record_store();

	// UNITY_BEGIN();
	// unity_run_test_by_name("Send a plain publish");
	// UNITY_END();
	// print_time_record_summary();
	// reset_time_record_store();

	// UNITY_BEGIN();
	// unity_run_test_by_name("Send a tls publish");
	// UNITY_END();
	// print_time_record_summary();
	// reset_time_record_store();


	UNITY_BEGIN();
	unity_run_test_by_name("Send 32 plain publishes");
	UNITY_END();

	UNITY_BEGIN();
	unity_run_test_by_name("Send 32 tls publishes");
	UNITY_END();
}

static void print_banner(const char *text) {
	printf("\n#### %s #####\n\n", text);
}