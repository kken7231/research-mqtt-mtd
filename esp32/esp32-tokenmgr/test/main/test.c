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
const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};
const esp_mqtt5_connection_property_config_t mqtt_connect_property = {
	.session_expiry_interval = 10,
	.maximum_packet_size = 1024,
};
static esp_netif_t *netif;

void setUp(void) {
	netif = comp_init();
}

void tearDown(void) {
	comp_deinit(netif);
}

static void print_banner(const char *text);

void app_main(void) {
	print_banner("Executing one test by its name");
	UNITY_BEGIN();
	unity_run_test_by_name("Get a publish token");
	UNITY_END();
	print_time_record_summary();
	reset_time_record_store();
}

static void print_banner(const char *text) {
	printf("\n#### %s #####\n\n", text);
}