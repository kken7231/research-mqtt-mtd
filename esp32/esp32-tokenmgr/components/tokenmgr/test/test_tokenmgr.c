/* test_mean.c: Implementation of a testable component.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <limits.h>

#include "tokenmgr.h"
#include "unity.h"

#define PLAIN_BROKER "192.168.11.16:1883"
#define TLS_BROKER "192.168.11.16:8883"
#define TOPIC_PUB "/sample/topic/pub"

static bool isZeroFilled(const uint8_t* arr, int arrlen) {
	for (int i = 0; i < arrlen; i++) {
		if (arr[i] != 0)
			return false;
	}
	return true;
}

static esp_mqtt5_publish_property_config_t publish_property = {
	.payload_format_indicator = 1,
	.response_topic = TOPIC_PUB,
};

extern const esp_mqtt_client_handle_t plain_mqtt_client;

TEST_CASE("Get a publish token", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 8,
		.access_type = ACCESS_PUB,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0};

	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
	TEST_ASSERT_FALSE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_FALSE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
}

TEST_CASE("Sends a publish", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 8,
		.access_type = ACCESS_PUB,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0};

	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
	TEST_ASSERT_FALSE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_FALSE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
}
