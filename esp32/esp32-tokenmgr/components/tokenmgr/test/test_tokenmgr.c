/* test_mean.c: Implementation of a testable component.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <limits.h>

#include "tokenmgr.h"
#include "unity.h"
#include "unity_test_runner.h"

#define TOPIC_PUB "/sample/topic/pub"

static bool isZeroFilled(const uint8_t* arr, int arrlen) {
	for (int i = 0; i < arrlen; i++) {
		if (arr[i] != 0)
			return false;
	}
	return true;
}

TEST_CASE("Get a publish token", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 16,
		.access_type = ACCESS_PUB,
		.enchash_enabled = false,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_TRUE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
	TEST_ASSERT_FALSE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_FALSE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
}

TEST_CASE("Base64 Encode of the token", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 16,
		.access_type = ACCESS_PUB,
		.enchash_enabled = false,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_TRUE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
	TEST_ASSERT_TRUE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
	TEST_ASSERT_FALSE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_FALSE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
	TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(timestamp, random_bytes, encoded_token));
	TEST_ASSERT_FALSE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
}

TEST_CASE("Send a plain publish", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 16,
		.access_type = ACCESS_PUB,
		.enchash_enabled = false,
	};
	const char* topic = TOPIC_PUB;
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_TRUE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
	TEST_ASSERT_TRUE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
	TEST_ASSERT_FALSE(isZeroFilled(timestamp, TIMESTAMP_LEN));
	TEST_ASSERT_FALSE(isZeroFilled(random_bytes, RANDOM_BYTES_LEN));
	TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(timestamp, random_bytes, encoded_token));
	TEST_ASSERT_FALSE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, "hello, world", 0));
}

TEST_CASE("Send a tls publish", "[pub]") {
	const char* topic = TOPIC_PUB;
	TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_TLS, topic, "hello, world", 0));
}

TEST_CASE("Send 32 plain publishes", "[pub]") {
	fetch_request_t fetch_req = {
		.num_tokens = 16,
		.access_type = ACCESS_PUB,
		.enchash_enabled = false,
	};
	const char* topic = TOPIC_PUB;
	char data[] = "hello, plain-00";
	uint8_t timestamp[TIMESTAMP_LEN] = {0}, random_bytes[RANDOM_BYTES_LEN] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	struct timeval start_tv, end_tv;
	long sum_usec = 0, elapsed_sec, elapsed_usec, avg_sec, avg_usec;
	for (char i = 0; i < 32; i++) {
		data[13] = '0' + (i / 10);
		data[14] = '0' + (i % 10);
		gettimeofday(&start_tv, NULL);
		TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, fetch_req, timestamp, random_bytes));
		TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(timestamp, random_bytes, encoded_token));
		TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, data, 0));
		gettimeofday(&end_tv, NULL);
		elapsed_sec = end_tv.tv_sec - start_tv.tv_sec;
		elapsed_usec = end_tv.tv_usec - start_tv.tv_usec;
		if (elapsed_usec < 0) {
			elapsed_sec--;
			elapsed_usec += 1000000;
		}
		sum_usec += elapsed_sec * 1000000 + elapsed_usec;
		avg_usec = sum_usec / ((long)i + 1);
		avg_sec = avg_usec / 1000000;
		avg_usec %= 1000000;
		printf("[%02d] %ld.%06ld sec (avg. %ld.%06ld)\n", i, elapsed_sec, elapsed_usec, avg_sec, avg_usec);
		sleep(1);
	}
}

TEST_CASE("Send 32 tls publishes", "[pub]") {
	const char* topic = TOPIC_PUB;
	char data[] = "hello, tls13-00";
	struct timeval start_tv, end_tv;
	long sum_usec = 0, elapsed_sec, elapsed_usec, avg_sec, avg_usec;
	for (char i = 0; i < 32; i++) {
		data[13] = '0' + (i / 10);
		data[14] = '0' + (i % 10);
		gettimeofday(&start_tv, NULL);
		TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_TLS, topic, data, 0));
		gettimeofday(&end_tv, NULL);
		elapsed_sec = end_tv.tv_sec - start_tv.tv_sec;
		elapsed_usec = end_tv.tv_usec - start_tv.tv_usec;
		if (elapsed_usec < 0) {
			elapsed_sec--;
			elapsed_usec += 1000000;
		}
		sum_usec += elapsed_sec * 1000000 + elapsed_usec;
		avg_usec = sum_usec / ((long)i + 1);
		avg_sec = avg_usec / 1000000;
		avg_usec %= 1000000;
		printf("[%02d] %ld.%06ld sec (avg. %ld.%06ld)\n", i, elapsed_sec, elapsed_usec, avg_sec, avg_usec);
		sleep(1);
	}
}
