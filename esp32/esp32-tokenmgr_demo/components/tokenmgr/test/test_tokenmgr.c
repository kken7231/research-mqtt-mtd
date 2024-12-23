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

static void byteArrayToHexString(const uint8_t* byteArray, size_t length) {
	for (size_t i = 0; i < length; i++) {
		printf("%02X", byteArray[i]);  // "%02X" ensures two digits with leading zeros if necessary
	}
	printf("\n");
}

TEST_CASE("Get a publish token", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_NONE,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t token[TOKEN_SIZE] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, NULL, NULL));
	TEST_ASSERT_FALSE(isZeroFilled(token, TOKEN_SIZE));
}

TEST_CASE("Base64 Encode of the token", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_NONE,
	};
	const char* topic = "/sample/topic/pub";
	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_TRUE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, NULL, NULL));
	TEST_ASSERT_FALSE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(token, encoded_token));
	TEST_ASSERT_FALSE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
}

TEST_CASE("Send a plain publish", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_NONE,
	};
	const char* topic = TOPIC_PUB;
	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	TEST_ASSERT_TRUE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_TRUE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, NULL, NULL));
	TEST_ASSERT_FALSE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(token, encoded_token));
	TEST_ASSERT_FALSE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, "hello, world", 0));
}

TEST_CASE("Send a plain AEAD publish", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_AES_128_GCM,
	};
	const char* topic = TOPIC_PUB;
	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	uint8_t* encryption_key = get_keylen(req.payload_aead_type) > 0 ? (uint8_t*)malloc(get_keylen(req.payload_aead_type)) : NULL;
	uint16_t cur_token_idx;
	uint8_t* sealed_data = NULL;
	size_t sealed_data_len;
	TEST_ASSERT_TRUE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_TRUE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, encryption_key, &cur_token_idx));
	TEST_ASSERT_FALSE(isZeroFilled(token, TOKEN_SIZE));
	TEST_ASSERT_NOT_NULL(encryption_key);
	TEST_ASSERT_FALSE(isZeroFilled(encryption_key, get_keylen(req.payload_aead_type)));
	TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(token, encoded_token));
	TEST_ASSERT_FALSE(isZeroFilled(encoded_token, BASE64_ENCODED_TOKEN_SIZE));
	TEST_ASSERT_EQUAL_INT(ESP_OK, seal_message(req.payload_aead_type, "hello, world", strlen("hello, world"), encryption_key, (uint64_t)cur_token_idx, &sealed_data, &sealed_data_len));
	TEST_ASSERT_EQUAL_INT(strlen("hello, world") + 16, sealed_data_len);
	TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, (const char*)sealed_data, sealed_data_len));
	free((void*)encryption_key);
}

TEST_CASE("Send a tls publish", "[pub]") {
	const char* topic = TOPIC_PUB;
	TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_TLS, topic, "hello, world", 0));
}

TEST_CASE("Send 32 plain publishes", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_NONE,
	};
	const char* topic = TOPIC_PUB;
	char data[] = "hello, plain-00";
	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	struct timeval start_tv, end_tv;
	long sum_usec = 0, elapsed_sec, elapsed_usec, avg_sec, avg_usec;
	for (char i = 0; i < 32; i++) {
		data[13] = '0' + (i / 10);
		data[14] = '0' + (i % 10);
		gettimeofday(&start_tv, NULL);
		TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, NULL, NULL));
		TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(token, encoded_token));
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

TEST_CASE("Send 32 plain AEAD publishes", "[pub]") {
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = 1,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_AES_128_GCM,
	};
	const char* topic = TOPIC_PUB;
	char data[] = "hello, paead-00";
	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	uint8_t* encryption_key = get_keylen(req.payload_aead_type) > 0 ? (uint8_t*)malloc(get_keylen(req.payload_aead_type)) : NULL;
	uint16_t cur_token_idx;
	uint8_t* sealed_data = NULL;
	size_t sealed_data_len;
	struct timeval start_tv, end_tv;
	long sum_usec = 0, elapsed_sec, elapsed_usec, avg_sec, avg_usec;
	for (char i = 0; i < 32; i++) {
		data[13] = '0' + (i / 10);
		data[14] = '0' + (i % 10);
		gettimeofday(&start_tv, NULL);
		TEST_ASSERT_EQUAL_INT(ESP_OK, get_token(topic, req, token, encryption_key, &cur_token_idx));
		TEST_ASSERT_EQUAL_INT(ESP_OK, b64encode_token(token, encoded_token));
		TEST_ASSERT_EQUAL_INT(ESP_OK, seal_message(req.payload_aead_type, data, strlen(data), encryption_key, (uint64_t)cur_token_idx, &sealed_data, &sealed_data_len));
		TEST_ASSERT_EQUAL_INT(ESP_OK, mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, (const char*)sealed_data, sealed_data_len));
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
	if (encryption_key) {
		free((void*)encryption_key);
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
