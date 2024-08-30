
#include "test.h"

#define TOPIC_PUB "/sample/topic/pub"
#define PLAIN_NONE_MSG_TEMP "hello, plain(none)-00"
#define PLAIN_AEAD_MSG_TEMP "hello, plain(aead)-00"
#define PLAIN_TLS_MSG_TEMP "hello, tls(aessha)-00"

extern int permit_time_logging;

#define TEST_INITIALIZE()                                            \
	struct timeval start_tv, end_tv;                                 \
	long sum_usec = 0, elapsed_sec, elapsed_usec, avg_sec, avg_usec; \
	long next_time = start_time;

#define TEST_CALCULATE_TIME()                                                                           \
	elapsed_sec = end_tv.tv_sec - start_tv.tv_sec;                                                      \
	elapsed_usec = end_tv.tv_usec - start_tv.tv_usec;                                                   \
	if (elapsed_usec < 0) {                                                                             \
		elapsed_sec--;                                                                                  \
		elapsed_usec += 1000000;                                                                        \
	}                                                                                                   \
	sum_usec += elapsed_sec * 1000000 + elapsed_usec;                                                   \
	avg_usec = sum_usec / ((long)i + 1);                                                                \
	avg_sec = avg_usec / 1000000;                                                                       \
	avg_usec %= 1000000;                                                                                \
	print_time_record_summary();                                                                        \
	reset_time_record_store();                                                                          \
	printf("[%02d] %ld.%06ld sec (avg. %ld.%06ld)\n", i, elapsed_sec, elapsed_usec, avg_sec, avg_usec); \
	next_time += 3 * 1000000;

int plain_none(long start_time, int num_tokens_divided_by_multiplier, int iter) {
	TEST_INITIALIZE();

	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = num_tokens_divided_by_multiplier,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_NONE,
	};
	char data[] = PLAIN_NONE_MSG_TEMP;
	permit_time_logging = 1;

	for (char i = 0; i < iter; i++) {
		data[19] = '0' + (i / 10);
		data[20] = '0' + (i % 10);
		do {
			usleep(100 * 1000);	 // wait for 100ms
			gettimeofday(&start_tv, NULL);
		} while (start_tv.tv_sec < next_time);
		if (get_token(TOPIC_PUB, req, token, NULL, NULL) != ESP_OK) {
			return -1;
		}
		if (b64encode_token(token, encoded_token) != ESP_OK) {
			return -1;
		}
		if (mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, data, 0) != ESP_OK) {
			return -1;
		}
		gettimeofday(&end_tv, NULL);
		TEST_CALCULATE_TIME();
	}
	return 0;
}

int plain_aead(long start_time, int num_tokens_divided_by_multiplier, int iter) {
	TEST_INITIALIZE();

	uint8_t token[TOKEN_SIZE] = {0}, encoded_token[BASE64_ENCODED_TOKEN_SIZE] = {0};
	uint8_t* encryption_key = get_keylen(PAYLOAD_AEAD_AES_128_GCM) > 0 ? (uint8_t*)malloc(get_keylen(PAYLOAD_AEAD_AES_128_GCM)) : NULL;
	uint16_t cur_token_idx;
	uint8_t* sealed_data = NULL;
	size_t sealed_data_len;

	issuer_request_t req = {
		.num_tokens_divided_by_multiplier = num_tokens_divided_by_multiplier,
		.access_type_is_pub = true,
		.payload_aead_type = PAYLOAD_AEAD_AES_128_GCM,
	};
	char data[] = PLAIN_AEAD_MSG_TEMP;
	permit_time_logging = 1;

	for (char i = 0; i < iter; i++) {
		data[19] = '0' + (i / 10);
		data[20] = '0' + (i % 10);
		do {
			usleep(100 * 1000);	 // wait for 100ms
			gettimeofday(&start_tv, NULL);
		} while (start_tv.tv_sec < next_time);
		if (get_token(TOPIC_PUB, req, token, encryption_key, &cur_token_idx) != ESP_OK) {
			return -1;
		}
		if (b64encode_token(token, encoded_token) != ESP_OK) {
			return -1;
		}
		if (seal_message(req.payload_aead_type, data, strlen(data), encryption_key, (uint64_t)cur_token_idx, &sealed_data, &sealed_data_len) != ESP_OK) {
			return -1;
		}
		if (mqtt_publish_qos0(MQTT_CLIENT_PLAIN, (const char*)encoded_token, data, 0) != ESP_OK) {
			return -1;
		}
		gettimeofday(&end_tv, NULL);
		TEST_CALCULATE_TIME();
	}
	return 0;
}

int tls(long start_time, int iter) {
	TEST_INITIALIZE();

	char data[] = PLAIN_AEAD_MSG_TEMP;
	permit_time_logging = 1;

	for (char i = 0; i < iter; i++) {
		data[19] = '0' + (i / 10);
		data[20] = '0' + (i % 10);
		do {
			usleep(100 * 1000);	 // wait for 100ms
			gettimeofday(&start_tv, NULL);
		} while (start_tv.tv_sec < next_time);
		if (mqtt_publish_qos0(MQTT_CLIENT_TLS, TOPIC_PUB, data, 0) != ESP_OK) {
			return -1;
		}
		gettimeofday(&end_tv, NULL);
		TEST_CALCULATE_TIME();
	}
	return 0;
}