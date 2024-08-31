#include <errno.h>

#include "config.h"
#include "esp_log.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "nvs_flash.h"
#include "test.h"
#include "tokenmgr.h"

static const char* TAG = "tokenmgr_app";

const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};

static time_t align_to_nearest_10_seconds(time_t t) {
	return (t / 10) * 10;
}

static void display_time(const char* label, time_t t) {
	char buffer[64];
	struct tm tm_time;

	setenv("TZ", "JST-9", 1);
	tzset();
	localtime_r(&t, &tm_time);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_time);
	printf("%s: %s\n", label, buffer);
}

void app_main(void) {
	tokenmgr_app_init();
	tokenmgr_init();
	display_time("Testing App started", time(NULL));
	display_time("Waiting for 30 sec...", time(NULL));
	sleep(30);

	display_time("Plain Test Start", time(NULL));
	if (plain_none(1, 32) != 0) {
		printf("Aborting...\n");
		return;
	}
	display_time("Plain Test End", time(NULL));
	tokenmgr_deinit();
	tokenmgr_init();

	display_time("Waiting for 30 sec...", time(NULL));
	sleep(30);

	display_time("Plain(AEAD) Test Start", time(NULL));
	if (plain_aead(1, 32) != 0) {
		printf("Aborting...\n");
		return;
	}
	display_time("Plain(AEAD) Test End", time(NULL));
	tokenmgr_deinit();
	tokenmgr_init();

	display_time("Waiting for 30 sec...", time(NULL));
	sleep(30);

	display_time("TLS Test Start", time(NULL));
	if (tls(32) != 0) {
		printf("Aborting...\n");
		return;
	}
	display_time("TLS Test End", time(NULL));
	tokenmgr_deinit();

	display_time("Test Ended", time(NULL));
}
