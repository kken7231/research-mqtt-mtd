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
	display_time("Waiting for 20s...", time(NULL));
	sleep(20);

	if (plain_none(1, 32) != 0) {
		printf("Aborting...\n");
		return;
	}
	tokenmgr_deinit();
	tokenmgr_init();
	display_time("Plain Test Ended. Waiting for 20s...", time(NULL));
	sleep(20);

	if (plain_aead(1, 32) != 0) {
		printf("Aborting...\n");
		return;
	}
	tokenmgr_deinit();
	tokenmgr_init();
	display_time("Plain(AEAD) Test Ended. Waiting for 20 sec...", time(NULL));
	sleep(20);

	if (tls(32) != 0) {
		printf("Aborting...\n");
		return;
	}
	tokenmgr_deinit();

	display_time("Test Ended", time(NULL));
}
