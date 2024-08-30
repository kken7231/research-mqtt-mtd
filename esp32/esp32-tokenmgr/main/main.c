#include <errno.h>

#include "config.h"
#include "esp_log.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "nvs_flash.h"
#include "test.h"
#include "tokenmgr.h"

static const char* TAG = "tokenmgr_app";

const int CIPHERSUITES_LIST[] = {MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};

static void app_init(void) {
	tokenmgr_app_init();
	tokenmgr_init();
}

static void app_deinit(void) {
	tokenmgr_deinit();
}

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
	printf("Testing App started\n");
	app_init();

	time_t current_time = time(NULL);
	time_t time_plain = align_to_nearest_10_seconds(current_time + 30);
	time_t time_aead = align_to_nearest_10_seconds(time_plain + 180);
	time_t time_tls = align_to_nearest_10_seconds(time_aead + 180);

	printf("\nAligned Times:\n");
	display_time("plain_none starts", time_plain);
	display_time("plain_aead starts", time_aead);
	display_time("tls starts", time_tls);

	plain_none(time_plain, 1, 32);
	plain_aead(time_aead, 1, 32);
	tls(time_tls, 32);

	app_deinit();
}
