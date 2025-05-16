#include "tokenmgr.h"

static const char *TAG = "tokenmgr_wifi";
static EventGroupHandle_t wifi_event_group;
static int wifi_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
		esp_wifi_connect();
	else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (wifi_retry_num < WIFI_MAX_RETRY) {
			esp_wifi_connect();
			wifi_retry_num++;
			ESP_LOGI(TAG, "retry to connect to the AP");
		} else
			xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
		ESP_LOGI(TAG, "Failed to connect to the AP");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ESP_LOGI(TAG, "IP address assigned:" IPSTR, IP2STR(&((ip_event_got_ip_t *)event_data)->ip_info.ip));
		wifi_retry_num = 0;
		xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

esp_netif_t *wifi_init_sta(void) {
	LOG_TIME_FUNC_START();
	wifi_event_group = xEventGroupCreate();
	esp_netif_t *netif = esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id, instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = wifi_sta_config,
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGI(TAG, "esp_wifi_start triggered");

	EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
										   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));

	if (bits & WIFI_CONNECTED_BIT)
		ESP_LOGI(TAG, "connected to ap SSID:%s", wifi_sta_config.ssid);
	else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", wifi_sta_config.ssid);
		goto wifi_init_sta_err;
	} else {
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
		goto wifi_init_sta_err;
	}

	ESP_ERROR_CHECK(mdns_init());
	ESP_ERROR_CHECK(mdns_hostname_set("client"));
	ESP_LOGI(TAG, "mdns hostname set to client");

	esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
	config.start = false;
	config.server_from_dhcp = true;
	config.index_of_first_server = 1;
	config.ip_event_to_renew = IP_EVENT_STA_GOT_IP;
	ESP_ERROR_CHECK(esp_netif_sntp_init(&config));
	ESP_ERROR_CHECK(esp_netif_sntp_start());
	ESP_LOGI(TAG, "esp_netif_sntp_start triggered");
	int sntp_retry = 0;
	while (esp_netif_sntp_sync_wait(1000 / portTICK_PERIOD_MS) == ESP_ERR_TIMEOUT && ++sntp_retry < SNTP_MAX_RETRY) {
		ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", sntp_retry, SNTP_MAX_RETRY);
	}
	sntp_sync_status_t sntp_status = sntp_get_sync_status();
	if (sntp_status == SNTP_SYNC_STATUS_COMPLETED) {
		ESP_LOGI(TAG, "time fixed with SNTP");
		LOG_TIME("Time fixed with SNTP");
		goto wifi_init_sta_finish;
	} else {
		ESP_LOGE(TAG, "time didn't fixed with SNTP");
		goto wifi_init_sta_err;
	}

wifi_init_sta_err:
	if (netif) {
		esp_wifi_stop();
		esp_wifi_deinit();
		esp_netif_destroy(netif);
	}
wifi_init_sta_finish:
	LOG_TIME_FUNC_END();
	return netif;
}
