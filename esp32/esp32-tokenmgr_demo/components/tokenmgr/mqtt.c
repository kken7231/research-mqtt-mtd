#include "tokenmgr.h"

static const char *TAG = "tokenmgr_mqtt";

static EventGroupHandle_t mqtt_plain_event_group, mqtt_tls_event_group;

static void mqtt_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	mqtt_client_type_t *client_type = (mqtt_client_type_t *)arg;
	const char *client_type_label = (*client_type == MQTT_CLIENT_PLAIN) ? "plain" : "tls";
	const EventGroupHandle_t client_group = (*client_type == MQTT_CLIENT_PLAIN) ? mqtt_plain_event_group : mqtt_tls_event_group;
	if ((esp_mqtt_event_id_t)event_id == MQTT_EVENT_CONNECTED) {
		ESP_LOGI(TAG, "Event MQTT_EVENT_CONNECTED (%s)", client_type_label);
		xEventGroupSetBits(client_group, MQTT_CONNECTED_BIT);
	} else if ((esp_mqtt_event_id_t)event_id == MQTT_EVENT_ERROR) {
		ESP_LOGE(TAG, "Event MQTT_EVENT_ERROR (%s)", client_type_label);
		xEventGroupSetBits(client_group, MQTT_FAIL_BIT);
	} else if ((esp_mqtt_event_id_t)event_id != MQTT_EVENT_BEFORE_CONNECT) {
		ESP_LOGE(TAG, "MQTT (%s) event other than MQTT_EVENT_CONNECTED: %ld", client_type_label, event_id);
		xEventGroupSetBits(client_group, MQTT_FAIL_BIT);
	}
}

esp_mqtt_client_handle_t mqtt_client_start(esp_mqtt_client_config_t *p_cfg, mqtt_client_type_t *p_client_type) {
	EventGroupHandle_t *p_event_group;
	esp_mqtt_client_handle_t mqtt_client;
	const char *mqtt_client_label;

	if (*p_client_type == MQTT_CLIENT_PLAIN) {
		p_event_group = &mqtt_plain_event_group;
		mqtt_client_label = "plain";
	} else {
		p_event_group = &mqtt_tls_event_group;
		mqtt_client_label = "tls";
	}
	*p_event_group = xEventGroupCreate();
	mqtt_client = esp_mqtt_client_init(p_cfg);
	if (!mqtt_client) {
		ESP_LOGE(TAG, "MQTT (%s) client initialization failed", mqtt_client_label);
		return NULL;
	}
	ESP_ERROR_CHECK(esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void *)p_client_type));
	ESP_ERROR_CHECK(esp_mqtt_client_start(mqtt_client));
	ESP_LOGI(TAG, "esp_mqtt_client_start triggered (%s)", mqtt_client_label);

	EventBits_t bits = xEventGroupWaitBits(*p_event_group,
										   MQTT_CONNECTED_BIT | MQTT_FAIL_BIT,
										   pdFALSE, pdFALSE, portMAX_DELAY);
	ESP_ERROR_CHECK(esp_mqtt_client_unregister_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler));
	if (bits & MQTT_CONNECTED_BIT)
		ESP_LOGI(TAG, "MQTT (%s) connected", mqtt_client_label);
	else {
		if (bits & MQTT_FAIL_BIT)
			ESP_LOGE(TAG, "MQTT (%s) connection failed", mqtt_client_label);
		else
			ESP_LOGE(TAG, "UNEXPECTED EVENT");
		if (mqtt_client)
			esp_mqtt_client_destroy(mqtt_client);
		return NULL;
	}
	return mqtt_client;
}

esp_err_t mqtt_publish_qos0(mqtt_client_type_t client_type, const char *topic, const char *data, int len_data) {
	LOG_TIME_FUNC_START();
	esp_err_t ret = ESP_OK;
	esp_mqtt_client_handle_t mqtt_client = NULL;
	CHECK_CURSTATE_IF_OPERATIONAL(ret, mqtt_publish_qos0_finish);
	const char *mqtt_client_label;

	if (client_type == MQTT_CLIENT_PLAIN) {
		esp_mqtt_client_config_t plain_cfg = {
			.broker.address.uri = PLAIN_BROKER_URI,
			.credentials.client_id = "esp32-plain-cli",
			.session.protocol_ver = MQTT_PROTOCOL_V_5,
			.network.disable_auto_reconnect = true,
		};
		mqtt_client_type_t plain_client_type = MQTT_CLIENT_PLAIN;
		mqtt_client_label = "plain";
		mqtt_client = mqtt_client_start(&plain_cfg, &plain_client_type);
	} else {
		esp_mqtt_client_config_t tls_cfg = {
			.broker = {
				.address.uri = TLS_BROKER_URI,
				.verification.crt_bundle_attach = esp_crt_bundle_attach,
			},
			.credentials = {
				.client_id = "esp32-tls-cli",
				.authentication = {
					.certificate = (const char *)client_crt_start,
					.key = (const char *)client_key_start,
				},
			},
			.session.protocol_ver = MQTT_PROTOCOL_V_5,
			.network.disable_auto_reconnect = true,
		};
		mqtt_client_type_t tls_client_type = MQTT_CLIENT_TLS;
		mqtt_client_label = "tls";
		mqtt_client = mqtt_client_start(&tls_cfg, &tls_client_type);
	}

	if (mqtt_client == NULL)
		goto mqtt_publish_qos0_finish;

	if (esp_mqtt_client_publish(mqtt_client, topic, data, len_data, 0, 0) != 0) {
		ESP_LOGE(TAG, "MQTT Publish (%s) failed", mqtt_client_label);
		ret = ESP_FAIL;
	} else {
		ESP_LOGI(TAG, "MQTT Publish (%s) success", mqtt_client_label);
	}
mqtt_publish_qos0_finish:
	if (mqtt_client) {
		esp_mqtt_client_disconnect(mqtt_client);
		esp_mqtt_client_destroy(mqtt_client);
	}

	LOG_TIME_FUNC_END();
	return ret;
}