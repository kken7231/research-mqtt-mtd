#ifndef TOKENMGR_CONFIG_H
#define TOKENMGR_CONFIG_H

#include "esp_wifi.h"

const wifi_sta_config_t wifi_sta_config = {
	// .ssid = "aBuffalo-T-E510",
	// .password = "penguink",
	.ssid = "koidelab",
	.password = "nni-8ugimrjnmw",
};

const char *PLAIN_BROKER_URI = "mqtt://server.local:1883";
const char *TLS_BROKER_URI = "mqtts://server.local:8883";
const char *ISSUER_HOST = "server.local";
const int ISSUER_PORT = 18883;

#endif