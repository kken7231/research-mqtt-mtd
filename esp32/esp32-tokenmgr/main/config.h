#ifndef TOKENMGR_CONFIG_H
#define TOKENMGR_CONFIG_H

#include <netdb.h>

#include "esp_wifi.h"

// #define WIFI_SSID "koidelab"
// #define WIFI_PASS "nni-8ugimrjnmw"

const wifi_sta_config_t wifi_sta_config = {
	.ssid = "aBuffalo-T-E510",
	.password = "penguink",
};

const char *PLAIN_BROKER_URI = "mqtt://192.168.11.16:1883";
const char *TLS_BROKER_URI = "mqtts://192.168.11.16:8883";

#define SET_IP_INFO(ip_info)                 \
	IP4_ADDR(&ip_info.ip, 192, 168, 11, 60); \
	IP4_ADDR(&ip_info.gw, 192, 168, 11, 1);  \
	IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

#endif