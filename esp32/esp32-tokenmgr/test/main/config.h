#ifndef TEST_TOKENMGR_CONFIG_H
#define TEST_TOKENMGR_CONFIG_H
#include <netdb.h>
#include "esp_wifi.h"

const wifi_sta_config_t wifi_sta_config = {
	// .ssid = "aBuffalo-T-E510",
	// .password = "penguink",
	.ssid = "koidelab",
	.password = "nni-8ugimrjnmw",
};

const char *PLAIN_BROKER_URI = "mqtt://192.168.11.11:1883";
const char *TLS_BROKER_URI = "mqtts://192.168.11.11:8883";

#define SET_IP_INFO(ip_info)                     \
	IP4_ADDR(&ip_info.ip, 192, 168, 11, 60); \
	IP4_ADDR(&ip_info.gw, 192, 168, 11, 1);  \
	IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

#endif