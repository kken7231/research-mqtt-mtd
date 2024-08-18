#include <Adafruit_INA260.h>
#include "WiFi.h"
#include <PubSubClient.h>
#include "time.h"

Adafruit_INA260 ina260 = Adafruit_INA260();
int loggingInterval = 1000;
long lastRead = 0;
float ss;
// WiFi
// const char *WIFI_SSID = "aBuffalo-T-E510";
// const char *WIFI_PASSWORD = "penguink";
const char *WIFI_SSID = "koidelab";
const char *WIFI_PASSWORD = "nni-8ugimrjnmw";
WiFiClient espClient;
PubSubClient client(espClient);

// Define NTP Client to get time
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 3600 * 9;  // GMT offset for Japan Standard Time (JST)
const int daylightOffset_sec = 0;

// MQTT broker details
const char* mqtt_broker = "192.168.11.6";
const char* topic = "watts_data";
const int mqtt_port = 31883;

char buffer[100];

void setup() {
  Serial.begin(115200);
  // Wait until serial port is opened
  while (!Serial) { delay(10); }
  Serial.println("Serial Connected");
  
  // Connect to WiFi
  while (WiFi.status() != WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    delay(10000);
  }
  Serial.println("WiFi Connected");

  // Initialize INA260 sensor
  if (!ina260.begin()) {
    Serial.println("Couldn't find INA260 chip");
    while (1);
  }
  Serial.println("Found INA260 chip");

  ina260.setAveragingCount(INA260_COUNT_64);
  ina260.setCurrentConversionTime(INA260_TIME_8_244_ms);
  ina260.setVoltageConversionTime(INA260_TIME_8_244_ms);

  client.setServer(mqtt_broker, mqtt_port);

  // Initialize and synchronize time with NTP server
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  Serial.println("Setup complete");
}

void loop() {
  long diff;
  diff = millis() - lastRead;

  if (diff >= loggingInterval) {
    lastRead += loggingInterval;

    float cur = ina260.readCurrent();
    float vol = ina260.readBusVoltage();
    float pow = ina260.readPower();

    if (client.connected() || client.connect("abc")) {
      // Get the current time in seconds since the Unix epoch
      time_t now;
      struct tm timeinfo;
      if (!getLocalTime(&timeinfo)) {
        Serial.println("Failed to obtain time");
        return;
      }
      time(&now);
    
      sprintf(buffer, "{\"ts\":%lu,\"cur\":%f,\"vol\":%f,\"pow\":%f}", (unsigned long)now, cur, vol, pow);
      Serial.println(buffer);
      client.publish(topic, buffer);
    }
  }
}