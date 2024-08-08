#include <Adafruit_INA260.h>
#include "WiFi.h"
#include <PubSubClient.h>

Adafruit_INA260 ina260 = Adafruit_INA260();
int loggingInterval;
long lastRead;
float ss;
// WiFi
const char *WIFI_SSID = "aBuffalo-T-E510";
const char *WIFI_PASSWORD = "penguink";
WiFiClient espClient;

// MQTTブローカー
const char *mqtt_broker = "192.168.11.16";
const char *topic = "esp32/test";
const int mqtt_port = 31883;
PubSubClient client(espClient);

char buffer[50];

void setup() {
  Serial.begin(115200);
  // Wait until serial port is opened
  while (!Serial) { delay(10); }
  Serial.println("Serial Connected");
  
  while (WiFi.status() != WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    delay(10000);
  }
  Serial.println("WiFi Connected");

  if (!ina260.begin()) {
    Serial.println("Couldn't find INA260 chip");
    while (1);
  }
  Serial.println("Found INA260 chip");

  ina260.setAveragingCount(INA260_COUNT_64);
  ina260.setCurrentConversionTime(INA260_TIME_8_244_ms);
  ina260.setVoltageConversionTime(INA260_TIME_8_244_ms);

  loggingInterval = 1000;
  lastRead = 0;
  client.setServer(mqtt_broker, mqtt_port);
}

void loop() {
  long diff;
  diff = millis() - lastRead;

  if(diff >= loggingInterval){
    lastRead += loggingInterval;

    float cur = ina260.readCurrent();
    float vol = ina260.readBusVoltage();
    float pow = ina260.readPower();

    if(client.connected() || client.connect("abc")) {
      sprintf(buffer, "{cur:%f,vol:%f,pow:%f}", cur, vol, pow);
      client.publish(topic, buffer);
    }
  }
}