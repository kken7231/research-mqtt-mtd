#include <Adafruit_INA260.h>
#include <WiFi.h>

Adafruit_INA260 ina260 = Adafruit_INA260();
int loggingInterval;
long lastRead;
float ss;
// WiFi
const char *ssid = "koidelab";
const char *password = "qweqweqwe";

// MQTTブローカー
const char *mqtt_broker = "broker.emqx.io";
const char *topic = "esp8266/test";
const char *mqtt_username = "emqx";
const char *mqtt_password = "public";
const int mqtt_port = 1883;

void setup() {
  Serial.begin(115200);
  // Wait until serial port is opened
  while (!Serial) { delay(10); }

  Serial.println("Adafruit INA260 Test");

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
}

void loop() {
  long diff;
  diff = millis() - lastRead;
  
  if(diff >= loggingInterval){
    lastRead += loggingInterval;

    Serial.print("Current: ");
    Serial.print(ina260.readCurrent());
    Serial.println(" mA");

    Serial.print("Bus Voltage: ");
    Serial.print(ina260.readBusVoltage());
    Serial.println(" mV");

    Serial.print("Power: ");
    Serial.print(ina260.readPower());
    Serial.println(" mW");

    Serial.println();
  }
}