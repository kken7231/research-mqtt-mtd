#include <Adafruit_INA260.h>
#include "WiFi.h"
#include <PubSubClient.h>
#include "time.h"

// Sensor
Adafruit_INA260 ina260 = Adafruit_INA260();
int loggingInterval = 500; // ms
unsigned long lastReadMillis = 0; 
const char* datetimeString = "2024-08-29 13:15:00";
time_t configuredStartTime = 0; // Configurable start time from string
float ss;

// WiFi
const char *WIFI_SSID = "aBuffalo-T-E510";
const char *WIFI_PASSWORD = "penguink";
// const char *WIFI_SSID = "koidelab";
// const char *WIFI_PASSWORD = "nni-8ugimrjnmw";
WiFiClient espClient;

// Define NTP Client to get time
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 3600 * 9;  // GMT offset for Japan Standard Time (JST)
const int daylightOffset_sec = 0;

// MQTT Broker
const char* mqtt_broker = "192.168.11.16";
const char* topic = "cli/watts";
const int mqtt_port = 31883;
PubSubClient client(espClient);

char buffer[100];

// Function to parse a datetime string and return a time_t value
time_t parseDatetimeString(const char* datetime) {
  struct tm tm;
  if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
    Serial.println("Failed to parse datetime string");
    return 0;
  }
  return mktime(&tm);
}

void setup() {
  Serial.begin(115200);
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
  ina260.setCurrentConversionTime(INA260_TIME_4_156_ms);
  ina260.setVoltageConversionTime(INA260_TIME_4_156_ms);

  client.setServer(mqtt_broker, mqtt_port);

  // Initialize and synchronize time with NTP server
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  
  // Set the configured start time from a string (example: "2023-09-01 10:00:00")
  configuredStartTime = parseDatetimeString(datetimeString);

  if (configuredStartTime == 0) {
    Serial.println("Invalid datetime string, aborting...");
    while (1);
  }

  Serial.print("Configured start time (Unix): ");
  Serial.println(configuredStartTime);
  
  lastReadMillis = millis(); // Capture the starting millis
  
  Serial.println("Setup complete");
}

void loop() {
  unsigned long currentMillis = millis();
  
  if (currentMillis - lastReadMillis >= loggingInterval) {
    lastReadMillis += loggingInterval;

    float cur = ina260.readCurrent();
    float vol = ina260.readBusVoltage();
    float pow = ina260.readPower();

    if (client.connected() || client.connect("abc")) {
      // Calculate the current time based on configuredStartTime and elapsed milliseconds
      unsigned long now = ((unsigned long)configuredStartTime + currentMillis) / 1000;
      unsigned long millisec = ((unsigned long)configuredStartTime + currentMillis) % 1000;

      sprintf(buffer, "{\"ts\":%lu.%03lu,\"cur\":%f,\"vol\":%f,\"pow\":%f}", (unsigned long)now, millisec, cur, vol, pow);
      Serial.println(buffer);
      client.publish(topic, buffer);

      client.loop();
    }
  }
}
