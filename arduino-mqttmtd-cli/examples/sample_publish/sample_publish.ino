#include <MQTTMTDClient.h>
#include <WiFi.h>

// --- Wi-Fi Configuration ---
// Replace with your network credentials
const char* ssid = "aBuffalo-G-E510";
const char* password = "penguink";

// --- MQTT Broker Configuration ---
// Replace with your MQTT broker's IP address or domain name
const char* mqtt_server = "haydn.local";
const int mqtt_port = 11883;  // Default MQTT port

const char* issuer_host = "haydn.local";
const uint16_t issuer_port = 18771;

const char* ca_crt = R"literal(-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIUC828ymPkWW12YCq2odwkpTEbUiIwDQYJKoZIhvcNAQEN
BQAwDTELMAkGA1UEAwwCY2EwHhcNMjUwNzAyMDgzNjE5WhcNMjYwNzAyMDgzNjE5
WjANMQswCQYDVQQDDAJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALlr03PrdsMxcKU8sKdgbT97MW6wXY1a/oIakQnaLVc/YSvXzM22BJ5N3iHynEHU
3o9UCQFWBkWAL5gVMah4hYKeTSFQ6o+XUfOsulh/BGatwe9+CbC0wpDidDT+fMGv
hDtYps1bhadVcnGbpzpPzgawIT4pkThq7zpxT7836ar8DYAd+LbxDqzYwYVN2z3w
Y/gU0e3DN4LaKrks1D+/DGgBxYnPc7VBLQuIJVCWkmNvBzDpMaQ9a+5o6SgEg45l
qHruOlaCxqZywdLI5ks0q0TsTTeV+GhDOMmMj6BQy7X2hXgdJfklTj94lx2b+lgK
oHFSS6g0dJAv5Z76pL1r9nsCAwEAAaNSMFAwDQYDVR0RBAYwBIICY2EwDwYDVR0P
AQH/BAUDAwcGADAdBgNVHQ4EFgQUXkwMMYXf2qGw/jq6w7zS/H+frHYwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAiKHlBrJo+QD9YGRmgUBj0Q9W
78eeost+8PcFyFU0n3ZcuLWS4MbWT7F0nS6yt8UGUlNmLCzI1nU+F4XKfQVvOlRO
vpCmX+yGe+56lgf3NK6tQH/ivaR58RYPpbSuqi64qpTbgFW+NDUxDVRnUOQK+5uv
tCpjPvn3UYhH6iRDLI0Z0kghbs3eZGlswVHjj65q73MYD/SzA+N8HM+YSYgRLBEE
zDvayhanXy9GWWaz+4VS53+HJ+XdIeaMkm+CS91vsXeP5aM8VaOvv+6wvre69Uau
yEKGRCNJnOjBkP/XOe173DHconrTPDz27HckxwiWlL0ODxfBXKvykkXOIsLz+A==
-----END CERTIFICATE-----)literal";

const char* cli_crt = R"literal(-----BEGIN CERTIFICATE-----
MIIC6TCCAdGgAwIBAgIUFyYxrzpRahUb3h6buWAZkQEi/GQwDQYJKoZIhvcNAQEN
BQAwDTELMAkGA1UEAwwCY2EwHhcNMjUwNzAyMDgzNjE5WhcNMjYwNzAyMDgzNjE5
WjASMRAwDgYDVQQDDAdjbGllbnQxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAteJyaBHKSZjqJZ/QlDzuuamjfcA9GQ+iDRyp8c7kBzKG2kT7lWgsYUW2
+3ujtFXZgdSSLPvqLQ9FthXz74ReC20DTEk6vdrHPp8WCvtx7vPKwrmF0GWCVzoy
ituu5qMOcJT36D601soE1LTc+fdwpxKF+T2D9HRRHXb5SqzCjJ3sxGZRfSL57PdX
MGGr5HpnllgBMfRpNnIWpMgnV16oEM3gbvAdvNU8XfRZThdiRUb7JqXGtvGC9WkG
TX1HVOGXG1WPji7qGUcpQhLVhYWC10kvEht5NNSolmElC3205VLn3C/QQrcpcyOV
qhKq9y8qherFcsC3eIIrdpoI2UP1uwIDAQABozwwOjASBgNVHREECzAJggdjbGll
bnQxMA8GA1UdDwEB/wQFAwMHoAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZI
hvcNAQENBQADggEBAKCEnTmQSxUCAMmutgUu7mP+Q/HFmoDzKmNnLNTKCeZZtuY8
V5fgFHOjGHc5EjautgWUOHGii7fs8A8bkYS+usmCct3wkdE1he2c9BHSOK4iH0AP
hxXOYzhMPKIop6oz4jXrivTrhjz6pgWsckCWfka4gbcebCYtIP6nziy6xE48TnAf
d8pqsT+UY87vb1CCQUeBbxgFQh3FDDD9KXJfdX6CUcIG7gRbP0rwXKmjo5sWiAiR
fQhfHLop17hPmZwJDkDRUIz+AFnMH4Dn/JbdGEEQd/IBYFVEj5ZKvRBNeYqQ7TWQ
FQ5Ymy3rhovQGwjY4YbNn0v8DfpifcCPFEJl3No=
-----END CERTIFICATE-----)literal";

const char* cli_key = R"literal(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC14nJoEcpJmOol
n9CUPO65qaN9wD0ZD6INHKnxzuQHMobaRPuVaCxhRbb7e6O0VdmB1JIs++otD0W2
FfPvhF4LbQNMSTq92sc+nxYK+3Hu88rCuYXQZYJXOjKK267mow5wlPfoPrTWygTU
tNz593CnEoX5PYP0dFEddvlKrMKMnezEZlF9Ivns91cwYavkemeWWAEx9Gk2chak
yCdXXqgQzeBu8B281Txd9FlOF2JFRvsmpca28YL1aQZNfUdU4ZcbVY+OLuoZRylC
EtWFhYLXSS8SG3k01KiWYSULfbTlUufcL9BCtylzI5WqEqr3LyqF6sVywLd4git2
mgjZQ/W7AgMBAAECggEAVyPfKSIA1yLmZ1E6hpLs0tHF7Pz5qLSXMI3/k8TJ9fLM
re0n1ax7urzCTpktVLxewXd88wVca+spvHOnE6VIw1OepWFePdB/7e4dCvTt4Iw3
o/RremzvtefBiEp48LHFPMX6QfAtBszx5JCkYDQe6kSTIFbLDgbeR+4UwKSlbuV3
n0AVcFWXMUiHDFL/5lJEpEpO/WrPxWOhPjxTRsrulY3ZZSKuTXSwDozQS8J9caTn
2UoM6Puu8V9lM/WIwlS2LfYXG/Y+E4vTQGAMT786usN+dwQKVvFY7sLMC1U/bm7C
3cIquxDUyPQxwcAnOGT2vo47wmmshIkOexWoVNpnsQKBgQD6Ki62Wk3m5oS17C3T
3RWboyOIaRnQVx3kbtcXv6HK1LcNR3UOzCYLqNURjDBY0m+YTJvVaMJnm0joCVZf
LJKTJHv9S1vV1iedsw4HIfI1/RBtqDP6xjzb8uGNtKA4CmUz6O3ktFVRu30EU1cL
9h+QbPzLbrjMlyhPOQ2lINV4KwKBgQC6IIpZB7bf2zvVUnQ6cbgO2uvAKhyTaoz1
QQV36aTGwqjAkJ7RrO1BvvGfkkwgoZwSPjLFwSgI1NuU0urp1o9uIWZHlsm4CdKs
gBE9B8Lg88naYxR36eKNst+iUAKO9DXP3Nw4eNtqxGYAGN7sySs7cSbuxW5HMqik
GZuTXjOgsQKBgFO9nxlnrUAn1jDXuJd9IGiS+agGFqAJKXZ4LARFH7G39va4/tRP
PkUU5Q4UsXJqLvT6YAfWI41vC76wsXr2frJGukKV4U35fBVsBLwafuvXpJIwhgXi
KikuapZ26lMYF7yCsm+mdhEAA99YzoCwiOxdr1mh3LaPuuyaGpk2Hn81AoGAQ+hx
cZAt+bi8ONWPkG9DLzBSiVcT+/kJGsYxX5HAS8Bj33Yka+3C1pT7BTRUUCeGkOVe
kuYpXCeFQeQ+Tzi4Nf87mOz8BgiXc9Z586FsSbTItcQmiKWtwfM8QrUcadnR9Ffp
hTUbIPYtHOX2F8BB5Lsg8EbaOGHUQ6MQLxFUltECgYEAlR2yqEsa72AETQr6VmnC
6KqmEMaE00g1slnsgzUyy7ZVsqitTAGvj65nrPDCSMhER9GAtxyCRSjaPDOJOIP/
xn4HNEDcFeaD0x3t6MeHKquX9KWggRwfG6JgxVBwqQwq5qBWnb6sVohf5z/coCXJ
vi/t8sDpsRcpZs0lvll9aOk=
-----END PRIVATE KEY-----)literal";

// --- MQTT Client Setup ---
WiFiClient espClient;
MQTTMTDClient client(espClient);

// --- Global Variables ---
long lastMsg = 0;
char msg[50];
int value = 0;

// Function to set up and connect to Wi-Fi
void setup_wifi() {
  delay(100);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  // Wait for the Wi-Fi connection to be established
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

// Function to reconnect to the MQTT broker
void reconnect() {
  // Loop until we're reconnected
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    // Create a random client ID
    String clientId = "ESP_Client-";
    clientId += String(random(0xffff), HEX);

    // Attempt to connect
    if (client.connect(clientId.c_str())) {
      Serial.println("connected");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void setup() {
  // Start the serial communication for debugging
  Serial.begin(115200);

  // Connect to Wi-Fi
  setup_wifi();

  // Configure the MQTT client
  client.init();
  client.setServer(mqtt_server, mqtt_port);
  client.setIssuerServer(issuer_host, issuer_port);
  client.setCACert(ca_crt);
  client.setCertificate(cli_crt);
  client.setPrivateKey(cli_key);
}


void loop() {
  // Ensure the client is connected to the MQTT broker
  if (!client.connected()) {
    reconnect();
  }
  // This is the non-blocking client loop that handles MQTT communication
  client.loop();

  // Publish a message every 2 seconds
  long now = millis();
  if (now - lastMsg > 2000) {
    lastMsg = now;
    snprintf(msg, 50, "hello world #%d", value);

    Serial.print("Publish message: ");
    Serial.println(msg);

    // Publish the message to the "outTopic"
    if (client.mtd_publish("topic/pubonly", msg)) {
      value++;
    }
  }
}
