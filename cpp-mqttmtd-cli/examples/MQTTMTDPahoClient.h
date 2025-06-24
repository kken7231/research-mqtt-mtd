//
// Created by kentarou on 2025/06/22.
//

#ifndef paho_client_h
#define paho_client_h

#include "MQTTClient.h"
#include <cstring>
#include <map>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "libmqttmtd.h"

struct CStringCompare {
    bool operator()(const char *a, const char *b) const {
        return strcmp(a, b) < 0;
    }
};

#ifndef NUM_TOKENS_DIV_4_PUBLISH
#define NUM_TOKENS_DIV_4_PUBLISH 32 // 128
#endif

#ifndef ISSUER_HOST
#define ISSUER_HOST "server"
#endif
#ifndef ISSUER_PORT
#define ISSUER_PORT "18771"
#endif

#ifndef MQTT_INTERFACE_URI
#define MQTT_INTERFACE_URI "mqtt://server:1883"
#endif

#ifndef CLIENT_ID
#define CLIENT_ID "client_id"
#endif

#ifndef AEAD_ALGORITHM
#define AEAD_ALGORITHM SupportedAlgorithm::Aes256Gcm
#endif

class MQTTMTDPahoClient {
private:
    std::map<const char *, TokenSet *, CStringCompare> token_sets;
    MQTTClient client;
    mbedtls_ssl_context ssl{};
    mbedtls_net_context server_fd{};

public:
    MQTTMTDPahoClient();

    ~MQTTMTDPahoClient();

    MQTTMTDPahoClient &setCACert(const char *rootCA);

    void requestTokens(bool is_pub, uint8_t num_tokens_div_4, SupportedAlgorithm algo, const char *topic);

    bool mtd_publish(const char *topic, const char *payload);

    bool mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength);

private:
    bool connect();

    bool print(const char *payload);

    size_t readBytes(uint8_t *out, size_t outlen);
};

#endif //paho_client_h
