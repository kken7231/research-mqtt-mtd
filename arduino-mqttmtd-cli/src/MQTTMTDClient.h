//
// Created by kentarou on 2025/06/22.
//

#ifndef MQTTMTDClient_h
#define MQTTMTDClient_h

#include <Arduino.h>
#include "PubSubClient.h"
#include <map>
#include "libmqttmtd.h"
#include <WiFiClientSecure.h>

struct CStringCompare {
    bool operator()(const char *a, const char *b) const {
        return strcmp(a, b) < 0;
    }
};

#ifndef NUM_TOKENS_DIV_4_PUBLISH
#define NUM_TOKENS_DIV_4_PUBLISH 32 // 128
#endif

#ifndef AEAD_ALGORITHM
#define AEAD_ALGORITHM SupportedAlgorithm::Aes256Gcm
#endif

class MQTTMTDClient : public PubSubClient {
private:
    std::map<const char *, TokenSet *, CStringCompare> token_sets;
    const char *issuer_host;
    uint16_t issuer_port = 18771;
    WiFiClientSecure _secure_client;

public:
    using PubSubClient::PubSubClient;

    bool init();

    void deinit();

    void setCACertForIssuer(const char *rootCA);

    void setCertificateForIssuer(const char *cert);

    void setPrivateKeyForIssuer(const char *key);

    void setIssuerServer(const char *host, uint16_t port);

    bool requestTokens(bool is_pub, uint8_t num_tokens_div_4, SupportedAlgorithm algo, const char *topic);

    bool mtd_publish(const char *topic, const char *payload);

    bool mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength);
};

#endif //MQTTMTDClient_h
