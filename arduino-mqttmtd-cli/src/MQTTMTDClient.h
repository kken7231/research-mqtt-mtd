//
// Created by kentarou on 2025/06/22.
//

#ifndef MQTTMTDClient_h
#define MQTTMTDClient_h

#include <Arduino.h>
#include "PubSubClient.h"
#include "WiFiClientSecure.h"
#include <map>

#define TIMESTAMP_LEN  6
#define TIMESTAMP_B64LEN TIMESTAMP_LEN / 3 * 4
#define RANDOM_LEN 6
#define TOKEN_LEN (TIMESTAMP_LEN + RANDOM_LEN)
#define TOKEN_B64LEN TOKEN_LEN / 3 * 4

enum SupportedAlgorithm {
    Aes128Gcm = 1,
    Aes256Gcm = 2,
    Chacha20Poly1305 = 3,
};

inline size_t getKeyLen(const SupportedAlgorithm algo) {
    switch (algo) {
        case Aes128Gcm:
            return 16;
        case Aes256Gcm:
        case Chacha20Poly1305:
            return 32;
        default:
            return 0;
    }
}

inline size_t getTagLen() {
    return 16;
}

inline size_t getNonceLen() {
    return 12;
}

class TokenSet {
private:
    const char *topic;
    uint8_t *timestamp;
    uint16_t num_tokens;
    uint16_t token_idx;
    bool is_pub;

    SupportedAlgorithm algo;
    psa_key_id_t aead_key_id;
    psa_key_id_t hmac_key_id;
    unsigned char *hmac_buf;
    uint8_t *nonce;

public:
    explicit TokenSet(const char *topic, uint8_t *timestamp,
                      uint16_t num_tokens,
                      bool is_pub,
                      SupportedAlgorithm algo, psa_key_id_t aead_key_id, psa_key_id_t hmac_key_id,
                      const uint8_t *nonce_padding
    );

    ~TokenSet();

    void getCurrentB64Token(char *out) const;

    void printCurrentToken() const;

    psa_status_t sealCli2Serv(uint8_t *in_out, size_t in_out_len) const;

    boolean incrementTokenIdx();
};

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
#define ISSUER_PORT 18771
#endif

#ifndef MQTT_INTERFACE_HOST
#define MQTT_INTERFACE_HOST "server"
#endif
#ifndef MQTT_INTERFACE_PORT
#define MQTT_INTERFACE_PORT 1883
#endif

#ifndef AEAD_ALGORITHM
#define AEAD_ALGORITHM SupportedAlgorithm::Aes256Gcm
#endif

class MQTTMTDClient : public PubSubClient {
private:
    std::map<const char *, TokenSet *, CStringCompare> token_sets;
    WiFiClientSecure _secure_client;

public:
    using PubSubClient::PubSubClient;

    MQTTMTDClient &setCACert(const char *rootCA);

    MQTTMTDClient &setCACertBundle(const uint8_t *bundle, size_t size);

    void requestTokens(bool is_pub, uint8_t num_tokens_div_4, SupportedAlgorithm algo, const char *topic);

    boolean mtd_publish(const char *topic, const char *payload);

    boolean mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength);
};

#endif //MQTTMTDClient_h
