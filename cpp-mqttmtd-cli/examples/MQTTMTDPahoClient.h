//
// Created by kentarou on 2025/06/22.
//

#ifndef paho_client_h
#define paho_client_h

#include "MQTTClient.h"
#include <cstring>
#include <iostream>
#include <map>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <memory>

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
#define MQTT_INTERFACE_URI "tcp://server:1883"
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

    struct MbedtlsSslFree { void operator()(mbedtls_ssl_context* p) const { mbedtls_ssl_free(p); delete p; } };
    struct MbedtlsNetFree { void operator()(mbedtls_net_context* p) const { mbedtls_net_free(p); delete p; } };
    struct MbedtlsEntropyFree { void operator()(mbedtls_entropy_context* p) const { mbedtls_entropy_free(p); delete p; } };
    struct MbedtlsCtrDrbgFree { void operator()(mbedtls_ctr_drbg_context* p) const { mbedtls_ctr_drbg_free(p); delete p; } };
    struct MbedtlsSslConfigFree { void operator()(mbedtls_ssl_config* p) const { mbedtls_ssl_config_free(p); delete p; } };
    struct MbedtlsX509CrtFree { void operator()(mbedtls_x509_crt* p) const { mbedtls_x509_crt_free(p); delete p; } };
    struct MbedtlsPkFree { void operator()(mbedtls_pk_context* p) const { mbedtls_pk_free(p); delete p; } };

    std::unique_ptr<mbedtls_pk_context, MbedtlsPkFree> clikey;
    std::unique_ptr<mbedtls_x509_crt, MbedtlsX509CrtFree> clicert;
    std::unique_ptr<mbedtls_x509_crt, MbedtlsX509CrtFree> cacert;
    std::unique_ptr<mbedtls_ssl_config, MbedtlsSslConfigFree> conf;
    std::unique_ptr<mbedtls_ctr_drbg_context, MbedtlsCtrDrbgFree> ctr_drbg;
    std::unique_ptr<mbedtls_entropy_context, MbedtlsEntropyFree> entropy;
    std::unique_ptr<mbedtls_net_context, MbedtlsNetFree> server_fd;
    std::unique_ptr<mbedtls_ssl_context, MbedtlsSslFree> ssl; // ssl must be deconstructed at last.

public:
    MQTTMTDPahoClient();

    ~MQTTMTDPahoClient();

    void setCACert(const char *root_ca);

    void setClientCertAndKey(const char *cert, const char *key);

    void requestTokens(bool is_pub, uint8_t num_tokens_div_4, SupportedAlgorithm algo, const char *topic);

    bool mtd_publish(const char *topic, const char *payload);

    bool mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength);

private:
    bool connect();

    size_t write(const uint8_t *payload, size_t plength);

    size_t readBytes(uint8_t *out, size_t outlen);
};

#endif //paho_client_h
