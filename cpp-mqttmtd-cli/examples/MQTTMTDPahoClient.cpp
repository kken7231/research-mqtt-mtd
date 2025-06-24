//
// Created by kentarou on 2025/06/22.
//

#include "MQTTMTDPahoClient.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include <iostream>


MQTTMTDPahoClient::MQTTMTDPahoClient() {
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    int rc;

    if ((rc = MQTTClient_create(&client, MQTT_INTERFACE_URI, CLIENT_ID,
                                MQTTCLIENT_PERSISTENCE_NONE, nullptr)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to create client, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }
    this->client = client;

    mbedtls_ssl_context ssl;
    mbedtls_net_context server_fd;
    this->ssl = ssl;
    this->server_fd = server_fd;
    // Initialize mbedTLS structures
    mbedtls_net_init(&this->server_fd);
    mbedtls_ssl_init(&this->ssl);
    // Associate the SSL object with the network context
    mbedtls_ssl_set_bio(&this->ssl, &this->server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
}

MQTTMTDPahoClient::~MQTTMTDPahoClient() {
    if (int rc; (rc = MQTTClient_disconnect(this->client, 10000)) != MQTTCLIENT_SUCCESS)
        printf("Failed to disconnect, return code %d\n", rc);
    MQTTClient_destroy(&this->client);
}

MQTTMTDPahoClient &MQTTMTDPahoClient::setCACert(const char *rootCA) {
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret;

    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Set up the SSL/TLS configuration
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        fprintf(stderr, " failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        exit(ret);
    }

    if ((ret = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char *>(rootCA),
                                      strlen(rootCA) + 1)) != 0) {
        fprintf(stderr, " failed! mbedtls_x509_crt_parse returned -0x%x\n", static_cast<unsigned int>(-ret));
        exit(ret);
    }
    // Set the trusted CA certificate for server verification
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED); // Require server certificate verification
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

    // Seed the random number generator
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     reinterpret_cast<const unsigned char *>("mqttmtd_client_example"),
                                     sizeof("mqttmtd_client_example"))) != 0) {
        fprintf(stderr, " failed! mbedtls_x509_crt_parse returned -0x%x\n", static_cast<unsigned int>(-ret));
        exit(ret);
    }
    // Set the random number generator
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Set up the SSL/TLS session
    if ((ret = mbedtls_ssl_setup(&this->ssl, &conf)) != 0) {
        fprintf(stderr, " failed! mbedtls_ssl_setup returned %d\n", ret);
        exit(ret);
    }

    // Set Server Name Indication (SNI)
    if ((ret = mbedtls_ssl_set_hostname(&this->ssl, ISSUER_HOST)) != 0) {
        fprintf(stderr, " failed! mbedtls_ssl_set_hostname returned %d\n", ret);
        exit(ret);
    }
    return *this;
}

bool MQTTMTDPahoClient::connect() {
    int ret;
    if ((ret = mbedtls_net_connect(&this->server_fd, ISSUER_HOST, ISSUER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        fprintf(stderr, " failed! mbedtls_net_connect returned %d\n", ret);
        return false;
    }
    while ((ret = mbedtls_ssl_handshake(&this->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, " failed! mbedtls_ssl_handshake returned -0x%x\n", (unsigned int) -ret);
            return false;
        }
    }
    uint32_t ret_uint32;
    if ((ret_uint32 = mbedtls_ssl_get_verify_result(&this->ssl)) != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", ret_uint32);
        fprintf(stderr, " failed! Peer certificate verification failed:\n%s\n", vrfy_buf);
        return false;
    }
    return true;
}

bool MQTTMTDPahoClient::print(const char *payload) {
    int ret;
    while ((ret = mbedtls_ssl_write(&this->ssl, reinterpret_cast<const unsigned char *>(payload), strlen(payload))) <=
           0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, " failed! mbedtls_ssl_write returned %d\n", ret);
            return false;
        }
    }
    return true;
}

size_t MQTTMTDPahoClient::readBytes(uint8_t *out, size_t outlen) {
    int offset = 0;
    do {
        memset(out, 0, outlen);
        const int ret = mbedtls_ssl_read(&this->ssl, out, outlen);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            std::cout << " connection closed by peer" << std::endl;
            return ret;
        }

        if (ret < 0) {
            fprintf(stderr, " failed! mbedtls_ssl_read returned %d", ret);
            return ret;
        }

        if (ret == 0) {
            std::cout << "EOF" << std::endl;
            return offset;
        }
        offset += ret;
    } while (true);
}


void MQTTMTDPahoClient::requestTokens(const bool is_pub,
                                      const uint8_t num_tokens_div_4, const SupportedAlgorithm algo,
                                      const char *topic) {
    if (this->token_sets[topic] != nullptr) {
        delete this->token_sets[topic];
        this->token_sets[topic] = nullptr;
    }

    // Connect to issuer
    std::cout << "Connect to issuer" << std::endl;
    if (!this->connect()) {
        std::cout << "Cannot connect to Issuer" << std::endl;
        return;
    }

    // Send request
    std::cout << "Send request" << std::endl;
    char request[5];
    request[0] = 0x20; // header
    request[1] = num_tokens_div_4;
    if (is_pub) {
        request[1] |= 0x80;
    }
    request[2] = algo;
    const size_t topic_len = strlen(topic);
    request[3] = (topic_len >> 8) & 0xFF;
    request[4] = topic_len & 0xFF;
    if (!this->print(request) || !this->print(topic)) {
        std::cout << "Cannot write to Issuer" << std::endl;
        return;
    }

    // Read response
    const auto response = static_cast<uint8_t *>(malloc(2 * sizeof(char)));
    const size_t actual_read = this->readBytes(response, 2);
    if (actual_read < 2 || response[0] != 0x21 || response[1] != 0x1) {
        std::cout << "Failed to read response" << std::endl;
        free(response);
        return;
    }
    free(response);

    const size_t key_len = getKeyLenFromAlgo(algo);
    const auto session_key = new uint8_t[key_len];
    if (this->readBytes(response, key_len) != key_len) {
        std::cout << "Failed to read a secret_key in a response" << std::endl;
        delete[] session_key;
        return;
    }
    const size_t nonce_padding_len = getNonceLenFromAlgo(algo);
    const auto nonce_padding = new uint8_t[nonce_padding_len];
    if (this->readBytes(nonce_padding, nonce_padding_len) != nonce_padding_len) {
        std::cout << "Failed to read a nonce_padding in a response" << std::endl;
        delete[] session_key;
        delete[] nonce_padding;
        return;
    }

    const auto timestamp = new uint8_t [TIMESTAMP_LEN];
    if (this->readBytes(timestamp, TIMESTAMP_LEN) != TIMESTAMP_LEN) {
        std::cout << "Failed to read a nonce_base in a response" << std::endl;
        delete[] session_key;
        delete[] nonce_padding;
        delete[] timestamp;
        return;
    }

    newTokenSet(
        is_pub,
        num_tokens_div_4,
        algo,
        topic, session_key, nonce_padding, timestamp,
        &this->token_sets[topic]
    );
    delete[] session_key;
    delete[] nonce_padding;
    delete[] timestamp;
}


bool MQTTMTDPahoClient::mtd_publish(const char *topic, const char *payload) {
    return mtd_publish(topic, reinterpret_cast<const uint8_t *>(payload), strlen(payload));
}

bool MQTTMTDPahoClient::mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength) {
    std::cout << "Check token sets" << std::endl;
    if (this->token_sets[topic] == nullptr) {
        this->requestTokens(true, NUM_TOKENS_DIV_4_PUBLISH, AEAD_ALGORITHM, topic);
    }
    const auto token_set = this->token_sets[topic];

    // Get the token
    std::cout << "Get the token" << std::endl;
    char token[TOKEN_B64LEN];
    token_set->getCurrentB64Token(token);

    // Seal the payload
    std::cout << "Seal the payload" << std::endl;
    auto *encrypted = static_cast<uint8_t *>(malloc(plength + token_set->getNonceLen()));
    memcpy(encrypted, payload, plength);
    token_set->sealCli2Serv(encrypted, plength + token_set->getTagLen());

    std::cout << "Sending out a publish" << std::endl;
    const auto result = MQTTClient_publish5(this->client, token, static_cast<int>(plength), encrypted, 0, 0, nullptr,
                                            nullptr);
    std::cout << "Sent" << std::endl;

    // Delete token_set if publish failed or fully used
    if (!result.reasonCode == MQTTREASONCODE_SUCCESS || !token_set->incrementTokenIdx()) {
        std::cout << "Deleting a token_set" << std::endl;
        this->token_sets.erase(topic);
    }
    free(encrypted);
    return result.reasonCode == MQTTREASONCODE_SUCCESS;
}
