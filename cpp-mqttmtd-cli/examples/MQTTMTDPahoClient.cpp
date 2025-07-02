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

#define MBEDTLS_USE_PSA_CRYPTO


MQTTMTDPahoClient::MQTTMTDPahoClient() {
    if (psa_status_t status; (status = psa_crypto_init()) != PSA_SUCCESS) {
        std::cerr << "Failed to initialize PSA Crypto implementation: " << status << std::endl;
        exit(EXIT_FAILURE);
    }

    // Initialize MQTTClient
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer5;
    int rc;
    if ((rc = MQTTClient_create(&client, MQTT_INTERFACE_URI, CLIENT_ID,
                                MQTTCLIENT_PERSISTENCE_NONE, nullptr)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to create client, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    conn_opts.keepAliveInterval = 20;
    conn_opts.cleanstart = 1;
    conn_opts.MQTTVersion = MQTTVERSION_5;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != 0) {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    this->client = client;
    ssl = std::unique_ptr<mbedtls_ssl_context, MbedtlsSslFree>(new mbedtls_ssl_context());
    server_fd = std::unique_ptr<mbedtls_net_context, MbedtlsNetFree>(new mbedtls_net_context());
    entropy = std::unique_ptr<mbedtls_entropy_context, MbedtlsEntropyFree>(new mbedtls_entropy_context());
    ctr_drbg = std::unique_ptr<mbedtls_ctr_drbg_context, MbedtlsCtrDrbgFree>(new mbedtls_ctr_drbg_context());
    conf = std::unique_ptr<mbedtls_ssl_config, MbedtlsSslConfigFree>(new mbedtls_ssl_config());
    cacert = std::unique_ptr<mbedtls_x509_crt, MbedtlsX509CrtFree>(new mbedtls_x509_crt());
    clicert = std::unique_ptr<mbedtls_x509_crt, MbedtlsX509CrtFree>(new mbedtls_x509_crt());
    clikey = std::unique_ptr<mbedtls_pk_context, MbedtlsPkFree>(new mbedtls_pk_context());

    // Initialize
    mbedtls_ssl_init(this->ssl.get());
    mbedtls_net_init(this->server_fd.get());
    mbedtls_entropy_init(this->entropy.get());
    mbedtls_ctr_drbg_init(this->ctr_drbg.get());
    mbedtls_ssl_config_init(this->conf.get());
    mbedtls_x509_crt_init(this->cacert.get());
    mbedtls_x509_crt_init(this->clicert.get());
    mbedtls_pk_init(this->clikey.get());

    int ret;
    std::cout << "Seeding the random number generator...";
    if ((ret = mbedtls_ctr_drbg_seed(this->ctr_drbg.get(), mbedtls_entropy_func, this->entropy.get(),
                                     reinterpret_cast<const unsigned char *>("mqttmtd_client"),
                                     strlen("mqttmtd_client"))) != 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_ctr_drbg_seed returned " << std::hex << ret << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << " OK" << std::endl;

    std::cout << "Setting up the SSL/TLS structure ...";
    if ((ret = mbedtls_ssl_config_defaults(this->conf.get(),
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_ssl_config_defaults returned " << std::hex << ret << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << " OK" << std::endl;

    mbedtls_ssl_conf_authmode(this->conf.get(), MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(this->conf.get(), mbedtls_ctr_drbg_random, this->ctr_drbg.get());
}

MQTTMTDPahoClient::~MQTTMTDPahoClient() {
    if (int rc; (rc = MQTTClient_disconnect(this->client, 10000)) != MQTTCLIENT_SUCCESS)
        printf("Failed to disconnect, return code %d\n", rc);
    MQTTClient_destroy(&this->client);
    for (const auto &[fst, snd]: this->token_sets) {
        delete snd;
    }
    token_sets.clear();
}

void MQTTMTDPahoClient::setCACert(const char *root_ca) {
    std::cout << "Loading the CA root certificate ...";
    if (int ret; (ret = mbedtls_x509_crt_parse(this->cacert.get(), reinterpret_cast<const unsigned char *>(root_ca),
                                               strlen(root_ca) + 1)) < 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_x509_crt_parse returned -0x" << std::hex << -ret << std::endl;
        return;
    }
    std::cout << " OK" << std::endl;
    mbedtls_ssl_conf_ca_chain(this->conf.get(), this->cacert.get(), nullptr);
}

void MQTTMTDPahoClient::setClientCertAndKey(const char *cert, const char *key) {
    int ret;
    std::cout << "Loading the Client key ...";
    if ((ret = mbedtls_pk_parse_key(this->clikey.get(), reinterpret_cast<const unsigned char *>(key),
                                    strlen(key) + 1, nullptr, 0, mbedtls_ctr_drbg_random, &ctr_drbg)) < 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_x509_crt_parse returned -0x" << std::hex << -ret << std::endl;
        return;
    }
    std::cout << " OK" << std::endl;

    std::cout << "Loading the Client certificate ...";
    if ((ret = mbedtls_x509_crt_parse(this->clicert.get(), reinterpret_cast<const unsigned char *>(cert),
                                      strlen(cert) + 1)) < 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_x509_crt_parse returned -0x" << std::hex << -ret << std::endl;
        return;
    }
    std::cout << " OK" << std::endl;

    std::cout << "Setting the Client key and certificate ...";
    if ((ret = mbedtls_ssl_conf_own_cert(this->conf.get(), this->clicert.get(), this->clikey.get())) != 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_ssl_config_defaults returned " << std::hex << -ret << std::endl;
    }
    std::cout << " OK" << std::endl;
}

bool MQTTMTDPahoClient::connect() {
    int ret;
    mbedtls_net_free(this->server_fd.get()); // 既存のソケットを閉じる
    mbedtls_net_init(this->server_fd.get()); // 新しいソケットを初期化

    mbedtls_ssl_free(this->ssl.get()); // 既存のSSLコンテキストを解放
    mbedtls_ssl_init(this->ssl.get()); // 新しいSSLコンテキストを初期化

    std::cout << "Connecting to tcp " << ISSUER_HOST << ":" << ISSUER_PORT << " ...";
    if ((ret = mbedtls_net_connect(this->server_fd.get(), ISSUER_HOST,
                                   ISSUER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        std::cout << " FAILED" << std::endl;
        std::cerr << "mbedtls_net_connect returned " << std::hex << ret << std::endl;
        return false;
    }
    std::cout << " OK" << std::endl;

    mbedtls_ssl_set_bio(this->ssl.get(), this->server_fd.get(), mbedtls_net_send, mbedtls_net_recv, nullptr);

    if ((ret = mbedtls_ssl_setup(this->ssl.get(), this->conf.get())) != 0) {
        std::cerr << "mbedtls_ssl_setup returned " << std::hex << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    if ((ret = mbedtls_ssl_set_hostname(this->ssl.get(), ISSUER_HOST)) != 0) {
        std::cerr << "mbedtls_ssl_set_hostname returned " << std::hex << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Performing the SSL/TLS handshake..." << std::flush;
    while ((ret = mbedtls_ssl_handshake(this->ssl.get())) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            std::cout << " FAILED" << std::endl;
            std::cerr << "mbedtls_ssl_config_defaults returned " << std::hex << -ret << std::endl;
            return false;
        }
    }
    std::cout << " OK" << std::endl;

    std::cout << "Verifying peer X.509 certificate...";
    if (uint32_t flags; (flags = mbedtls_ssl_get_verify_result(this->ssl.get())) != 0) {
        std::cout << " FAILED" << std::endl;
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        return false;
    }
    std::cout << " OK" << std::endl;
    return true;
}

size_t MQTTMTDPahoClient::write(const uint8_t *payload, size_t plength) {
    int ret;
    while ((ret = mbedtls_ssl_write(this->ssl.get(), payload, plength)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, " failed! mbedtls_ssl_write returned -0x%x\n", -ret);
            return 0; // write が失敗した場合は0を返す
        }
    }
    return ret;
}

size_t MQTTMTDPahoClient::readBytes(uint8_t *out, size_t outlen) {
    int offset = 0;
    do {
        memset(out, 0, outlen);
        const int ret = mbedtls_ssl_read(this->ssl.get(), out + offset, outlen - offset);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            std::cout << " connection closed by peer" << std::endl;
            return 0;
        }

        if (ret < 0) {
            fprintf(stderr, " failed! mbedtls_ssl_read returned %d\n", ret);
            return 0;
        }

        if (ret == 0) {
            std::cout << "EOF" << std::endl;
            return offset;
        }
        offset += ret;
    } while (offset < outlen);
    return offset;
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
    uint8_t request[5];
    request[0] = 0x20; // header
    request[1] = num_tokens_div_4;
    if (is_pub) {
        request[1] |= 0x80;
    }
    request[2] = algo;
    const size_t topic_len = strlen(topic);
    request[3] = (topic_len >> 8) & 0xFF;
    request[4] = topic_len & 0xFF;
    std::cout << "Sending request: \"" << topic << "\"(" << strlen(topic) << ")" << std::endl;
    if (!this->write(request, 5) || !this->write(reinterpret_cast<const uint8_t *>(topic), topic_len)) {
        std::cout << "Cannot write to Issuer" << std::endl;
        return;
    }

    // Read response
    uint8_t response[2];
    if (const size_t actual_read = this->readBytes(response, 2);
        actual_read < 2 || response[0] != 0x21) {
        std::cout << "Failed to read response " << actual_read << ":" << std::hex << (int) response[0] << std::endl;
        return;
    }
    if (response[1] != 0x1) {
        std::cout << "Verification failed" << std::endl;
        return;
    }

    const size_t key_len = getKeyLenFromAlgo(algo);
    const auto session_key = new uint8_t[key_len];
    if (this->readBytes(session_key, key_len) != key_len) {
        std::cout << "Failed to read a session_key in a response" << std::endl;
        delete[] session_key;
        return;
    }
    const size_t nonce_padding_len = getNonceLenFromAlgo(algo) - 4;
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
    std::cout << "Token retrieved." << std::endl;
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
    char b64token[TOKEN_B64LEN + 1];
    if (psa_status_t status; (status = token_set->getCurrentB64Token(b64token)) != 0) {
        std::cout << "Failed to get current token: " << status << std::endl;
    }
    b64token[TOKEN_B64LEN] = '\0';
    std::cout << "topic: " << token_set->topic << "(" << strlen(token_set->topic) << ")" << std::endl;

    // Seal the payload
    std::cout << "Seal the payload" << std::endl;
    const int encryped_len = plength + token_set->getTagLen();
    const auto encrypted = new uint8_t[encryped_len];
    memcpy(encrypted, payload, plength);
    token_set->sealCli2Serv(encrypted, encryped_len);


    if (MQTTClient_isConnected(this->client) == MQTTCLIENT_DISCONNECTED) {
        std::cout << "MQTT client is not connected" << std::endl;
        delete[] encrypted;
        return false;
    }

    std::cout << "Sending out a publish. token = " << b64token << "(" << std::dec << strlen(b64token) <<
            "), payload len = " << encryped_len << std::endl;
    const MQTTResponse resp = MQTTClient_publish5(this->client, b64token, encryped_len, encrypted, 0, 0, nullptr,
                                                  nullptr);
    if (resp.reasonCode != MQTTREASONCODE_SUCCESS) {
        std::cout << "Failed to publish token: " << std::dec << resp.reasonCode << std::endl;
    } else {
        std::cout << "Publish success" << std::endl;
    }

    // Delete token_set if publish failed or fully used
    if (!resp.reasonCode == MQTTREASONCODE_SUCCESS || !token_set->incrementTokenIdx()) {
        std::cout << "Deleting a token_set" << std::endl;
        this->token_sets.erase(topic);
    }
    delete[] encrypted;
    return resp.reasonCode == MQTTREASONCODE_SUCCESS;
}
