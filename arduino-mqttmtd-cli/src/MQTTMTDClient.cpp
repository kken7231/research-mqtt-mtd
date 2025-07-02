//
// Created by kentarou on 2025/06/22.
//

#include "MQTTMTDClient.h"

#define MBEDTLS_USE_PSA_CRYPTO

bool MQTTMTDClient::init() {
    psa_status_t status;
    if ((status = psa_crypto_init()) != PSA_SUCCESS) {
        Serial.printf("Failed to initialize PSA Crypto implementation: %d\n", status);
        return false;
    }
    return true;
}

void MQTTMTDClient::deinit() {
    for (const auto &[fst, snd]: this->token_sets) {
        delete snd;
    }
    token_sets.clear();
}

void MQTTMTDClient::setCACertForIssuer(const char *root_ca) {
    this->_secure_client.setCACert(root_ca);
}

void MQTTMTDClient::setCertificateForIssuer(const char *cert) {
    this->_secure_client.setCertificate(cert);
}

void MQTTMTDClient::setPrivateKeyForIssuer(const char *key) {
    this->_secure_client.setPrivateKey(key);
}

void MQTTMTDClient::setIssuerServer(const char *host, uint16_t port) {
    this->issuer_host = host;
    this->issuer_port = port;
}

bool MQTTMTDClient::requestTokens(const bool is_pub,
                                  const uint8_t num_tokens_div_4, const SupportedAlgorithm algo, const char *topic) {
    if (this->token_sets[topic] != nullptr) {
        delete this->token_sets[topic];
        this->token_sets[topic] = nullptr;
    }

    // Connect to issuer
    if (!this->_secure_client.connect(this->issuer_host, this->issuer_port)) {
        Serial.println("Cannot connect to Issuer");
        return false;
    }
    Serial.println("Connected to Issuer");

    // Send request
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
    if (!this->_secure_client.write(request, 5) || !this->_secure_client.write(
            reinterpret_cast<const uint8_t *>(topic), topic_len)) {
        println("Cannot write to Issuer");
        this->_secure_client.stop();
        return false;
    }
    this->_secure_client.flush();
    Serial.println("Request sent to Issuer");

    // Read response
    // Wait for up to a second for data to become available
    int timeout = 10000;
    while (this->_secure_client.available() < 2 && timeout > 0) {
        delay(1);
        timeout--;
    }
    uint8_t response[2];
    const int actual_read = this->_secure_client.read(response, 2);
    if (actual_read != 2 || response[0] != 0x21 || response[1] != 0x1) {
        Serial.println("Failed to read response");
        Serial.printf("actual_read:%d, [0]%x, [1]%x\n", actual_read, response[0], response[1]);
        this->_secure_client.stop();
        return false;
    }


    const size_t key_len = getKeyLenFromAlgo(algo);
    // Wait for up to a second for data to become available
    timeout = 10000;
    while (this->_secure_client.available() < key_len && timeout > 0) {
        delay(1);
        timeout--;
    }
    const auto session_key = new uint8_t[key_len];
    if (this->_secure_client.readBytes(session_key, key_len) != key_len) {
        Serial.println("Failed to read a secret_key in a response");
        delete[] session_key;
        this->_secure_client.stop();
        return false;
    }


    const size_t nonce_padding_len = getNonceLenFromAlgo(algo) - 4;
    timeout = 10000;
    while (this->_secure_client.available() < nonce_padding_len && timeout > 0) {
        delay(1);
        timeout--;
    }
    const auto nonce_padding = new uint8_t[nonce_padding_len];
    if (this->_secure_client.readBytes(nonce_padding, nonce_padding_len) != nonce_padding_len) {
        Serial.println("Failed to read a nonce_padding in a response");
        delete[] session_key;
        delete[] nonce_padding;
        this->_secure_client.stop();
        return false;
    }

    // Wait for up to a second for data to become available
    timeout = 10000;
    while (this->_secure_client.available() < TIMESTAMP_LEN && timeout > 0) {
        delay(1);
        timeout--;
    }
    const auto timestamp = new uint8_t [TIMESTAMP_LEN];
    if (this->_secure_client.readBytes(timestamp, TIMESTAMP_LEN) != TIMESTAMP_LEN) {
        Serial.println("Failed to read a timestamp in a response");
        delete[] session_key;
        delete[] nonce_padding;
        delete[] timestamp;
        this->_secure_client.stop();
        return false;
    }
    this->_secure_client.stop();
    Serial.println("Response read from Issuer");

    psa_status_t status = newTokenSet(
        is_pub,
        num_tokens_div_4,
        algo,
        topic, session_key, nonce_padding, timestamp,
        &this->token_sets[topic]
    );
    delete[] session_key;
    delete[] nonce_padding;
    delete[] timestamp;
    return status == PSA_SUCCESS;
}


bool MQTTMTDClient::mtd_publish(const char *topic, const char *payload) {
    return mtd_publish(topic, reinterpret_cast<const uint8_t *>(payload), strlen(payload));
}

bool MQTTMTDClient::mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength) {
    Serial.println("Check token sets");
    if (this->token_sets[topic] == nullptr) {
        if (!this->requestTokens(true, NUM_TOKENS_DIV_4_PUBLISH, AEAD_ALGORITHM, topic)) {
            Serial.println("Failed to request tokens");
            return false;
        }
    }
    Serial.println("Fetched tokens");

    const auto token_set = this->token_sets[topic];

    // Get the token
    Serial.println("Get the token");
    char b64token[TOKEN_B64LEN + 1];

    if (token_set->getCurrentB64Token(b64token) != 0) {
        Serial.println("Failed to get current token");
        return false;
    }
    b64token[TOKEN_B64LEN] = '\0';
    Serial.printf("topic %s\n", token_set->topic);

    // Seal the payload
    const int encryped_len = plength + token_set->getTagLen();
    const auto encrypted = new uint8_t[encryped_len];
    memcpy(encrypted, payload, plength);
    token_set->sealCli2Serv(encrypted, encryped_len);

    const auto result = publish(b64token, encrypted, plength, false);

    // Delete token_set if publish failed or fully used
    if (!result || !token_set->incrementTokenIdx()) {
        Serial.println("Deleting a token_set");
        this->token_sets.erase(topic);
    }
    delete[] encrypted;
    return result;
}
