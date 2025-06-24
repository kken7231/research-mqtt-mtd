//
// Created by kentarou on 2025/06/22.
//

#include "MQTTMTDClient.h"

MQTTMTDClient &MQTTMTDClient::setCACert(const char *rootCA) {
    this->_secure_client.setCACert(rootCA);
    return *this;
}

MQTTMTDClient &MQTTMTDClient::setCACertBundle(const uint8_t *bundle, size_t size) {
    this->_secure_client.setCACertBundle(bundle, size);
    return *this;
}

void MQTTMTDClient::requestTokens(const bool is_pub,
                                  const uint8_t num_tokens_div_4, const SupportedAlgorithm algo, const char *topic) {
    if (this->token_sets[topic] != nullptr) {
        delete this->token_sets[topic];
        this->token_sets[topic] = nullptr;
    }

    // Connect to issuer
    if (!this->_secure_client.connect(ISSUER_HOST, ISSUER_PORT)) {
        Serial.println("Cannot connect to Issuer");
        return;
    }

    // Send request
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
    this->_secure_client.print(request);
    this->_secure_client.print(topic);

    // Read response
    const auto response = new char[2];
    const size_t actual_read = this->_secure_client.readBytes(response, 2);
    if (actual_read < 2 || response[0] != 0x21 || response[1] != 0x1) {
        Serial.println("Failed to read response");
        this->_secure_client.stop();
        free(response);
        return;
    }
    delete[] response;

    const size_t key_len = getKeyLenFromAlgo(algo);
    const auto session_key = new uint8_t[key_len];
    if (this->_secure_client.readBytes(response, key_len) != key_len) {
        Serial.println("Failed to read a secret_key in a response");
        this->_secure_client.stop();
        delete[] session_key;
        return;
    }
    const size_t nonce_padding_len = getNonceLenFromAlgo(algo);
    const auto nonce_padding = new uint8_t[nonce_padding_len];
    if (this->_secure_client.readBytes(nonce_padding, nonce_padding_len) != nonce_padding_len) {
        Serial.println("Failed to read a nonce_padding in a response");
        this->_secure_client.stop();
        delete[] session_key;
        delete[] nonce_padding;
        return;
    }

    const auto timestamp = new uint8_t [TIMESTAMP_LEN];
    if (this->_secure_client.readBytes(timestamp, TIMESTAMP_LEN) != TIMESTAMP_LEN) {
        Serial.println("Failed to read a nonce_base in a response");
        this->_secure_client.stop();
        delete[] session_key;
        delete[] nonce_padding;
        delete[] timestamp;
        return;
    }
    this->_secure_client.stop();

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


bool MQTTMTDClient::mtd_publish(const char *topic, const char *payload) {
    return mtd_publish(topic, reinterpret_cast<const uint8_t *>(payload), strlen(payload));
}

bool MQTTMTDClient::mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength) {
    if (this->token_sets[topic] == nullptr) {
        this->requestTokens(true, NUM_TOKENS_DIV_4_PUBLISH, AEAD_ALGORITHM, topic);
    }
    const auto token_set = this->token_sets[topic];

    // Get the token
    char token[TOKEN_B64LEN];
    token_set->getCurrentB64Token(token);

    // Seal the payload
    auto *encrypted = static_cast<uint8_t *>(malloc(plength + token_set->getNonceLen()));
    memcpy(encrypted, payload, plength);
    token_set->sealCli2Serv(encrypted, plength + token_set->getTagLen());

    const auto result = publish(token, encrypted, plength, false);

    // Delete token_set if publish failed or fully used
    if (!result || !token_set->incrementTokenIdx()) {
        Serial.println("Deleting a token_set");
        this->token_sets.erase(topic);
    }
    free(encrypted);
    return result;
}
