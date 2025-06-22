//
// Created by kentarou on 2025/06/22.
//

#include "MQTTMTDClient.h"
#include "mbedtls/md.h"
#include "mbedtls/psa_util.h"

extern "C" {
#include "libb64/cencode.h"
}

TokenSet::TokenSet(const char *topic, uint8_t *timestamp, const uint16_t num_tokens, const bool is_pub,
                   const SupportedAlgorithm algo, psa_key_id_t aead_key_id, psa_key_id_t hmac_key_id,
                   const uint8_t *nonce_padding) {
    this->topic = topic;

    this->timestamp = timestamp;
    this->num_tokens = num_tokens;
    this->token_idx = 0;
    this->is_pub = is_pub;

    this->algo = algo;
    this->aead_key_id = aead_key_id;
    this->hmac_key_id = hmac_key_id;
    this->hmac_buf = new unsigned char[256 / 8];
    this->nonce = new unsigned char[getNonceLen()];
    memcpy(this->nonce, nonce_padding, getNonceLen() - 4);
}

TokenSet::~TokenSet() {
    free(this->timestamp);
    psa_destroy_key(this->aead_key_id);
    psa_destroy_key(this->hmac_key_id);
    delete[] this->hmac_buf;
    delete[] this->nonce;
}

void TokenSet::getCurrentB64Token(char *out) const {
    // timestamp
    base64_encode_chars(reinterpret_cast<const char *>(this->timestamp), TIMESTAMP_LEN, out);

    // random
    // HMAC calculation
    size_t mac_len;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

    psa_status_t psa_status = psa_mac_sign_setup(&operation, this->hmac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (psa_status != PSA_SUCCESS) {
        goto on_error;
    }

    psa_status = psa_mac_update(&operation, reinterpret_cast<const uint8_t *>(this->topic), strlen(this->topic));
    if (psa_status != PSA_SUCCESS) {
        goto on_error;
    }

    psa_status = psa_mac_update(&operation, reinterpret_cast<const uint8_t *>(&token_idx), 2);
    if (psa_status != PSA_SUCCESS) {
        goto on_error;
    }

    psa_status = psa_mac_sign_finish(&operation, this->hmac_buf, 256 / 8, &mac_len);
    if (psa_status != PSA_SUCCESS) {
        goto on_error;
    }

    base64_encode_chars(reinterpret_cast<const char *>(this->hmac_buf), RANDOM_LEN, out + TIMESTAMP_B64LEN);
    return;

on_error:
    Serial.print("Error getting MAC:");
    Serial.println(psa_status);
}

void TokenSet::printCurrentToken() const {
    char token[TOKEN_B64LEN];
    this->getCurrentB64Token(token);
    Serial.print("Current token: ");
    Serial.println(token);
}

boolean TokenSet::incrementTokenIdx() {
    this->token_idx++;
    return this->token_idx < this->num_tokens;
}

psa_status_t TokenSet::sealCli2Serv(uint8_t *in_out, const size_t in_out_len) const {
    psa_algorithm_t algo = 0;
    switch (this->algo) {
        case Aes128Gcm:
        case Aes256Gcm:
            algo = PSA_ALG_GCM;
            break;
        case Chacha20Poly1305:
            algo = PSA_ALG_GCM;
    }
    size_t nonce_offset = getNonceLen() - 4;
    this->nonce[nonce_offset++] = 0;
    this->nonce[nonce_offset++] = 0;
    this->nonce[nonce_offset++] = static_cast<uint8_t>(this->token_idx >> 8 & 0xFF);
    this->nonce[nonce_offset] = static_cast<uint8_t>(this->token_idx & 0xFF);
    return psa_aead_encrypt(
        this->aead_key_id, algo, this->nonce, getNonceLen(), nullptr, 0,
        in_out, in_out_len - getTagLen(), in_out,
        in_out_len, nullptr
    );
}

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
    const auto request = static_cast<char *>(malloc((1 + 1 + 1 + 2) * sizeof(char)));
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
    free(request);

    // Read response
    const auto response = static_cast<char *>(malloc(2 * sizeof(char)));
    const size_t actual_read = this->_secure_client.readBytes(response, 2);
    this->_secure_client.stop();
    if (actual_read < 2 || response[0] != 0x21 || response[1] != 0x1) {
        Serial.println("Failed to read response");
        free(response);
        return;
    }
    free(response);

    const size_t key_len = getKeyLen(algo);
    const auto session_key = static_cast<uint8_t *>(malloc(key_len * sizeof(char)));
    if (this->_secure_client.readBytes(response, key_len) != key_len) {
        Serial.println("Failed to read a secret_key in a response");
        free(session_key);
        return;
    }
    const size_t nonce_padding_len = getNonceLen();
    const auto nonce_padding_bytes = static_cast<uint8_t *>(malloc(nonce_padding_len * sizeof(char)));
    if (this->_secure_client.readBytes(nonce_padding_bytes, nonce_padding_len) != nonce_padding_len) {
        Serial.println("Failed to read a nonce_padding in a response");
        free(session_key);
        free(nonce_padding_bytes);
        return;
    }

    const auto timestamp = static_cast<uint8_t *>(malloc(TIMESTAMP_LEN * sizeof(char)));
    if (this->_secure_client.readBytes(timestamp, TIMESTAMP_LEN) != TIMESTAMP_LEN) {
        Serial.println("Failed to read a nonce_base in a response");
        free(session_key);
        free(nonce_padding_bytes);
        free(timestamp);
        return;
    }

    // Aead key
    psa_key_id_t session_key_id;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_algorithm_t algorithm = 0;
    switch (algo) {
        case Aes128Gcm:
            algorithm = PSA_ALG_GCM;
            psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
            psa_set_key_bits(&attributes, 128);
            break;
        case Aes256Gcm:
            algorithm = PSA_ALG_GCM;
            psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
            psa_set_key_bits(&attributes, 256);
            break;
        case Chacha20Poly1305:
            algorithm = PSA_ALG_CHACHA20_POLY1305;
            psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
            psa_set_key_bits(&attributes, 256);
            break;
    }
    psa_set_key_algorithm(&attributes, algorithm);
    psa_status_t psa_status = psa_import_key(&attributes, session_key, key_len, &session_key_id);
    psa_reset_key_attributes(&attributes);
    if (psa_status != PSA_SUCCESS) {
        Serial.println("Failed to initialize a session key for encryption");
        free(session_key);
        free(nonce_padding_bytes);
        free(timestamp);
        return;
    }

    // HMAC key
    psa_key_id_t hmac_key_id;
    attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, getKeyLen(algo) * 8);
    psa_status = psa_import_key(&attributes, session_key, key_len, &hmac_key_id);
    psa_reset_key_attributes(&attributes);
    free(session_key);
    if (psa_status != PSA_SUCCESS) {
        Serial.println("Failed to initialize a session key for hash");
        psa_destroy_key(session_key_id);
        free(nonce_padding_bytes);
        free(timestamp);
        return;
    }

    auto *token_set = new TokenSet(topic, timestamp, num_tokens_div_4 * 4, is_pub, algo, session_key_id, hmac_key_id,
                                   nonce_padding_bytes);
    this->token_sets[topic] = token_set;
    free(nonce_padding_bytes);
}


boolean MQTTMTDClient::mtd_publish(const char *topic, const char *payload) {
    return mtd_publish(topic, reinterpret_cast<const uint8_t *>(payload), strlen(payload));
}


boolean MQTTMTDClient::mtd_publish(const char *topic, const uint8_t *payload, unsigned int plength) {
    if (this->token_sets[topic] == nullptr) {
        this->requestTokens(true, NUM_TOKENS_DIV_4_PUBLISH, AEAD_ALGORITHM, topic);
    }

    // Get the token
    char token[TOKEN_B64LEN];
    this->token_sets[topic]->getCurrentB64Token(token);

    // Seal the payload
    auto *encrypted = static_cast<uint8_t *>(malloc(plength + getTagLen()));
    memcpy(encrypted, payload, plength);
    this->token_sets[topic]->sealCli2Serv(encrypted, plength + getTagLen());

    const auto result = publish(token, encrypted, plength, false);

    // Delete token_set if publish failed or fully used
    if (!result || !this->token_sets[topic]->incrementTokenIdx()) {
        Serial.println("Deleting a token_set");
        this->token_sets.erase(topic);
    }
    free(encrypted);
    return result;
}
