//
// Created by kentarito on 2025/06/24.
//

#include "libmqttmtd.h"
#include <cstring>
#include "mbedtls/psa_util.h"
#include "mbedtls/base64.h"

size_t getKeyLenFromAlgo(const enum SupportedAlgorithm algo) {
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

size_t getTagLenFromAlgo(const enum SupportedAlgorithm algo) {
    return 16;
}

size_t getNonceLenFromAlgo(const enum SupportedAlgorithm algo) {
    return 12;
}

psa_status_t newTokenSet(
    const bool is_pub,
    const uint8_t num_tokens_div_4,
    const SupportedAlgorithm algo,
    const char *topic,
    const uint8_t *session_key,
    const uint8_t *nonce_padding,
    const uint8_t *timestamp,
    TokenSet **out
) {
    const size_t key_len = getKeyLenFromAlgo(algo);
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
    if (psa_status != PSA_SUCCESS) return psa_status;

    // HMAC key
    psa_key_id_t hmac_key_id;
    attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_status = psa_import_key(&attributes, session_key, key_len, &hmac_key_id);
    psa_reset_key_attributes(&attributes);
    if (psa_status != PSA_SUCCESS) {
        psa_destroy_key(session_key_id);
        return psa_status;
    }

    delete *out;
    *out = new TokenSet(topic, timestamp, num_tokens_div_4 * 4, is_pub, algo, session_key_id, hmac_key_id,
                        nonce_padding);
    return PSA_SUCCESS;
}

TokenSet::TokenSet(const char *topic, const uint8_t *timestamp, const uint16_t num_tokens, const bool is_pub,
                   const SupportedAlgorithm algo, const psa_key_id_t aead_key_id, const psa_key_id_t hmac_key_id,
                   const uint8_t *nonce_padding) {
    this->topic = topic;

    memcpy(this->timestamp, timestamp, TIMESTAMP_LEN);
    this->num_tokens = num_tokens;
    this->token_idx = 0;
    this->is_pub = is_pub;

    this->algo = algo;
    this->aead_key_id = aead_key_id;
    this->hmac_key_id = hmac_key_id;
    this->hmac_buf = new unsigned char [256 / 8];
    this->nonce = new unsigned char [this->getNonceLen()];
    memcpy(this->nonce, nonce_padding, this->getNonceLen() - 4);
}

TokenSet::~TokenSet() {
    psa_destroy_key(this->aead_key_id);
    psa_destroy_key(this->hmac_key_id);
    delete[] this->hmac_buf;
    delete[] this->nonce;
}

psa_status_t TokenSet::getCurrentB64Token(char *out) const {
    // timestamp
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(out), strlen(out), nullptr, this->timestamp,
                              TIMESTAMP_LEN) != 0)
        return PSA_ERROR_GENERIC_ERROR;

    // random
    // HMAC calculation
    size_t mac_len;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

    psa_status_t psa_status = psa_mac_sign_setup(&operation, this->hmac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (psa_status != PSA_SUCCESS) return psa_status;

    psa_status = psa_mac_update(&operation, reinterpret_cast<const uint8_t *>(this->topic), strlen(this->topic));
    if (psa_status != PSA_SUCCESS) return psa_status;

    psa_status = psa_mac_update(&operation, reinterpret_cast<const uint8_t *>(&token_idx), 2);
    if (psa_status != PSA_SUCCESS) return psa_status;

    psa_status = psa_mac_sign_finish(&operation, this->hmac_buf, 256 / 8, &mac_len);
    if (psa_status != PSA_SUCCESS) return psa_status;

    if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(out + TIMESTAMP_B64LEN), RANDOM_LEN, nullptr,
                              this->hmac_buf,
                              RANDOM_LEN) != 0)
        return PSA_ERROR_GENERIC_ERROR;
    return PSA_SUCCESS;
}

bool TokenSet::incrementTokenIdx() {
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
    size_t nonce_offset = this->getNonceLen() - 4;
    this->nonce[nonce_offset++] = 0;
    this->nonce[nonce_offset++] = 0;
    this->nonce[nonce_offset++] = static_cast<uint8_t>(this->token_idx >> 8 & 0xFF);
    this->nonce[nonce_offset] = static_cast<uint8_t>(this->token_idx & 0xFF);
    return psa_aead_encrypt(
        this->aead_key_id, algo, this->nonce, this->getNonceLen(), nullptr, 0,
        in_out, in_out_len - this->getTagLen(), in_out,
        in_out_len, nullptr
    );
}


size_t TokenSet::getKeyLen() const {
    return getKeyLenFromAlgo(this->algo);
}

size_t TokenSet::getTagLen() const {
    return getTagLenFromAlgo(this->algo);
}

size_t TokenSet::getNonceLen() const {
    return getNonceLenFromAlgo(this->algo);
}
