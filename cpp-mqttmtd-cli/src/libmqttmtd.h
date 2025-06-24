//
// Created by kentarito on 2025/06/24.
//

#ifndef libmqttmtd_h
#define libmqttmtd_h

#include "mbedtls/psa_util.h"
#include <cstdint>

#define TIMESTAMP_LEN  6
#define TIMESTAMP_B64LEN (TIMESTAMP_LEN / 3 * 4)
#define RANDOM_LEN 6
#define TOKEN_LEN (TIMESTAMP_LEN + RANDOM_LEN)
#define TOKEN_B64LEN (TOKEN_LEN / 3 * 4)

enum SupportedAlgorithm {
    Aes128Gcm = 1,
    Aes256Gcm = 2,
    Chacha20Poly1305 = 3,
};

size_t getKeyLenFromAlgo(SupportedAlgorithm algo);

size_t getTagLenFromAlgo(SupportedAlgorithm algo);

size_t getNonceLenFromAlgo(SupportedAlgorithm algo);

struct TokenSet {
    const char *topic;
    uint8_t timestamp[TIMESTAMP_LEN];
    uint16_t num_tokens;
    uint16_t token_idx;
    bool is_pub;

    SupportedAlgorithm algo;
    psa_key_id_t aead_key_id;
    psa_key_id_t hmac_key_id;
    unsigned char *hmac_buf;
    uint8_t *nonce;

    TokenSet(
        const char *topic,
        const uint8_t *timestamp,
        uint16_t num_tokens,
        bool
        is_pub,
        SupportedAlgorithm algo, psa_key_id_t aead_key_id, psa_key_id_t hmac_key_id,

        const uint8_t *nonce_padding
    );

    ~
    TokenSet(


    );

    psa_status_t getCurrentB64Token(char *out) const;

    psa_status_t sealCli2Serv(uint8_t *in_out, size_t in_out_len) const;

    bool incrementTokenIdx();

    size_t getKeyLen() const;

    size_t getTagLen() const;

    size_t getNonceLen() const;
};

psa_status_t newTokenSet(
    bool is_pub,
    uint8_t num_tokens_div_4,
    SupportedAlgorithm algo,
    const char *topic,
    const uint8_t *session_key,
    const uint8_t *nonce_padding,
    const uint8_t *timestamp,
    TokenSet **out
);

#endif //libmqttmtd_h
