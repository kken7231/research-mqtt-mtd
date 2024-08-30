#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Encryption function using AES-GCM
int encrypt_aes_gcm(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key,
                    const unsigned char *iv, size_t iv_len, unsigned char *ciphertext, unsigned char *tag) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, iv_len,
                                    NULL, 0, plaintext, ciphertext, 16, tag);

    mbedtls_gcm_free(&gcm);
    return ret;
}

// Decryption function using AES-GCM
int decrypt_aes_gcm(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key,
                    const unsigned char *iv, size_t iv_len, const unsigned char *tag, unsigned char *plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }
    
    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, iv_len, NULL, 0, tag, 16, ciphertext, plaintext);

    mbedtls_gcm_free(&gcm);
    return ret;
}

int main() {
    // Provided key and IV
    unsigned char key[16] = {
        0x39, 0x74, 0xBC, 0x08, 0x99, 0x3A, 0x24, 0xBF,
        0xED, 0x9F, 0x24, 0xD1, 0x89, 0x93, 0x60, 0x95
    };
    unsigned char iv[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe2, 0x40, 
        0x00, 0x00, 0x00, 0x00
    };
    // Example plaintext
    unsigned char plaintext[] = "hello, world";
    size_t plaintext_len = strlen((char *)plaintext);

    print_hex("Key (hex): ", key, 16);
    print_hex("IV (hex): ", iv, 12);
    print_hex("Plaintext (hex): ", plaintext, plaintext_len);

    // Buffers for ciphertext and tag
    unsigned char ciphertext[128];
    unsigned char tag[16];
    unsigned char decrypted_text[128];

    // Encrypt the plaintext
    if (encrypt_aes_gcm(plaintext, plaintext_len, key, iv, sizeof(iv), ciphertext, tag) != 0) {
        printf("Encryption failed\n");
        return 1;
    }

    print_hex("Ciphertext (hex): ", ciphertext, plaintext_len);
    print_hex("Tag (hex): ", tag, 16);

    // Decrypt the ciphertext
    if (decrypt_aes_gcm(ciphertext, plaintext_len, key, iv, sizeof(iv), tag, decrypted_text) != 0) {
        printf("Decryption failed: MAC check failed\n");
        return 1;
    }

    // Null-terminate the decrypted text
    decrypted_text[plaintext_len] = '\0';
    printf("Decrypted Text: %s\n", decrypted_text);

    return 0;
}