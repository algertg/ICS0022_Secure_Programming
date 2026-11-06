#ifndef PWMAN_CRYPTO_H
#define PWMAN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define PWMAN_KEY_SIZE 32
#define PWMAN_SALT_SIZE 16
#define PWMAN_NONCE_SIZE 24
#define PWMAN_TAG_SIZE 16

/* Derive a key from the master password using Argon2id. */
int crypto_derive_key(const char *password, const unsigned char *salt,
                      uint64_t opslimit, size_t memlimit,
                      unsigned char *key);

/* XChaCha20-Poly1305 authenticated encryption helpers. */
int crypto_encrypt(const unsigned char *plain, size_t plain_length,
                   const unsigned char *associated_data, size_t ad_length,
                   const unsigned char *nonce, const unsigned char *key,
                   unsigned char *cipher, size_t *cipher_length);

int crypto_decrypt(const unsigned char *cipher, size_t cipher_length,
                   const unsigned char *associated_data, size_t ad_length,
                   const unsigned char *nonce, const unsigned char *key,
                   unsigned char *plain, size_t *plain_length);

void crypto_random(unsigned char *buffer, size_t length);
void crypto_wipe(void *buffer, size_t length);

#endif
