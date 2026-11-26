#include "crypto.h"

#include <sodium.h>
#include <ctype.h>
#include <string.h>

int crypto_derive_key(const char *password, const unsigned char *salt,
                      uint64_t opslimit, size_t memlimit,
                      unsigned char *key)
{
    if (password == NULL || password[0] == '\0' || salt == NULL || key == NULL) {
        return 0;
    }

    return crypto_pwhash(key, PWMAN_KEY_SIZE, password,
                         (unsigned long long)strlen(password), salt,
                         (unsigned long long)opslimit, memlimit,
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}

int crypto_encrypt(const unsigned char *plain, size_t plain_length,
                   const unsigned char *associated_data, size_t ad_length,
                   const unsigned char *nonce, const unsigned char *key,
                   unsigned char *cipher, size_t *cipher_length)
{
    unsigned long long result_length = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher, &result_length, plain, (unsigned long long)plain_length,
            associated_data, (unsigned long long)ad_length, NULL, nonce, key) != 0) {
        return 0;
    }

    *cipher_length = (size_t)result_length;
    return 1;
}

int crypto_decrypt(const unsigned char *cipher, size_t cipher_length,
                   const unsigned char *associated_data, size_t ad_length,
                   const unsigned char *nonce, const unsigned char *key,
                   unsigned char *plain, size_t *plain_length)
{
    unsigned long long result_length = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, &result_length, NULL, cipher,
            (unsigned long long)cipher_length, associated_data,
            (unsigned long long)ad_length, nonce, key) != 0) {
        return 0;
    }

    *plain_length = (size_t)result_length;
    return 1;
}

void crypto_random(unsigned char *buffer, size_t length)
{
    randombytes_buf(buffer, length);
}

void crypto_wipe(void *buffer, size_t length)
{
    sodium_memzero(buffer, length);
}

void *crypto_secure_alloc(size_t length)
{
    void *buffer;

    if (length == 0) {
        return NULL;
    }
    buffer = sodium_malloc(length);
    if (buffer == NULL) {
        return NULL;
    }
    if (sodium_mlock(buffer, length) != 0) {
        sodium_free(buffer);
        return NULL;
    }
    return buffer;
}

void crypto_secure_free(void *buffer)
{
    if (buffer != NULL) {
        sodium_free(buffer);
    }
}

int crypto_text_is_valid(const char *text, size_t text_size,
                         size_t max_length, int allow_empty)
{
    size_t length;
    size_t i;

    if (text == NULL || text_size == 0 ||
        max_length > text_size - 1) {
        return 0;
    }

    length = 0;
    while (length < text_size && text[length] != '\0') {
        length++;
    }
    if (length == text_size) {
        return 0;
    }
    if (length == 0) {
        return allow_empty;
    }
    if (length > max_length) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)text[i];
        if (iscntrl(ch)) {
            return 0;
        }
    }
    if (isspace((unsigned char)text[0]) ||
        isspace((unsigned char)text[length - 1])) {
        return 0;
    }
    return 1;
}
