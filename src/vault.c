#define _POSIX_C_SOURCE 200809L
#include "vault.h"
#include "crypto.h"

#include <sodium.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Version 1 header follows the layout in docs/DESIGN.md. */
#define MAGIC_SIZE 8
#define HEADER_SIZE 138
#define WRAPPED_DEK_SIZE (PWMAN_KEY_SIZE + PWMAN_TAG_SIZE)
#define PLAIN_MAX_SIZE 65536
#define FILE_MAX_SIZE (HEADER_SIZE + PLAIN_MAX_SIZE + PWMAN_TAG_SIZE)
#define KDF_ID_ARGON2ID 1
#define KDF_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define KDF_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

#define OFF_VERSION 8
#define OFF_KDF_ID 9
#define OFF_OPSLIMIT 10
#define OFF_MEMLIMIT 18
#define OFF_SALT 26
#define OFF_WRAP_NONCE 42
#define OFF_WRAPPED_DEK 66
#define OFF_BODY_NONCE 114

static const unsigned char vault_magic[MAGIC_SIZE] = {
    'P', 'W', 'M', 'N', 'V', 'L', 'T', '1'
};

static void write_u32(unsigned char *buffer, uint32_t value)
{
    buffer[0] = (unsigned char)(value & 0xff);
    buffer[1] = (unsigned char)((value >> 8) & 0xff);
    buffer[2] = (unsigned char)((value >> 16) & 0xff);
    buffer[3] = (unsigned char)((value >> 24) & 0xff);
}

static uint32_t read_u32(const unsigned char *buffer)
{
    return (uint32_t)buffer[0] |
           ((uint32_t)buffer[1] << 8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static void write_u64(unsigned char *buffer, uint64_t value)
{
    unsigned int i;
    for (i = 0; i < 8; i++) {
        buffer[i] = (unsigned char)((value >> (8 * i)) & 0xff);
    }
}

static uint64_t read_u64(const unsigned char *buffer)
{
    uint64_t value = 0;
    int i;
    for (i = 7; i >= 0; i--) {
        value = (value << 8) | buffer[i];
    }
    return value;
}

static int put_string(unsigned char *output, size_t capacity,
                      size_t *position, const char *value, size_t field_size)
{
    const char *end = memchr(value, '\0', field_size);
    size_t length;

    if (end == NULL || *position > capacity || capacity - *position < 4) {
        return 0;
    }

    length = (size_t)(end - value);
    if (length > capacity - *position - 4) {
        return 0;
    }

    write_u32(output + *position, (uint32_t)length);
    *position += 4;
    memcpy(output + *position, value, length);
    *position += length;
    return 1;
}

static int get_string(const unsigned char *input, size_t input_length,
                      size_t *position, char *output, size_t output_size)
{
    uint32_t length;

    if (*position > input_length || input_length - *position < 4) {
        return 0;
    }

    length = read_u32(input + *position);
    *position += 4;
    if (length >= output_size || *position > input_length ||
        length > input_length - *position) {
        return 0;
    }

    memcpy(output, input + *position, length);
    output[length] = '\0';
    *position += length;
    return 1;
}

static int serialize_vault(const Vault *vault, unsigned char *output,
                           size_t output_size, size_t *output_length)
{
    size_t position = 4;
    unsigned int i;

    if (vault->count > VAULT_MAX_ENTRIES || output_size < 4) {
        return 0;
    }

    write_u32(output, vault->count);
    for (i = 0; i < vault->count; i++) {
        const Credential *entry = &vault->entries[i];
        if (!put_string(output, output_size, &position, entry->service,
                        sizeof(entry->service)) ||
            !put_string(output, output_size, &position, entry->username,
                        sizeof(entry->username)) ||
            !put_string(output, output_size, &position, entry->password,
                        sizeof(entry->password))) {
            return 0;
        }
    }

    *output_length = position;
    return 1;
}

static int deserialize_vault(const unsigned char *input, size_t input_length,
                             Vault *vault)
{
    Vault loaded = {0};
    size_t position = 4;
    uint32_t count;
    unsigned int i;

    if (input_length < 4) {
        return 0;
    }

    count = read_u32(input);
    if (count > VAULT_MAX_ENTRIES) {
        return 0;
    }

    loaded.count = count;
    for (i = 0; i < loaded.count; i++) {
        Credential *entry = &loaded.entries[i];
        if (!get_string(input, input_length, &position, entry->service,
                        sizeof(entry->service)) ||
            !get_string(input, input_length, &position, entry->username,
                        sizeof(entry->username)) ||
            !get_string(input, input_length, &position, entry->password,
                        sizeof(entry->password))) {
            crypto_wipe(&loaded, sizeof(loaded));
            return 0;
        }
    }

    if (position != input_length) {
        crypto_wipe(&loaded, sizeof(loaded));
        return 0;
    }

    *vault = loaded;
    crypto_wipe(&loaded, sizeof(loaded));
    return 1;
}

static int write_all(int fd, const unsigned char *data, size_t length)
{
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(fd, data + written, length - written);
        if (result <= 0) {
            return 0;
        }
        written += (size_t)result;
    }
    return 1;
}

static int write_vault_file(const char *path, const unsigned char *data,
                            size_t length)
{
    char *temporary_path;
    size_t path_length = strlen(path);
    int fd;
    int success = 0;

    temporary_path = malloc(path_length + 5);
    if (temporary_path == NULL) {
        return 0;
    }
    snprintf(temporary_path, path_length + 5, "%s.tmp", path);

    fd = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        if (fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
            write_all(fd, data, length) && fsync(fd) == 0) {
            success = 1;
        }
        if (close(fd) != 0) {
            success = 0;
        }
        if (success && rename(temporary_path, path) != 0) {
            success = 0;
        }
    }

    if (!success) {
        (void)unlink(temporary_path);
    }
    free(temporary_path);
    return success;
}

int vault_save(const char *path, const char *master_password, const Vault *vault)
{
    unsigned char file_data[FILE_MAX_SIZE] = {0};
    unsigned char plaintext[PLAIN_MAX_SIZE] = {0};
    unsigned char kek[PWMAN_KEY_SIZE] = {0};
    unsigned char dek[PWMAN_KEY_SIZE] = {0};
    size_t plaintext_length = 0;
    size_t wrapped_length = 0;
    size_t body_length = 0;
    int success = 0;

    if (path == NULL || master_password == NULL || vault == NULL) {
        return 0;
    }

    if (!serialize_vault(vault, plaintext, sizeof(plaintext), &plaintext_length)) {
        goto cleanup;
    }

    memcpy(file_data, vault_magic, MAGIC_SIZE);
    file_data[OFF_VERSION] = 1;
    file_data[OFF_KDF_ID] = KDF_ID_ARGON2ID;
    write_u64(file_data + OFF_OPSLIMIT, KDF_OPSLIMIT);
    write_u64(file_data + OFF_MEMLIMIT, KDF_MEMLIMIT);

    crypto_random(file_data + OFF_SALT, PWMAN_SALT_SIZE);
    crypto_random(file_data + OFF_WRAP_NONCE, PWMAN_NONCE_SIZE);
    crypto_random(file_data + OFF_BODY_NONCE, PWMAN_NONCE_SIZE);
    crypto_random(dek, sizeof(dek));

    if (!crypto_derive_key(master_password, file_data + OFF_SALT,
                           KDF_OPSLIMIT, KDF_MEMLIMIT, kek)) {
        goto cleanup;
    }

    /* The first 66 header bytes are authenticated while wrapping the DEK. */
    if (!crypto_encrypt(dek, sizeof(dek), file_data, OFF_WRAPPED_DEK,
                        file_data + OFF_WRAP_NONCE, kek,
                        file_data + OFF_WRAPPED_DEK, &wrapped_length) ||
        wrapped_length != WRAPPED_DEK_SIZE) {
        goto cleanup;
    }

    /* The complete header is authenticated together with the encrypted body. */
    if (!crypto_encrypt(plaintext, plaintext_length, file_data, HEADER_SIZE,
                        file_data + OFF_BODY_NONCE, dek,
                        file_data + HEADER_SIZE, &body_length)) {
        goto cleanup;
    }

    success = write_vault_file(path, file_data, HEADER_SIZE + body_length);

cleanup:
    crypto_wipe(file_data, sizeof(file_data));
    crypto_wipe(plaintext, sizeof(plaintext));
    crypto_wipe(kek, sizeof(kek));
    crypto_wipe(dek, sizeof(dek));
    return success;
}

int vault_load(const char *path, const char *master_password, Vault *vault)
{
    unsigned char file_data[FILE_MAX_SIZE] = {0};
    unsigned char plaintext[PLAIN_MAX_SIZE] = {0};
    unsigned char kek[PWMAN_KEY_SIZE] = {0};
    unsigned char dek[PWMAN_KEY_SIZE] = {0};
    FILE *file = NULL;
    long file_length;
    size_t plaintext_length = 0;
    size_t dek_length = 0;
    size_t body_length;
    int success = 0;

    if (vault == NULL) {
        return 0;
    }
    vault_clear(vault);

    if (path == NULL || master_password == NULL) {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        goto cleanup;
    }

    file_length = ftell(file);
    if (file_length < (long)(HEADER_SIZE + PWMAN_TAG_SIZE + 4) ||
        file_length > (long)FILE_MAX_SIZE || fseek(file, 0, SEEK_SET) != 0) {
        goto cleanup;
    }

    if (fread(file_data, 1, (size_t)file_length, file) != (size_t)file_length) {
        goto cleanup;
    }
    fclose(file);
    file = NULL;

    if (memcmp(file_data, vault_magic, MAGIC_SIZE) != 0 ||
        file_data[OFF_VERSION] != 1 ||
        file_data[OFF_KDF_ID] != KDF_ID_ARGON2ID ||
        read_u64(file_data + OFF_OPSLIMIT) != KDF_OPSLIMIT ||
        read_u64(file_data + OFF_MEMLIMIT) != KDF_MEMLIMIT) {
        goto cleanup;
    }

    if (!crypto_derive_key(master_password, file_data + OFF_SALT,
                           KDF_OPSLIMIT, KDF_MEMLIMIT, kek)) {
        goto cleanup;
    }

    if (!crypto_decrypt(file_data + OFF_WRAPPED_DEK, WRAPPED_DEK_SIZE,
                        file_data, OFF_WRAPPED_DEK,
                        file_data + OFF_WRAP_NONCE, kek,
                        dek, &dek_length) || dek_length != PWMAN_KEY_SIZE) {
        goto cleanup;
    }

    body_length = (size_t)file_length - HEADER_SIZE;
    if (!crypto_decrypt(file_data + HEADER_SIZE, body_length,
                        file_data, HEADER_SIZE,
                        file_data + OFF_BODY_NONCE, dek,
                        plaintext, &plaintext_length)) {
        goto cleanup;
    }

    success = deserialize_vault(plaintext, plaintext_length, vault);

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    crypto_wipe(file_data, sizeof(file_data));
    crypto_wipe(plaintext, sizeof(plaintext));
    crypto_wipe(kek, sizeof(kek));
    crypto_wipe(dek, sizeof(dek));
    if (!success) {
        vault_clear(vault);
    }
    return success;
}

void vault_clear(Vault *vault)
{
    if (vault != NULL) {
        crypto_wipe(vault, sizeof(*vault));
    }
}
