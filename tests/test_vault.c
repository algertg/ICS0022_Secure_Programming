#include "vault.h"

#include <sodium.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define TEST_FILE "test-vault.db"
#define TEST_PASSWORD "test-password-not-for-display"

static int check(int condition, const char *description)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", description);
        return 0;
    }
    printf("PASS: %s\n", description);
    return 1;
}

static int vault_file_is_private(const char *path)
{
    struct stat file_info;
    return stat(path, &file_info) == 0 &&
           (file_info.st_mode & 0777) == 0600;
}

static int file_contains_password(const char *path)
{
    unsigned char buffer[70000];
    const size_t secret_length = strlen(TEST_PASSWORD);
    size_t length;
    size_t i;
    FILE *file = fopen(path, "rb");
    int found = 0;

    if (file == NULL) {
        return 1;
    }
    length = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    for (i = 0; i + secret_length <= length; i++) {
        if (memcmp(buffer + i, TEST_PASSWORD, secret_length) == 0) {
            found = 1;
            break;
        }
    }
    sodium_memzero(buffer, sizeof(buffer));
    return found;
}

int main(void)
{
    Vault original = {0};
    Vault loaded = {0};
    int passed = 1;

    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium.\n");
        return 1;
    }

    original.count = 1;
    strcpy(original.entries[0].service, "example.com");
    strcpy(original.entries[0].username, "student");
    strcpy(original.entries[0].password, TEST_PASSWORD);

    passed &= check(vault_save(TEST_FILE, "correct-master-password", &original),
                    "vault can be saved");
    passed &= check(!file_contains_password(TEST_FILE),
                    "credential password is not stored as cleartext");
    passed &= check(vault_file_is_private(TEST_FILE),
                    "vault file permissions are owner-only (0600)");
    passed &= check(vault_load(TEST_FILE, "correct-master-password", &loaded),
                    "correct master password unlocks the vault");
    passed &= check(loaded.count == 1 &&
                    strcmp(loaded.entries[0].service, "example.com") == 0 &&
                    strcmp(loaded.entries[0].username, "student") == 0 &&
                    strcmp(loaded.entries[0].password, TEST_PASSWORD) == 0,
                    "credential data is recovered correctly");

    vault_clear(&loaded);
    passed &= check(!vault_load(TEST_FILE, "wrong-master-password", &loaded),
                    "incorrect master password is rejected");

    {
        FILE *file = fopen(TEST_FILE, "r+b");
        int last_byte;
        int changed = 0;

        if (file != NULL && fseek(file, -1L, SEEK_END) == 0) {
            last_byte = fgetc(file);
            if (last_byte != EOF && fseek(file, -1L, SEEK_END) == 0 &&
                fputc(last_byte ^ 1, file) != EOF) {
                changed = 1;
            }
            fclose(file);
        }
        passed &= check(changed &&
                        !vault_load(TEST_FILE, "correct-master-password", &loaded),
                        "modified ciphertext is rejected");
    }

    remove(TEST_FILE);
    vault_clear(&original);
    vault_clear(&loaded);

    if (!passed) {
        return 1;
    }
    printf("All vault tests passed.\n");
    return 0;
}
