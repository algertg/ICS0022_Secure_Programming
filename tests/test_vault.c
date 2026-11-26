#define _POSIX_C_SOURCE 200809L
#include "vault.h"
#include "crypto.h"
#include "log.h"
#include "user_store.h"

#include <sodium.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_FILE "test-vault.db"
#define TEST_ALICE_FILE "users/test_alice.vault"
#define TEST_BOB_FILE "users/test_bob.vault"
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

static int directory_is_private(const char *path)
{
    struct stat directory_info;
    return stat(path, &directory_info) == 0 &&
           S_ISDIR(directory_info.st_mode) &&
           (directory_info.st_mode & 0777) == 0700;
}

static int logger_is_structured_and_secret_free(void)
{
    FILE *capture = tmpfile();
    int saved_stderr = -1;
    int redirected = 0;
    char output[128] = {0};
    size_t output_length;
    int result = 0;

    if (capture == NULL) {
        return 0;
    }

    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0 ||
        dup2(fileno(capture), STDERR_FILENO) < 0) {
        goto cleanup;
    }
    redirected = 1;
    log_event(LOG_EVENT_RECORD_ADD, LOG_STATUS_SUCCESS);
    log_event(LOG_EVENT_VAULT_UNLOCK, LOG_STATUS_FAILURE);
    fflush(stderr);
    if (dup2(saved_stderr, STDERR_FILENO) < 0) {
        goto cleanup;
    }
    redirected = 0;

    rewind(capture);
    output_length = fread(output, 1, sizeof(output) - 1, capture);
    output[output_length] = '\0';
    result = strcmp(output, "event=record_add status=success\n"
                            "event=vault_unlock status=failure\n") == 0 &&
             strstr(output, TEST_PASSWORD) == NULL;

cleanup:
    if (redirected) {
        (void)dup2(saved_stderr, STDERR_FILENO);
    }
    if (saved_stderr >= 0) {
        close(saved_stderr);
    }
    fclose(capture);
    sodium_memzero(output, sizeof(output));
    return result;
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
    Vault *original;
    Vault *loaded;
    int passed = 1;

    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium.\n");
        return 1;
    }

    original = crypto_secure_alloc(sizeof(*original));
    loaded = crypto_secure_alloc(sizeof(*loaded));
    passed &= check(original != NULL && loaded != NULL,
                    "vault test data uses locked secure memory");
    if (original == NULL || loaded == NULL) {
        crypto_secure_free(original);
        crypto_secure_free(loaded);
        return 1;
    }

    {
        unsigned char *secure_secret = crypto_secure_alloc(PWMAN_KEY_SIZE);
        size_t i;
        int wiped = 1;

        passed &= check(secure_secret != NULL,
                        "secure memory allocation succeeds");
        if (secure_secret != NULL) {
            memset(secure_secret, 0xA5, PWMAN_KEY_SIZE);
            crypto_wipe(secure_secret, PWMAN_KEY_SIZE);
            for (i = 0; i < PWMAN_KEY_SIZE; i++) {
                if (secure_secret[i] != 0) {
                    wiped = 0;
                }
            }
            passed &= check(wiped, "secret buffers are wiped");
            crypto_secure_free(secure_secret);
        }
    }

    {
        char valid_field[] = "example.com";
        char empty_field[] = "";
        char newline_field[] = "bad\nfield";
        char edge_whitespace[] = " bad";
        char too_long_field[] = "long";
        char unterminated_field[] = {'n', 'o', 'n'};

        passed &= check(crypto_text_is_valid(valid_field, sizeof(valid_field),
                                             sizeof(valid_field) - 1, 0),
                        "valid text is accepted");
        passed &= check(!crypto_text_is_valid(empty_field, sizeof(empty_field),
                                              sizeof(empty_field) - 1, 0),
                        "empty required text is rejected");
        passed &= check(crypto_text_is_valid(empty_field, sizeof(empty_field),
                                             sizeof(empty_field) - 1, 1),
                        "empty optional text is accepted");
        passed &= check(!crypto_text_is_valid(newline_field, sizeof(newline_field),
                                              sizeof(newline_field) - 1, 0),
                        "control characters are rejected");
        passed &= check(!crypto_text_is_valid(edge_whitespace, sizeof(edge_whitespace),
                                              sizeof(edge_whitespace) - 1, 0),
                        "edge whitespace is rejected");
        passed &= check(!crypto_text_is_valid(too_long_field, sizeof(too_long_field),
                                              2, 0),
                        "text exceeding its field limit is rejected");
        passed &= check(!crypto_text_is_valid(unterminated_field,
                                              sizeof(unterminated_field),
                                              sizeof(unterminated_field) - 1, 0),
                        "unterminated field buffers are rejected");
    }

    {
        char alice_path[USER_VAULT_PATH_SIZE];
        char bob_path[USER_VAULT_PATH_SIZE];
        char small_path[4];
        char long_username[USER_NAME_SIZE + 1];

        passed &= check(user_is_valid_name("alice_1"),
                        "valid account name is accepted");
        passed &= check(!user_is_valid_name("../alice") &&
                        !user_is_valid_name("alice/bob") &&
                        !user_is_valid_name(""),
                        "path traversal and separators are rejected in account names");
        memset(long_username, 'a', sizeof(long_username) - 1);
        long_username[sizeof(long_username) - 1] = '\0';
        passed &= check(!user_is_valid_name(long_username),
                        "overlong account names are rejected");
        passed &= check(user_vault_path("alice", alice_path, sizeof(alice_path)) &&
                        user_vault_path("bob", bob_path, sizeof(bob_path)) &&
                        strcmp(alice_path, bob_path) != 0,
                        "each account maps to a separate vault path");
        passed &= check(!user_vault_path("alice", small_path, sizeof(small_path)),
                        "short path buffers are rejected");
        passed &= check(user_session_authorized(1, "alice", alice_path) &&
                        !user_session_authorized(0, "alice", alice_path) &&
                        !user_session_authorized(1, "alice", bob_path),
                        "record session access requires the matching authenticated account");
    }

    passed &= check(logger_is_structured_and_secret_free(),
                    "structured logs contain event/status and no test secret");

    original->count = 1;
    strcpy(original->entries[0].service, "example.com");
    strcpy(original->entries[0].username, "student");
    strcpy(original->entries[0].password, TEST_PASSWORD);

    passed &= check(vault_save(TEST_FILE, "correct-master-password", original),
                    "vault can be saved");
    passed &= check(!file_contains_password(TEST_FILE),
                    "credential password is not stored as cleartext");
    passed &= check(vault_file_is_private(TEST_FILE),
                    "vault file permissions are owner-only (0600)");
    passed &= check(vault_load(TEST_FILE, "correct-master-password", loaded),
                    "correct master password unlocks the vault");
    passed &= check(loaded->count == 1 &&
                    strcmp(loaded->entries[0].service, "example.com") == 0 &&
                    strcmp(loaded->entries[0].username, "student") == 0 &&
                    strcmp(loaded->entries[0].password, TEST_PASSWORD) == 0,
                    "credential data is recovered correctly");

    {
        Vault *bob_vault = crypto_secure_alloc(sizeof(*bob_vault));
        int storage_ready = user_store_prepare();

        passed &= check(storage_ready && directory_is_private("users"),
                        "account storage directory is owner-only (0700)");
        if (bob_vault == NULL || !storage_ready) {
            passed &= check(0, "account isolation test setup succeeds");
        } else {
            memset(bob_vault, 0, sizeof(*bob_vault));
            passed &= check(user_store_has_accounts() == 0,
                            "isolated test account store starts empty");
            passed &= check(vault_save(TEST_ALICE_FILE, "alice-test-master",
                                       original) &&
                            vault_save(TEST_BOB_FILE, "bob-test-master",
                                       bob_vault),
                            "separate user vaults can be created");
            passed &= check(user_vault_exists("test_alice") == 1 &&
                            user_vault_exists("test_bob") == 1 &&
                            user_store_has_accounts() == 1,
                            "account vaults are private, owned and discoverable");
            passed &= check(!vault_load(TEST_ALICE_FILE, "bob-test-master",
                                        loaded),
                            "another account's master password cannot unlock this vault");
            passed &= check(vault_load(TEST_BOB_FILE, "bob-test-master",
                                       loaded) &&
                            loaded->count == 0,
                            "account can unlock only its own empty vault");
        }
        crypto_secure_free(bob_vault);
    }

    vault_clear(loaded);
    passed &= check(!vault_load(TEST_FILE, "wrong-master-password", loaded),
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
                        !vault_load(TEST_FILE, "correct-master-password", loaded),
                        "modified ciphertext is rejected");
    }

    remove(TEST_FILE);
    remove(TEST_ALICE_FILE);
    remove(TEST_ALICE_FILE ".tmp");
    remove(TEST_BOB_FILE);
    remove(TEST_BOB_FILE ".tmp");
    (void)rmdir("users");
    vault_clear(original);
    vault_clear(loaded);
    crypto_secure_free(original);
    crypto_secure_free(loaded);

    if (!passed) {
        return 1;
    }
    printf("All vault tests passed.\n");
    return 0;
}
