#include "cli.h"
#include "auth.h"
#include "crypto.h"
#include "log.h"
#include "user_store.h"
#include "vault.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LEGACY_VAULT_PATH "vault.db"
#define INPUT_SIZE 256
#define MASTER_PASSWORD_SIZE 256

typedef struct {
    char username[USER_NAME_SIZE];
    char vault_path[USER_VAULT_PATH_SIZE];
    Vault *vault;
    char *master_password;
    int authenticated;
} UserSession;

static int session_is_authorized(const UserSession *session)
{
    return session != NULL &&
           session->vault != NULL && session->master_password != NULL &&
           user_session_authorized(session->authenticated, session->username,
                                   session->vault_path);
}

static int read_line(const char *prompt, char *output, size_t output_size)
{
    size_t length;
    int ch;

    printf("%s", prompt);
    fflush(stdout);
    if (fgets(output, (int)output_size, stdin) == NULL) {
        return 0;
    }

    length = strlen(output);
    if (length > 0 && output[length - 1] == '\n') {
        output[length - 1] = '\0';
    } else {
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* Discard input that does not fit in the buffer. */
        }
        if (length == output_size - 1) {
            printf("Input is too long.\n");
            return 0;
        }
    }
    return crypto_text_is_valid(output, output_size,
                                output_size - 1, 1);
}

static int save_changes(const UserSession *session, LogEvent event)
{
    if (!session_is_authorized(session)) {
        return 0;
    }
    if (!vault_save(session->vault_path, session->master_password,
                    session->vault)) {
        log_event(event, LOG_STATUS_FAILURE);
        printf("Could not save the vault.\n");
        return 0;
    }
    log_event(event, LOG_STATUS_SUCCESS);
    printf("Changes saved.\n");
    return 1;
}

static void list_credentials(const UserSession *session)
{
    unsigned int i;

    if (!session_is_authorized(session)) {
        printf("Not authorized.\n");
        return;
    }
    if (session->vault->count == 0) {
        printf("The vault is empty.\n");
        return;
    }

    printf("\nSaved credentials (passwords are not displayed):\n");
    printf("%-5s %-24s %-30s\n", "ID", "SERVICE", "USERNAME");
    printf("---------------------------------------------------------------\n");
    for (i = 0; i < session->vault->count; i++) {
        printf("%-5u %-24s %-30s\n", i + 1,
               session->vault->entries[i].service,
               session->vault->entries[i].username);
    }
}

static int read_entry_number(const UserSession *session, unsigned int *index)
{
    char input[INPUT_SIZE];
    char *end;
    unsigned long value;
    size_t i;

    if (!session_is_authorized(session) ||
        !read_line("Credential ID: ", input, sizeof(input)) || input[0] == '\0') {
        return 0;
    }
    for (i = 0; input[i] != '\0'; i++) {
        if (!isdigit((unsigned char)input[i])) {
            printf("Invalid credential ID.\n");
            return 0;
        }
    }

    value = strtoul(input, &end, 10);
    if (*end != '\0' || value == 0 || value > session->vault->count) {
        printf("Invalid credential ID.\n");
        return 0;
    }

    *index = (unsigned int)value - 1;
    return 1;
}

static int read_credential(Credential *entry, const char *service_prompt)
{
    if (!read_line(service_prompt, entry->service, sizeof(entry->service)) ||
        !read_line("Username: ", entry->username, sizeof(entry->username)) ||
        !auth_read_hidden("Password (hidden): ", entry->password, sizeof(entry->password))) {
        printf("Input cancelled.\n");
        crypto_wipe(entry, sizeof(*entry));
        return 0;
    }

    if (!crypto_text_is_valid(entry->service, sizeof(entry->service),
                              sizeof(entry->service) - 1, 0) ||
        !crypto_text_is_valid(entry->username, sizeof(entry->username),
                              sizeof(entry->username) - 1, 0) ||
        !crypto_text_is_valid(entry->password, sizeof(entry->password),
                              sizeof(entry->password) - 1, 0)) {
        printf("Invalid service, username or password.\n");
        crypto_wipe(entry, sizeof(*entry));
        return 0;
    }
    return 1;
}

static void add_credential(UserSession *session)
{
    Credential *entry = crypto_secure_alloc(sizeof(Credential));

    if (!session_is_authorized(session)) {
        printf("Not authorized.\n");
        return;
    }
    if (session->vault->count >= VAULT_MAX_ENTRIES) {
        printf("The vault is full.\n");
        return;
    }
    if (entry == NULL) {
        printf("Could not allocate secure memory.\n");
        return;
    }
    memset(entry, 0, sizeof(*entry));
    if (!read_credential(entry, "Service: ")) {
        crypto_secure_free(entry);
        return;
    }

    session->vault->entries[session->vault->count] = *entry;
    session->vault->count++;
    (void)save_changes(session, LOG_EVENT_RECORD_ADD);
    crypto_secure_free(entry);
}

static void update_credential(UserSession *session)
{
    unsigned int index;
    Credential *replacement = crypto_secure_alloc(sizeof(Credential));

    if (!session_is_authorized(session)) {
        printf("Not authorized.\n");
        return;
    }
    list_credentials(session);
    if (replacement == NULL) {
        printf("Could not allocate secure memory.\n");
        return;
    }
    memset(replacement, 0, sizeof(*replacement));
    if (!read_entry_number(session, &index)) {
        crypto_secure_free(replacement);
        return;
    }
    if (!read_credential(replacement, "New service: ")) {
        crypto_secure_free(replacement);
        return;
    }

    crypto_wipe(&session->vault->entries[index], sizeof(Credential));
    session->vault->entries[index] = *replacement;
    (void)save_changes(session, LOG_EVENT_RECORD_UPDATE);
    crypto_secure_free(replacement);
}

static void delete_credential(UserSession *session)
{
    unsigned int index;
    unsigned int i;

    if (!session_is_authorized(session)) {
        printf("Not authorized.\n");
        return;
    }
    list_credentials(session);
    if (!read_entry_number(session, &index)) {
        return;
    }

    crypto_wipe(&session->vault->entries[index], sizeof(Credential));
    for (i = index; i + 1 < session->vault->count; i++) {
        session->vault->entries[i] = session->vault->entries[i + 1];
    }
    crypto_wipe(&session->vault->entries[session->vault->count - 1],
                sizeof(Credential));
    session->vault->count--;
    (void)save_changes(session, LOG_EVENT_RECORD_DELETE);
}

int cli_run(void)
{
    UserSession session = {0};
    char choice_text[INPUT_SIZE];
    char *choice_end;
    unsigned long choice_value;
    const char *unlock_path;
    int account_exists;
    int account_count;
    int importing_legacy = 0;
    int creating;
    int result = 1;
    int choice = 0;

    session.vault = crypto_secure_alloc(sizeof(Vault));
    session.master_password = crypto_secure_alloc(MASTER_PASSWORD_SIZE);
    if (session.vault == NULL || session.master_password == NULL) {
        printf("Could not allocate secure memory.\n");
        goto cleanup;
    }
    memset(session.vault, 0, sizeof(*session.vault));
    memset(session.master_password, 0, MASTER_PASSWORD_SIZE);

    printf("pwman - simple password manager\n");
    if (!read_line("Username: ", session.username, sizeof(session.username)) ||
        !user_is_valid_name(session.username)) {
        printf("Invalid username. Use 1-32 letters, digits, '_' or '-'.\n");
        goto cleanup;
    }
    if (!user_store_prepare() ||
        !user_vault_path(session.username, session.vault_path,
                         sizeof(session.vault_path))) {
        printf("Could not access account storage.\n");
        goto cleanup;
    }

    account_exists = user_vault_exists(session.username);
    if (account_exists < 0) {
        printf("Could not access account storage.\n");
        goto cleanup;
    }
    account_count = user_store_has_accounts();
    if (account_count < 0) {
        printf("Could not access account storage.\n");
        goto cleanup;
    }

    importing_legacy = account_exists == 0 && account_count == 0 &&
                       access(LEGACY_VAULT_PATH, F_OK) == 0;
    creating = account_exists == 0 && !importing_legacy;
    unlock_path = importing_legacy ? LEGACY_VAULT_PATH : session.vault_path;
    if (creating) {
        printf("No account vault found. A new account will be created.\n");
    }

    if (!auth_prompt_master_password(session.master_password,
                                     MASTER_PASSWORD_SIZE, creating)) {
        goto cleanup;
    }

    if (creating) {
        if (!vault_save(session.vault_path, session.master_password,
                        session.vault)) {
            log_event(LOG_EVENT_VAULT_CREATE, LOG_STATUS_FAILURE);
            printf("Could not create the vault.\n");
            goto cleanup;
        }
        log_event(LOG_EVENT_VAULT_CREATE, LOG_STATUS_SUCCESS);
        printf("Account created and unlocked.\n");
    } else if (!vault_load(unlock_path, session.master_password,
                           session.vault)) {
        log_event(LOG_EVENT_VAULT_UNLOCK, LOG_STATUS_FAILURE);
        printf("Unlock failed. Check the master password or vault file.\n");
        goto cleanup;
    } else {
        log_event(LOG_EVENT_VAULT_UNLOCK, LOG_STATUS_SUCCESS);
        if (importing_legacy &&
            !vault_save(session.vault_path, session.master_password,
                        session.vault)) {
            log_event(LOG_EVENT_VAULT_IMPORT, LOG_STATUS_FAILURE);
            printf("Could not import the existing vault.\n");
            goto cleanup;
        }
        if (importing_legacy) {
            log_event(LOG_EVENT_VAULT_IMPORT, LOG_STATUS_SUCCESS);
            printf("Existing vault imported. The original vault was retained.\n");
        } else {
            printf("Account unlocked.\n");
        }
    }
    session.authenticated = 1;

    while (choice != 5) {
        printf("\n1. Add credential\n");
        printf("2. List credentials\n");
        printf("3. Update credential\n");
        printf("4. Delete credential\n");
        printf("5. Lock and exit\n");

        if (!read_line("Choice: ", choice_text, sizeof(choice_text))) {
            break;
        }
        choice = 0;
        {
            size_t i;
            int digits_only = choice_text[0] != '\0';
            for (i = 0; digits_only && choice_text[i] != '\0'; i++) {
                if (!isdigit((unsigned char)choice_text[i])) {
                    digits_only = 0;
                }
            }
            if (digits_only) {
                choice_value = strtoul(choice_text, &choice_end, 10);
                if (*choice_end == '\0' && choice_value <= 5) {
                    choice = (int)choice_value;
                }
            }
        }

        switch (choice) {
            case 1:
                add_credential(&session);
                break;
            case 2:
                list_credentials(&session);
                break;
            case 3:
                update_credential(&session);
                break;
            case 4:
                delete_credential(&session);
                break;
            case 5:
                printf("Vault locked. Goodbye.\n");
                break;
            default:
                printf("Please choose a number from 1 to 5.\n");
                break;
        }
    }

    result = 0;

cleanup:
    session.authenticated = 0;
    crypto_secure_free(session.master_password);
    crypto_secure_free(session.vault);
    return result;
}
