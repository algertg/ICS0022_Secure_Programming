#include "cli.h"
#include "auth.h"
#include "crypto.h"
#include "vault.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VAULT_PATH "vault.db"
#define INPUT_SIZE 256
#define MASTER_PASSWORD_SIZE 256

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
    return 1;
}

static int save_changes(const Vault *vault, const char *master_password)
{
    if (!vault_save(VAULT_PATH, master_password, vault)) {
        printf("Could not save the vault.\n");
        return 0;
    }
    printf("Changes saved.\n");
    return 1;
}

static void list_credentials(const Vault *vault)
{
    unsigned int i;

    if (vault->count == 0) {
        printf("The vault is empty.\n");
        return;
    }

    printf("\nSaved credentials (passwords are not displayed):\n");
    printf("%-5s %-24s %-30s\n", "ID", "SERVICE", "USERNAME");
    printf("---------------------------------------------------------------\n");
    for (i = 0; i < vault->count; i++) {
        printf("%-5u %-24s %-30s\n", i + 1,
               vault->entries[i].service, vault->entries[i].username);
    }
}

static int read_entry_number(const Vault *vault, unsigned int *index)
{
    char input[INPUT_SIZE];
    char *end;
    unsigned long value;

    if (!read_line("Credential ID: ", input, sizeof(input)) || input[0] == '\0') {
        return 0;
    }

    value = strtoul(input, &end, 10);
    while (*end != '\0' && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0' || value == 0 || value > vault->count) {
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

    if (entry->service[0] == '\0' || entry->username[0] == '\0' ||
        entry->password[0] == '\0') {
        printf("Service, username and password cannot be empty.\n");
        crypto_wipe(entry, sizeof(*entry));
        return 0;
    }
    return 1;
}

static void add_credential(Vault *vault, const char *master_password)
{
    Credential entry = {0};

    if (vault->count >= VAULT_MAX_ENTRIES) {
        printf("The vault is full.\n");
        return;
    }
    if (!read_credential(&entry, "Service: ")) {
        return;
    }

    vault->entries[vault->count] = entry;
    vault->count++;
    (void)save_changes(vault, master_password);
    crypto_wipe(&entry, sizeof(entry));
}

static void update_credential(Vault *vault, const char *master_password)
{
    unsigned int index;
    Credential replacement = {0};

    list_credentials(vault);
    if (!read_entry_number(vault, &index)) {
        return;
    }
    if (!read_credential(&replacement, "New service: ")) {
        return;
    }

    crypto_wipe(&vault->entries[index], sizeof(Credential));
    vault->entries[index] = replacement;
    (void)save_changes(vault, master_password);
    crypto_wipe(&replacement, sizeof(replacement));
}

static void delete_credential(Vault *vault, const char *master_password)
{
    unsigned int index;
    unsigned int i;

    list_credentials(vault);
    if (!read_entry_number(vault, &index)) {
        return;
    }

    crypto_wipe(&vault->entries[index], sizeof(Credential));
    for (i = index; i + 1 < vault->count; i++) {
        vault->entries[i] = vault->entries[i + 1];
    }
    crypto_wipe(&vault->entries[vault->count - 1], sizeof(Credential));
    vault->count--;
    (void)save_changes(vault, master_password);
}

int cli_run(void)
{
    Vault vault = {0};
    char master_password[MASTER_PASSWORD_SIZE] = {0};
    char choice_text[INPUT_SIZE];
    int creating = access(VAULT_PATH, F_OK) != 0;
    int choice = 0;

    printf("pwman - simple password manager\n");
    if (creating) {
        printf("No vault found. A new vault will be created.\n");
    }

    if (!auth_prompt_master_password(master_password,
                                     sizeof(master_password), creating)) {
        crypto_wipe(master_password, sizeof(master_password));
        return 1;
    }

    if (creating) {
        if (!vault_save(VAULT_PATH, master_password, &vault)) {
            printf("Could not create the vault.\n");
            crypto_wipe(master_password, sizeof(master_password));
            vault_clear(&vault);
            return 1;
        }
        printf("Vault created and unlocked.\n");
    } else if (!vault_load(VAULT_PATH, master_password, &vault)) {
        printf("Unlock failed. Check the master password or vault file.\n");
        crypto_wipe(master_password, sizeof(master_password));
        vault_clear(&vault);
        return 1;
    } else {
        printf("Vault unlocked.\n");
    }

    while (choice != 5) {
        printf("\n1. Add credential\n");
        printf("2. List credentials\n");
        printf("3. Update credential\n");
        printf("4. Delete credential\n");
        printf("5. Lock and exit\n");

        if (!read_line("Choice: ", choice_text, sizeof(choice_text))) {
            break;
        }
        choice = atoi(choice_text);

        switch (choice) {
            case 1:
                add_credential(&vault, master_password);
                break;
            case 2:
                list_credentials(&vault);
                break;
            case 3:
                update_credential(&vault, master_password);
                break;
            case 4:
                delete_credential(&vault, master_password);
                break;
            case 5:
                printf("Vault locked. Goodbye.\n");
                break;
            default:
                printf("Please choose a number from 1 to 5.\n");
                break;
        }
    }

    crypto_wipe(master_password, sizeof(master_password));
    vault_clear(&vault);
    return 0;
}
