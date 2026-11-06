#ifndef PWMAN_VAULT_H
#define PWMAN_VAULT_H

#define VAULT_MAX_ENTRIES 100
#define VAULT_SERVICE_SIZE 100
#define VAULT_USERNAME_SIZE 100
#define VAULT_PASSWORD_SIZE 256

/* A credential stays in memory only while the vault is unlocked. */
typedef struct {
    char service[VAULT_SERVICE_SIZE];
    char username[VAULT_USERNAME_SIZE];
    char password[VAULT_PASSWORD_SIZE];
} Credential;

typedef struct {
    unsigned int count;
    Credential entries[VAULT_MAX_ENTRIES];
} Vault;

/* Return 1 on success and 0 on failure. */
int vault_save(const char *path, const char *master_password, const Vault *vault);
int vault_load(const char *path, const char *master_password, Vault *vault);
void vault_clear(Vault *vault);

#endif
