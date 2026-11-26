#ifndef PWMAN_USER_STORE_H
#define PWMAN_USER_STORE_H

#include <stddef.h>

#define USER_NAME_SIZE 33
#define USER_VAULT_PATH_SIZE 48

int user_is_valid_name(const char *username);
int user_store_prepare(void);
int user_vault_path(const char *username, char *path, size_t path_size);
int user_session_authorized(int authenticated, const char *username,
                            const char *vault_path);
/* Returns 1 if accounts exist, 0 if none exist, and -1 on error. */
int user_store_has_accounts(void);
/* Returns 1 for a valid existing vault, 0 if absent, and -1 if unsafe/error. */
int user_vault_exists(const char *username);

#endif
