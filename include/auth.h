#ifndef PWMAN_AUTH_H
#define PWMAN_AUTH_H

#include <stddef.h>

/* Read a secret without echoing it to the terminal. */
int auth_read_hidden(const char *prompt, char *output, size_t output_size);

/* Read and optionally confirm the master password. */
int auth_prompt_master_password(char *password, size_t password_size,
                                int creating_vault);

#endif
