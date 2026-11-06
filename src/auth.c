#include "auth.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define MIN_MASTER_PASSWORD 8

int auth_read_hidden(const char *prompt, char *output, size_t output_size)
{
    struct termios old_settings;
    struct termios new_settings;
    size_t length;
    int ch;

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &old_settings) != 0) {
        fprintf(stderr, "Password input needs an interactive terminal.\n");
        return 0;
    }

    new_settings = old_settings;
    new_settings.c_lflag &= (tcflag_t)~ECHO;

    printf("%s", prompt);
    fflush(stdout);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_settings) != 0) {
        return 0;
    }

    if (fgets(output, (int)output_size, stdin) == NULL) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings);
        printf("\n");
        crypto_wipe(output, output_size);
        return 0;
    }

    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings);
    printf("\n");

    length = strlen(output);
    if (length > 0 && output[length - 1] == '\n') {
        output[length - 1] = '\0';
    } else {
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* Discard the rest of an overlong password. */
        }
        if (length == output_size - 1) {
            crypto_wipe(output, output_size);
            fprintf(stderr, "Password is too long.\n");
            return 0;
        }
    }

    return output[0] != '\0';
}

int auth_prompt_master_password(char *password, size_t password_size,
                                int creating_vault)
{
    char confirmation[256] = {0};

    if (!auth_read_hidden(creating_vault ? "Choose master password (hidden): " :
                                     "Master password (hidden): ",
                     password, password_size)) {
        return 0;
    }

    if (!creating_vault) {
        return 1;
    }

    if (strlen(password) < MIN_MASTER_PASSWORD) {
        printf("Use at least %d characters for the master password.\n",
               MIN_MASTER_PASSWORD);
        crypto_wipe(password, password_size);
        return 0;
    }

    if (!auth_read_hidden("Repeat master password (hidden): ", confirmation,
                     sizeof(confirmation))) {
        crypto_wipe(password, password_size);
        crypto_wipe(confirmation, sizeof(confirmation));
        return 0;
    }

    if (strcmp(password, confirmation) != 0) {
        printf("The passwords did not match.\n");
        crypto_wipe(password, password_size);
        crypto_wipe(confirmation, sizeof(confirmation));
        return 0;
    }

    crypto_wipe(confirmation, sizeof(confirmation));
    return 1;
}
