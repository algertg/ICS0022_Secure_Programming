#define _POSIX_C_SOURCE 200809L
#include "user_store.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define USER_STORE_DIRECTORY "users"
#define VAULT_SUFFIX ".vault"

int user_is_valid_name(const char *username)
{
    size_t i;
    size_t length;

    if (username == NULL) {
        return 0;
    }

    length = strlen(username);
    if (length == 0 || length >= USER_NAME_SIZE) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)username[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')) {
            return 0;
        }
    }
    return 1;
}

int user_store_prepare(void)
{
    struct stat info;

    if (mkdir(USER_STORE_DIRECTORY, S_IRWXU) != 0 && errno != EEXIST) {
        return 0;
    }
    if (lstat(USER_STORE_DIRECTORY, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() || chmod(USER_STORE_DIRECTORY, S_IRWXU) != 0 ||
        stat(USER_STORE_DIRECTORY, &info) != 0 ||
        (info.st_mode & 0777) != 0700) {
        return 0;
    }
    return 1;
}

int user_vault_path(const char *username, char *path, size_t path_size)
{
    int written;

    if (!user_is_valid_name(username) || path == NULL) {
        return 0;
    }
    written = snprintf(path, path_size, USER_STORE_DIRECTORY "/%s" VAULT_SUFFIX,
                       username);
    return written >= 0 && (size_t)written < path_size;
}

int user_session_authorized(int authenticated, const char *username,
                            const char *vault_path)
{
    char expected_path[USER_VAULT_PATH_SIZE];

    return authenticated && vault_path != NULL &&
           user_vault_path(username, expected_path, sizeof(expected_path)) &&
           strcmp(vault_path, expected_path) == 0;
}

int user_store_has_accounts(void)
{
    DIR *directory = opendir(USER_STORE_DIRECTORY);
    struct dirent *entry;
    int found = 0;

    if (directory == NULL) {
        return errno == ENOENT ? 0 : -1;
    }

    while ((entry = readdir(directory)) != NULL) {
        size_t length = strlen(entry->d_name);
        size_t suffix_length = sizeof(VAULT_SUFFIX) - 1;
        if (length > suffix_length &&
            strcmp(entry->d_name + length - suffix_length, VAULT_SUFFIX) == 0) {
            found = 1;
            break;
        }
    }

    if (closedir(directory) != 0) {
        return -1;
    }
    return found;
}

int user_vault_exists(const char *username)
{
    char path[USER_VAULT_PATH_SIZE];
    struct stat info;

    if (!user_vault_path(username, path, sizeof(path))) {
        return -1;
    }
    if (lstat(path, &info) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 0777) != 0600) {
        return -1;
    }
    return 1;
}
