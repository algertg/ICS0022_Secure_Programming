#include "cli.h"

#include <sodium.h>
#include <stdio.h>
#include <sys/resource.h>

int main(void)
{
    struct rlimit core_limit = {0, 0};

    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium.\n");
        return 1;
    }

    if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
        fprintf(stderr, "Could not disable core dumps.\n");
        return 1;
    }

    return cli_run();
}
