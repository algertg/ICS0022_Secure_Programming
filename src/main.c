#include "cli.h"

#include <sodium.h>
#include <stdio.h>

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium.\n");
        return 1;
    }

    return cli_run();
}
