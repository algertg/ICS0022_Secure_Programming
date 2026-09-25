#include <stdio.h>
#include <sodium.h>

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "error: libsodium init failed\n");
        return 1;
    }

    /* TODO: dispatch to cli.c command parser */
    (void)argc;
    (void)argv;
    printf("pwman: no commands implemented yet (Checkpoint 1 scaffold)\n");
    return 0;
}
