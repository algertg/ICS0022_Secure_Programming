#!/usr/bin/env bash
# Run this from the root of your already-cloned repo in WSL:
#   bash setup.sh
set -euo pipefail

mkdir -p src include docs tests

# ---------------------------------------------------------------- README ---
cat > README.md << 'EOF'
# pwman — a local, single-user password manager (C)

## Scope

`pwman` is a command-line password manager. It stores credentials
(title, username, password, URL, notes) in a single encrypted vault file
on the local filesystem. This is a local-first tool: no network sync, no
multi-user support, no browser extension, in this phase of the project.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture, threat model,
and the cryptographic/vault-format decisions behind this scope.

## Planned commands

| Command | Description |
|---|---|
| `pwman init <vault-path>` | Create a new empty vault, prompting for and setting the master password |
| `pwman unlock <vault-path>` | Verify the master password and start a session (subsequent commands operate on it) |
| `pwman add <title>` | Add a new entry (prompts for username/password/url/notes) |
| `pwman get <title>` | Copy an entry's password to the clipboard (or print with `--show`) |
| `pwman list` | List entry titles/usernames (never prints passwords) |
| `pwman rm <title>` | Remove an entry |
| `pwman gen [length]` | Generate a random password |
| `pwman lock` | End the session / wipe in-memory secrets |

Commands and flags may change as the implementation progresses; this table
reflects the plan as of Checkpoint 1.

## Dependencies

- A C compiler (`gcc` or `clang`)
- [`libsodium`](https://libsodium.org) (dev headers), for the KDF and AEAD
  primitives

On Debian/Ubuntu (including WSL):

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

## Build

```bash
make
```

This produces the `pwman` binary in the repo root.

## Run

```bash
./pwman init ./vault.db
./pwman add "example.com"
./pwman list
./pwman get "example.com"
```

## Project status

Checkpoint 1: architecture, threat model, and initial vault/crypto design
decisions are documented; repository scaffolding is in place. No
functional code yet — see `docs/DESIGN.md` for what's being built next.

## Repository layout

```
.
├── docs/
│   └── DESIGN.md      # architecture, threat model, crypto/vault decisions
├── include/           # public headers for each module
├── src/                # module implementations + main.c
├── tests/              # unit/integration tests
├── Makefile
└── README.md
```
EOF

# ------------------------------------------------------------ .gitignore ---
cat > .gitignore << 'EOF'
# build output
pwman
*.o
*.tmp

# local test vaults
*.db
*.vault

# editor/OS cruft
.vscode/
*.swp
.DS_Store
EOF

# -------------------------------------------------------------- Makefile ---
cat > Makefile << 'EOF'
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Iinclude -g
LDLIBS  := -lsodium

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
BIN := pwman

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJ)
EOF

# ------------------------------------------------------------- src stubs ---
cat > src/main.c << 'EOF'
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
EOF

cat > include/crypto.h << 'EOF'
#ifndef PWMAN_CRYPTO_H
#define PWMAN_CRYPTO_H

/* Crypto module: KDF, AEAD encrypt/decrypt, CSPRNG, secure memory.
 * See docs/DESIGN.md section 4.1 for the chosen primitives. */

#endif /* PWMAN_CRYPTO_H */
EOF

cat > include/auth.h << 'EOF'
#ifndef PWMAN_AUTH_H
#define PWMAN_AUTH_H

/* User-management module: master password prompt, KEK derivation,
 * session/unlock state, attempt limiting. */

#endif /* PWMAN_AUTH_H */
EOF

cat > include/vault.h << 'EOF'
#ifndef PWMAN_VAULT_H
#define PWMAN_VAULT_H

/* Storage layer: vault file format, atomic read/write, entry
 * serialization. See docs/DESIGN.md section 4.3 for the file format. */

#endif /* PWMAN_VAULT_H */
EOF

cat > include/cli.h << 'EOF'
#ifndef PWMAN_CLI_H
#define PWMAN_CLI_H

/* CLI layer: argument parsing and command dispatch. */

#endif /* PWMAN_CLI_H */
EOF

touch tests/.gitkeep

echo "Scaffold created."
echo "Next:"
echo "  git add -A"
echo "  git commit -m 'Checkpoint 1: design doc + repo scaffold'"
