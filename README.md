# pwman — a small local password manager in C

`pwman` is a command-line password manager for one local user. It stores service
names, usernames and passwords in one encrypted vault file. This is a learning
project: it does not include cloud sync, browser extensions or a password
recovery feature.

## Features in Checkpoint 2

- Create a vault with a master password.
- Unlock an existing vault only after authenticated decryption succeeds.
- Add, list, update and delete credential records.
- Encrypt the vault contents before writing them to disk.
- Hide master-password and credential-password input while typing.
- List services and usernames without displaying stored passwords.

## Dependencies

- GCC (or another C11 compiler)
- GNU Make
- libsodium development headers and library

On Debian/Ubuntu or WSL:

```sh
sudo apt update
sudo apt install build-essential make libsodium-dev
```

## Build

From the repository root:

```sh
make
```

This creates the `pwman` executable.

## Run

```sh
./pwman
```

On the first run, the program asks you to choose and confirm a master
password. It creates `vault.db` in the current directory. On later runs, it
asks for the master password and opens the vault only if verification succeeds.

The menu lets you add, list, update and delete credentials. Password input is
not echoed by the terminal. The list view displays service names and usernames
only; stored passwords are never printed.

To remove compiled files and local test data:

```sh
make clean
```

## Tests

```sh
make test
```

The vault tests check encryption at rest, correct and incorrect master-password
handling, credential recovery, owner-only file permissions and rejection of
modified ciphertext.

## Encryption design

- libsodium's Argon2id KDF derives a key-encryption key from the master password
  and a random 16-byte salt.
- A random 32-byte data-encryption key encrypts the serialized vault contents.
- The data-encryption key is encrypted with the derived key.
- XChaCha20-Poly1305 authenticates both encrypted pieces. A new random 24-byte
  nonce is generated for each encryption operation.
- KDF parameters are stored in the vault header and checked before the KDF is
  run. The master password itself is never stored.
- The vault is written through a temporary file with owner-only permissions,
  then renamed into place.

The current checkpoint uses a small length-prefixed binary record format to
avoid adding a JSON dependency. The vault format is versioned so it can be
changed in a later checkpoint.

## Project layout

```text
.
├── docs/
│   ├── DESIGN.md
│   └── CHECKPOINT_2.md
├── include/      # Public interfaces
├── src/          # CLI, authentication, crypto and vault storage
├── tests/        # Vault tests
├── Makefile
└── README.md
```
