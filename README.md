# pwman — a small local password manager in C

`pwman` is a local command-line password manager with separate application
accounts. Each username has a separate encrypted vault and master password.
This is a learning project: it does not include cloud sync, browser extensions
or a password recovery feature.

## Features in Checkpoint 2

- Create a vault with a master password.
- Unlock an existing vault only after authenticated decryption succeeds.
- Add, list, update and delete credential records.
- Encrypt the vault contents before writing them to disk.
- Hide master-password and credential-password input while typing.
- List services and usernames without displaying stored passwords.
- Keep each account's records in its own encrypted vault under `users/`.

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

On each run, the program asks for an account username. New accounts choose and
confirm a master password; existing accounts unlock only their own encrypted
vault. Usernames are limited to letters, digits, `_` and `-`. Vault files are
stored in a private `users/` directory with owner-only permissions.
There is no central account registry; an account is represented by its vault file.

If a legacy `vault.db` exists and no account vaults exist yet, the first account
can import it using its existing master password. The original file is retained.

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

The tests cover encrypted storage and authentication, account vault isolation,
account/path validation, structured secret-free logs, protected memory
allocation and wiping, text validation, and owner-only file permissions.

## Encryption design

- Key events are written to standard error as structured `event` and `status`
  fields. Log labels are fixed by the program; passwords, usernames, services,
  vault contents and other user-provided data are not logged.

- All required text fields reject empty values, control characters and leading or
  trailing whitespace. Menu choices and credential IDs must contain digits only.
  Parsed vault records are revalidated before use and malformed records are rejected.

- Secret-bearing buffers use libsodium's protected allocations and are page-locked;
  allocation fails if locking fails. Buffers are zeroed on free, and the process
  refuses to start if it cannot disable core dumps.

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
