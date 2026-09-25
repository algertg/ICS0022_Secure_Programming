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
