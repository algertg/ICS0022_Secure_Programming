# Checkpoint 2 progress note — Week 9

## Implemented

- Added a working local vault file (`vault.db`).
- Added credential storage with add, list, update and delete operations.
- Added master-password setup and unlock. The vault opens only when the
  encrypted data-encryption key and vault contents authenticate successfully.
- Used libsodium Argon2id to derive the key-encryption key from the master
  password and a random salt.
- Used XChaCha20-Poly1305 to encrypt the data-encryption key and vault contents.
- Generated random nonces and used authenticated data to protect the header.
- Added hidden terminal input for master passwords and credential passwords.
  The interface lists service names and usernames only, never stored passwords.
- Added tests for encryption at rest, correct/incorrect unlock, data recovery
  owner-only file permissions and tampered ciphertext.
- Added build, run and test instructions for a clean Debian/Ubuntu machine.

## Build and test

```sh
sudo apt update
sudo apt install build-essential make libsodium-dev
make
make test
./pwman
```

## Current limitations

- This checkpoint is a simple local learning project, not an audited password
  manager.
- The interface does not display or copy a stored password back out.
- The vault supports up to 100 credential records in this version.
- There is no password reset or recovery if the master password is lost.
- The current serialized record format is a small binary format; a later
  checkpoint can add fields such as URL and notes.
