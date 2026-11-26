# Password Manager - Checkpoint 3 Report

## Introduction

This project is a small command-line password manager written in C. Its purpose
is to store account credentials in encrypted files and to give each application
user a separate vault. A vault can contain up to 100 records. Each record stores
a service name, a username and a password.

The program is intended as a local learning project, not as a replacement for a
professionally audited password manager. It does not use a network, synchronize
data between devices, or provide a way to recover a forgotten master password.

## Implementation

The program asks for an account name whenever it starts. Account names are
restricted to letters, digits, underscores and hyphens. Each name maps to a
separate encrypted vault in the `users/` directory. When the user enters the
correct master password, the program unlocks that account's vault. Record
operations are allowed only while the session is authenticated and its account
name matches the selected vault path.

New accounts choose and confirm a master password. The master password is not
stored in the vault. Instead, the program uses libsodium's Argon2id function to
derive a key-encryption key from the password and a random salt. A separate
random data-encryption key encrypts the vault contents. The program uses
XChaCha20-Poly1305 to encrypt and authenticate the data, so changes to the
ciphertext are detected when the vault is opened. The vault uses a
length-prefixed binary record format.

When saving, the program writes a temporary file with owner-only permissions,
then flushes and renames it into place. The account directory is restricted to
the current operating-system user. If an older `vault.db` exists and no
application accounts have been created, the first account can import it by
entering its existing master password. The original file is kept.

Secret data is held in libsodium protected memory. The program checks that
memory locking succeeds, clears secret buffers when they are freed, and refuses
to start if it cannot disable core dumps. Password input is hidden while typing.
Required text fields reject empty values, control characters and leading or
trailing whitespace. Account names are checked before being used to build vault
paths. Logs contain fixed event and status labels, not account names or
credential data.

The tests cover encrypted storage, correct and incorrect master passwords,
tamper detection, account path and session checks, file permissions, validation
cases, memory allocation and wiping, and the structure of log output. The
automated suite is run with `make test`, and the program is built with `make`.

## Security Analysis

Encryption protects stored credentials if someone obtains a vault file without
knowing its master password. Argon2id makes repeated password guesses more
expensive, while XChaCha20-Poly1305 checks that encrypted data has not been
modified. Separate vault files and passwords keep one application account's
records separate from another's. The directory and vault permissions also
reduce access by other operating-system users.

The program takes additional steps to reduce exposure while it is running.
Master passwords, encryption keys, and in-memory vault data use protected,
locked allocations. These buffers are cleared when released. Core dumps are
disabled because they could otherwise contain secrets. Hidden terminal input
and fixed-format logging reduce the chance of passwords appearing on screen or
in logs.

There are still important limits. This project has not had a professional
security audit. Application accounts are self-created and are not managed by a
central registration system. Accounts running under the same operating-system
user are not isolated from that user at the file-system level; their vaults
remain encrypted, but a process with the same operating-system permissions may
still copy or delete the files. A compromised operating system or a
privileged administrator can also access a running process. New master
passwords must be at least eight characters long, but the program does not
provide a password-strength meter or rate limiting. There is no password
recovery, cloud backup, clipboard feature, or automatic timeout while the
vault is unlocked.

## Conclusion

Checkpoint 3 adds separate encrypted vaults for application accounts, checks
account access before record operations, and improves the handling of secrets
in memory. The current tests pass and cover the main encryption, validation,
logging and account-separation behavior. This is a useful security-programming
project, but its limits mean it should not be treated as a fully audited
product for protecting important real-world passwords.
