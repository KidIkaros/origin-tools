# origin-pass(1) — encrypted password vault + 2FA authenticator

## NAME

origin-pass — encrypted password vault and 2FA authenticator (TOTP/HOTP/OCRA)

## SYNOPSIS

```
origin-pass init [--vault <path>] [--tier nano|standard|sovereign] [--passphrase-file <file>]
origin-pass unlock --vault <path> --passphrase-file <file> [--session-token <name>]
            [--session-ttl <secs>] [--auto-rotate [--auto-rotate-threshold <secs>] [--auto-rotate-ttl <secs>]]
origin-pass lock --session-token <name>
origin-pass lock-all [--dir <store>] [--vault <path>]
origin-pass add <name> --type password|otp|ocra [--secret-file <file>|--secret-stdin]
            [--url <url>] [--notes <text>] [--force]
            [--suite <ocrasuite>] [--hotp] [--period <secs>] [--digits <n>] [--algo sha1|sha256|sha512]
origin-pass get <name> --vault <path> [--auto-clear <secs>]
origin-pass list --vault <path>
origin-pass rm <name> --vault <path>
origin-pass code <name> --vault <path> [--algo …] [--period …] [--digits …] [--counter <n>] [--auto-clear <secs>]
            [--ocra --challenge <q> [--counter <n>] [--pin <s>] [--force]]
            [--key-file <path>]                 # testing escape hatch
origin-pass export-qr <name> --vault <path> [--issuer <name>]
origin-pass import-qr <uri|@file> --vault <path> [--force]
origin-pass change-passphrase --vault <path> --passphrase-file <old> --new-passphrase-file <new>
origin-pass generate [--length <n>] [--exclude-symbols] [--exclude-digits] [--exclude-upper]
            [--passphrase [--words <n>]]
origin-pass tokens list [--dir <store>] [--format table|json] [--remaining <mins>]
origin-pass tokens revoke <name> [--dir <store>]
origin-pass tokens rotate <name> [--ttl <secs>] [--dir <store>]
origin-pass tokens renew <name> [--ttl <secs>] [--dir <store>]
origin-pass tokens revoke-all [--expired-only] [--dir <store>]
origin-pass tokens prune [--dir <store>]
```

Every vault command accepts either `--passphrase-file <file>` or
`--session-token <name>` to unlock (mutually exclusive flags).
`$ORIGIN_PASS_TOKEN` supplies the token when neither flag is given;
explicit flags always win.

## DESCRIPTION

`origin-pass` is a self-contained password manager and authenticator.
A **vault** is a single encrypted file (default `~/.origin/pass.vault`)
holding entries: passwords, TOTP/HOTP shared secrets, and OCRA
challenge-response keys.

**Cryptography.** The vault passphrase is stretched with Argon2id at one
of three memory tiers — `nano`, `standard` (default), `sovereign` —
and the resulting master key encrypts a ChaCha20-BLAKE3 AEAD envelope.
Each entry is encrypted under its own HKDF-SHA3-256-derived key, so
ciphertexts never share a key. Secrets are zeroized in memory, and
writes are atomic (tmp + rename + fsync).

**Secrets never enter argv.** Use `--secret-file` or `--secret-stdin`
for entry secrets and `--passphrase-file` for the vault passphrase;
the interactive prompts are for human use only.

## COMMANDS

### init

Create a new vault. The passphrase is sourced from `--passphrase-file`
or prompted twice (confirmation). Refuses to overwrite an existing
vault file. `--tier` selects the Argon2id memory tier.

### unlock / lock / lock-all

`unlock` verifies the passphrase and — with `--session-token` — writes a
persisted bearer token (see session-tokens(7), stored in this repo as
`docs/session-tokens.md`). It retains nothing in memory. `lock
--session-token <name>` revokes one token; a bare `lock` errors (there
is no in-process state to drop). `lock-all [--dir] [--vault]` revokes
every token in the store — or only those bound to one vault — and
errors when nothing was revoked.

### add

Store a new entry (`--force` overwrites). Types:

- **password** — the secret is an arbitrary UTF-8 string.
- **otp** — the secret is a base32-encoded shared key. `--hotp`
  selects HOTP (counter-based) instead of the default TOTP; `--period`,
  `--digits` (4..=10), and `--algo` (sha1/sha256/sha512) configure the
  algorithm. The counter starts at 0 and auto-increments per use.
- **ocra** — RFC 6287 challenge-response. `--suite` takes an OCRASuite
  string (`OCRA-1:HOTP-SHA1-6:QN08`, `C-QN08-PSHA1`, `QA10-T1M`,
  `QH8-S512`, …) and the secret is the raw binary key (≥ 16 bytes).

### get / list / rm

`get` prints the secret (optionally `--auto-clear <secs>` overwrites
the terminal after display). `list` shows names and types only.
`rm` deletes an entry.

### code

Compute a one-time code. Without `--ocra`, reads the entry's stored
TOTP/HOTP parameters (CLI `--algo`/`--period`/`--digits`/`--counter`
override). HOTP counters auto-increment and persist. With
`--ocra --challenge <q>`, computes an OCRA response from the entry's
suite — validating the challenge format, advancing `C-` counters, and
checking the replay-nonce ledger (re-used challenges are refused unless
`--force`). `--pin` supplies the P-slot string for PIN suites;
`--key-file` bypasses the vault (testing escape hatch).

### export-qr / import-qr

`export-qr` renders the entry's otpauth:// URI as a terminal QR code
(`--issuer` overrides the embedded issuer). `import-qr` parses an
otpauth:// URI (literal, or `@file` to read from disk) into a new
entry (`--force` to overwrite).

### change-passphrase

Re-derives the master key with a new passphrase and re-encrypts the
vault header. **Rejects `--session-token`**: rotation invalidates
outstanding tokens (their sealed key no longer matches).

### generate

Print a random secret to stdout and its true entropy estimate to
stderr — so `origin-pass generate | origin-pass add … --secret-stdin`
never pollutes the secret. Passwords use the SDK CSPRNG with rejection
sampling (no modulo bias); passphrases draw from a 256-word list
(exactly 8 bits/word). Entropy is computed from the *actual* charset /
list size, never a nominal claim.

### tokens

Manage the persisted session-token store (`~/.origin/tokens/`, bare
names resolve there; `--dir` overrides). See session-tokens(7) for the
file format and threat model.

- **list** — table (name, token id, created/expires UTC, time
  remaining, auto-rotate policy, vault, status) with a summary line on
  stderr; `--format json` adds `expires_in_secs` and the auto-rotate
  threshold/ttl. `--remaining <mins>` filters to tokens expiring
  within the window and **exits 1 when any match, 0 otherwise** —
  a scriptable "needs attention" signal that works with `--format json`
  too (empty array + exit 0 when nothing matches).
- **revoke <name>** — delete one token (missing token is an error).
- **rotate <name> [--ttl]** — refresh in place with a **new** bearer
  key + id + expiry; no passphrase while valid.
- **renew <name> [--ttl]** — extend expiry while keeping the **same**
  bearer key, id, nonce, and seal.
- **revoke-all [--expired-only]** — clear the store (or just expired).
- **prune** — revoke expired + unreadable (corrupt) tokens, reporting
  each one; lenient success when nothing to do.

## EXIT STATUS

`0` on success. `1` on error (bad passphrase, missing entry, tampered
vault/token, …), or — for `tokens list --remaining <mins>` — when at
least one token matches the expiry window.

## ENVIRONMENT

- `HOME` — used for `~/` expansion and the default token store.
- `ORIGIN_PASS_TOKEN` — fallback session token for any command that
  accepts `--session-token` (explicit flags win; bare names resolve
  into the store just like the flag).

## SECURITY NOTES

- The vault passphrase and entry secrets never appear in argv.
- Session tokens are bearer credentials — possession unlocks the vault
  until expiry. Protect them like SSH keys.
- The OCRA replay ledger is a convenience guard, not a security
  boundary (an attacker who can read the ledger can delete it).
- Prefer `--auto-clear` when displaying codes on a shared terminal.

## EXAMPLES

```bash
# Create a vault and add a password:
origin-pass init --vault ~/.origin/pass.vault --tier standard
origin-pass generate | origin-pass add github --type password \
    --secret-stdin --passphrase-file ~/.pw

# Add a TOTP entry and get a code:
origin-pass add github-2fa --type otp --secret-file /tmp/key.b32 \
    --passphrase-file ~/.pw
origin-pass code github-2fa --vault ~/.origin/pass.vault --passphrase-file ~/.pw

# Unlock once, then script without the passphrase:
origin-pass unlock --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw --session-token work --auto-rotate
ORIGIN_PASS_TOKEN=work origin-pass get github --vault ~/.origin/pass.vault

# Cleanup:
origin-pass tokens list --remaining 15        # alert if any expire soon
origin-pass tokens prune                      # drop expired + corrupt
origin-pass lock-all                          # end the session strictly
```

## SEE ALSO

`docs/session-tokens.md` (token file format, lifecycle, threat model),
`../DESIGN.md` (vault format, KDF tiers, implementation sequence),
`origin-identity` (sibling `~/.origin` store conventions).
