# `origin-pass`

Encrypted password vault + 2FA authenticator (TOTP/HOTP/OCRA) built on
[`origin-crypto-sdk`](https://github.com/ikaros-digital/origin-crypto-sdk).

> **Status**: v0.5.0 — fully functional CLI. All commands implemented.

See `../DESIGN.md` for the full design specification (vault format, threat
model, implementation sequence). `docs/origin-pass.1.md` is a
man-page-style reference for the whole CLI; `docs/session-tokens.md`
covers the token file format and threat model in depth.

## Features

- **Password vault**: Argon2id KDF (Nano/Standard/Sovereign tiers),
  ChaCha20-BLAKE3 AEAD encryption, per-entry keys via HKDF-SHA3-256.
- **Password generator**: `generate` produces random passwords (length +
  charset exclusions) or word-based passphrases, with honest entropy
  reporting on stderr (exact bits, computed from the actual charset /
  wordlist sizes; the wordlist is 256 words = 8 bits/word).
- **Session tokens**: `unlock --session-token <path>` writes a persisted
  bearer token (mode 0600, `--session-ttl` default 8h) that lets any
  subsequent command unlock without the passphrase; `lock --session-token`
  revokes it. Tokens live in the managed store `~/.origin/tokens/` (a
  bare name like `--session-token work` resolves there) and the `tokens`
  command lists, revokes, rotates, renews, prunes, or bulk-revokes
  them: `tokens list [--format json] [--remaining <mins>]` (with a
  time-remaining column, an auto-rotate column, a valid/expired/
  unreadable summary line, and a scriptable `--remaining` filter —
  JSON mode included — that exits 1 when near-expiry tokens exist),
  `tokens revoke <name>`, `tokens rotate <name> [--ttl <secs>]`
  (refresh the bearer key + expiry without the passphrase),
  `tokens renew <name> [--ttl <secs>]` (extend expiry while keeping
  the same bearer key), `tokens revoke-all [--expired-only]`,
  `tokens prune` (drop expired + unreadable tokens, reporting each
  one), plus `lock-all` for a strict "nothing left" session end
  (optionally scoped with `--vault <path>`). `$ORIGIN_PASS_TOKEN` can supply the token to any
  command instead of `--session-token` (explicit flags win), and
  `unlock --auto-rotate` refreshes a token in place whenever a command
  uses it with less than `--auto-rotate-threshold` (default 15m) of
  lifetime left, so long-running workflows never die mid-session. The
  token file is the credential — protect it like an SSH key. See
  `docs/session-tokens.md` for the file format and threat model.
- **TOTP/HOTP**: RFC 6238 / RFC 4226 compliant. SHA-1, SHA-256, SHA-512.
  Configurable period and digits. HOTP counter auto-increments and persists.
- **OCRA**: RFC 6287 challenge-response with full OCRASuite support:
  `add --type ocra --suite "OCRA-1:HOTP-SHA1-6:QN08"` stores the key +
  suite; `code --ocra --challenge <q>` validates the challenge against the
  suite (QN/QH/QA formats), handles counter (auto-increment + persist) and
  timestamp (T<num><unit>) suites, and supports PIN suites (`--pin`). A
  bounded replay-nonce ledger (`<vault>.ocra-ledger.json`) refuses to
  re-issue a response for an already-used challenge (`--force` overrides).
- **QR provisioning**: `export-qr` renders otpauth:// URIs as terminal QR
  codes. `import-qr` parses them back into vault entries.
- **Atomic writes**: vault persistence uses tmp-file + rename + fsync.
- **Zeroizing**: master key and secrets scrubbed on drop.

## Quick start

```bash
# 1. Initialize a new vault:
origin-pass init --vault ~/.origin/pass.vault --tier nano

# 2. Generate a strong password (entropy reported on stderr):
origin-pass generate --length 24

# 3. Generate a memorable passphrase (8 words × 8 bits = 64 bits):
origin-pass generate --passphrase --words 8

# 4. Add a password entry (pipe a generated secret straight in):
origin-pass generate | origin-pass add github.com --type password \
    --secret-stdin \
    --passphrase-file ~/.pw-demo

# 5. Add a TOTP entry:
origin-pass add github-2fa --type otp \
    --secret-file /tmp/totp-secret.b32 \
    --passphrase-file ~/.pw-demo

# 6. Add an HOTP entry:
origin-pass add bank-token --type otp --hotp \
    --secret-file /tmp/hotp-secret.b32 \
    --passphrase-file ~/.pw-demo

# 7. Add an OCRA challenge-response entry (RFC 6287 suite):
origin-pass add bank-ocra --type ocra \
    --suite "OCRA-1:HOTP-SHA1-6:QN08" \
    --secret-file /tmp/ocra-key.bin \
    --passphrase-file ~/.pw-demo

# 8. List entries (no secrets shown):
origin-pass list --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 9. Retrieve a password:
origin-pass get github.com --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 10. Compute a TOTP/HOTP code:
origin-pass code github-2fa --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 11. Compute an OCRA challenge-response code (replay-guarded):
origin-pass code bank-ocra --vault ~/.origin/pass.vault \
    --ocra --challenge 12345678 \
    --passphrase-file ~/.pw-demo

# 12. Unlock once, then use the vault without the passphrase (8h TTL):
origin-pass unlock --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo \
    --session-token pass
origin-pass get github.com --vault ~/.origin/pass.vault \
    --session-token pass

# 12b. Or let $ORIGIN_PASS_TOKEN carry the token (no flag per call;
#      bare names resolve into ~/.origin/tokens just like the flag):
export ORIGIN_PASS_TOKEN=pass
origin-pass get github.com --vault ~/.origin/pass.vault

# 12c. Auto-rotate on use: refresh the token whenever a command uses it
#      with under 15 minutes of lifetime left:
origin-pass unlock --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo \
    --session-token pass --auto-rotate

# 13. Revoke the session token when done:
origin-pass lock --session-token ~/.origin/pass.token

# 13a. Or extend it without the passphrase (new bearer key + expiry):
origin-pass tokens rotate pass --ttl 86400

# 13b. Or manage tokens in the store: list them (table shows time
#      remaining + auto-rotate + a summary line; JSON adds
#      expires_in_secs and the auto-rotate threshold/ttl)…
origin-pass tokens list
origin-pass tokens list --format json

# 13b′. Alert when any token expires within 15 minutes (exit code 1
#       if so — handy for cron/shell checks):
origin-pass tokens list --remaining 15

# 13c. …revoke one by bare name…
origin-pass tokens revoke pass

# 13d. …or revoke everything (optionally only expired):
origin-pass tokens revoke-all
origin-pass tokens revoke-all --expired-only

# 13e. …or end the session strictly — error if nothing was revoked:
origin-pass lock-all
origin-pass lock-all --vault ~/.origin/pass.vault   # per-vault scope

# 13e′. Clean up expired + corrupt tokens (reports each one):
origin-pass tokens prune

# 13f. Extend a token without changing its bearer key (same key, new
#      expiry — unlike rotate, which mints a fresh key):
origin-pass tokens renew pass --ttl 86400

# 14. Import from an otpauth:// URI:
origin-pass import-qr --vault ~/.origin/pass.vault \
    "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme" \
    --passphrase-file ~/.pw-demo

# 15. Export as QR code:
origin-pass export-qr github-2fa --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 16. Change passphrase (invalidates session tokens — not allowed with one):
origin-pass change-passphrase --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-old --new-passphrase-file ~/.pw-new
```

## Security notes

- Secrets are never passed via argv (use `--secret-file` or `--secret-stdin`).
- The vault passphrase is sourced from `--passphrase-file` or an interactive
  TTY prompt (never argv).
- HOTP counters auto-increment after each `code` call and persist to disk.
- OCRA counter suites (`C-`) auto-increment their stored counter per use;
  an explicit `--counter` is a verification call and does not advance it.
- The OCRA replay-nonce ledger refuses to re-issue a response for an
  already-used challenge (`--force` opts out). It lives at
  `<vault>.ocra-ledger.json` and is a convenience guard, not a security
  boundary (an attacker with the ledger file can delete it).
- `generate` prints the secret to stdout and the entropy estimate to
  stderr, so piping into `add --secret-stdin` never pollutes the secret.
- Session tokens are **bearer credentials** (like an SSH private key):
  possession of the file unlocks the vault until the token expires. The
  file is written mode 0600; `lock --session-token` revokes it. File
  format, lifecycle, and threat model are documented in
  `docs/session-tokens.md`.
- `--auto-clear <secs>` overwrites the terminal after displaying a code.

## Testing

```bash
cargo test -p origin-pass
```

97 unit tests (RFC 4226/6238/6287 vectors, suite parser, session tokens,
token store + `tokens`/`lock-all` commands + rotation + renewal +
auto-rotate + remaining-filter predicate + prune, replay ledger,
generator, vault round-trips, CLI dispatch) + 18 shell-out integration
tests (real binary, real clap parsing).

## License

Apache-2.0 (matches `origin-crypto-sdk`).
