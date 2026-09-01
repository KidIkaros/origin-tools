# origin-pass(1) — SESSION TOKENS

## NAME

session tokens — persisted vault unlock credentials for `origin-pass`

## SYNOPSIS

```
origin-pass unlock --vault <vault> --passphrase-file <pw> --session-token <name> [--session-ttl <secs>] [--auto-rotate]
origin-pass tokens list [--dir <store>] [--format table|json] [--remaining <mins>]
origin-pass tokens revoke <name> [--dir <store>]
origin-pass tokens rotate <name> [--ttl <secs>] [--dir <store>]
origin-pass tokens renew <name> [--ttl <secs>] [--dir <store>]
origin-pass tokens revoke-all [--expired-only] [--dir <store>]
origin-pass tokens prune [--dir <store>]
origin-pass lock --session-token <name>
origin-pass lock-all [--dir <store>] [--vault <path>]
origin-pass <vault-command> --vault <vault> --session-token <name>
ORIGIN_PASS_TOKEN=<name> origin-pass <vault-command> --vault <vault>
```

## DESCRIPTION

A session token lets every `origin-pass` command unlock a vault **without
the passphrase** for a limited time. It is a **bearer credential**: whoever
holds the token file can unlock the vault until the token expires —
exactly like an SSH private key. Protect it accordingly.

Tokens live in the managed store `~/.origin/tokens/` (override with
`--dir` on `tokens`/`lock-all`, or pass an explicit path to
`--session-token` on any command). A **bare name** such as `work`
resolves to `~/.origin/tokens/work.token`; anything with a path
separator, a `./` prefix, or a `~/` prefix is treated as a literal
path.

## TOKEN FILE FORMAT

A token file is a JSON document, written atomically (tmp + rename) with
mode `0600` on Unix. Format version is 1. Tokens written before
auto-rotate existed simply lack the `auto_rotate` field (serde defaults).

```
{
  "version": 1,
  "token_id":        "<32 hex chars, random>",   // uniqueness / rotation marker
  "created_at":      <unix seconds>,
  "expires_at":      <unix seconds>,
  "nonce":           "<48 hex chars, random 24-byte nonce>",
  "token_key":       "<64 hex chars, random 32-byte bearer key>",
  "sealed_master_key": "<hex ciphertext>",
  "vault":           "<vault path recorded at unlock time, informational>",
  "auto_rotate":     {"threshold": 900, "ttl": 3600}   // optional
}
```

`sealed_master_key` is the vault master key encrypted with
**ChaCha20-BLAKE3** (AEAD) under `token_key` with application-bound
additional data (`origin-pass session token v1`). Consequences:

- The master key **never appears in cleartext on disk** — a hexdump of
  the file shows only ciphertext.
- **Tampering is detected on read** (AEAD tag failure) rather than
  silently producing a garbage key, so the command fails loudly.
- Truncation, invalid hex, unknown `version`, or an unparseable file are
  all distinct, descriptive errors.

## STORE LAYOUT

```
~/.origin/tokens/
├── work.token      # bare name "work"
├── home.token      # bare name "home"
└── <anything>.token
```

Only `*.token` files are managed. `tokens list` surfaces corrupt or
foreign files as `unreadable` (so they can be revoked) instead of
failing the listing; `tokens revoke-all` and `lock-all` never touch
non-`.token` files. A store directory that does not exist yet is an
empty listing, not an error.

## COMMANDS

### unlock — mint a token

`unlock --session-token <name>` verifies the passphrase, then writes a
token sealing the master key. `--session-ttl <secs>` (default 8h) sets
the lifetime; the file is written mode `0600`.

`--auto-rotate` attaches a rotation policy to the token: whenever any
command uses the token and less than `--auto-rotate-threshold` (default
15 minutes) of lifetime remains, the token is refreshed in place
(new bearer key + id + nonce + expiry) — a side effect of use, so a
long-running workflow never dies mid-session. `--auto-rotate-ttl <secs>`
sets the fresh lifetime (default: `--session-ttl`).

### tokens list — inspect

Shows name, truncated token id, created/expires (UTC), time remaining
(`3d 4h`, `2h 5m`, `45m`, `10s`, or `expired`), the auto-rotate policy
(`15m→8h` = threshold→fresh ttl, or `-`), bound vault, and status
(`valid` / `expired` / `unreadable`). A summary line on stderr counts
valid/expired/unreadable. `--format json` emits the full metadata as a
JSON array, adding `expires_in_secs` (null for unreadable),
`auto_rotate`, `auto_rotate_threshold`, and `auto_rotate_ttl` for shell
parsing. Listing reads only file metadata — nothing is unsealed.

`--remaining <mins>` filters the listing to tokens expiring within the
window (expired tokens always match; unreadable files are excluded) and
**exits 1 when at least one matches, 0 otherwise** — a scriptable
"needs attention" signal for cron/shell checks. The summary line is
suppressed in filtered mode; the exit code is the signal. The semantics
are identical with `--format json`: matches → a JSON array of matching
tokens and exit 1; no matches → `[]` and exit 0.

### tokens revoke — revoke one

Deletes a single token. Bare names resolve into the store. Revoking a
missing token is an error (surfaces typos) rather than a silent no-op.

### tokens rotate — refresh in place

Unseals the master key from the **current** token (no passphrase needed
while it is valid), then writes a fresh token to the same path: new
`token_id`, new `token_key`, new nonce, new expiry. The vault binding is
preserved. `--ttl <secs>` sets the new lifetime; without it, the
original lifetime is preserved.

Rotating an **expired** token is refused — you must re-mint with
`unlock --session-token` and the passphrase.

> Rotation refreshes the token at its path. It does **not** revoke
> copies of the old file: a copy made earlier still contains a valid
> sealed key with its own expiry. To invalidate a leaked copy, revoke
> the token (delete the file) and mint a new one.

### tokens renew — extend without a new key

`tokens renew <name> [--ttl <secs>]` pushes `expires_at` forward while
keeping the **same** bearer key, token id, nonce, and AEAD seal — only
the expiry changes. Use this when the current key is trusted and you
only need more time (say, extending an agent session). `--ttl` sets the
new window from now (default: the token's lifetime span from creation);
the auto-rotate policy is preserved. Contrast `tokens rotate`, which
mints a fresh bearer key. Like rotate, it needs no passphrase while the
token is valid and refuses expired tokens.

### tokens prune — clean up dead tokens

`tokens prune` revokes expired **and** unreadable (corrupt/foreign)
tokens — dead weight that can never unlock anything — while never
touching valid tokens. It reports each pruned file (`pruned: name
(expired|unreadable)`) and a final count, and succeeds leniently with
`nothing to prune` when there is nothing to do.

### tokens revoke-all / lock-all — revoke everything

`tokens revoke-all [--expired-only]` clears the whole store (or only
expired tokens). `lock-all [--vault <path>]` does the same but errors
when nothing was revoked (matching `lock`'s strictness), and `--vault`
filters to tokens bound to one vault. Unreadable/corrupt tokens are
always revoked by both.

### Environment variable

`$ORIGIN_PASS_TOKEN` supplies the token to any token-consuming command
(`get`, `list`, `add`, `rm`, `code`, `export-qr`, `import-qr`, `lock`)
instead of `--session-token` — handy in scripts that don't want to name
a token per invocation. **Explicit flags always win**: a `--session-token`
or `--passphrase-file` flag overrides the env var. The value goes
through the same resolution as the flag, so a bare store name works
(`ORIGIN_PASS_TOKEN=work` ≡ `--session-token work`).

### lock — revoke a single token

`lock --session-token <name>` is the "end the session" verb: it revokes
the token file (bare names resolve into the store). Since v0.5 there is
no in-process vault state to drop, so a bare `lock` errors with
guidance.

## THREAT MODEL

**What possession means.** The token file is the credential. An attacker
who reads the file can unlock the vault for the token's remaining
lifetime — no passphrase, no second factor. This is equivalent to
stealing `~/.ssh/id_ed25519`.

**Mitigations.**

| Threat | Mitigation |
| --- | --- |
| Token file leaked on disk | Mode `0600`; master key never in cleartext (AEAD seal) |
| Token file stolen | Bounded lifetime (`--session-ttl`, default 8h); revoke on suspicion |
| Token file modified in place | AEAD tag check fails the read with a clear error |
| Token file copied | Nothing short of revoking the token invalidates copies — delete it and re-mint |
| Expired token replayed | `expires_at` is checked on every read |
| Token store read by another user | Store dir under `~/.origin`, files `0600` |

**What a token is NOT.** It is not a second factor (possession alone
unlocks). It does not survive `change-passphrase` — rotating the
passphrase re-derives the master key, so `change-passphrase` refuses
`--session-token` and any outstanding tokens are invalidated (their
sealed key no longer matches the new master key).

**Unsealing only happens in memory.** The plaintext master key exists
only inside the process, is wrapped in `Zeroizing`, and every local
copy (nonce, token key, plaintext buffer) is scrubbed before the read
returns.

**Auto-rotate trades a little control for uptime.** A token with an
`auto_rotate` policy refreshes itself (new bearer key, new id, extended
expiry) the first time it is used below its threshold — the refresh
uses the token's own sealed key, so no passphrase is involved, but it
means a used token can keep itself alive indefinitely as long as it is
exercised at least once per threshold window. That is the intent for
long-running agents; for a strictly time-boxed credential, mint without
`--auto-rotate`. The env var is no weaker than the flag — both are just
ways to point at the same bearer file.

## EXAMPLES

```bash
# Mint an 8-hour token by bare name:
origin-pass unlock --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw --session-token work

# Use it from scripts without the passphrase:
origin-pass get github --vault ~/.origin/pass.vault --session-token work

# See what's valid:
origin-pass tokens list
origin-pass tokens list --format json

# Extend a session without re-entering the passphrase:
origin-pass tokens rotate work --ttl 86400

# …or keep the exact same bearer key and just buy more time:
origin-pass tokens renew work --ttl 86400

# Alert when any token expires within 15 minutes (exit 1 if so;
# --format json gives a parseable array with the same exit semantics):
origin-pass tokens list --remaining 15 || echo "tokens expiring soon"
origin-pass tokens list --remaining 15 --format json >/dev/null || notify

# Drop expired + corrupt tokens, reporting each one:
origin-pass tokens prune

# Mint a token that refreshes itself on use (for long-running agents):
origin-pass unlock --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw --session-token agent \
    --auto-rotate --auto-rotate-threshold 900 --auto-rotate-ttl 86400

# Scripts: carry the token in the environment instead of a flag:
export ORIGIN_PASS_TOKEN=work
origin-pass get github --vault ~/.origin/pass.vault

# End a session:
origin-pass lock --session-token work
origin-pass lock-all          # or: lock-all --vault ~/.origin/pass.vault
```

## SEE ALSO

`origin-pass(1)`, `../DESIGN.md` (vault format, KDF tiers, threat
model), `origin-identity` (same `~/.origin` store convention).
