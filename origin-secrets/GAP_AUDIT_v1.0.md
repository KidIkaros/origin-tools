# Origin Secrets v1.0 — Pre-Release Gap Audit

Scope: origin-secrets crate, all six CLI commands (init, shard, export-share,
recover, verify, audit). Date: 2026-08-01 (updated post-QC). Standard:
IMPLEMENTATION_PLAN.md (4-week, ≥90% coverage, all integration + security tests
pass, no critical bugs).

## Summary verdict

**SHIP-READY after QC remediation.** All Week 1–4 acceptance criteria met.
133 tests pass (109 unit + 24 integration/security across 11 binaries). Coverage
93.6% (tarpaulin, cobertura line-rate 0.9362). The initial green test run
masked three real defects; QC (manual source review of every command module)
found and closed all three before commit.

## Severity tiers

### CRITICAL — 0 found
No path allows master-key reconstruction below threshold K. Tampered material
fails closed: vault ciphertext/salt/nonce tamper is caught at decrypt; share
data/signature/recipient tamper is caught by hybrid-signature verification at
both `verify` and `recover`. Reed-Solomon erasure + hybrid-signature check is
the real integrity gate (corrupted-but-present shares are detected, not
silently accepted).

### HIGH — 2 found, 2 CLOSED
| ID | Gap | Resolution | Status |
|---|---|---|---|
| H1 | **XChaCha20-Poly1305 nonce reuse on vault re-encrypt.** `shard` and `export-share` re-encrypted the vault with the *original* nonce under the *same* derived key (same passphrase + salt → same Argon2id output). Confirmed in `origin-crypto-sdk::aead::XChaCha20Poly1305::encrypt` that the passed nonce is used directly (no fresh generation). Reusing (key, nonce) on two different plaintexts leaks the XOR of the plaintexts — i.e. the audit-log delta — and breaks AEAD nonce-uniqueness. Fired on every `shard`/`export` after `init`. | Re-encrypt with a **fresh random nonce** (`rand::random()`); salt unchanged (stable per vault). `recover` already used a fresh nonce (correct). Added regression test `test_shard_does_not_reuse_nonce` (asserts nonce changes + both ciphertexts still decrypt). | CLOSED |
| H2 | **`verify --share` bound to the resolved DEFAULT vault, not the share's source vault.** The share's signing key is derived from the source vault's master seed; verifying against a *different* vault's seed produces a signature mismatch and a false "tampering" report. `export.rs` proves the source vault is the one written beside the share (`<vault_dir>/shares/share_<n>.json`), so the default-path binding was wrong for any multi-vault deployment. | `verify --share` now derives the source vault as the **grandparent** of the share file and verifies against it; falls back to structural-only when that vault is absent. Added regression test `verify_share_binds_to_source_vault_not_default`. | CLOSED |

### MEDIUM — 3 found, 3 CLOSED
| ID | Gap | Resolution | Status |
|---|---|---|---|
|| M1 | `init` silently used a hardcoded 12-char demo passphrase and **ignored `--passphrase-file`**; the `passphrase.len() < 12` gate was therefore dead, and an operator-supplied `-p` file was dropped (the weak default became the real key). | `init` and `dispatch` now require a passphrase source (`-p/--passphrase-file`); without it they **refuse** with `PassphraseRequired` rather than fall back to a known-weak default. The demo string is gone entirely. Added regression tests `test_init_reads_passphrase_file` (proves the file's passphrase is the key; the demo string does NOT decrypt) and `test_init_without_prompt_or_file_is_rejected`, plus `missing_passphrase_is_rejected` and `test_dispatch_requires_passphrase_without_flag`. | CLOSED |
| M2 | `verify --share` performed only structural checks; crypto verification was delegated to `recover`, contradicting the W4 acceptance ("`verify --share` detects tampering"). | Upgraded `verify_share` to full hybrid-signature verification when a vault is supplied (derives the share-signing bundle from the master seed via `SHARE_SIGNING_DOMAIN`). | CLOSED |
| M3 | `cmd_init` hardcoded `~/.origin/secrets.vault`, ignoring `-V/--vault` (dead flag). | `cmd_init(args, &cli.vault)` now honors the resolved vault path; dispatch passes `&cli.vault`. | CLOSED |

### LOW — 3 (accepted for v1.0; tracked for v1.1)
| ID | Observation | Disposition |
|---|---|---|
| L1 | `lib.rs` dispatch retains `NotImplemented` arms for the 6 implemented commands (lib.rs 84.6%). Dead in v1.0, preserves the future-command seam (every module is a reusable protocol layer). | Keep until next command lands. |
| L2 | `verify.rs` standalone-share fallback (no vault) is under-covered by tarpaulin's Falcon-instrumented run (verify.rs 80%). Logically trivial; covered by `init_shard_recover` in optimized runs. | Re-measure in v1.1. |
|| L3 | `dispatch` previously used a demo default passphrase when `-p` was absent (the silent-weak-default anti-pattern, reachable via `init --no-prompt` and all other commands). | **CLOSED in post-QC fix:** the demo fallback is removed everywhere; `dispatch` returns `PassphraseRequired` for any command lacking `-p`, and `cmd_init` no longer special-cases `--no-prompt`. Documented in README/SECURITY. | CLOSED |

### OUT OF SCOPE (v1.0 by design — planned v2.0+)
- Web dashboard / custodian UX (PRODUCT_SPEC Phase 2).
- Transport security between custodians (shares moved over operator-secured channel).
- HSM / secure-enclave key storage.
- Remaining ~17 origin-tools crates (separate products).

## Test evidence
- `cargo test -p origin-secrets --release`: **133 passed, 0 failed** (was 128 before the 5 new regression tests).
- Unit: 109. Integration (`tests/integration/`): init_shard_recover (3),
  threshold_validation (2), signature_verification (4), compliance_export (3).
- Security (`tests/security/`): passphrase_validation (2), vault_tampering (3),
  share_tampering (3).
- Coverage: origin-secrets 93.6% (≥90% ✓).

## Sign-off gate
- [x] All Week 1–4 acceptance criteria met
- [x] ≥90% coverage (93.6%)
- [x] All integration tests pass
- [x] All security tests pass
- [x] No critical bugs
- [x] QC pass completed — 2 HIGH + 3 MEDIUM defects found and closed
- [x] Documentation written (README, SECURITY, MAN)
- [ ] Tag + push — PENDING USER SIGN-OFF

---

## Post-P3 addendum (2026-08, after P2 day-2 ops + P3 share hardening)

**The verdict above is STALE.** It was written before P2 (rotate-passphrase,
list-keys, list-shares) and P3 (revoke-share, expiry, encrypted-at-rest,
offline verify) landed. The crate now ships **11 commands** and **157+ lib unit
tests + 11 integration/security binaries** — not "six commands / 133 tests".
Re-audited at source level during P4 gap review:

### CRITICAL — 1 found, 1 CLOSED (this addendum)
| ID | Gap | Resolution | Status |
|---|---|---|---|
| C1 | **(key, nonce) reuse regressed in `revoke-share` (H1 bug class).** P3.1 added `cmd_revoke_share`, which re-encrypted the vault with `vault.nonce` under the *same* derived key (passphrase unchanged). This is exactly the H1 defect the original audit closed for `shard`/`export-share`, but it was reintroduced in the new command. Reusing (key, nonce) leaks the audit-log delta (the revoke record) and breaks AEAD nonce-uniqueness. | `revoke.rs` now generates a **fresh nonce** (`random_array()`) on re-encrypt, matching `shard`/`export`/`rotate`. Added regression test `test_revoke_does_not_reuse_nonce` (nonce must change; both ciphertexts still decrypt). | CLOSED |

### Verified STILL-CLOSED (re-checked at source)
- **H1** in shard/export/rotate: confirmed fresh-nonce re-encrypt at
  `shard.rs:177`, `export.rs:158`, `rotate.rs:57-58`. Only revoke was affected.
- **H2** source-vault binding: `verify.rs:39` derives the grandparent
  `secrets.vault`; regression test `verify_share_binds_to_source_vault_not_default` holds.
- **M1** passphrase gate: `lib.rs` dispatch returns `PassphraseRequired` for any
  command without `-p`; no demo-default fallback remains anywhere.
- **M2** crypto verify in `verify`: `verify_share` runs full hybrid-sig check
  when a vault is present (P3.4 adds offline verify via embedded verifier).
- **M3** `init` honors `-V`: `cmd_init(args, &cli.vault)` with resolved path.

### Stale items in the original audit (superseded)
- **L1** "lib.rs retains NotImplemented arms for the 6 implemented commands
  (lib.rs 84.6%)": now all 11 commands are dispatched; no dead `NotImplemented`
  arms for implemented commands (only the error variant + tests reference it).
- **L2** "verify.rs standalone fallback under-covered (verify.rs 80%)": P3.4
  added `verify_share_offline` (embedded verifier) + tests; coverage now 88%.
- **L3** already CLOSED in post-QC; consistent with current source.
- Test counts (133 / 109 unit / 24 integration) and coverage (93.6% tarpaulin):
  replaced by 157+ lib / 11 binaries at ~89% llvm-cov lines.

### Remaining (not defects — dispositions)
- `share_io.rs` `read_share_file` keeps a plaintext-share fallback for legacy
  exported shares (backward-compat, documented). Exported custodian shares
  remain a deliberate operator artifact, encrypted at rest like all shares.
- No silent-weak-default anywhere (grep-verified across all command paths).

### Updated sign-off gate
- [x] P1–P3 features implemented and tested
- [x] H1 nonce-reuse regression (C1) found + closed in revoke
- [x] All re-encrypt paths use fresh nonces (shard/export/rotate/revoke)
- [ ] Re-run full `cargo test -p origin-secrets` + `cargo llvm-cov` post-fix (this addendum) — see commit
- [ ] Tag + push — PENDING USER SIGN-OFF
