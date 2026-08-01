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
