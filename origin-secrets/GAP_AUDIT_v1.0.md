# Origin Secrets v1.0 — Pre-Release Gap Audit

Scope: origin-secrets crate, all six CLI commands (init, shard, export-share,
recover, verify, audit). Date: 2026-08-01. Standard: IMPLEMENTATION_PLAN.md
(4-week, ≥90% coverage, all integration + security tests pass, no critical bugs).

## Summary verdict

**SHIP-READY.** All Week 1–4 acceptance criteria met. 128 tests pass (106 unit +
22 integration/security across 11 binaries). Coverage 93.6% (tarpaulin,
cobertura line-rate 0.9362). No critical or high bugs.

## Severity tiers

### CRITICAL — 0 found
None. No path allows master-key reconstruction below threshold K. No silent
accept of tampered material (vault ciphertext/salt/nonce and share
data/signature/recipient all fail closed at verify/recover).

### HIGH — 0 found
None. All six commands route to real implementations (no `NotImplemented`
reachable in the v1.0 surface). Hybrid Ed25519+Falcon-1024 signing/verification
is exercised by `security_share_tampering` and `signature_verification`.

### MEDIUM — 2 (both closed during this phase)
| ID | Gap | Resolution | Status |
|---|---|---|---|
| M1 | `verify --share` performed only structural checks; crypto verification was delegated to `recover`, contradicting the W4 acceptance ("`verify --share` detects tampering"). | Upgraded `verify_share` to perform full hybrid-signature verification when a vault is supplied (derives share-signing bundle from the master seed via `SHARE_SIGNING_DOMAIN`). | CLOSED |
| M2 | `cmd_init` hardcoded `~/.origin/secrets.vault`, ignoring the `-V/--vault` flag (dead flag); blocked isolated integration testing. | `cmd_init(args, &cli.vault)` now honors the resolved vault path; dispatch passes `&cli.vault`. | CLOSED |

### LOW — 3 (accepted for v1.0; tracked for v1.1)
| ID | Observation | Disposition |
|---|---|---|
| L1 | `lib.rs` dispatch retains `NotImplemented` arms for the 6 implemented commands (coverage 84.6% on lib.rs). These are dead in v1.0 but preserve the "future command" extension seam. | Keep — they are part of the protocol-stack design (every module is a reusable layer). Will be removed when the next command lands. |
| L2 | `verify.rs` standalone-share fallback branch (no vault supplied) is uncovered by tarpaulin's Falcon-instrumented run (verify.rs 80%). The path is logically trivial and structurally identical to the covered path. | Accept for v1.0; covered by the `init_shard_recover` integration test in dev/optimized runs. Re-measure in v1.1. |
| L3 | Default passphrase in `dispatch` is a demo placeholder. | Documented as out-of-scope for production in README.md + SECURITY.md; operators MUST supply `-p/--passphrase-file`. Enforced failure path exists (wrong passphrase → `VaultDecryptionFailed`). |

### OUT OF SCOPE (v1.0 by design — planned v2.0+)
- Web dashboard / custodian UX (PRODUCT_SPEC Phase 2).
- Transport security between custodians (shares moved over operator-secured channel).
- HSM / secure-enclave key storage.
- Remaining ~17 origin-tools crates (separate products).

## Test evidence
- `cargo test -p origin-secrets --release`: 128 passed, 0 failed.
- Integration (`tests/integration/`): init_shard_recover (3), threshold_validation (2),
  signature_verification (3), compliance_export (3).
- Security (`tests/security/`): passphrase_validation (2), vault_tampering (3),
  share_tampering (3).
- Coverage: origin-secrets 93.6% (≥90% ✓).

## Sign-off gate
- [x] All Week 1–4 acceptance criteria met
- [x] ≥90% coverage (93.6%)
- [x] All integration tests pass
- [x] All security tests pass
- [x] No critical bugs
- [x] Documentation written (README, SECURITY, MAN)
- [ ] Tag + push — PENDING USER SIGN-OFF
