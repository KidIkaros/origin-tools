# Changelog — origin-provenance

## 0.4.5 (2026-09-21) — timestamp skew fix (writer/verifier contract)

- **Bug fix (found by live same-second dogfood):** `create` + `append` in
  one wall-clock second made amendment H's strictly-increasing rule stamp
  `last + 1` — a timestamp one second in the FUTURE — which the verifier's
  step 6 then rejected: an author could not verify their own just-written
  manifest until the clock ticked. Step 6 now accepts checkpoints up to
  `VerifyPolicy::max_future_skew_secs` (new field, default 2s,
  verifier-owned per ZTNA) beyond verifier-local now; futures beyond skew
  still fail `manifest-invalid (timestamp)`. Regression tests:
  `same_second_batch_edit_verifies_immediately_within_skew`,
  `future_beyond_skew_is_still_timestamp_failure`,
  `default_policy_carries_two_second_skew` (111 tests).

## 0.4.4 (2026-09-21) — revocation integration (P-05)

- Verify engine step 7 wired to the origin-attest revocation journal:
  `is_revoked(signer_fingerprint)` in the normative order, producing the
  distinct `manifest-invalid (signer-revoked, as of journal tip T)` verdict.
- Integrity-first honesty (spec §7): `verify_integrity()` AND record
  signature checks run BEFORE any revocation result is used. A broken
  chain, unparseable file, or forged record ⇒ verification PROCEEDS with
  the verbatim footer warning `WARNING: journal integrity check failed —
  revocation status unreliable.` — never a false "revoked", never a false
  "clean". Journal absence is stated as NOT checked (absence is not
  evidence of absence).
- Revoked attestors are excluded from the distinct-attestor threshold
  count (degraded-intact disclosure unchanged).
- `as of` composes the journal tip: min(latest checkpoint, last journal
  record time) whenever a journal is present — a claim is only as fresh
  as the most recent revocation sweep.
- Default journal path: `revocations.json` next to the asset
  (`--journal`-overridable via `VerifyPolicy.journal_path`).
- Revocation target convention: `SHA3-256(signer_or_attestor_fingerprint_hex)`
  (`verify::revocation_target`); journal-side identity is the journal-native
  Falcon pk fingerprint (origin-attest `revoker_fingerprint_hex`).
- Discovery + C2PA annotation channel (0.4.3 line, shipped in this
  workspace series): watermark fallback discovery, hand-rolled minimal
  C2PA reader, annotation orthogonal to verdicts.

## 0.4.3 and earlier

- See workspace history: encoding recipes (P-01), OPM model + CLI
  (P-02), verify engine core (P-03), discovery + C2PA (P-04).
