# Domain Pitfalls

**Domain:** Digital Wallet with Origin Tools
**Researched:** 2026-08-14

## Critical Pitfalls

Mistakes that cause rewrites or major issues.

### Pitfall 1: Reimplementing Existing Cryptography
**What goes wrong:** Writing custom signing, encryption, or hashing instead of using `origin-crypto-sdk`.
**Why it happens:** "Not invented here" syndrome, misunderstanding existing capabilities.
**Consequences:** Security vulnerabilities, bugs, wasted effort, duplicated work.
**Prevention:** Always check existing crates first; use `origin-crypto-sdk` for all crypto operations.
**Detection:** If you're writing cryptographic code, you're likely reimplementing something.

### Pitfall 2: Cross-Domain Key Reuse
**What goes wrong:** Using the same key for different purposes (signing, encryption, different chains).
**Why it happens:** Lazy key management, misunderstanding domain separation.
**Consequences:** Key compromise across contexts, reduced security.
**Prevention:** Always use domain-separated derivation: `derive_child_seed(&master, "wallet", 0)`.
**Detection:** Check for hardcoded keys or lack of domain strings in derivation.

### Pitfall 3: Plaintext Seed/Key Storage
**What goes wrong:** Storing seeds or private keys without encryption.
**Why it happens:** Convenience, debugging, lack of security awareness.
**Consequences:** Key theft, funds loss, complete wallet compromise.
**Prevention:** Always encrypt with `origin-seal` or `origin-common` envelope; use `origin-identity` for seed management.
**Detection:** Check for unencrypted files containing seeds or keys.

## Moderate Pitfalls

### Pitfall 1: Ignoring Post-Quantum Security
**What goes wrong:** Using only classical signatures (Ed25519) without post-quantum hybrid.
**Why it happens:** Performance concerns, unfamiliarity with PQ primitives.
**Consequences:** Future vulnerability to quantum attacks.
**Prevention:** Use `origin-identity`'s hybrid signing (Ed25519 + Falcon-1024) by default.
**Detection:** Check for usage of `ed25519_dalek` directly instead of `origin_identity::CombinedSignature`.

### Pitfall 2: Weak Passphrase for Encryption
**What goes wrong:** Using weak passphrases for wallet encryption.
**Why it happens:** User convenience, lack of passphrase guidance.
**Consequences:** Brute-force attacks, wallet compromise.
**Prevention:** Use `origin-common`'s `resolve_passphrase_confirm()`; enforce minimum entropy.
**Detection:** Check for passphrase strength validation.

### Pitfall 3: Missing Idempotency in Transactions
**What goes wrong:** Duplicate transactions processed due to network retries.
**Why it happens:** Lack of idempotency keys, improper handling.
**Consequences:** Double-spending, incorrect balances.
**Prevention:** Use transaction IDs as idempotency keys; store processed IDs in wallet state.
**Detection:** Check for duplicate transaction IDs in transaction history.

## Minor Pitfalls

### Pitfall 1: Hardcoded Derivation Paths
**What goes wrong:** Using fixed derivation paths without configuration.
**Why it happens:** Simplicity, lack of flexibility.
**Consequences:** Incompatibility with other wallets, rigidity.
**Prevention:** Make derivation paths configurable; document default paths.
**Detection:** Check for hardcoded path strings in derivation code.

### Pitfall 2: Insufficient Backup Guidance
**What goes wrong:** Users don't backup their wallet properly.
**Why it happens:** Poor UX, lack of education.
**Consequences:** Funds loss if device is lost/damaged.
**Prevention:** Use `origin-shard` for K-of-N backup; provide clear backup instructions.
**Detection:** Check for backup guidance in wallet documentation.

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Wallet Core | Reimplementing crypto | Use existing origin crates |
| Address Encoding | Non-standard formats | Use bech32/base58 libraries |
| State Persistence | Plaintext storage | Encrypt with origin-seal |
| Transaction Construction | Missing idempotency | Use transaction IDs |
| CLI Interface | Weak passphrases | Use resolve_passphrase_confirm() |

## Sources

- `/home/ikaaros/Coding/Gold/origin-tools/` (workspace analysis)
- System Design Notes: Digital Wallet
- Cryptographic best practices (NIST SP 800-57)
