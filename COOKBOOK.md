# Cookbook

Practical recipes for composing origin-tools. All examples use the unified
`origin` binary; the standalone `origin-*` binaries accept identical flags.

---

## Setup

```bash
# Initialize your identity (one-time)
origin identity keygen --name personal

# List identities
origin identity list
```

## Recipe 1: Encrypted File Sharing

Split a file, encrypt each shard, share with different people.

```bash
# Split into 4 data + 2 parity shards (tolerate 2 missing)
origin shard split --input secret.pdf --output ./shards \
  --data-shards 4 --parity-shards 2

# Encrypt each shard
for f in ./shards/shard_*.bin; do
  origin seal encrypt --input "$f" --output "${f}.enc" --passphrase-file pass.txt
done

# Recipient recovers (needs any 4 of the 6 shards)
origin shard recover --input ./shards --output recovered.pdf \
  --data-shards 4 --parity-shards 2
```

## Recipe 2: Deterministic Key Derivation

Derive purpose-specific keys from your master seed.

```bash
# Derive a child seed for "email"
origin seed derive --seed $(origin seed generate) --domain "email"

# Derive from your suite identity instead
origin seed derive --identity --domain "wallet" --passphrase-file pass.txt

# Different domains → completely different keys (HKDF-SHA3-256)
```

## Recipe 3: Proof of Data Integrity (MMR)

Build an append-only log and prove membership.

```bash
# Append entries (data is hex)
origin proof append --state log.json --data 656e74727931 --output log.json
origin proof append --state log.json --data 656e74727932 --output log.json

# Get the root hash
ROOT=$(origin proof root --state log.json)

# Generate a proof for leaf 0
origin proof prove --state log.json --index 0 > proof_0.json

# Anyone can verify against the root
origin proof verify --proof proof_0.json --root "$ROOT"
```

## Recipe 4: Stealth Address + PoW

Create a stealth address and prove work to use it.

```bash
# Derive stealth master keys
origin stealth master --seed <hex>

# Generate a one-time address at index 42
origin stealth address --seed <hex> --index 42

# Solve a PoW challenge (difficulty = leading zero bits)
origin stealth solve --seed <hex> --index 42 --difficulty 20 > pow.json

# Verify the proof
origin stealth verify --proof pow.json --index 42 --seed <hex>
```

## Recipe 5: Schnorr Proofs (Batch)

Prove knowledge across multiple messages efficiently.

```bash
# Generate a keypair
origin schnorr keygen --seed <hex>

# Create a proof of knowledge
origin schnorr prove --input message.txt --secret <hex> --public <hex> > proof.json

# Verify it
origin schnorr verify --proof proof.json --input message.txt

# Batch verify from a JSON array of {proof, public_key, message}
origin schnorr batch-verify --input proofs.json
```

## Recipe 6: Entropy Quality Gate

Verify data quality before using it as a seed.

```bash
# Analyze the entropy distribution
origin entropy analyze --input random.bin --format text

# Check quality against requirements for a 256-bit seed
origin entropy check --input random.bin --bits 256
```

## Recipe 7: Full Pipeline (End-to-End)

The complete workflow tested in `origin-cross-tests`:

```bash
# 1. Generate a seed
SEED=$(origin seed generate)

# 2. Encrypt it as a blob
origin seed blob-create --seed "$SEED" --output seed.blob --passphrase-file pass.txt

# 3. Shard the encrypted blob
origin shard split --input seed.blob --output ./shards \
  --data-shards 4 --parity-shards 2

# 4. Lose 2 shards (simulate disaster)
rm ./shards/shard_2.bin ./shards/shard_5.bin

# 5. Recover from remaining 4 shards
origin shard recover --input ./shards --output recovered.blob \
  --data-shards 4 --parity-shards 2

# 6. Decrypt the recovered blob
RECOVERED_SEED=$(origin seed blob-recover --input recovered.blob --passphrase-file pass.txt)

# 7. Verify seed integrity
[ "$SEED" = "$RECOVERED_SEED" ] && echo "Pipeline OK"
```

## Tips

- **Isolated testing**: Set `ORIGIN_HOME=/tmp/test-origin` to avoid
  touching your real identity.
- **CI tier**: Use `--tier nano` for fast Argon2id (64 MiB, 3 iterations).
- **Piping**: All tools accept stdin/stdout by default (omit `--input`/`--output`).
- **Identity**: Most tools accept `--identity` to derive from your suite
  identity instead of passing an explicit `--seed`.
