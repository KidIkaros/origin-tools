# Cookbook

Practical recipes for composing origin-tools.

---

## Setup

```bash
# Initialize your identity (one-time)
origin-identity init

# Verify it works
origin-identity list
```

## Recipe 1: Encrypted File Sharing

Split a file, encrypt each shard, share with different people.

```bash
# Split into 6 shards (tolerate 2 missing)
origin-shard split --input secret.pdf --output-dir ./shards --total 6 --data 4

# Encrypt each shard
for f in ./shards/shard_*.bin; do
  origin-seal encrypt --input "$f" --output "${f}.enc" --passphrase-file pass.txt
done

# Recipient recovers (needs any 4 shards)
origin-shard recover --input-dir ./shards --output recovered.pdf
```

## Recipe 2: Deterministic Key Derivation

Derive purpose-specific keys from your master seed.

```bash
# Derive a signing key for "email"
origin-seed derive --seed $(origin-identity show --seed) --domain "email" --index 0

# Derive a separate key for "ssh"
origin-seed derive --seed $(origin-identity show --seed) --domain "ssh" --index 0

# Different domains → completely different keys (HKDF-SHA3-256)
```

## Recipe 3: Proof of Data Integrity (MMR)

Build an append-only log and prove membership.

```bash
# Append entries
origin-proof append --state log.json --data "entry 1"
origin-proof append --state log.json --data "entry 2"
origin-proof append --state log.json --data "entry 3"

# Get the root hash
ROOT=$(origin-proof root --state log.json)

# Generate a proof for entry 0
origin-proof prove --state log.json --index 0 --output proof_0.json

# Anyone can verify against the root
origin-proof verify --proof proof_0.json --root "$ROOT"
```

## Recipe 4: Stealth Address + PoW

Create a stealth address and prove work to use it.

```bash
# Derive stealth master keys
origin-stealth master --seed $(origin-identity show --seed)

# Generate a one-time address
origin-stealth address --seed $(origin-identity show --seed) --index 42

# Solve a PoW challenge (difficulty = leading zero bits)
origin-stealth solve --seed $(origin-identity show --seed) \
  --difficulty 20 --destination "payment-hint" --output pow.json

# Verify the proof
origin-stealth verify --proof pow.json --destination "payment-hint"
```

## Recipe 5: Schnorr Proofs (Batch)

Prove knowledge across multiple messages efficiently.

```bash
# Generate a keypair
origin-schnorr keygen --seed $(origin-identity show --seed) --output keys.json

# Create proofs for multiple messages
for msg in msg1.txt msg2.txt msg3.txt; do
  origin-schnorr prove --input "$msg" --seed $(origin-identity show --seed) \
    --output "proof_${msg%.txt}.json"
done

# Batch verify all at once
origin-schnorr batch-verify --proofs ./proofs/ --inputs ./messages/
```

## Recipe 6: Entropy Quality Gate

Verify data quality before using it as a seed.

```bash
# Check entropy meets threshold
origin-entropy check --input random.bin --min-entropy 7.9

# Analyze the distribution
origin-entropy analyze --input random.bin

# Generate verified random bytes
origin-entropy generate --bits 256 --output seed.bin
```

## Recipe 7: Full Pipeline (End-to-End)

The complete workflow tested in `origin-cross-tests`:

```bash
# 1. Generate a seed
SEED=$(origin-seed generate)

# 2. Encrypt it as a blob
origin-seed blob --seed "$SEED" --passphrase-file pass.txt --output seed.enc

# 3. Shard the encrypted blob
origin-shard split --input seed.enc --output-dir ./shards --total 6 --data 4

# 4. Lose 2 shards (simulate disaster)
rm ./shards/shard_2.bin ./shards/shard_5.bin

# 5. Recover from remaining 4 shards
origin-shard recover --input-dir ./shards --output recovered.enc

# 6. Decrypt the recovered blob
RECOVERED_SEED=$(origin-seed recover --input recovered.enc --passphrase-file pass.txt)

# 7. Verify seed integrity
[ "$SEED" = "$RECOVERED_SEED" ] && echo "Pipeline OK"

# 8. Sign with the recovered seed
origin-schnorr prove --input message.txt --seed "$RECOVERED_SEED" --output proof.json
origin-schnorr verify --proof proof.json --input message.txt
```

## Tips

- **Isolated testing**: Set `ORIGIN_HOME=/tmp/test-origin` to avoid
  touching your real identity.
- **CI tier**: Use `nano` tier in CI for fast Argon2id (64 MiB, 3 iterations).
- **Piping**: All tools accept `--input -` for stdin and `--output -` for stdout.
- **Formats**: Default output is hex. Use `--format base64` where supported.
