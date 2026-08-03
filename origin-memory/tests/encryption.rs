// SPDX-License-Identifier: Apache-2.0

//! P4: encryption at rest — secret nodes are encrypted on disk, decryptable in
//! session, and tamper-detection works through the AEAD.

use origin_memory::{Memory, MemoryNode};

const SEED: [u8; 32] = [42u8; 32];

#[test]
fn secret_node_encrypts_at_rest_and_decrypts() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    let plaintext_body = "The asset arrived at 0300 via the north gate.";
    let node = MemoryNode::from_markdown(
        "secret-1",
        &format!(
            "---\ntitle: Classified\ntime: 2004-06-01\ntopic: [ops]\nevidence: documented\n---\n{}\n",
            plaintext_body
        ),
    )
    .unwrap();

    mem.add_secret(node).expect("add_secret");

    // (1) decrypt_body recovers the plaintext (body includes surrounding newlines).
    let recovered = mem.decrypt_body("secret-1").expect("decrypt");
    assert!(
        recovered.contains(plaintext_body),
        "plaintext recovered: {}",
        recovered
    );

    // (2) On disk, the body column is [encrypted] — not readable.
    let on_disk_body: String = mem
        .store()
        .conn()
        .query_row("SELECT body FROM nodes WHERE id = 'secret-1'", [], |row| {
            row.get(0)
        })
        .expect("query");
    assert_eq!(on_disk_body, "[encrypted]", "body is not plaintext on disk");

    // (3) The encrypted body column IS populated (hex nonce+ciphertext).
    let enc = mem
        .store()
        .encrypted_body("secret-1")
        .expect("encrypted body exists");
    assert!(
        enc.len() > 48,
        "encrypted hex is non-trivial: {} chars",
        enc.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secret_node_survives_reload() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p4-reload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let plaintext_body = "Meeting at the old warehouse, 2200 hours.";
    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        let node = MemoryNode::from_markdown(
            "secret-2",
            &format!(
                "---\ntitle: Meeting\ntime: 2004-06-01\ntopic: [ops]\nevidence: documented\n---\n{}\n",
                plaintext_body
            ),
        )
        .unwrap();
        mem.add_secret(node).expect("add_secret");
    }

    // Reload with the same seed — decryption key is deterministic.
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    let recovered = mem.decrypt_body("secret-2").expect("decrypt after reload");
    assert!(
        recovered.contains(plaintext_body),
        "plaintext recovered after reload"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_seed_cannot_decrypt() {
    let dir =
        std::env::temp_dir().join(format!("origin-memory-p4-wrongkey-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let plaintext_body = "Should not be readable with a different seed.";
    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        let node = MemoryNode::from_markdown(
            "secret-3",
            &format!(
                "---\ntitle: Hidden\ntime: 2004-06-01\ntopic: [x]\nevidence: documented\n---\n{}\n",
                plaintext_body
            ),
        )
        .unwrap();
        mem.add_secret(node).expect("add_secret");
    }

    // Reload with a DIFFERENT seed — AEAD auth fails, decrypt returns None.
    let wrong_seed = [99u8; 32];
    let mem = Memory::open(&dir, &wrong_seed, "origin-memory-test").expect("reopen");
    assert!(
        mem.decrypt_body("secret-3").is_none(),
        "wrong seed cannot decrypt"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
