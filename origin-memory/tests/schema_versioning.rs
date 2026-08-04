// SPDX-License-Identifier: Apache-2.0

//! R4: schema versioning — `PRAGMA user_version` stamp, forward migration of
//! legacy databases, and hard refusal of databases stamped *newer* than this
//! build (silent downgrade would lose future columns).
//!
//! Closes L1 from the gap audit: before real data exists, give the schema a
//! version and a migration harness so we never have to hand-recover a DB.

use origin_memory::persist::SCHEMA_VERSION;
use origin_memory::Memory;
use rusqlite::Connection;

const SEED: [u8; 32] = [11u8; 32];

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("origin-memory-r4-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn fresh_store_is_stamped_at_current_version() {
    let dir = fresh_dir("fresh");
    let mem = Memory::open(&dir, &SEED, "r4-test").expect("open");
    assert_eq!(
        mem.schema_version().expect("read"),
        SCHEMA_VERSION,
        "new database must be stamped at the current version"
    );
    // Idempotent: reopening doesn't bump the stamp.
    drop(mem);
    let mem2 = Memory::open(&dir, &SEED, "r4-test").expect("reopen");
    assert_eq!(mem2.schema_version().expect("read"), SCHEMA_VERSION);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_v0_database_migrates_forward_preserving_data() {
    let dir = fresh_dir("legacy");
    std::fs::create_dir_all(&dir).unwrap();

    // Build a genuine pre-R4 database: the old 12-column nodes table,
    // NO user_version stamp, NO layer_root/body_encrypted columns.
    {
        let conn = Connection::open(dir.join("memory.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE nodes (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                time        TEXT NOT NULL,
                time_end    TEXT,
                topics      TEXT NOT NULL,
                evidence    TEXT NOT NULL,
                tier        TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                body        TEXT NOT NULL,
                ed25519_sig TEXT NOT NULL,
                falcon_sig  TEXT NOT NULL,
                signer      TEXT NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes (id, title, time, time_end, topics, evidence, tier, content_hash, body, ed25519_sig, falcon_sig, signer)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                "legacy-node",
                "Legacy",
                "2004-06-01",
                None::<String>,
                "geo",
                "documented",
                "sovereign",
                "deadbeef",
                "old body",
                "aa",
                "bb",
                "cc",
            ],
        )
        .unwrap();
    }

    // Opening with the new code must migrate v0 -> current, keeping the row.
    let mem = Memory::open(&dir, &SEED, "r4-test").expect("open legacy");
    assert_eq!(
        mem.schema_version().expect("read"),
        SCHEMA_VERSION,
        "legacy database must be stamped after migration"
    );
    let loaded = mem.node_ids();
    assert!(
        loaded.contains(&"legacy-node".to_string()),
        "legacy data survives migration: {:?}",
        loaded
    );

    // The new columns now exist and are NULL for the migrated row.
    {
        let conn = Connection::open(dir.join("memory.sqlite")).unwrap();
        let has_layer_root: i32 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('nodes') WHERE name = 'layer_root'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let has_body_encrypted: i32 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('nodes') WHERE name = 'body_encrypted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_layer_root, 1, "layer_root column added");
        assert_eq!(has_body_encrypted, 1, "body_encrypted column added");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn newer_database_is_rejected_not_degraded() {
    let dir = fresh_dir("future");
    std::fs::create_dir_all(&dir).unwrap();

    // Stamp the database as a *future* schema this build can't read.
    {
        let conn = Connection::open(dir.join("memory.sqlite")).unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
    }

    let result = Memory::open(&dir, &SEED, "r4-test");
    match result {
        Ok(_) => panic!("a newer-than-supported database must refuse to open"),
        Err(e) => {
            let err = format!("{e:?}");
            assert!(
                err.contains("newer"),
                "error must explain the version mismatch: {}",
                err
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
