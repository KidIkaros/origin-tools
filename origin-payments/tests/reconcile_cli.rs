// SPDX-License-Identifier: Apache-2.0

//! P5: reconciliation through the real `origin-payments` binary —
//! pull a PSP settlement file (provenance-stamped), run the comparison,
//! checkpoint into the MMR, and export compliance evidence.

use std::process::Command;

use origin_payments::audit;
use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::store::PaymentStore;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_origin-payments"))
}

fn run(bin: &mut Command) -> std::process::Output {
    let out = bin.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {}\nstderr: {}",
        format!("{:?}", bin),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn reconcile_cli_pull_run_export() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    let store = PaymentStore::open(&root).unwrap();

    // Two settled orders in the journal (library-side setup; the CLI
    // surfaces them through the store the binary shares).
    for (id, amount) in [("o1", "3.15"), ("o2", "5.00")] {
        let mut order = PaymentOrder::new("checkout", "mesh", amount, "USD");
        order.payment_order_id = id.to_string();
        order.transition(OrderStatus::Executing).unwrap();
        order.transition(OrderStatus::Success).unwrap();
        store.insert_order(&order).unwrap();
    }

    // PSP settlement file: o1 matches, o2 differs (adjustable), ghost is
    // unknown internally (unclassifiable).
    let file = dir.path().join("settlement.json");
    std::fs::write(
        &file,
        r#"{"rows": [
            {"payment_order_id": "o1", "amount": "3.15"},
            {"payment_order_id": "o2", "amount": "4.99"},
            {"payment_order_id": "ghost", "amount": "1.00"}
        ]}"#,
    )
    .unwrap();

    run(bin().args([
        "--home",
        &home,
        "reconcile-pull",
        "--date",
        "2026-08-23",
        "--file",
        file.to_str().unwrap(),
    ]));

    let out = run(bin().args([
        "--home",
        &home,
        "--json",
        "reconcile-run",
        "--date",
        "2026-08-23",
    ]));
    let run_json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(run_json["status"], "MISMATCHES");
    assert_eq!(run_json["matches"], 1);
    assert_eq!(run_json["mismatches"].as_array().unwrap().len(), 2);
    let classes: Vec<&str> = run_json["mismatches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["class"].as_str().unwrap())
        .collect();
    assert!(classes.contains(&"ADJUSTABLE"));
    assert!(classes.contains(&"UNCLASSIFIABLE"));
    let mmr_checkpoint: [u8; 32] = run_json["mmr_checkpoint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // The checkpoint leaf is provable in the persisted MMR.
    let mmr = store.load_mmr().unwrap();
    assert_eq!(mmr.leaf_count(), 1);
    let proof = mmr.prove(0).unwrap();
    assert!(
        mmr.verify_proof(&proof, &mmr_checkpoint),
        "checkpoint provable"
    );

    // Compliance export (SOC2 shape) written.
    let run_id = run_json["run_id"].as_str().unwrap();
    let export_path = dir.path().join("soc2.json");
    run(bin().args([
        "--home",
        &home,
        "reconcile-export",
        "--run",
        run_id,
        "--format",
        "soc2",
        "--out",
        export_path.to_str().unwrap(),
    ]));
    assert!(export_path.exists());
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    assert_eq!(doc["framework"], "soc2");
    assert_eq!(doc["matches"], 1);
    assert_eq!(doc["evidence"].as_array().unwrap().len(), 2);

    // The reconcile actions landed in the audit chain and it verifies.
    assert!(audit::verify(&store).unwrap());
    let records = store.audit_records().unwrap();
    assert!(records.iter().any(|r| r.entry_type == audit::AT_RECONCILE));
}
