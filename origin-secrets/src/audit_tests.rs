//! Unit tests for Audit module

use crate::audit::{AuditEntry, ComplianceFormat, Operation, OperationDetails, VerifyTarget};
use crate::share::HybridSignature;

fn make_sig() -> HybridSignature {
    HybridSignature {
        ed25519: vec![1u8; 64],
        falcon1024: vec![2u8; 1332],
    }
}

fn make_entry(operation: Operation, details: OperationDetails) -> AuditEntry {
    AuditEntry {
        entry_id: "entry-1".to_string(),
        operation,
        key_id: "master-seed".to_string(),
        timestamp: "2026-07-30T21:27:45Z".to_string(),
        operator: "alice".to_string(),
        details,
        signature: make_sig(),
    }
}

#[test]
fn test_audit_entry_creation() {
    let entry = make_entry(
        Operation::Init,
        OperationDetails::Success {
            message: "Vault initialized".to_string(),
        },
    );

    assert_eq!(entry.entry_id, "entry-1");
    assert_eq!(entry.operation, Operation::Init);
    assert_eq!(entry.operator, "alice");
    assert_eq!(entry.key_id, "master-seed");
}

#[test]
fn test_audit_entry_serialization() {
    let entry = make_entry(
        Operation::Shard {
            threshold: 3,
            total_shares: 5,
        },
        OperationDetails::Success {
            message: "Sharded master key".to_string(),
        },
    );

    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

    assert_eq!(entry.entry_id, deserialized.entry_id);
    assert_eq!(entry.operation, deserialized.operation);
    assert_eq!(entry.operator, deserialized.operator);
    assert_eq!(entry.key_id, deserialized.key_id);
}

#[test]
fn test_audit_entry_all_operations() {
    let operations = [
        Operation::Init,
        Operation::Shard {
            threshold: 3,
            total_shares: 5,
        },
        Operation::ExportShare {
            share_number: 1,
            recipient: "alice".to_string(),
        },
        Operation::Recover {
            shares_used: vec!["1".to_string(), "2".to_string(), "3".to_string()],
        },
        Operation::Verify {
            target: VerifyTarget::Vault,
        },
        Operation::AuditExport {
            format: ComplianceFormat::SOC2,
        },
    ];

    for (i, op) in operations.iter().enumerate() {
        let mut entry = make_entry(
            op.clone(),
            OperationDetails::Success {
                message: "ok".to_string(),
            },
        );
        entry.entry_id = format!("entry-{}", i);

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.operation, deserialized.operation);
    }
}

#[test]
fn test_audit_entry_failure_details() {
    let entry = make_entry(
        Operation::Init,
        OperationDetails::Failure {
            error: "KDF failed".to_string(),
        },
    );

    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

    assert_eq!(entry.details, deserialized.details);
    match &deserialized.details {
        OperationDetails::Failure { error } => assert_eq!(error, "KDF failed"),
        _ => panic!("Expected failure details"),
    }
}

#[test]
fn test_audit_entry_with_compliance_formats() {
    let formats = [
        ComplianceFormat::SOC2,
        ComplianceFormat::PciDss {
            version: "4.0".to_string(),
        },
        ComplianceFormat::Hipaa {
            section: "164.312".to_string(),
        },
    ];

    for (i, format) in formats.iter().enumerate() {
        let mut entry = make_entry(
            Operation::AuditExport {
                format: format.clone(),
            },
            OperationDetails::Success {
                message: "Exported".to_string(),
            },
        );
        entry.entry_id = format!("entry-{}", i);

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.operation, deserialized.operation);
    }
}

#[test]
fn test_audit_entry_roundtrip_file() {
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let entry = make_entry(
        Operation::Recover {
            shares_used: vec!["1".to_string(), "2".to_string()],
        },
        OperationDetails::Success {
            message: "Recovered".to_string(),
        },
    );

    let serialized = serde_json::to_string(&entry).unwrap();
    std::fs::write(path, serialized).unwrap();

    let read_back = std::fs::read_to_string(path).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&read_back).unwrap();

    assert_eq!(entry.entry_id, deserialized.entry_id);
    assert_eq!(entry.operator, deserialized.operator);
}

#[test]
fn test_audit_entry_timestamp_formats() {
    let timestamps = vec![
        "2026-07-30T21:27:45Z",
        "2026-07-30T21:27:45.123Z",
        "2026-07-30T21:27:45+00:00",
        "1690747665",
    ];

    for ts in timestamps {
        let mut entry = make_entry(
            Operation::Init,
            OperationDetails::Success {
                message: "ok".to_string(),
            },
        );
        entry.timestamp = ts.to_string();

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.timestamp, deserialized.timestamp);
    }
}

#[test]
fn test_audit_entry_empty_fields() {
    let entry = AuditEntry {
        entry_id: String::new(),
        operation: Operation::Init,
        key_id: String::new(),
        timestamp: String::new(),
        operator: String::new(),
        details: OperationDetails::Success {
            message: String::new(),
        },
        signature: HybridSignature {
            ed25519: vec![],
            falcon1024: vec![],
        },
    };

    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

    assert_eq!(entry.entry_id, deserialized.entry_id);
    assert_eq!(entry.operator, deserialized.operator);
    assert_eq!(entry.key_id, deserialized.key_id);
}

#[test]
fn test_audit_entry_unicode_operator() {
    let mut entry = make_entry(
        Operation::Init,
        OperationDetails::Success {
            message: "ok".to_string(),
        },
    );
    entry.operator = "用户".to_string();

    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

    assert_eq!(entry.operator, deserialized.operator);
}

#[test]
fn test_audit_entry_long_details() {
    let long_details = "x".repeat(1000);

    let entry = make_entry(
        Operation::AuditExport {
            format: ComplianceFormat::SOC2,
        },
        OperationDetails::Success {
            message: long_details.clone(),
        },
    );

    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

    match &deserialized.details {
        OperationDetails::Success { message } => {
            assert_eq!(message.as_str(), long_details.as_str())
        }
        _ => panic!("Expected success details"),
    }
}

#[test]
fn test_compliance_format_serialization() {
    let formats = vec![
        ComplianceFormat::SOC2,
        ComplianceFormat::PciDss {
            version: "4.0".to_string(),
        },
        ComplianceFormat::Hipaa {
            section: "164.312".to_string(),
        },
    ];

    for format in formats {
        let serialized = serde_json::to_string(&format).unwrap();
        let deserialized: ComplianceFormat = serde_json::from_str(&serialized).unwrap();

        assert_eq!(format, deserialized);
    }
}

#[test]
fn test_verify_target_serialization() {
    let targets = vec![
        VerifyTarget::Vault,
        VerifyTarget::Share("share1.json".to_string()),
        VerifyTarget::RecoveryLog("recovery.log".to_string()),
    ];

    for target in targets {
        let serialized = serde_json::to_string(&target).unwrap();
        let deserialized: VerifyTarget = serde_json::from_str(&serialized).unwrap();

        assert_eq!(target, deserialized);
    }
}

#[test]
fn test_operation_serialization_all_types() {
    let operations = vec![
        Operation::Shard {
            threshold: 2,
            total_shares: 4,
        },
        Operation::ExportShare {
            share_number: 3,
            recipient: "test@test.com".to_string(),
        },
        Operation::Recover {
            shares_used: vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
            ],
        },
        Operation::Verify {
            target: VerifyTarget::Share("share.json".to_string()),
        },
    ];

    for op in operations {
        let serialized = serde_json::to_string(&op).unwrap();
        let deserialized: Operation = serde_json::from_str(&serialized).unwrap();

        assert_eq!(op, deserialized);
    }
}

#[test]
fn test_operation_details_serialization() {
    let details = vec![
        OperationDetails::Success {
            message: "ok".to_string(),
        },
        OperationDetails::Failure {
            error: "failed".to_string(),
        },
    ];

    for d in details {
        let serialized = serde_json::to_string(&d).unwrap();
        let deserialized: OperationDetails = serde_json::from_str(&serialized).unwrap();

        assert_eq!(d, deserialized);
    }
}
