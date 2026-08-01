//! Audit log data structures and operations

use serde::{Deserialize, Serialize};

/// Audit entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub entry_id: String,
    pub operation: Operation,
    pub key_id: String,
    pub timestamp: String,
    pub operator: String,
    pub details: OperationDetails,
    pub signature: crate::share::HybridSignature,
}

/// Operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Operation {
    Init,
    Shard { threshold: u8, total_shares: u8 },
    ExportShare { share_number: u8, recipient: String },
    Recover { shares_used: Vec<String> },
    Verify { target: VerifyTarget },
    AuditExport { format: ComplianceFormat },
}

/// Operation details
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationDetails {
    Success { message: String },
    Failure { error: String },
}

/// Verify target
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerifyTarget {
    Vault,
    Share(String),
    RecoveryLog(String),
}

/// Compliance framework
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum ComplianceFormat {
    SOC2,
    PciDss { version: String },
    Hipaa { section: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_roundtrip() {
        let entry = AuditEntry {
            entry_id: "audit-001-20260730-212745".to_string(),
            operation: Operation::Init,
            key_id: "test-key".to_string(),
            timestamp: "2026-07-30T21:27:45Z".to_string(),
            operator: "alice@company.com".to_string(),
            details: OperationDetails::Success {
                message: "Vault initialized".to_string(),
            },
            signature: crate::share::HybridSignature {
                ed25519: vec![1u8; 64],
                falcon1024: vec![2u8; 1332],
            },
        };

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.entry_id, deserialized.entry_id);
        assert_eq!(entry.key_id, deserialized.key_id);
    }
}
