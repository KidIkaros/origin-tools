//! Tests for dispatch function and CLI parsing

use crate::cli::{AuditArgs, Cli, Commands, ExportArgs, InitArgs, RecoverArgs, ShardArgs, VerifyArgs};
use crate::dispatch;
use crate::error::Error;
use clap::Parser;
use std::path::PathBuf;

fn make_cli(command: Commands) -> Cli {
    Cli {
        vault: "/tmp/test.vault".into(),
        passphrase_file: None,
        config: "/tmp/config.toml".into(),
        verbose: false,
        quiet: false,
        command,
    }
}

#[test]
fn test_dispatch_init() {
    let cli = make_cli(Commands::Init(InitArgs {
        tier: "standard".to_string(),
        no_prompt: true,
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
}

#[test]
fn test_dispatch_shard_routes_to_impl() {
    // shard is implemented; dispatch should reach cmd_shard and fail on the
    // missing default vault (not return NotImplemented).
    let cli = make_cli(Commands::Shard(ShardArgs {
        key: "master".to_string(),
        threshold: 3,
        shares: 5,
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
    // Default vault path does not exist in test env -> VaultNotFound.
    assert!(matches!(result, Err(Error::VaultNotFound(_))));
}

#[test]
fn test_dispatch_export_routes_to_impl() {
    // export-share is implemented; dispatch should reach cmd_export_share and
    // fail on the missing share file (not return NotImplemented).
    let cli = make_cli(Commands::ExportShare(ExportArgs {
        share: 1,
        out: "/tmp/share.json".into(),
        recipient: Some("alice".to_string()),
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
    assert!(matches!(result, Err(Error::ShareNotFound { .. })));
}

#[test]
fn test_dispatch_recover_routes_to_impl() {
    // recover is implemented; dispatch should reach cmd_recover and fail on the
    // missing share files (not return NotImplemented).
    let cli = make_cli(Commands::Recover(RecoverArgs {
        shares: vec!["/tmp/s1".into(), "/tmp/s2".into()],
        out: None,
        vault_out: None,
        tier: "standard".to_string(),
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
    assert!(matches!(result, Err(Error::ShareNotFound { .. })));
}

#[test]
fn test_dispatch_verify_routes_to_impl() {
    // verify is implemented; dispatch with a nonexistent vault path should reach
    // cmd_verify and return VaultNotFound (not NotImplemented).
    let cli = make_cli(Commands::Verify(VerifyArgs {
        vault_path: Some("/tmp/vault.json".into()),
        share: None,
        recovery_log: None,
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
    assert!(matches!(result, Err(Error::VaultNotFound(_))));
}

#[test]
fn test_dispatch_audit_routes_to_impl() {
    // audit is implemented; dispatch with a nonexistent vault path should reach
    // cmd_audit and return VaultNotFound (not NotImplemented).
    let cli = make_cli(Commands::Audit(AuditArgs {
        show_recovery_log: false,
        show_all_logs: false,
        filter_key: None,
        filter_user: None,
        filter_start: None,
        filter_end: None,
        export_soc2: None,
        export_pcidss: None,
        export_hipaa: None,
    }));

    let result = dispatch(cli);
    assert!(!matches!(result, Err(Error::NotImplemented(_))));
    assert!(matches!(result, Err(Error::VaultNotFound(_))));
}

#[test]
fn test_cli_parsing_init() {
    let cli = Cli::parse_from([
        "origin-secrets",
        "--vault",
        "/tmp/v.json",
        "init",
        "--tier",
        "sovereign",
        "--no-prompt",
    ]);

    assert_eq!(cli.vault, PathBuf::from("/tmp/v.json"));
    match cli.command {
        Commands::Init(args) => {
            assert_eq!(args.tier, "sovereign");
            assert!(args.no_prompt);
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_cli_parsing_shard() {
    let cli = Cli::parse_from([
        "origin-secrets",
        "shard",
        "--key",
        "master",
        "--threshold",
        "3",
        "--shares",
        "5",
    ]);

    match cli.command {
        Commands::Shard(args) => {
            assert_eq!(args.key, "master");
            assert_eq!(args.threshold, 3);
            assert_eq!(args.shares, 5);
        }
        _ => panic!("Expected Shard command"),
    }
}

#[test]
fn test_cli_parsing_export() {
    let cli = Cli::parse_from([
        "origin-secrets",
        "export-share",
        "--share",
        "2",
        "--out",
        "/tmp/s2.json",
        "--recipient",
        "alice",
    ]);

    match cli.command {
        Commands::ExportShare(args) => {
            assert_eq!(args.share, 2);
            assert_eq!(args.out, PathBuf::from("/tmp/s2.json"));
            assert_eq!(args.recipient, Some("alice".to_string()));
        }
        _ => panic!("Expected ExportShare command"),
    }
}

#[test]
fn test_cli_parsing_recover() {
    let cli = Cli::parse_from(["origin-secrets", "recover", "s1", "s2", "s3"]);

    match cli.command {
        Commands::Recover(args) => {
            assert_eq!(args.shares.len(), 3);
        }
        _ => panic!("Expected Recover command"),
    }
}

#[test]
fn test_cli_parsing_verify() {
    let cli = Cli::parse_from([
        "origin-secrets",
        "verify",
        "--vault-path",
        "/tmp/vault.json",
    ]);

    match cli.command {
        Commands::Verify(args) => {
            assert_eq!(args.vault_path, Some(PathBuf::from("/tmp/vault.json")));
        }
        _ => panic!("Expected Verify command"),
    }
}

#[test]
fn test_cli_parsing_audit() {
    let cli = Cli::parse_from([
        "origin-secrets",
        "audit",
        "--export-soc2",
        "/tmp/soc2.json",
    ]);

    match cli.command {
        Commands::Audit(args) => {
            assert_eq!(args.export_soc2, Some(PathBuf::from("/tmp/soc2.json")));
        }
        _ => panic!("Expected Audit command"),
    }
}

#[test]
fn test_cli_default_tier() {
    let cli = Cli::parse_from(["origin-secrets", "init"]);

    match cli.command {
        Commands::Init(args) => {
            assert_eq!(args.tier, "standard");
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_cli_verbose_quiet_flags() {
    let cli = Cli::parse_from(["origin-secrets", "--verbose", "init"]);
    assert!(cli.verbose);
    assert!(!cli.quiet);

    let cli = Cli::parse_from(["origin-secrets", "--quiet", "init"]);
    assert!(cli.quiet);
    assert!(!cli.verbose);
}
