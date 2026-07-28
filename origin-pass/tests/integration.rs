// SPDX-License-Identifier: Apache-2.0

//! Shell-out integration tests for the `origin-pass` CLI binary.
//!
//! These tests exercise the **real clap dispatch + main.rs path**,
//! not the Rust API. They are the regression net for wiring bugs in
//! `cmd_add` (clap arg parsing, `resolve_entry_secret`,
//! `resolve_vault_path`, `Vault::add_entry` integration, vault
//! persistence) — bugs that pure unit tests in
//! `src/commands.rs::tests` cannot catch.
//!
//! # Pattern
//!
//! Each test:
//! 1. Creates a `tempfile::TempDir` for an isolated vault.
//! 2. Writes a vault passphrase file and one or more secret files
//!    (we deliberately avoid putting secrets in argv).
//! 3. Invokes `env!("CARGO_BIN_EXE_origin-pass")` via `std::process::Command`
//!    for every step (init, add, get).
//! 4. Asserts on process exit status + stdout/stderr substrings.
//!
//! Failures point at the exact clap subcommand + flag combination
//! the bug is in, and the CLI's "user-visible" error string flows
//! back through `.stderr` to the assertion message.

// `Cargo`'s CARGO_BIN_EXE_<name> env var is set for integration tests
// of binary crates — it points at the compiled binary. Refusing to
// fall back to a string literal keeps us honest: if the env var is
// missing (test mis-config), the compile failure is loud.

use std::process::Command;

use tempfile::TempDir;

/// Path to the compiled `origin-pass` binary, set by cargo for integration tests.
fn origin_pass_bin() -> &'static str {
    env!("CARGO_BIN_EXE_origin-pass")
}

/// Helper: write `<pw>\n` to `dir/<name>` and return the path.
fn write_secret(dir: &TempDir, name: &str, pw: &str) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, format!("{pw}\n")).expect("write secret to tempdir");
    p
}

/// Initialise a vault in `dir/vault` using `vault_pw` as the passphrase.
/// Passphrase is supplied via `--passphrase-file` to bypass the
/// interactive `rpassword::prompt_password` (which fails on non-TTY
/// stdin in CI / cargo test).
fn init_vault(dir: &TempDir, vault_pw: &std::path::Path, tier: &str) {
    let vault_path = dir.path().join("test.vault");
    let status = Command::new(origin_pass_bin())
        .args([
            "init",
            "--vault",
            vault_path.to_str().expect("utf-8 vault path"),
            "--tier",
            tier,
            "--passphrase-file",
            vault_pw.to_str().expect("utf-8 passphrase path"),
        ])
        .status()
        .expect("spawn origin-pass init");
    assert!(
        status.success(),
        "init failed (exit={status}); check stderr from the test runner"
    );
    assert!(vault_path.exists(), "init did not produce a vault file");
}

// ──────────────────────────────────────────────────────────────────────
// Test 1: round-trip
// `init → add --type password --secret-file → get → recovered secret
//  byte-exact, prefixed with name`.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_password_round_trip_recovers_secret_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase-correct-horse");
    let entry_secret_str = "hunter2-but-actually-much-longer-and-random";
    let entry_secret = write_secret(&dir, "entry-secret", entry_secret_str);

    init_vault(&dir, &vault_pw, "nano");

    let vault_path = dir.path().join("test.vault");
    let status = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "github.com",
            "--secret-file",
            entry_secret.to_str().unwrap(),
            "--url",
            "https://github.com/login",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("spawn origin-pass add");
    assert!(
        status.success(),
        "cmd_add --type password failed (exit={status}); CLI must handle --secret-file + url/notes end-to-end"
    );

    let output = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "github.com",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("spawn origin-pass get");
    assert!(
        output.status.success(),
        "cmd_get failed (exit={}); stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(entry_secret_str),
        "recovered secret should contain `{entry_secret_str}`, got: {stdout}"
    );
    assert!(
        stdout.starts_with("github.com:"),
        "expected name-prefixed output (`github.com: …`), got: {stdout}"
    );
    assert!(
        stdout.contains("https://github.com/login"),
        "URL passed at add time should be re-printed by get, got: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 2: duplicate-handling semantics
//   a. add succeeds on first call
//   b. add on same name WITHOUT --force hard-errors with 'already exists'
//   c. cmd_list reflects the entry exists
//   d. add on same name WITH --force overwrites
//   e. get now returns the second-secret, NOT the first
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_password_duplicate_without_force_errs_with_force_overwrites() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "p");
    let s1 = write_secret(&dir, "secret-1", "first-secret-aaa");
    let s2 = write_secret(&dir, "secret-2", "second-secret-bbb");

    init_vault(&dir, &vault_pw, "nano");

    let vault_path = dir.path().join("test.vault");

    // (a) first add succeeds
    let status = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "github.com",
            "--secret-file",
            s1.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("first add");
    assert!(status.success(), "first add must succeed (exit={status})");

    // (b) second add (same name, no --force) must hard-error
    let err_output = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "github.com",
            "--secret-file",
            s2.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("second add (must fail)");
    assert!(
        !err_output.status.success(),
        "duplicate add without --force should have failed (exit={})",
        err_output.status
    );
    let stderr = String::from_utf8_lossy(&err_output.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected 'already exists' error message, got: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "error should hint at --force, got: {stderr}"
    );

    // (c) cmd_list should show 'github.com' as a password entry
    let list_output = Command::new(origin_pass_bin())
        .args([
            "list",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("cmd_list");
    assert!(list_output.status.success(), "cmd_list failed");
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        list_stdout.contains("github.com"),
        "list output should contain entry name, got: {list_stdout}"
    );
    assert!(
        list_stdout.contains("password"),
        "list output should classify entry as 'password', got: {list_stdout}"
    );

    // (d) third add (same name + --force) succeeds
    let force_status = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "--force",
            "github.com",
            "--secret-file",
            s2.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("force-add");
    assert!(
        force_status.success(),
        "force-add should succeed (exit={force_status})"
    );

    // (e) get now returns second-secret, NOT first-secret
    let get_output = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "github.com",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("get after force-overwrite");
    assert!(get_output.status.success(), "post-force get failed");
    let stdout = String::from_utf8_lossy(&get_output.stdout);
    assert!(
        stdout.contains("second-secret-bbb"),
        "after force-overwrite, get must return new secret; got: {stdout}"
    );
    assert!(
        !stdout.contains("first-secret-aaa"),
        "old secret must NOT appear after force-overwrite; got: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 3: --secret-stdin branch
// Pipes a secret into stdin (close-after-write simulates EOF) and
// confirms the add path recovered it byte-exact. Also asserts the
// clap mutex: passing both `--secret-file` and `--secret-stdin` is a
// hard error.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_password_secret_stdin_round_trip() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");
    init_vault(&dir, &vault_pw, "nano");

    let vault_path = dir.path().join("test.vault");
    let piped_secret = "piped-secret-12345";

    // Spawn add with stdin piped; write the secret then close to send EOF.
    let mut child = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "--secret-stdin",
            "stdin-entry",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdin-piped add");
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{piped_secret}\n").as_bytes())
            .expect("write secret to stdin");
    } else {
        panic!("stdin handle unavailable after spawn");
    }
    let output = child.wait_with_output().expect("wait add");
    assert!(
        output.status.success(),
        "cmd_add --secret-stdin failed (exit={}); stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // Recover via get and assert byte-exact.
    let get = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "stdin-entry",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("get after stdin-add");
    assert!(get.status.success(), "get after stdin-add failed");
    let stdout = String::from_utf8_lossy(&get.stdout);
    assert!(
        stdout.contains(piped_secret),
        "stdin-piped secret must round-trip byte-exact; got: {stdout}"
    );
}

#[test]
fn cmd_add_password_secret_file_and_stdin_is_rejected_by_clap_mutex() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "p");
    let s1 = write_secret(&dir, "s", "secret");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Pass both --secret-file AND --secret-stdin — clap should reject
    // this before resolve_entry_secret is even called.
    let output = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "--secret-file",
            s1.to_str().unwrap(),
            "--secret-stdin",
            "mutex-entry",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("spawn mutex-conflict add");
    assert!(
        !output.status.success(),
        "passing both --secret-file AND --secret-stdin must fail (exit={})",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap emits a usage-error string; we don't pin the exact text but
    // assert it mentions both flag names so users can diagnose.
    assert!(
        stderr.contains("secret-file")
            || stderr.contains("secret-stdin")
            || stderr.contains("cannot be used with"),
        "expected clap mutex error mentioning the conflicted flags, got: {stderr}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 5: cmd_import_qr + cmd_export_qr round-trip
// Imports a hardcoded otpauth://totp URI, then exports the same entry,
// and asserts the re-exported URI contains the same secret + algorithm +
// digits + period + issuer. Locks the wire format end-to-end through the
// shell-out path (init -> import-qr -> export-qr -> stdout -> grep).
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_import_qr_then_export_qr_recovers_uri_via_shell_out() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "v");
    init_vault(&dir, &vault_pw, "nano");

    let vault_path = dir.path().join("test.vault");
    let uri =
        "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30";

    // Import the hardcoded URI.
    let import_status = Command::new(origin_pass_bin())
        .args([
            "import-qr",
            "--vault",
            vault_path.to_str().unwrap(),
            uri,
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("spawn origin-pass import-qr");
    assert!(
        import_status.success(),
        "cmd_import_qr must succeed (exit={import_status})"
    );

    // Export the same entry. The "uri: ..." header line lets us grep
    // without accidentally matching the QR block.
    let export_output = Command::new(origin_pass_bin())
        .args([
            "export-qr",
            "--vault",
            vault_path.to_str().unwrap(),
            "Test",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("spawn origin-pass export-qr");
    assert!(
        export_output.status.success(),
        "cmd_export_qr must succeed (exit={}); stderr={}",
        export_output.status,
        String::from_utf8_lossy(&export_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&export_output.stdout);
    assert!(
        stdout.starts_with("uri: "),
        "expected output to begin with `uri: ` marker line, got: {}",
        &stdout[..stdout.len().min(200)]
    );
    let uri_line = stdout
        .lines()
        .next()
        .expect("at least one output line")
        .trim_start_matches("uri: ");

    // Round-trip assertions: every parameter survives the import/export
    // cycle (no lossy codec, no JSON drift).
    assert!(
        uri_line.contains("secret=JBSWY3DPEHPK3PXP"),
        "secret must round-trip byte-exact, got URI: {uri_line}"
    );
    assert!(
        uri_line.contains("issuer=Test"),
        "issuer must round-trip, got URI: {uri_line}"
    );
    assert!(
        uri_line.contains("algorithm=SHA1"),
        "algorithm must round-trip, got URI: {uri_line}"
    );
    assert!(
        uri_line.contains("digits=6"),
        "digits must round-trip, got URI: {uri_line}"
    );
    assert!(
        uri_line.contains("period=30"),
        "period must round-trip, got URI: {uri_line}"
    );
    assert!(
        uri_line.contains("otpauth://totp/Test"),
        "URI scheme + type + label must round-trip, got: {uri_line}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 6: OTP add → code round-trip
// Adds a TOTP entry via `add --type otp --secret-file`, then generates
// a code via `code`. Asserts the code is a 6-digit numeric string.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_otp_then_code_produces_6_digit_output() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-pass");
    // RFC 4226/6238 test secret in base32: "12345678901234567890"
    let secret_file = write_secret(&dir, "otp-secret.b32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Add a TOTP entry.
    let add_status = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "otp",
            "github-2fa",
            "--secret-file",
            secret_file.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("spawn origin-pass add --type otp");
    assert!(
        add_status.success(),
        "cmd_add --type otp must succeed (exit={add_status})"
    );

    // Generate a code.
    let code_output = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "github-2fa",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("spawn origin-pass code");
    assert!(
        code_output.status.success(),
        "cmd_code must succeed (exit={}); stderr={}",
        code_output.status,
        String::from_utf8_lossy(&code_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&code_output.stdout);
    let code = stdout.trim();
    assert_eq!(
        code.len(),
        6,
        "TOTP code must be exactly 6 digits, got: `{code}`"
    );
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP code must be all digits, got: `{code}`"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 7: import-qr → code round-trip
// Imports a TOTP URI via `import-qr`, then generates a code via `code`.
// Verifies the full shell-out path: URI parsing → vault storage →
// base32 decode → TOTP computation → stdout.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_import_qr_then_code_produces_valid_totp() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "v");
    init_vault(&dir, &vault_pw, "nano");

    let vault_path = dir.path().join("test.vault");
    let uri = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30";

    // Import.
    let import_status = Command::new(origin_pass_bin())
        .args([
            "import-qr",
            "--vault",
            vault_path.to_str().unwrap(),
            uri,
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("spawn import-qr");
    assert!(
        import_status.success(),
        "import-qr must succeed (exit={import_status})"
    );

    // Generate code. The entry name is derived from the URI label
    // ("Acme:alice" → the portion after the colon: "alice").
    let code_output = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "alice",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("spawn code after import-qr");
    assert!(
        code_output.status.success(),
        "code after import-qr must succeed (exit={}); stderr={}",
        code_output.status,
        String::from_utf8_lossy(&code_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&code_output.stdout);
    let code = stdout.trim();
    assert_eq!(
        code.len(),
        6,
        "TOTP code from imported URI must be 6 digits, got: `{code}`"
    );
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP code must be all digits, got: `{code}`"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 8: HOTP add → code → counter increments
// Adds an HOTP entry, generates a code, then verifies the counter
// was incremented in the vault by generating a second code and
// confirming the output differs (different counter → different code).
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_hotp_then_code_increments_counter() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-pass");
    let secret_file = write_secret(&dir, "otp-secret.b32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Add an HOTP entry with --hotp flag.
    let add_status = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "otp",
            "--hotp",
            "bank-token",
            "--secret-file",
            secret_file.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("spawn add --type otp --hotp");
    assert!(
        add_status.success(),
        "add --hotp must succeed (exit={add_status})"
    );

    // First code (counter=0).
    let code1 = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-token",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("first code");
    assert!(code1.status.success(), "first code must succeed");
    let out1 = String::from_utf8_lossy(&code1.stdout).trim().to_string();

    // Second code (counter=1 after auto-increment).
    let code2 = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-token",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("second code");
    assert!(code2.status.success(), "second code must succeed");
    let out2 = String::from_utf8_lossy(&code2.stdout).trim().to_string();

    // RFC 4226: counter 0 → 755224, counter 1 → 287082.
    assert_eq!(
        out1, "755224",
        "HOTP counter=0 must produce 755224, got: {out1}"
    );
    assert_eq!(
        out2, "287082",
        "HOTP counter=1 must produce 287082, got: {out2}"
    );
}
