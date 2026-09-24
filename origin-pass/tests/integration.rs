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

// ──────────────────────────────────────────────────────────────────────
// Test 9: generate — password + passphrase, entropy on stderr
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_generate_produces_password_of_requested_length() {
    let output = Command::new(origin_pass_bin())
        .args(["generate", "--length", "24"])
        .output()
        .expect("spawn origin-pass generate");
    assert!(
        output.status.success(),
        "generate must succeed (exit={}); stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pw = stdout.trim();
    assert_eq!(pw.len(), 24, "password must be 24 chars, got: `{pw}`");
    assert!(
        pw.chars().any(|c| "!@#$%^&*()-_=+[]{};:,.?/~".contains(c)),
        "default charset should include a symbol, got: `{pw}`"
    );
    // Entropy estimate goes to stderr so it never pollutes a pipeline.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("entropy:"),
        "expected an entropy line on stderr, got: {stderr}"
    );
}

#[test]
fn cmd_generate_excluded_charset_and_passphrase() {
    // Lowercase-only password: no symbols, no digits, no uppercase.
    let out = Command::new(origin_pass_bin())
        .args([
            "generate",
            "--length",
            "32",
            "--exclude-symbols",
            "--exclude-digits",
            "--exclude-upper",
        ])
        .output()
        .expect("generate lowercase");
    assert!(out.status.success(), "generate lowercase must succeed");
    let pw = String::from_utf8_lossy(&out.stdout);
    assert!(
        pw.trim().chars().all(|c| c.is_ascii_lowercase()),
        "lowercase-only password expected, got: `{pw}`"
    );

    // Passphrase: 4 words joined by '-'.
    let out = Command::new(origin_pass_bin())
        .args(["generate", "--passphrase", "--words", "4"])
        .output()
        .expect("generate passphrase");
    assert!(out.status.success(), "generate passphrase must succeed");
    let phrase = String::from_utf8_lossy(&out.stdout);
    let words: Vec<&str> = phrase.trim().split('-').collect();
    assert_eq!(
        words.len(),
        4,
        "passphrase must have 4 words, got: `{phrase}`"
    );
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())),
        "passphrase words must be lowercase, got: `{phrase}`"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("entropy: 32.0 bits"),
        "4 words × 8 bits = 32 bits, got stderr: {stderr}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 10: session tokens — unlock once, reuse across processes
// ──────────────────────────────────────────────────────────────────────

#[test]
fn session_token_unlock_reuse_and_revoke() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");
    let entry_secret = write_secret(&dir, "entry-secret", "top-secret-value");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Add an entry (passphrase-based).
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
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .status()
        .expect("add");
    assert!(status.success(), "add must succeed");

    // Unlock once, writing a session token.
    let token_path = dir.path().join("session.token");
    let unlock = Command::new(origin_pass_bin())
        .args([
            "unlock",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
            "--session-token",
            token_path.to_str().unwrap(),
            "--session-ttl",
            "3600",
        ])
        .output()
        .expect("unlock with token");
    assert!(
        unlock.status.success(),
        "unlock --session-token must succeed (exit={}); stderr={}",
        unlock.status,
        String::from_utf8_lossy(&unlock.stderr)
    );
    assert!(token_path.exists(), "session token file must be written");
    assert!(
        String::from_utf8_lossy(&unlock.stderr).contains("session token written"),
        "expected 'session token written' on stderr"
    );

    // Reuse the token in a FRESH process without the passphrase.
    let get = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "github.com",
            "--session-token",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("get via session token");
    assert!(
        get.status.success(),
        "get via session token must succeed (exit={}); stderr={}",
        get.status,
        String::from_utf8_lossy(&get.stderr)
    );
    assert!(
        String::from_utf8_lossy(&get.stdout).contains("top-secret-value"),
        "secret must be recoverable via session token"
    );

    // list via token too (any vault command accepts it).
    let list = Command::new(origin_pass_bin())
        .args([
            "list",
            "--vault",
            vault_path.to_str().unwrap(),
            "--session-token",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("list via session token");
    assert!(list.status.success(), "list via session token must succeed");
    assert!(String::from_utf8_lossy(&list.stdout).contains("github.com"));

    // add + code via token too — regression: `code` (TOTP path) used to
    // reject --session-token in its pre-flight passphrase check.
    let secret_b32 = write_secret(&dir, "totp.b32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    let add_otp = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "otp",
            "token-2fa",
            "--secret-file",
            secret_b32.to_str().unwrap(),
            "--session-token",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("add otp via session token");
    assert!(
        add_otp.status.success(),
        "add --type otp via session token must succeed (exit={}); stderr={}",
        add_otp.status,
        String::from_utf8_lossy(&add_otp.stderr)
    );
    let code_out = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "token-2fa",
            "--session-token",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("code via session token");
    assert!(
        code_out.status.success(),
        "code via session token must succeed (exit={}); stderr={}",
        code_out.status,
        String::from_utf8_lossy(&code_out.stderr)
    );
    let code = String::from_utf8_lossy(&code_out.stdout);
    assert_eq!(code.trim().len(), 6, "TOTP code must be 6 digits");

    // Revoke: lock --session-token deletes the file.
    let lock = Command::new(origin_pass_bin())
        .args(["lock", "--session-token", token_path.to_str().unwrap()])
        .output()
        .expect("lock --session-token");
    assert!(lock.status.success(), "lock must succeed");
    assert!(!token_path.exists(), "lock must delete the token file");

    // After revocation the token no longer works.
    let get2 = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "github.com",
            "--session-token",
            token_path.to_str().unwrap(),
        ])
        .output()
        .expect("get after revocation");
    assert!(
        !get2.status.success(),
        "revoked token must fail (exit={})",
        get2.status
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 11: `tokens` command — list / revoke / revoke-all lifecycle
// ──────────────────────────────────────────────────────────────────────

#[test]
fn tokens_command_lists_and_revokes_session_tokens() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");
    // Custom token store, isolated from the real ~/.origin/tokens.
    let store = dir.path().join("tokens");

    // Write two session tokens into the store.
    for name in ["work", "home"] {
        let unlock = Command::new(origin_pass_bin())
            .args([
                "unlock",
                "--vault",
                vault_path.to_str().unwrap(),
                "--passphrase-file",
                vault_pw.to_str().unwrap(),
                "--session-token",
                store.join(format!("{name}.token")).to_str().unwrap(),
                "--session-ttl",
                "3600",
            ])
            .output()
            .expect("unlock with token");
        assert!(
            unlock.status.success(),
            "unlock for {name} must succeed; stderr={}",
            String::from_utf8_lossy(&unlock.stderr)
        );
    }

    // Table listing shows both tokens as valid.
    let list = Command::new(origin_pass_bin())
        .args(["tokens", "list", "--dir", store.to_str().unwrap()])
        .output()
        .expect("tokens list");
    assert!(list.status.success(), "tokens list must succeed");
    let table = String::from_utf8_lossy(&list.stdout);
    assert!(table.contains("work.token"), "table must list work.token");
    assert!(table.contains("home.token"), "table must list home.token");
    assert!(
        table.contains("valid"),
        "unexpired tokens show status valid"
    );

    // JSON listing is parseable and complete.
    let json_out = Command::new(origin_pass_bin())
        .args([
            "tokens",
            "list",
            "--dir",
            store.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("tokens list --format json");
    assert!(
        json_out.status.success(),
        "tokens list --format json must succeed"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("json listing must parse");
    let rows = parsed.as_array().expect("json listing must be an array");
    assert_eq!(rows.len(), 2, "json listing must contain both tokens");
    let names: Vec<&str> = rows.iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(names.contains(&"work.token") && names.contains(&"home.token"));

    // Revoke one token by bare name, resolved into the custom store.
    let revoke = Command::new(origin_pass_bin())
        .args(["tokens", "revoke", "work", "--dir", store.to_str().unwrap()])
        .output()
        .expect("tokens revoke");
    assert!(
        revoke.status.success(),
        "tokens revoke must succeed; stderr={}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    assert!(
        !store.join("work.token").exists(),
        "revoked token file must be deleted"
    );
    assert!(
        store.join("home.token").exists(),
        "other tokens must survive"
    );

    // The revoked token no longer unlocks the vault.
    let get = Command::new(origin_pass_bin())
        .args([
            "get",
            "--vault",
            vault_path.to_str().unwrap(),
            "any-entry",
            "--session-token",
            store.join("work.token").to_str().unwrap(),
        ])
        .output()
        .expect("get with revoked token");
    assert!(
        !get.status.success(),
        "revoked token must fail to unlock (exit={})",
        get.status
    );

    // Revoke-all clears the rest.
    let revoke_all = Command::new(origin_pass_bin())
        .args(["tokens", "revoke-all", "--dir", store.to_str().unwrap()])
        .output()
        .expect("tokens revoke-all");
    assert!(
        revoke_all.status.success(),
        "tokens revoke-all must succeed; stderr={}",
        String::from_utf8_lossy(&revoke_all.stderr)
    );
    assert!(
        !store.join("home.token").exists(),
        "revoke-all must clear the store"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 12: bare-name lock / lock-all / tokens rotate (HOME-isolated)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn bare_name_lock_lock_all_and_token_rotation() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Point HOME at the tempdir so bare store names resolve into
    // <tmp>/.origin/tokens instead of the real home directory.
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = home.join(".origin/tokens");

    let run = |args: &[&str]| {
        Command::new(origin_pass_bin())
            .env("HOME", &home)
            .args(args)
            .output()
            .expect("spawn origin-pass")
    };

    // Mint two tokens via bare names: `--session-token work` → work.token.
    for name in ["work", "home"] {
        let unlock = run(&[
            "unlock",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
            "--session-token",
            name,
            "--session-ttl",
            "3600",
        ]);
        assert!(
            unlock.status.success(),
            "unlock --session-token {name} (bare) must succeed; stderr={}",
            String::from_utf8_lossy(&unlock.stderr)
        );
        assert!(
            store.join(format!("{name}.token")).exists(),
            "bare name must resolve into the store"
        );
    }

    // `lock --session-token work` (bare name) revokes it.
    let lock = run(&["lock", "--session-token", "work"]);
    assert!(
        lock.status.success(),
        "lock --session-token work (bare) must succeed; stderr={}",
        String::from_utf8_lossy(&lock.stderr)
    );
    assert!(
        !store.join("work.token").exists(),
        "bare-name lock must revoke"
    );
    assert!(
        store.join("home.token").exists(),
        "other tokens must survive"
    );

    // `tokens rotate home` refreshes the token in place (no passphrase).
    let rotate = run(&["tokens", "rotate", "home", "--ttl", "7200"]);
    assert!(
        rotate.status.success(),
        "tokens rotate must succeed; stderr={}",
        String::from_utf8_lossy(&rotate.stderr)
    );
    assert!(
        store.join("home.token").exists(),
        "rotate must not delete the token"
    );
    // The rotated token still unlocks the vault (same master key).
    // `list` proves the unlock without needing a named entry.
    let list = run(&[
        "list",
        "--vault",
        vault_path.to_str().unwrap(),
        "--session-token",
        "home",
    ]);
    assert!(
        list.status.success(),
        "rotated token must still unlock (exit={}); stderr={}",
        list.status,
        String::from_utf8_lossy(&list.stderr)
    );

    // `lock-all` revokes everything left (bare, store-wide).
    let lock_all = run(&["lock-all"]);
    assert!(
        lock_all.status.success(),
        "lock-all must succeed; stderr={}",
        String::from_utf8_lossy(&lock_all.stderr)
    );
    assert!(
        !store.join("home.token").exists(),
        "lock-all must revoke the remaining token"
    );

    // lock-all with nothing left errors (matches bare `lock` strictness).
    let again = run(&["lock-all"]);
    assert!(
        !again.status.success(),
        "lock-all on an empty store must error"
    );
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nothing to lock"),
        "empty lock-all must say nothing to lock"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 13: $ORIGIN_PASS_TOKEN env var + auto-rotate + list summary
// ──────────────────────────────────────────────────────────────────────

#[test]
fn env_var_token_and_auto_rotate_and_list_summary() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");
    let entry_secret = write_secret(&dir, "entry-secret", "env-token-secret");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Point HOME at the tempdir so bare names resolve into it.
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = home.join(".origin/tokens");
    let run = |args: &[&str], env: Option<(&str, &str)>| {
        let mut cmd = Command::new(origin_pass_bin());
        cmd.env("HOME", &home);
        if let Some((k, v)) = env {
            cmd.env(k, v);
        }
        cmd.args(args).output().expect("spawn origin-pass")
    };

    // Add an entry, then mint an auto-rotating token with a 3s TTL.
    let add = run(
        &[
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "password",
            "github.com",
            "--secret-file",
            entry_secret.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ],
        None,
    );
    assert!(add.status.success(), "add must succeed");
    let unlock = run(
        &[
            "unlock",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
            "--session-token",
            "work",
            "--session-ttl",
            "3",
            "--auto-rotate",
        ],
        None,
    );
    assert!(
        unlock.status.success(),
        "unlock --auto-rotate must succeed; stderr={}",
        String::from_utf8_lossy(&unlock.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unlock.stderr).contains("auto-rotate"),
        "unlock should announce the auto-rotate policy"
    );

    let token_id_before = read_token_id(&store.join("work.token"));

    // Use the token via $ORIGIN_PASS_TOKEN (no --session-token flag). The
    // use also triggers auto-rotation: remaining (~3s) < default 900s
    // threshold, so the file is refreshed with a new bearer key + id.
    let get = run(
        &["get", "--vault", vault_path.to_str().unwrap(), "github.com"],
        Some((
            "ORIGIN_PASS_TOKEN",
            store.join("work.token").to_str().unwrap(),
        )),
    );
    assert!(
        get.status.success(),
        "get via ORIGIN_PASS_TOKEN must succeed (exit={}); stderr={}",
        get.status,
        String::from_utf8_lossy(&get.stderr)
    );
    assert!(
        String::from_utf8_lossy(&get.stdout).contains("env-token-secret"),
        "secret must be recoverable via the env var"
    );
    assert_ne!(
        read_token_id(&store.join("work.token")),
        token_id_before,
        "using a low-lifetime auto-rotate token must refresh it in place"
    );

    // `tokens list` shows the remaining column + a summary line.
    let list = run(&["tokens", "list"], None);
    assert!(list.status.success(), "tokens list must succeed");
    let table = String::from_utf8_lossy(&list.stdout);
    assert!(
        table.contains("remaining"),
        "table must have a remaining column"
    );
    let stderr = String::from_utf8_lossy(&list.stderr);
    assert!(
        stderr.contains("summary: 1 valid"),
        "summary must count the valid token, got stderr: {stderr}"
    );

    // `lock` works from the env var alone (no flag).
    let lock = run(
        &["lock"],
        Some((
            "ORIGIN_PASS_TOKEN",
            store.join("work.token").to_str().unwrap(),
        )),
    );
    assert!(
        lock.status.success(),
        "lock via ORIGIN_PASS_TOKEN must succeed; stderr={}",
        String::from_utf8_lossy(&lock.stderr)
    );
    assert!(
        !store.join("work.token").exists(),
        "env-var lock must revoke"
    );
}

/// Read the token_id field from a token file (for rotation assertions).
fn read_token_id(path: &std::path::Path) -> String {
    let raw = std::fs::read_to_string(path).expect("read token file");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse token json");
    v["token_id"].as_str().expect("token_id field").to_string()
}

// ──────────────────────────────────────────────────────────────────────
// Test 14: `tokens list --remaining` exit codes + `tokens renew`
// ──────────────────────────────────────────────────────────────────────

#[test]
fn remaining_filter_exit_codes_and_renew() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = home.join(".origin/tokens");
    let run = |args: &[&str]| {
        Command::new(origin_pass_bin())
            .env("HOME", &home)
            .args(args)
            .output()
            .expect("spawn origin-pass")
    };

    // One short-lived token (60s) and one long-lived (3600s).
    for (name, ttl) in [("soon", "60"), ("later", "3600")] {
        let unlock = run(&[
            "unlock",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
            "--session-token",
            name,
            "--session-ttl",
            ttl,
        ]);
        assert!(unlock.status.success(), "unlock {name} must succeed");
    }

    // --remaining 5: only the 60s token matches → exit 1 (alert).
    let near = run(&["tokens", "list", "--remaining", "5"]);
    assert_eq!(near.status.code(), Some(1), "matches must exit 1");
    let stdout = String::from_utf8_lossy(&near.stdout);
    assert!(stdout.contains("soon.token"), "short token must match");
    assert!(
        !stdout.contains("later.token"),
        "long token must be filtered out"
    );

    // No matches → exit 0 with an informative stderr line.
    let none = run(&["tokens", "list", "--remaining", "0"]);
    assert_eq!(none.status.code(), Some(0), "no matches must exit 0");
    assert!(
        String::from_utf8_lossy(&none.stderr).contains("no tokens expire within"),
        "empty filtered list should say so"
    );

    // Renew `soon`: same token id + bearer key, expiry pushed out.
    let soon_path = store.join("soon.token");
    let id_before = read_token_id(&soon_path);
    let expires_before: i64 =
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&soon_path).unwrap())
            .unwrap()["expires_at"]
            .as_i64()
            .unwrap();

    let renew = run(&["tokens", "renew", "soon", "--ttl", "7200"]);
    assert!(
        renew.status.success(),
        "tokens renew must succeed; stderr={}",
        String::from_utf8_lossy(&renew.stderr)
    );
    let renewed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&soon_path).unwrap()).unwrap();
    assert_eq!(
        renewed["token_id"].as_str().unwrap(),
        id_before,
        "renew must keep the token id"
    );
    assert!(
        renewed["expires_at"].as_i64().unwrap() > expires_before,
        "renew must extend the expiry"
    );

    // After renew, `soon` no longer matches a 5-minute window → exit 0.
    let after = run(&["tokens", "list", "--remaining", "5"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "renewed token must no longer match"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 15: `tokens prune` + JSON `--remaining` exit-code semantics
// ──────────────────────────────────────────────────────────────────────

#[test]
fn prune_and_json_remaining_exit_codes() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-passphrase");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = home.join(".origin/tokens");
    let run = |args: &[&str]| {
        Command::new(origin_pass_bin())
            .env("HOME", &home)
            .args(args)
            .output()
            .expect("spawn origin-pass")
    };

    for (name, ttl) in [("soon", "60"), ("later", "3600")] {
        let unlock = run(&[
            "unlock",
            "--vault",
            vault_path.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
            "--session-token",
            name,
            "--session-ttl",
            ttl,
        ]);
        assert!(unlock.status.success(), "unlock {name} must succeed");
    }
    // A corrupt token file — prune must clean it; the remaining filter
    // must exclude it (no expiry to judge).
    std::fs::write(store.join("garbage.token"), b"not json").unwrap();

    // JSON + --remaining: matches → exit 1, parseable array with only
    // the matching token.
    let near = run(&["tokens", "list", "--remaining", "5", "--format", "json"]);
    assert_eq!(near.status.code(), Some(1), "json matches must exit 1");
    let rows: serde_json::Value = serde_json::from_slice(&near.stdout).expect("json array");
    let names: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["soon.token"],
        "only the near-expiry token matches"
    );

    // Backdate soon's expiry so prune treats it as expired (a 60s token
    // is still valid this soon after minting).
    {
        let path = store.join("soon.token");
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["expires_at"] = serde_json::json!(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 10
        );
        std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }

    // Prune: removes expired + unreadable, keeps valid, reports counts.
    let prune = run(&["tokens", "prune"]);
    assert!(prune.status.success(), "prune must succeed");
    let stderr = String::from_utf8_lossy(&prune.stderr);
    assert!(
        stderr.contains("pruned: soon.token (expired)"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("pruned: garbage.token (unreadable)"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pruned 2 token(s)"), "stderr: {stderr}");
    assert!(
        store.join("later.token").exists(),
        "valid tokens must survive"
    );
    assert!(!store.join("soon.token").exists());
    assert!(!store.join("garbage.token").exists());

    // JSON + --remaining after prune: no matches → exit 0, empty array.
    let after = run(&["tokens", "list", "--remaining", "5", "--format", "json"]);
    assert_eq!(after.status.code(), Some(0), "no matches must exit 0");
    let rows: serde_json::Value = serde_json::from_slice(&after.stdout).expect("json array");
    assert_eq!(
        rows.as_array().unwrap().len(),
        0,
        "empty array when nothing matches"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 16: OCRA add + code + replay ledger (RFC 6287 vector)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_ocra_then_code_matches_rfc_vector_and_rejects_replay() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-pass");
    // RFC 6287 §A.1 key: ASCII "12345678901234567890" (20 bytes).
    let key_file = write_secret(&dir, "ocra-key", "12345678901234567890");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // Add an OCRA entry with the canonical suite.
    let add = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "ocra",
            "bank-ocra",
            "--suite",
            "OCRA-1:HOTP-SHA1-6:QN08",
            "--secret-file",
            key_file.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("add --type ocra");
    assert!(
        add.status.success(),
        "add --type ocra must succeed (exit={}); stderr={}",
        add.status,
        String::from_utf8_lossy(&add.stderr)
    );

    // Generate the RFC 6287 §A.1 test vector: QN08 challenge "00000000" → 196958.
    let code = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-ocra",
            "--ocra",
            "--challenge",
            "00000000",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("code --ocra");
    assert!(
        code.status.success(),
        "code --ocra must succeed (exit={}); stderr={}",
        code.status,
        String::from_utf8_lossy(&code.stderr)
    );
    let stdout = String::from_utf8_lossy(&code.stdout);
    assert_eq!(
        stdout.trim(),
        "196958",
        "RFC 6287 §A.1 QN08/SHA1/6 challenge 00000000 must produce 196958, got: `{stdout}`"
    );

    // Replaying the same challenge is refused by the ledger.
    let replay = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-ocra",
            "--ocra",
            "--challenge",
            "00000000",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("replay code");
    assert!(
        !replay.status.success(),
        "replaying a used challenge must fail (exit={})",
        replay.status
    );
    let replay_err = String::from_utf8_lossy(&replay.stderr);
    assert!(
        replay_err.contains("replay"),
        "expected a replay error, got: {replay_err}"
    );

    // --force re-issues it (explicit override).
    let forced = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-ocra",
            "--ocra",
            "--challenge",
            "00000000",
            "--force",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("forced replay");
    assert!(
        forced.status.success(),
        "--force must override the replay check (exit={}); stderr={}",
        forced.status,
        String::from_utf8_lossy(&forced.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&forced.stdout).trim(),
        "196958",
        "forced replay must produce the same code"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Test 12: OCRA counter suite — counter auto-increments across uses
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cmd_add_ocra_counter_suite_auto_increments() {
    let dir = TempDir::new().expect("tempdir");
    let vault_pw = write_secret(&dir, "vault-pw", "vault-pass");
    let key_file = write_secret(&dir, "ocra-key", "12345678901234567890");

    init_vault(&dir, &vault_pw, "nano");
    let vault_path = dir.path().join("test.vault");

    // C-QN08: counter + 8-digit numeric challenge.
    let add = Command::new(origin_pass_bin())
        .args([
            "add",
            "--vault",
            vault_path.to_str().unwrap(),
            "--type",
            "ocra",
            "bank-counter",
            "--suite",
            "OCRA-1:HOTP-SHA1-6:C-QN08",
            "--secret-file",
            key_file.to_str().unwrap(),
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("add counter suite");
    assert!(
        add.status.success(),
        "add counter suite must succeed (exit={}); stderr={}",
        add.status,
        String::from_utf8_lossy(&add.stderr)
    );

    let run_code = |challenge: &str| -> std::process::Output {
        Command::new(origin_pass_bin())
            .args([
                "code",
                "--vault",
                vault_path.to_str().unwrap(),
                "bank-counter",
                "--ocra",
                "--challenge",
                challenge,
                "--passphrase-file",
                vault_pw.to_str().unwrap(),
            ])
            .output()
            .expect("code with counter suite")
    };

    // First use: stored counter 0 → persisted as 1.
    let c1 = run_code("11111111");
    assert!(c1.status.success(), "first counter use must succeed");
    let out1 = String::from_utf8_lossy(&c1.stdout).trim().to_string();
    assert_eq!(out1.len(), 6);

    // Second use with a different challenge: stored counter 1 → 2.
    let c2 = run_code("22222222");
    assert!(c2.status.success(), "second counter use must succeed");
    let out2 = String::from_utf8_lossy(&c2.stdout).trim().to_string();
    assert_eq!(out2.len(), 6);

    // Explicit --counter override must NOT advance the stored counter:
    // it is a verification call. Compute with --counter 2 and challenge
    // 33333333 (recording fp(33333333, 2) in the ledger), then run the
    // plain path with --force against the SAME challenge: if the stored
    // counter is still 2, both codes match; if the override had advanced
    // it to 3, they would differ.
    let override_run = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-counter",
            "--ocra",
            "--challenge",
            "33333333",
            "--counter",
            "2",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("counter override");
    assert!(override_run.status.success(), "override run must succeed");
    let out_override = String::from_utf8_lossy(&override_run.stdout)
        .trim()
        .to_string();

    // Plain run with --force (the fp was already recorded by the override).
    let plain = Command::new(origin_pass_bin())
        .args([
            "code",
            "--vault",
            vault_path.to_str().unwrap(),
            "bank-counter",
            "--ocra",
            "--challenge",
            "33333333",
            "--force",
            "--passphrase-file",
            vault_pw.to_str().unwrap(),
        ])
        .output()
        .expect("plain run after override");
    assert!(plain.status.success(), "plain run must succeed");
    let out_plain = String::from_utf8_lossy(&plain.stdout).trim().to_string();
    assert_eq!(
        out_plain, out_override,
        "plain run must use the same (stored) counter as the explicit override — \
         the override must not advance the persisted counter"
    );
}
