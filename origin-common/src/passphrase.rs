//! Passphrase resolution — read from file or prompt on stderr.

/// Resolve a passphrase from a file or prompt the user.
///
/// If `passphrase_file` is provided, reads the passphrase from that file
/// (trimmed of trailing newlines). Otherwise, prompts on stderr (hidden input).
pub fn resolve_passphrase(passphrase_file: Option<&str>) -> Result<String, String> {
    match passphrase_file {
        Some(path) => {
            let s = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file '{}': {e}", path))?;
            let trimmed = s.trim_end_matches('\n').trim_end_matches('\r').to_string();
            if trimmed.is_empty() {
                eprintln!("warning: passphrase file '{}' is empty", path);
            }
            Ok(trimmed)
        }
        None => rpassword::prompt_password("Passphrase: ")
            .map_err(|e| format!("passphrase prompt failed: {e}")),
    }
}

/// Resolve a passphrase from a file or prompt the user, confirming via a
/// second prompt. Used during initial setup (init/create).
pub fn resolve_passphrase_confirm(passphrase_file: Option<&str>) -> Result<String, String> {
    match passphrase_file {
        Some(path) => {
            let s = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file '{}': {e}", path))?;
            let trimmed = s.trim_end_matches('\n').trim_end_matches('\r').to_string();
            if trimmed.is_empty() {
                eprintln!("warning: passphrase file '{}' is empty", path);
            }
            Ok(trimmed)
        }
        None => {
            let a = rpassword::prompt_password("Passphrase: ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))?;
            let b = rpassword::prompt_password("Confirm passphrase: ")
                .map_err(|e| format!("passphrase confirm failed: {e}"))?;
            if a != b {
                return Err("passphrases do not match".to_string());
            }
            Ok(a)
        }
    }
}
