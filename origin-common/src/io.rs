//! Shared IO utilities for the origin-tools suite.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

/// Read input from a file or stdin.
///
/// If `path` is provided, reads from that file. Otherwise reads from stdin.
pub fn read_input(path: Option<&str>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) => fs::read(p).map_err(|e| format!("cannot read '{}': {e}", p)),
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

/// Write output to a file or stdout.
///
/// If `path` is provided, writes to that file (creating parent directories if needed).
/// Otherwise writes to stdout.
pub fn write_output(path: Option<&str>, data: &[u8]) -> Result<(), String> {
    match path {
        Some(p) => {
            if let Some(parent) = Path::new(p).parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(|e| {
                        format!("cannot create directory '{}': {e}", parent.display())
                    })?;
                }
            }
            fs::write(p, data).map_err(|e| format!("cannot write '{}': {e}", p))
        }
        None => {
            io::stdout()
                .write_all(data)
                .map_err(|e| format!("cannot write to stdout: {e}"))?;
            Ok(())
        }
    }
}

/// Atomically replace `path` with `contents`: write to a temp file in the same
/// directory, then `rename` over the target. A crash mid-write leaves the
/// original file intact (no partial content), so this is safe for vault state
/// that must survive restart. Shared so origin-secrets / origin-memory use one
/// implementation instead of each rolling their own.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create directory '{}': {e}", parent.display()))?;
        }
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_path = tempfile_path(dir)?;
    {
        let mut tmp = fs::File::create(&tmp_path)
            .map_err(|e| format!("cannot create temp file '{}': {e}", tmp_path.display()))?;
        tmp.write_all(contents)
            .map_err(|e| format!("cannot write temp file: {e}"))?;
        tmp.flush()
            .map_err(|e| format!("cannot flush temp file: {e}"))?;
    }
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("cannot rename temp file to '{}': {e}", path.display()))?;
    Ok(())
}

/// Compute a unique temp file path inside `dir` (or the system temp dir).
fn tempfile_path(dir: Option<&Path>) -> Result<std::path::PathBuf, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let name = format!(".tmp-{pid}-{nanos}");
    Ok(match dir {
        Some(d) => d.join(&name),
        None => std::env::temp_dir().join(&name),
    })
}
