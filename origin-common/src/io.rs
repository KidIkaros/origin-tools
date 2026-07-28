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
