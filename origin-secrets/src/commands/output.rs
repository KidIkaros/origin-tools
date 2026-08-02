//! Shared command-output helpers for typed machine-readable responses.

use crate::error::Error;
use serde::Serialize;
use std::io::IsTerminal;

/// Semantic terminal style used by human-facing product output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Plain,
    Success,
    Warning,
    Critical,
}

/// Apply a semantic style only when stdout is a TTY and `NO_COLOR` is absent.
/// JSON and redirected output remain byte-stable and decoration-free.
pub fn style(label: &str, kind: Style) -> String {
    if !std::io::stdout().is_terminal() || std::env::var_os("NO_COLOR").is_some() {
        return label.to_string();
    }
    let code = match kind {
        Style::Plain => "0",
        Style::Success => "32",
        Style::Warning => "33",
        Style::Critical => "31",
    };
    format!("\x1b[{code}m{label}\x1b[0m")
}

/// Serialize one typed response without allowing formatting concerns to leak
/// into command business logic.
pub fn serialize_json<T: Serialize>(value: &T, context: &str) -> Result<String, Error> {
    serde_json::to_string(value)
        .map_err(|e| Error::IoError(format!("serialize {context} response: {e}")))
}

/// Serialize and write one typed response to stdout.
pub fn print_json<T: Serialize>(value: &T, context: &str) -> Result<(), Error> {
    println!("{}", serialize_json(value, context)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestResponse {
        ok: bool,
        count: usize,
    }

    #[test]
    fn style_is_plain_when_stdout_is_not_a_tty() {
        assert_eq!(style("Status", Style::Success), "Status");
    }

    #[test]
    fn serialize_json_preserves_typed_fields() {
        let output = serialize_json(&TestResponse { ok: true, count: 2 }, "test").unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["count"], 2);
    }
}
