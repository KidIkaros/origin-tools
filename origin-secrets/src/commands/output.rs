//! Shared command-output helpers for typed machine-readable responses.

use crate::error::Error;
use serde::Serialize;

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
    fn serialize_json_preserves_typed_fields() {
        let output = serialize_json(&TestResponse { ok: true, count: 2 }, "test").unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["count"], 2);
    }
}
