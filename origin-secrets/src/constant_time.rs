//! Constant-time utilities for security-sensitive operations.
//!
//! Uses `subtle::ConstantTimeEq` to prevent timing side-channels in
//! comparisons of secret or security-critical data.

use subtle::ConstantTimeEq;

/// Constant-time comparison for byte slices.
/// Returns true if equal, false otherwise — execution time is independent of input.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison for strings (e.g., passphrases).
/// Returns true if equal, false otherwise.
pub fn str_eq(a: &str, b: &str) -> bool {
    bytes_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time comparison for u8 values (e.g., share numbers).
pub fn u8_eq(a: u8, b: u8) -> bool {
    a.ct_eq(&b).into()
}

/// Constant-time comparison for u32 values.
pub fn u32_eq(a: u32, b: u32) -> bool {
    a.ct_eq(&b).into()
}

/// Constant-time check if a value is zero.
pub fn is_zero<T: ConstantTimeEq + Default>(value: &T) -> bool {
    let zero = T::default();
    value.ct_eq(&zero).into()
}

/// Constant-time check if a u8 value is in a set.
/// Iterates through all elements to avoid timing leaks from early exit.
pub fn u8_in_set(value: u8, set: &[u8]) -> bool {
    let mut found = false;
    for &elem in set {
        found |= u8_eq(value, elem);
    }
    found
}

/// Constant-time check if a u8 value is in a HashSet.
/// Converts to slice first to avoid HashSet's variable-time lookup.
pub fn u8_in_hashset(value: u8, set: &std::collections::HashSet<u8>) -> bool {
    u8_in_set(value, &set.iter().copied().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_eq() {
        assert!(bytes_eq(b"hello", b"hello"));
        assert!(!bytes_eq(b"hello", b"world"));
        assert!(!bytes_eq(b"hello", b"hell"));
        assert!(!bytes_eq(b"", b"hello"));
    }

    #[test]
    fn test_str_eq() {
        assert!(str_eq("secret", "secret"));
        assert!(!str_eq("secret", "secret1"));
        assert!(!str_eq("", "secret"));
    }

    #[test]
    fn test_u8_eq() {
        assert!(u8_eq(5, 5));
        assert!(!u8_eq(5, 6));
        assert!(!u8_eq(0, 255));
    }

    #[test]
    fn test_u32_eq() {
        assert!(u32_eq(100, 100));
        assert!(!u32_eq(100, 101));
    }

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&0u8));
        assert!(is_zero(&0u32));
        assert!(!is_zero(&1u8));
    }
}
