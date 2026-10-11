use core::fmt;

use crate::hash::Hash256;
use crate::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidDigit { index: usize },
    Length { expected: usize, got: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex string has an odd number of digits"),
            Self::InvalidDigit { index } => write!(f, "invalid hex digit at position {index}"),
            Self::Length { expected, got } => write!(f, "expected {expected} bytes, got {got}"),
        }
    }
}

impl core::error::Error for HexError {}

/// Lowercase hex with a `0x` prefix.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

/// Decodes hex, with or without a `0x` prefix, in either case.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let offset = s.len() - digits.len();
    if digits.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let value = |i: usize| match digits.as_bytes()[i] {
        c @ b'0'..=b'9' => Ok(c - b'0'),
        c @ b'a'..=b'f' => Ok(c - b'a' + 10),
        c @ b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::InvalidDigit { index: offset + i }),
    };
    (0..digits.len() / 2).map(|i| Ok(value(2 * i)? << 4 | value(2 * i + 1)?)).collect()
}

/// Decodes exactly 32 bytes of hex.
pub fn decode_hash(s: &str) -> Result<Hash256, HexError> {
    let bytes = decode(s)?;
    bytes.as_slice().try_into().map_err(|_| HexError::Length { expected: 32, got: bytes.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(encode([0xde, 0xad, 0x01]), "0xdead01");
        assert_eq!(encode([]), "0x");
        assert_eq!(decode("0xDEad01"), Ok(vec![0xde, 0xad, 0x01]));
        assert_eq!(decode("dead"), Ok(vec![0xde, 0xad]));
        assert_eq!(decode(""), Ok(vec![]));
        let h = [7u8; 32];
        assert_eq!(decode_hash(&encode(h)), Ok(h));
    }

    #[test]
    fn errors() {
        assert_eq!(decode("0xabc"), Err(HexError::OddLength));
        assert_eq!(decode("0x0g"), Err(HexError::InvalidDigit { index: 3 }));
        assert_eq!(decode_hash("0x00"), Err(HexError::Length { expected: 32, got: 1 }));
    }
}
