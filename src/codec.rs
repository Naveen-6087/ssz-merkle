use std::fmt;

use crate::Ssz;

pub const OFFSET_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength { expected: usize, got: usize },
    NotMultiple { len: usize, item_size: usize },
    InvalidBool(u8),
    TooManyElements { limit: usize, got: usize },
    WrongElementCount { expected: usize, got: usize },
    InvalidOffset { offset: usize, reason: &'static str },
    MissingDelimiter,
    NonZeroPadding,
    TooManyBits { limit: usize, got: usize },
    IllegalType(&'static str),
    InField { field: &'static str, source: Box<DecodeError> },
    InElement { index: usize, source: Box<DecodeError> },
}

impl DecodeError {
    pub fn in_field(self, field: &'static str) -> Self {
        Self::InField { field, source: Box::new(self) }
    }

    pub fn in_element(self, index: usize) -> Self {
        Self::InElement { index, source: Box::new(self) }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => write!(f, "expected {expected} bytes, got {got}"),
            Self::NotMultiple { len, item_size } => {
                write!(f, "{len} bytes is not a multiple of the {item_size}-byte item size")
            }
            Self::InvalidBool(b) => write!(f, "invalid boolean byte 0x{b:02x}"),
            Self::TooManyElements { limit, got } => write!(f, "{got} elements exceed the limit of {limit}"),
            Self::WrongElementCount { expected, got } => write!(f, "expected {expected} elements, got {got}"),
            Self::InvalidOffset { offset, reason } => write!(f, "invalid offset {offset}: {reason}"),
            Self::MissingDelimiter => write!(f, "bitlist has no length delimiter bit"),
            Self::NonZeroPadding => write!(f, "bitvector has non-zero padding bits"),
            Self::TooManyBits { limit, got } => write!(f, "{got} bits exceed the limit of {limit}"),
            Self::IllegalType(why) => write!(f, "illegal type: {why}"),
            Self::InField { field, source } => write!(f, "field `{field}`: {source}"),
            Self::InElement { index, source } => write!(f, "element {index}: {source}"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn write_offset(out: &mut Vec<u8>, offset: usize) {
    let offset = u32::try_from(offset).expect("ssz: serialized object exceeds 2^32 bytes");
    out.extend_from_slice(&offset.to_le_bytes());
}

fn read_offset(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + OFFSET_LEN].try_into().expect("4 bytes")) as usize
}

pub fn expect_len(bytes: &[u8], expected: usize) -> Result<(), DecodeError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidLength { expected, got: bytes.len() })
    }
}

pub fn encoded_len_of<T: Ssz>(items: &[T]) -> usize {
    match T::fixed_size() {
        Some(size) => size * items.len(),
        None => items.iter().map(|item| OFFSET_LEN + item.encoded_len()).sum(),
    }
}

pub fn encode_items<T: Ssz>(items: &[T], out: &mut Vec<u8>) {
    if T::fixed_size().is_some() {
        for item in items {
            item.encode_into(out);
        }
        return;
    }
    let start = out.len();
    out.resize(start + OFFSET_LEN * items.len(), 0);
    for (i, item) in items.iter().enumerate() {
        let offset = u32::try_from(out.len() - start).expect("ssz: serialized object exceeds 2^32 bytes");
        out[start + OFFSET_LEN * i..start + OFFSET_LEN * (i + 1)].copy_from_slice(&offset.to_le_bytes());
        item.encode_into(out);
    }
}

pub enum Count {
    Exact(usize),
    AtMost(usize),
    Unbounded,
}

impl Count {
    fn check(&self, got: usize) -> Result<(), DecodeError> {
        match *self {
            Count::Exact(expected) if got != expected => {
                Err(DecodeError::WrongElementCount { expected, got })
            }
            Count::AtMost(limit) if got > limit => Err(DecodeError::TooManyElements { limit, got }),
            _ => Ok(()),
        }
    }
}

pub fn decode_items<T: Ssz>(bytes: &[u8], count: Count) -> Result<Vec<T>, DecodeError> {
    if let Some(size) = T::fixed_size() {
        if size == 0 {
            return Err(DecodeError::IllegalType("zero-sized element"));
        }
        if bytes.len() % size != 0 {
            return Err(DecodeError::NotMultiple { len: bytes.len(), item_size: size });
        }
        count.check(bytes.len() / size)?;
        return bytes
            .chunks(size)
            .enumerate()
            .map(|(i, chunk)| T::from_ssz(chunk).map_err(|e| e.in_element(i)))
            .collect();
    }

    if bytes.is_empty() {
        count.check(0)?;
        return Ok(Vec::new());
    }
    if bytes.len() < OFFSET_LEN {
        return Err(DecodeError::InvalidLength { expected: OFFSET_LEN, got: bytes.len() });
    }
    let first = read_offset(bytes, 0);
    if first == 0 || first % OFFSET_LEN != 0 {
        return Err(DecodeError::InvalidOffset {
            offset: first,
            reason: "first offset is not a positive multiple of 4",
        });
    }
    if first > bytes.len() {
        return Err(DecodeError::InvalidOffset { offset: first, reason: "out of bounds" });
    }
    let n = first / OFFSET_LEN;
    count.check(n)?;
    let mut offsets: Vec<usize> = (0..n).map(|i| read_offset(bytes, i * OFFSET_LEN)).collect();
    offsets.push(bytes.len());
    offsets
        .windows(2)
        .enumerate()
        .map(|(i, w)| {
            if w[1] < w[0] {
                return Err(DecodeError::InvalidOffset { offset: w[1], reason: "offsets decrease" });
            }
            if w[1] > bytes.len() {
                return Err(DecodeError::InvalidOffset { offset: w[1], reason: "out of bounds" });
            }
            T::from_ssz(&bytes[w[0]..w[1]]).map_err(|e| e.in_element(i))
        })
        .collect()
}

/// Splits a serialized container into one slice per field, validating the
/// offsets of variable-size fields.
pub fn split_container<'a>(bytes: &'a [u8], sizes: &[Option<usize>]) -> Result<Vec<&'a [u8]>, DecodeError> {
    let fixed_len: usize = sizes.iter().map(|s| s.unwrap_or(OFFSET_LEN)).sum();
    if bytes.len() < fixed_len {
        return Err(DecodeError::InvalidLength { expected: fixed_len, got: bytes.len() });
    }

    let mut parts = Vec::with_capacity(sizes.len());
    let mut variable = Vec::new();
    let mut cursor = 0;
    for size in sizes {
        match size {
            Some(size) => {
                parts.push(Some(&bytes[cursor..cursor + size]));
                cursor += size;
            }
            None => {
                variable.push((parts.len(), read_offset(bytes, cursor)));
                parts.push(None);
                cursor += OFFSET_LEN;
            }
        }
    }

    if variable.is_empty() {
        expect_len(bytes, fixed_len)?;
    } else if variable[0].1 != fixed_len {
        return Err(DecodeError::InvalidOffset {
            offset: variable[0].1,
            reason: "first offset does not end the fixed part",
        });
    }
    for (i, &(field, start)) in variable.iter().enumerate() {
        let end = variable.get(i + 1).map_or(bytes.len(), |&(_, next)| next);
        if end < start {
            return Err(DecodeError::InvalidOffset { offset: end, reason: "offsets decrease" });
        }
        if end > bytes.len() {
            return Err(DecodeError::InvalidOffset { offset: end, reason: "out of bounds" });
        }
        parts[field] = Some(&bytes[start..end]);
    }
    Ok(parts.into_iter().map(|p| p.expect("every field assigned")).collect())
}
