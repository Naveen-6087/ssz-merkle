use crate::codec::DecodeError;
use crate::collections::LengthError;
use crate::hash::Hash256;
use crate::merkle::{merkleize, merkleize_progressive, mix_in_length, pack};
use crate::prelude::*;
use crate::schema::Schema;
use crate::ssz::Ssz;
use crate::tree::Tree;
use crate::value::Value;

/// Bits packed little-endian within bytes, without any delimiter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn zeroed(len: usize) -> Self {
        Self { bytes: vec![0; len.div_ceil(8)], len }
    }

    fn from_bools(bits: &[bool]) -> Self {
        let mut out = Self::zeroed(bits.len());
        for (i, &b) in bits.iter().enumerate() {
            out.set(i, b);
        }
        out
    }

    fn get(&self, i: usize) -> Option<bool> {
        (i < self.len).then(|| self.bytes[i / 8] >> (i % 8) & 1 == 1)
    }

    fn set(&mut self, i: usize, value: bool) {
        assert!(i < self.len, "bit index {i} out of range for length {}", self.len);
        if value {
            self.bytes[i / 8] |= 1 << (i % 8);
        } else {
            self.bytes[i / 8] &= !(1 << (i % 8));
        }
    }

    fn push(&mut self, value: bool) {
        if self.len % 8 == 0 {
            self.bytes.push(0);
        }
        self.len += 1;
        self.set(self.len - 1, value);
    }

    fn with_delimiter(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        if self.len % 8 == 0 {
            out.push(1);
        } else {
            out[self.len / 8] |= 1 << (self.len % 8);
        }
        out
    }

    fn from_delimited(bytes: &[u8]) -> Result<Self, DecodeError> {
        let last = *bytes.last().ok_or(DecodeError::MissingDelimiter)?;
        if last == 0 {
            return Err(DecodeError::MissingDelimiter);
        }
        let top = 7 - last.leading_zeros() as usize;
        let len = (bytes.len() - 1) * 8 + top;
        let mut stored = bytes[..len.div_ceil(8)].to_vec();
        if top > 0 {
            *stored.last_mut().expect("top > 0 implies a byte") &= (1 << top) - 1;
        }
        Ok(Self { bytes: stored, len })
    }
}

/// `Bitvector[N]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Bitvector<const N: usize>(Bits);

impl<const N: usize> Default for Bitvector<N> {
    fn default() -> Self {
        Self(Bits::zeroed(N))
    }
}

impl<const N: usize> Bitvector<N> {
    pub fn from_bools(bits: &[bool]) -> Result<Self, LengthError> {
        if bits.len() == N {
            Ok(Self(Bits::from_bools(bits)))
        } else {
            Err(LengthError { bound: N, got: bits.len() })
        }
    }

    pub fn get(&self, i: usize) -> Option<bool> {
        self.0.get(i)
    }

    pub fn set(&mut self, i: usize, value: bool) {
        self.0.set(i, value);
    }

    pub fn len(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        N == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }
}

impl<const N: usize> Ssz for Bitvector<N> {
    fn fixed_size() -> Option<usize> {
        Some(N.div_ceil(8))
    }

    fn encoded_len(&self) -> usize {
        N.div_ceil(8)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.bytes);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        if N == 0 {
            return Err(DecodeError::IllegalType("Bitvector of length 0"));
        }
        crate::codec::expect_len(bytes, N.div_ceil(8))?;
        if N % 8 != 0 && bytes[N / 8] >> (N % 8) != 0 {
            return Err(DecodeError::NonZeroPadding);
        }
        Ok(Self(Bits { bytes: bytes.to_vec(), len: N }))
    }

    fn hash_tree_root(&self) -> Hash256 {
        merkleize(&pack(&self.0.bytes), Some(N.div_ceil(256)))
    }

    fn tree(&self) -> Tree {
        Tree::from_chunks(&pack(&self.0.bytes), N.div_ceil(256))
    }

    fn schema() -> Schema {
        Schema::Bitvector { len: N }
    }

    fn to_value(&self) -> Value {
        Value::Bytes(self.0.bytes.clone())
    }
}

/// `Bitlist[N]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bitlist<const N: usize>(Bits);

impl<const N: usize> Bitlist<N> {
    pub fn from_bools(bits: &[bool]) -> Result<Self, LengthError> {
        if bits.len() <= N {
            Ok(Self(Bits::from_bools(bits)))
        } else {
            Err(LengthError { bound: N, got: bits.len() })
        }
    }

    pub fn with_len(len: usize) -> Result<Self, LengthError> {
        if len <= N { Ok(Self(Bits::zeroed(len))) } else { Err(LengthError { bound: N, got: len }) }
    }

    pub fn get(&self, i: usize) -> Option<bool> {
        self.0.get(i)
    }

    pub fn set(&mut self, i: usize, value: bool) {
        self.0.set(i, value);
    }

    pub fn push(&mut self, value: bool) -> Result<(), LengthError> {
        if self.0.len == N {
            return Err(LengthError { bound: N, got: N + 1 });
        }
        self.0.push(value);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.0.len
    }

    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }
}

impl<const N: usize> Ssz for Bitlist<N> {
    fn fixed_size() -> Option<usize> {
        None
    }

    fn encoded_len(&self) -> usize {
        self.0.len / 8 + 1
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.with_delimiter());
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bits = Bits::from_delimited(bytes)?;
        if bits.len > N {
            return Err(DecodeError::TooManyBits { limit: N, got: bits.len });
        }
        Ok(Self(bits))
    }

    fn hash_tree_root(&self) -> Hash256 {
        mix_in_length(&merkleize(&pack(&self.0.bytes), Some(N.div_ceil(256))), self.0.len as u64)
    }

    fn tree(&self) -> Tree {
        Tree::from_chunks(&pack(&self.0.bytes), N.div_ceil(256)).with_length(self.0.len as u64)
    }

    fn schema() -> Schema {
        Schema::Bitlist { limit: N }
    }

    fn to_value(&self) -> Value {
        Value::Bytes(self.0.with_delimiter())
    }
}

/// `ProgressiveBitlist` (EIP-7916).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProgressiveBitlist(Bits);

impl ProgressiveBitlist {
    pub fn from_bools(bits: &[bool]) -> Self {
        Self(Bits::from_bools(bits))
    }

    pub fn get(&self, i: usize) -> Option<bool> {
        self.0.get(i)
    }

    pub fn push(&mut self, value: bool) {
        self.0.push(value);
    }

    pub fn len(&self) -> usize {
        self.0.len
    }

    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }
}

impl Ssz for ProgressiveBitlist {
    fn fixed_size() -> Option<usize> {
        None
    }

    fn encoded_len(&self) -> usize {
        self.0.len / 8 + 1
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.with_delimiter());
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        Bits::from_delimited(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Hash256 {
        mix_in_length(&merkleize_progressive(&pack(&self.0.bytes)), self.0.len as u64)
    }

    fn tree(&self) -> Tree {
        let leaves = pack(&self.0.bytes).into_iter().map(Tree::Leaf).collect();
        Tree::progressive(leaves).with_length(self.0.len as u64)
    }

    fn schema() -> Schema {
        Schema::ProgressiveBitlist
    }

    fn to_value(&self) -> Value {
        Value::Bytes(self.0.with_delimiter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitlist_delimiter() {
        let empty = Bitlist::<8>::default();
        assert_eq!(empty.to_ssz(), [0x01]);
        let bits = Bitlist::<16>::from_bools(&[true, false, true, true, false, false, false, false]).unwrap();
        assert_eq!(bits.to_ssz(), [0b0000_1101, 0x01]);
        assert_eq!(Bitlist::<16>::from_ssz(&bits.to_ssz()), Ok(bits));
        let five = Bitlist::<5>::from_bools(&[true; 3]).unwrap();
        assert_eq!(five.to_ssz(), [0b0000_1111]);
    }

    #[test]
    fn bitlist_rejects() {
        assert_eq!(Bitlist::<8>::from_ssz(&[]), Err(DecodeError::MissingDelimiter));
        assert_eq!(Bitlist::<8>::from_ssz(&[0x0f, 0x00]), Err(DecodeError::MissingDelimiter));
        assert_eq!(
            Bitlist::<3>::from_ssz(&[0b0001_0000]),
            Err(DecodeError::TooManyBits { limit: 3, got: 4 })
        );
    }

    #[test]
    fn bitvector_padding() {
        assert!(Bitvector::<4>::from_ssz(&[0x0f]).is_ok());
        assert_eq!(Bitvector::<4>::from_ssz(&[0x1f]), Err(DecodeError::NonZeroPadding));
        assert!(Bitvector::<8>::from_ssz(&[0xff]).is_ok());
        assert!(Bitvector::<9>::from_ssz(&[0xff]).is_err());
    }

    #[test]
    fn push_and_get() {
        let mut bits = ProgressiveBitlist::default();
        for i in 0..20 {
            bits.push(i % 3 == 0);
        }
        assert_eq!(bits.len(), 20);
        assert_eq!(bits.get(3), Some(true));
        assert_eq!(bits.get(4), Some(false));
        assert_eq!(bits.get(20), None);
        assert_eq!(ProgressiveBitlist::from_ssz(&bits.to_ssz()), Ok(bits));
    }
}
