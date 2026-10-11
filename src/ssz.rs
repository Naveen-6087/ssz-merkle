use crate::codec::{DecodeError, expect_len};
use crate::gindex::GeneralizedIndex;
use crate::hash::Hash256;
use crate::prelude::*;
use crate::schema::{PathElem, PathError, Schema};
use crate::tree::Tree;
use crate::u256::U256;
use crate::value::Value;

/// An SSZ type: serialization, Merkleization and type shape.
pub trait Ssz: Sized {
    /// Serialized size of fixed-size types, `None` for variable-size types.
    fn fixed_size() -> Option<usize>;

    fn is_basic() -> bool {
        false
    }

    fn encoded_len(&self) -> usize;

    fn encode_into(&self, out: &mut Vec<u8>);

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError>;

    fn hash_tree_root(&self) -> Hash256;

    /// The full Merkle tree whose root is `hash_tree_root`, for proofs.
    fn tree(&self) -> Tree;

    fn schema() -> Schema;

    fn to_value(&self) -> Value;

    /// Generalized index of `path` within this type.
    fn generalized_index(path: &[PathElem]) -> Result<GeneralizedIndex, PathError> {
        Self::schema().generalized_index(path)
    }

    fn to_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }
}

fn basic_chunk(bytes: &[u8]) -> Hash256 {
    let mut chunk = [0u8; 32];
    chunk[..bytes.len()].copy_from_slice(bytes);
    chunk
}

macro_rules! impl_uint {
    ($($t:ty),+) => {$(
        impl Ssz for $t {
            fn fixed_size() -> Option<usize> {
                Some(size_of::<$t>())
            }

            fn is_basic() -> bool {
                true
            }

            fn encoded_len(&self) -> usize {
                size_of::<$t>()
            }

            fn encode_into(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }

            fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
                expect_len(bytes, size_of::<$t>())?;
                Ok(<$t>::from_le_bytes(bytes.try_into().expect("length checked")))
            }

            fn hash_tree_root(&self) -> Hash256 {
                basic_chunk(&self.to_le_bytes())
            }

            fn tree(&self) -> Tree {
                Tree::Leaf(self.hash_tree_root())
            }

            fn schema() -> Schema {
                Schema::Basic { size: size_of::<$t>() }
            }

            fn to_value(&self) -> Value {
                Value::Uint(self.to_string())
            }
        }
    )+};
}

impl_uint!(u8, u16, u32, u64, u128);

impl Ssz for U256 {
    fn fixed_size() -> Option<usize> {
        Some(32)
    }

    fn is_basic() -> bool {
        true
    }

    fn encoded_len(&self) -> usize {
        32
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, 32)?;
        Ok(U256(bytes.try_into().expect("length checked")))
    }

    fn hash_tree_root(&self) -> Hash256 {
        self.0
    }

    fn tree(&self) -> Tree {
        Tree::Leaf(self.0)
    }

    fn schema() -> Schema {
        Schema::Basic { size: 32 }
    }

    fn to_value(&self) -> Value {
        Value::Uint(self.to_string())
    }
}

impl Ssz for bool {
    fn fixed_size() -> Option<usize> {
        Some(1)
    }

    fn is_basic() -> bool {
        true
    }

    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        expect_len(bytes, 1)?;
        match bytes[0] {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(DecodeError::InvalidBool(b)),
        }
    }

    fn hash_tree_root(&self) -> Hash256 {
        basic_chunk(&[u8::from(*self)])
    }

    fn tree(&self) -> Tree {
        Tree::Leaf(self.hash_tree_root())
    }

    fn schema() -> Schema {
        Schema::Basic { size: 1 }
    }

    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_round_trip() {
        let v: u64 = 0x0102_0304_0506_0708;
        let bytes = v.to_ssz();
        assert_eq!(bytes, [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(u64::from_ssz(&bytes), Ok(v));
        assert_eq!(v.hash_tree_root()[..8], bytes[..]);
        assert!(u64::from_ssz(&bytes[..7]).is_err());
        assert!(u16::from_ssz(&[1, 2, 3]).is_err());
    }

    #[test]
    fn bool_strict() {
        assert_eq!(bool::from_ssz(&[1]), Ok(true));
        assert_eq!(bool::from_ssz(&[0]), Ok(false));
        assert_eq!(bool::from_ssz(&[2]), Err(DecodeError::InvalidBool(2)));
        assert!(bool::from_ssz(&[]).is_err());
    }

    #[test]
    fn u256_is_its_own_chunk() {
        let v = U256::from(42u64);
        assert_eq!(v.hash_tree_root(), v.0);
        assert_eq!(U256::from_ssz(&v.to_ssz()), Ok(v));
    }
}
