use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::codec::{Count, DecodeError, decode_items, encode_items, encoded_len_of, expect_len};
use crate::hash::Hash256;
use crate::merkle::{merkleize, merkleize_progressive, mix_in_length, pack};
use crate::schema::Schema;
use crate::ssz::Ssz;
use crate::tree::Tree;
use crate::value::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LengthError {
    pub bound: usize,
    pub got: usize,
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "length {} does not fit bound {}", self.got, self.bound)
    }
}

impl std::error::Error for LengthError {}

fn element_chunks<T: Ssz>(items: &[T]) -> Vec<Hash256> {
    if T::is_basic() {
        let mut bytes = Vec::with_capacity(encoded_len_of(items));
        encode_items(items, &mut bytes);
        pack(&bytes)
    } else {
        items.iter().map(Ssz::hash_tree_root).collect()
    }
}

fn element_subtrees<T: Ssz>(items: &[T]) -> Vec<Tree> {
    if T::is_basic() {
        element_chunks(items).into_iter().map(Tree::Leaf).collect()
    } else {
        items.iter().map(Ssz::tree).collect()
    }
}

fn chunk_limit<T: Ssz>(n: usize) -> usize {
    if T::is_basic() { (n * T::fixed_size().expect("basic types are fixed-size")).div_ceil(32) } else { n }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).expect("length fits in u64")
}

macro_rules! deref_vec {
    (impl [$($gen:tt)*] for $ty:ty => $elem:ty) => {
        impl<$($gen)*> Deref for $ty {
            type Target = [$elem];

            fn deref(&self) -> &[$elem] {
                &self.0
            }
        }

        impl<$($gen)*> DerefMut for $ty {
            fn deref_mut(&mut self) -> &mut [$elem] {
                &mut self.0
            }
        }
    };
}

/// `Vector[T, N]`: exactly `N` elements.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vector<T, const N: usize>(Vec<T>);

impl<T, const N: usize> Vector<T, N> {
    pub fn new(items: Vec<T>) -> Result<Self, LengthError> {
        if items.len() == N { Ok(Self(items)) } else { Err(LengthError { bound: N, got: items.len() }) }
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: Default, const N: usize> Default for Vector<T, N> {
    fn default() -> Self {
        Self(std::iter::repeat_with(T::default).take(N).collect())
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for Vector<T, N> {
    type Error = LengthError;

    fn try_from(items: Vec<T>) -> Result<Self, LengthError> {
        Self::new(items)
    }
}

deref_vec!(impl [T, const N: usize] for Vector<T, N> => T);

impl<T: Ssz, const N: usize> Ssz for Vector<T, N> {
    fn fixed_size() -> Option<usize> {
        T::fixed_size().map(|size| size * N)
    }

    fn encoded_len(&self) -> usize {
        encoded_len_of(&self.0)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_items(&self.0, out);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        if N == 0 {
            return Err(DecodeError::IllegalType("Vector of length 0"));
        }
        decode_items(bytes, Count::Exact(N)).map(Self)
    }

    fn hash_tree_root(&self) -> Hash256 {
        merkleize(&element_chunks(&self.0), Some(chunk_limit::<T>(N)))
    }

    fn tree(&self) -> Tree {
        Tree::from_subtrees(element_subtrees(&self.0), chunk_limit::<T>(N))
    }

    fn schema() -> Schema {
        Schema::Vector { elem: Box::new(T::schema()), len: N }
    }

    fn to_value(&self) -> Value {
        Value::List(self.0.iter().map(Ssz::to_value).collect())
    }
}

/// `List[T, N]`: at most `N` elements.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct List<T, const N: usize>(Vec<T>);

impl<T, const N: usize> List<T, N> {
    pub fn new(items: Vec<T>) -> Result<Self, LengthError> {
        if items.len() <= N { Ok(Self(items)) } else { Err(LengthError { bound: N, got: items.len() }) }
    }

    pub fn push(&mut self, item: T) -> Result<(), LengthError> {
        if self.0.len() == N {
            return Err(LengthError { bound: N, got: N + 1 });
        }
        self.0.push(item);
        Ok(())
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const N: usize> Default for List<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for List<T, N> {
    type Error = LengthError;

    fn try_from(items: Vec<T>) -> Result<Self, LengthError> {
        Self::new(items)
    }
}

deref_vec!(impl [T, const N: usize] for List<T, N> => T);

impl<T: Ssz, const N: usize> Ssz for List<T, N> {
    fn fixed_size() -> Option<usize> {
        None
    }

    fn encoded_len(&self) -> usize {
        encoded_len_of(&self.0)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_items(&self.0, out);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_items(bytes, Count::AtMost(N)).map(Self)
    }

    fn hash_tree_root(&self) -> Hash256 {
        let data = merkleize(&element_chunks(&self.0), Some(chunk_limit::<T>(N)));
        mix_in_length(&data, len_u64(self.0.len()))
    }

    fn tree(&self) -> Tree {
        Tree::from_subtrees(element_subtrees(&self.0), chunk_limit::<T>(N)).with_length(len_u64(self.0.len()))
    }

    fn schema() -> Schema {
        Schema::List { elem: Box::new(T::schema()), limit: N }
    }

    fn to_value(&self) -> Value {
        Value::List(self.0.iter().map(Ssz::to_value).collect())
    }
}

/// `ProgressiveList[T]` (EIP-7916): unbounded, merkleized progressively.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProgressiveList<T>(pub Vec<T>);

impl<T> From<Vec<T>> for ProgressiveList<T> {
    fn from(items: Vec<T>) -> Self {
        Self(items)
    }
}

deref_vec!(impl [T] for ProgressiveList<T> => T);

impl<T: Ssz> Ssz for ProgressiveList<T> {
    fn fixed_size() -> Option<usize> {
        None
    }

    fn encoded_len(&self) -> usize {
        encoded_len_of(&self.0)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_items(&self.0, out);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_items(bytes, Count::Unbounded).map(Self)
    }

    fn hash_tree_root(&self) -> Hash256 {
        mix_in_length(&merkleize_progressive(&element_chunks(&self.0)), len_u64(self.0.len()))
    }

    fn tree(&self) -> Tree {
        Tree::progressive(element_subtrees(&self.0)).with_length(len_u64(self.0.len()))
    }

    fn schema() -> Schema {
        Schema::ProgressiveList { elem: Box::new(T::schema()) }
    }

    fn to_value(&self) -> Value {
        Value::List(self.0.iter().map(Ssz::to_value).collect())
    }
}

/// `ByteVector[N]` / `BytesN`: same SSZ as `Vector[byte, N]`, shown as hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ByteVector<const N: usize>(Vec<u8>);

impl<const N: usize> ByteVector<N> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LengthError> {
        if bytes.len() == N { Ok(Self(bytes)) } else { Err(LengthError { bound: N, got: bytes.len() }) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Default for ByteVector<N> {
    fn default() -> Self {
        Self(vec![0; N])
    }
}

impl<const N: usize> From<[u8; N]> for ByteVector<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes.to_vec())
    }
}

deref_vec!(impl [const N: usize] for ByteVector<N> => u8);

impl<const N: usize> Ssz for ByteVector<N> {
    fn fixed_size() -> Option<usize> {
        Some(N)
    }

    fn encoded_len(&self) -> usize {
        N
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        if N == 0 {
            return Err(DecodeError::IllegalType("ByteVector of length 0"));
        }
        expect_len(bytes, N)?;
        Ok(Self(bytes.to_vec()))
    }

    fn hash_tree_root(&self) -> Hash256 {
        merkleize(&pack(&self.0), Some(N.div_ceil(32)))
    }

    fn tree(&self) -> Tree {
        Tree::from_chunks(&pack(&self.0), N.div_ceil(32))
    }

    fn schema() -> Schema {
        Schema::Vector { elem: Box::new(Schema::Basic { size: 1 }), len: N }
    }

    fn to_value(&self) -> Value {
        Value::Bytes(self.0.clone())
    }
}

/// `ByteList[N]`: same SSZ as `List[byte, N]`, shown as hex.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ByteList<const N: usize>(Vec<u8>);

impl<const N: usize> ByteList<N> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LengthError> {
        if bytes.len() <= N { Ok(Self(bytes)) } else { Err(LengthError { bound: N, got: bytes.len() }) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

deref_vec!(impl [const N: usize] for ByteList<N> => u8);

impl<const N: usize> Ssz for ByteList<N> {
    fn fixed_size() -> Option<usize> {
        None
    }

    fn encoded_len(&self) -> usize {
        self.0.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn from_ssz(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > N {
            return Err(DecodeError::TooManyElements { limit: N, got: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }

    fn hash_tree_root(&self) -> Hash256 {
        mix_in_length(&merkleize(&pack(&self.0), Some(N.div_ceil(32))), len_u64(self.0.len()))
    }

    fn tree(&self) -> Tree {
        Tree::from_chunks(&pack(&self.0), N.div_ceil(32)).with_length(len_u64(self.0.len()))
    }

    fn schema() -> Schema {
        Schema::List { elem: Box::new(Schema::Basic { size: 1 }), limit: N }
    }

    fn to_value(&self) -> Value {
        Value::Bytes(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_and_list_bounds() {
        assert!(Vector::<u8, 3>::new(vec![1, 2]).is_err());
        let mut list = List::<u16, 2>::new(vec![1]).unwrap();
        list.push(2).unwrap();
        assert!(list.push(3).is_err());
        assert!(List::<u16, 2>::from_ssz(&[1, 0, 2, 0, 3, 0]).is_err());
        assert!(List::<u16, 2>::from_ssz(&[1, 0, 2]).is_err());
    }

    #[test]
    fn byte_types_match_generic_types() {
        let bytes: Vec<u8> = (0..40).collect();
        let bv = ByteVector::<40>::new(bytes.clone()).unwrap();
        let gv = Vector::<u8, 40>::new(bytes.clone()).unwrap();
        assert_eq!(bv.hash_tree_root(), gv.hash_tree_root());
        assert_eq!(bv.to_ssz(), gv.to_ssz());
        let bl = ByteList::<100>::new(bytes.clone()).unwrap();
        let gl = List::<u8, 100>::new(bytes).unwrap();
        assert_eq!(bl.hash_tree_root(), gl.hash_tree_root());
        assert_eq!(bl.tree().root(), gl.tree().root());
    }

    #[test]
    fn variable_size_elements_round_trip() {
        let inner = |v: Vec<u16>| List::<u16, 8>::new(v).unwrap();
        let list =
            List::<List<u16, 8>, 4>::new(vec![inner(vec![1, 2]), inner(vec![]), inner(vec![3])]).unwrap();
        let bytes = list.to_ssz();
        assert_eq!(bytes.len(), list.encoded_len());
        assert_eq!(List::<List<u16, 8>, 4>::from_ssz(&bytes), Ok(list));
    }

    #[test]
    fn zero_length_vector_is_illegal() {
        assert_eq!(Vector::<u8, 0>::from_ssz(&[]), Err(DecodeError::IllegalType("Vector of length 0")));
    }
}
