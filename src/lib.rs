#![forbid(unsafe_code)]

pub mod bits;
pub mod codec;
pub mod collections;
#[doc(hidden)]
pub mod container;
pub mod deneb;
pub mod gindex;
pub mod hash;
pub mod merkle;
pub mod proof;
pub mod schema;
mod ssz;
pub mod tree;
mod u256;
mod value;

pub use bits::{Bitlist, Bitvector, ProgressiveBitlist};
pub use codec::DecodeError;
pub use collections::{ByteList, ByteVector, LengthError, List, ProgressiveList, Vector};
pub use gindex::GeneralizedIndex;
pub use hash::Hash256;
pub use proof::{ProofError, calculate_merkle_root, verify_merkle_multiproof, verify_merkle_proof};
pub use schema::{PathElem, PathError, Schema};
pub use ssz::Ssz;
pub use tree::{Tree, TreeError};
pub use u256::U256;
pub use value::Value;

/// A single-item proof: the leaf at `gindex` and its branch (leaf level first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub gindex: GeneralizedIndex,
    pub leaf: Hash256,
    pub branch: Vec<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    Path(PathError),
    Tree(TreeError),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(e) => e.fmt(f),
            Self::Tree(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ProveError {}

/// Builds the proof for the node reached by `path` inside `value`.
pub fn prove<T: Ssz>(value: &T, path: &[PathElem]) -> Result<Proof, ProveError> {
    let gindex = T::schema().generalized_index(path).map_err(ProveError::Path)?;
    let tree = value.tree();
    let leaf = tree.node_root(gindex).map_err(ProveError::Tree)?;
    let branch = tree.prove(gindex).map_err(ProveError::Tree)?;
    Ok(Proof { gindex, leaf, branch })
}

impl Proof {
    pub fn verify(&self, root: &Hash256) -> bool {
        verify_merkle_proof(&self.leaf, &self.branch, self.gindex, root)
    }
}
