#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod bits;
pub mod codec;
pub mod collections;
#[doc(hidden)]
pub mod container;
pub mod deneb;
pub mod gindex;
pub mod hash;
pub mod hex;
pub mod light_client;
pub mod merkle;
pub mod proof;
mod prove;
pub mod schema;
#[cfg(feature = "serde")]
mod serde;
mod ssz;
pub mod tree;
mod u256;
mod value;

pub use bits::{Bitlist, Bitvector, ProgressiveBitlist};
pub use codec::DecodeError;
pub use collections::{ByteList, ByteVector, LengthError, List, ProgressiveList, Vector};
pub use gindex::GeneralizedIndex;
pub use hash::Hash256;
pub use proof::{
    ProofError, calculate_merkle_root, calculate_multi_merkle_root, verify_merkle_multiproof,
    verify_merkle_proof,
};
pub use prove::{Multiproof, Proof, ProveError, prove, prove_multi};
pub use schema::{PathElem, PathError, Schema, parse_path};
pub use ssz::Ssz;
pub use tree::{Tree, TreeError};
pub use u256::U256;
pub use value::Value;

mod prelude {
    #[allow(unused_imports)]
    pub(crate) use alloc::{
        borrow::ToOwned,
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

#[doc(hidden)]
pub mod __private {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}
