#![no_std]

use ssz_merkle::{Hash256, List, PathElem, Ssz, prove, ssz_container};

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Header {
        pub slot: u64,
        pub roots: List<u64, 16>,
    }
}

pub fn root(header: &Header) -> Hash256 {
    header.hash_tree_root()
}

pub fn check(header: &Header, trusted: &Hash256) -> bool {
    prove(header, &[PathElem::Index(0)]).is_ok_and(|p| p.verify(trusted))
}
