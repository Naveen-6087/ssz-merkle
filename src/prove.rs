use core::fmt;

use crate::gindex::GeneralizedIndex;
use crate::hash::Hash256;
use crate::prelude::*;
use crate::proof::{ProofError, calculate_merkle_root, calculate_multi_merkle_root};
use crate::schema::{PathElem, PathError};
use crate::ssz::Ssz;
use crate::tree::{Tree, TreeError};

/// A single-item proof: the leaf at `gindex` and its branch (leaf level first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub gindex: GeneralizedIndex,
    pub leaf: Hash256,
    pub branch: Vec<Hash256>,
}

/// A proof for several leaves sharing one set of helper nodes, ordered as
/// [`helper_indices`](crate::gindex::helper_indices) returns them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multiproof {
    pub gindices: Vec<GeneralizedIndex>,
    pub leaves: Vec<Hash256>,
    pub helpers: Vec<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    Path(PathError),
    Tree(TreeError),
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(e) => e.fmt(f),
            Self::Tree(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for ProveError {}

impl From<PathError> for ProveError {
    fn from(e: PathError) -> Self {
        Self::Path(e)
    }
}

impl From<TreeError> for ProveError {
    fn from(e: TreeError) -> Self {
        Self::Tree(e)
    }
}

/// Builds the proof for the node reached by `path` inside `value`.
pub fn prove<T: Ssz>(value: &T, path: &[PathElem]) -> Result<Proof, ProveError> {
    let gindex = T::schema().generalized_index(path)?;
    Ok(Proof::from_tree(&value.tree(), gindex)?)
}

/// Builds one multiproof covering every path. The tree is built once, and
/// nodes shared between the branches are included only once.
pub fn prove_multi<T: Ssz, P: AsRef<[PathElem]>>(value: &T, paths: &[P]) -> Result<Multiproof, ProveError> {
    let schema = T::schema();
    let gindices =
        paths.iter().map(|p| schema.generalized_index(p.as_ref())).collect::<Result<Vec<_>, _>>()?;
    Ok(Multiproof::from_tree(&value.tree(), gindices)?)
}

impl Proof {
    pub fn from_tree(tree: &Tree, gindex: GeneralizedIndex) -> Result<Self, TreeError> {
        Ok(Self { gindex, leaf: tree.node_root(gindex)?, branch: tree.prove(gindex)? })
    }

    /// The root this proof commits to.
    pub fn root(&self) -> Result<Hash256, ProofError> {
        calculate_merkle_root(&self.leaf, &self.branch, self.gindex)
    }

    pub fn verify(&self, root: &Hash256) -> bool {
        self.root().is_ok_and(|r| r == *root)
    }

    /// Verifies the proof and checks that its gindex is the one `path`
    /// resolves to in `T`. Use this when the proof comes from an untrusted
    /// party: a valid branch for the wrong gindex proves a different value.
    pub fn verify_path<T: Ssz>(&self, path: &[PathElem], root: &Hash256) -> bool {
        T::schema().generalized_index(path).is_ok_and(|g| g == self.gindex) && self.verify(root)
    }

    /// Depth of the leaf (`floorlog2(gindex)` in the specs).
    pub fn depth(&self) -> u32 {
        self.gindex.depth()
    }

    /// Position of the leaf in its level (`get_subtree_index` in the specs).
    pub fn subtree_index(&self) -> u64 {
        self.gindex.subtree_index()
    }
}

impl Multiproof {
    pub fn from_tree(tree: &Tree, gindices: Vec<GeneralizedIndex>) -> Result<Self, TreeError> {
        let leaves = gindices.iter().map(|&g| tree.node_root(g)).collect::<Result<Vec<_>, _>>()?;
        let helpers = tree.multiproof(&gindices)?;
        Ok(Self { gindices, leaves, helpers })
    }

    pub fn root(&self) -> Result<Hash256, ProofError> {
        calculate_multi_merkle_root(&self.leaves, &self.helpers, &self.gindices)
    }

    pub fn verify(&self, root: &Hash256) -> bool {
        self.root().is_ok_and(|r| r == *root)
    }

    /// Like [`Proof::verify_path`], for every path in order.
    pub fn verify_paths<T: Ssz, P: AsRef<[PathElem]>>(&self, paths: &[P], root: &Hash256) -> bool {
        let schema = T::schema();
        paths.len() == self.gindices.len()
            && paths
                .iter()
                .zip(&self.gindices)
                .all(|(p, &g)| schema.generalized_index(p.as_ref()).is_ok_and(|want| want == g))
            && self.verify(root)
    }

    /// The leaf proven at `gindex`, if it is part of this proof.
    pub fn leaf(&self, gindex: GeneralizedIndex) -> Option<&Hash256> {
        self.gindices.iter().position(|&g| g == gindex).map(|i| &self.leaves[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::parse_path;
    use crate::{List, ssz_container};

    ssz_container! {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        struct Inner {
            a: u64,
            b: List<u32, 100>,
        }
    }

    ssz_container! {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        struct Outer {
            x: u16,
            inner: Inner,
            ys: List<u64, 1024>,
        }
    }

    fn sample() -> Outer {
        Outer {
            x: 7,
            inner: Inner { a: 9, b: List::new(vec![1, 2, 3]).unwrap() },
            ys: List::new((0..40).collect()).unwrap(),
        }
    }

    #[test]
    fn single_proof() {
        let v = sample();
        let root = v.hash_tree_root();
        let p = prove(&v, &parse_path("inner.a")).unwrap();
        assert!(p.verify(&root));
        assert_eq!(p.root().unwrap(), root);
        assert_eq!(p.leaf, 9u64.hash_tree_root());
        assert_eq!(p.depth() as usize, p.branch.len());
        assert_eq!(p.subtree_index(), p.gindex.get() - (1 << p.depth()));
        assert!(p.verify_path::<Outer>(&parse_path("inner.a"), &root));
        assert!(!p.verify_path::<Outer>(&parse_path("x"), &root));
        assert!(!p.verify_path::<Outer>(&parse_path("nope"), &root));
    }

    #[test]
    fn multiproof_matches_single_proofs() {
        let v = sample();
        let root = v.hash_tree_root();
        let paths = ["x", "inner.b.2", "ys.__len__", "ys.39"].map(parse_path);
        let m = prove_multi(&v, &paths).unwrap();
        assert!(m.verify(&root));
        assert!(m.verify_paths::<Outer, _>(&paths, &root));
        assert!(!m.verify_paths::<Outer, _>(&paths[..3], &root));
        for p in &paths {
            let single = prove(&v, p).unwrap();
            assert_eq!(m.leaf(single.gindex), Some(&single.leaf));
        }
        let singles: usize = paths.iter().map(|p| prove(&v, p).unwrap().branch.len()).sum();
        assert!(m.helpers.len() < singles);

        let mut bad = m.clone();
        bad.leaves[1][0] ^= 1;
        assert!(!bad.verify(&root));
        let mut short = m.clone();
        short.helpers.pop();
        assert!(short.root().is_err());
    }

    #[test]
    fn errors() {
        let v = sample();
        assert!(matches!(prove(&v, &parse_path("inner.c")), Err(ProveError::Path(_))));
        assert!(matches!(prove_multi(&v, &[parse_path("ys.5000")]), Err(ProveError::Path(_))));
        let below = GeneralizedIndex::new(1 << 40).unwrap();
        assert!(Proof::from_tree(&Tree::Leaf([0; 32]), below).is_err());
    }
}
