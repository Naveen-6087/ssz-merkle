use crate::prelude::*;
use core::fmt;

use crate::gindex::{GeneralizedIndex, helper_indices};
use crate::hash::{Hash256, hash_pair, length_chunk, zero_hash};
use crate::merkle::depth_for;

/// A materialized Merkle tree. Zero padding is kept virtual, so trees for
/// lists with huge limits stay small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tree {
    Leaf(Hash256),
    Zero(usize),
    Node { root: Hash256, left: Box<Tree>, right: Box<Tree> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    BelowLeaf(GeneralizedIndex),
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowLeaf(g) => write!(f, "generalized index {g} is below a leaf of the tree"),
        }
    }
}

impl core::error::Error for TreeError {}

impl Tree {
    pub fn root(&self) -> Hash256 {
        match self {
            Self::Leaf(h) => *h,
            Self::Zero(depth) => zero_hash(*depth),
            Self::Node { root, .. } => *root,
        }
    }

    pub fn node(left: Tree, right: Tree) -> Tree {
        Self::Node {
            root: hash_pair(&left.root(), &right.root()),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Binary tree over `subtrees`, zero padded to `next_pow_of_two(limit)`.
    pub fn from_subtrees(subtrees: Vec<Tree>, limit: usize) -> Tree {
        assert!(subtrees.len() <= limit.max(1), "tree: {} leaves exceed limit {limit}", subtrees.len());
        let n = subtrees.len();
        build(&mut subtrees.into_iter(), n, depth_for(limit))
    }

    pub fn from_chunks(chunks: &[Hash256], limit: usize) -> Tree {
        Self::from_subtrees(chunks.iter().copied().map(Tree::Leaf).collect(), limit)
    }

    /// EIP-7916 progressive layout, mirroring `merkleize_progressive`.
    pub fn progressive(subtrees: Vec<Tree>) -> Tree {
        fn go(mut subtrees: Vec<Tree>, num_leaves: usize) -> Tree {
            if subtrees.is_empty() {
                return Tree::Leaf([0u8; 32]);
            }
            let rest = subtrees.split_off(num_leaves.min(subtrees.len()));
            let first = Tree::from_subtrees(subtrees, num_leaves);
            Tree::node(go(rest, num_leaves * 4), first)
        }
        go(subtrees, 1)
    }

    pub fn with_length(self, len: u64) -> Tree {
        Tree::node(self, Tree::Leaf(length_chunk(len)))
    }

    /// The subtree rooted at `index`.
    pub fn get(&self, index: GeneralizedIndex) -> Result<Tree, TreeError> {
        let mut node = self;
        for level in (0..index.depth()).rev() {
            match node {
                Tree::Node { left, right, .. } => node = if index.bit(level) { right } else { left },
                Tree::Zero(d) if *d as u32 > level => return Ok(Tree::Zero(*d - level as usize - 1)),
                _ => return Err(TreeError::BelowLeaf(index)),
            }
        }
        Ok(node.clone())
    }

    pub fn node_root(&self, index: GeneralizedIndex) -> Result<Hash256, TreeError> {
        let mut node = self;
        let mut zero_depth = None;
        for level in (0..index.depth()).rev() {
            if let Some(d) = zero_depth.as_mut() {
                if *d == 0 {
                    return Err(TreeError::BelowLeaf(index));
                }
                *d -= 1;
                continue;
            }
            match node {
                Tree::Node { left, right, .. } => {
                    node = if index.bit(level) { right } else { left };
                }
                Tree::Zero(d) if *d > 0 => zero_depth = Some(*d - 1),
                _ => return Err(TreeError::BelowLeaf(index)),
            }
        }
        Ok(zero_depth.map_or_else(|| node.root(), zero_hash))
    }

    /// Merkle branch for `index`, leaf level first.
    pub fn prove(&self, index: GeneralizedIndex) -> Result<Vec<Hash256>, TreeError> {
        index
            .branch_indices()
            .into_iter()
            .map(|sibling| self.node_root(sibling).map_err(|_| TreeError::BelowLeaf(index)))
            .collect()
    }

    /// Helper nodes for a multiproof, ordered like [`helper_indices`].
    pub fn multiproof(&self, indices: &[GeneralizedIndex]) -> Result<Vec<Hash256>, TreeError> {
        for &index in indices {
            self.node_root(index)?;
        }
        helper_indices(indices).into_iter().map(|h| self.node_root(h)).collect()
    }
}

fn build(it: &mut impl Iterator<Item = Tree>, n: usize, depth: usize) -> Tree {
    if n == 0 {
        return Tree::Zero(depth);
    }
    if depth == 0 {
        return it.next().expect("tree: leaf count mismatch");
    }
    let half = 1usize << (depth - 1);
    let left = build(it, n.min(half), depth - 1);
    let right = build(it, n.saturating_sub(half), depth - 1);
    Tree::node(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{merkleize, merkleize_progressive, mix_in_length};
    use crate::proof::{verify_merkle_multiproof, verify_merkle_proof};

    fn chunks(n: u8) -> Vec<Hash256> {
        (0..n).map(|i| [i + 1; 32]).collect()
    }

    fn g(i: u64) -> GeneralizedIndex {
        GeneralizedIndex::new(i).unwrap()
    }

    #[test]
    fn roots_match_merkleize() {
        for n in 0..12u8 {
            let c = chunks(n);
            for limit in [n as usize, 16, 1 << 20] {
                if (n as usize) <= limit {
                    assert_eq!(Tree::from_chunks(&c, limit).root(), merkleize(&c, Some(limit)));
                }
            }
            let progressive = Tree::progressive(c.iter().copied().map(Tree::Leaf).collect());
            assert_eq!(progressive.root(), merkleize_progressive(&c));
            let listed = Tree::from_chunks(&c, 32).with_length(u64::from(n));
            assert_eq!(listed.root(), mix_in_length(&merkleize(&c, Some(32)), u64::from(n)));
        }
    }

    #[test]
    fn proofs_verify_including_zero_padding() {
        let c = chunks(5);
        let tree = Tree::from_chunks(&c, 1 << 10);
        let root = tree.root();
        for leaf in 0..8u64 {
            let index = g((1 << 10) + leaf);
            let branch = tree.prove(index).unwrap();
            let value = tree.node_root(index).unwrap();
            assert!(verify_merkle_proof(&value, &branch, index, &root));
        }
        // A leaf deep inside the virtual zero padding.
        let index = g((1 << 10) + 1000);
        assert_eq!(tree.node_root(index).unwrap(), [0u8; 32]);
        assert!(verify_merkle_proof(&[0u8; 32], &tree.prove(index).unwrap(), index, &root));
    }

    #[test]
    fn below_leaf_is_an_error() {
        let tree = Tree::from_chunks(&chunks(2), 2);
        assert_eq!(tree.node_root(g(8)), Err(TreeError::BelowLeaf(g(8))));
        assert!(tree.prove(g(8)).is_err());
        assert!(Tree::Zero(1).node_root(g(4)).is_err());
        assert_eq!(Tree::Zero(2).node_root(g(7)).unwrap(), [0u8; 32]);
    }

    #[test]
    fn get_returns_subtrees() {
        let tree = Tree::from_chunks(&chunks(4), 4);
        assert_eq!(tree.get(g(2)).unwrap().root(), merkleize(&chunks(4)[..2], None));
        assert_eq!(tree.get(g(7)).unwrap(), Tree::Leaf([4; 32]));
    }

    #[test]
    fn multiproof_from_tree() {
        let tree = Tree::from_chunks(&chunks(7), 8);
        let indices = [g(8), g(11), g(14)];
        let proof = tree.multiproof(&indices).unwrap();
        let leaves: Vec<_> = indices.iter().map(|&i| tree.node_root(i).unwrap()).collect();
        assert!(verify_merkle_multiproof(&leaves, &proof, &indices, &tree.root()));
    }
}
