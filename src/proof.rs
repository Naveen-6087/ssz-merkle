use std::collections::BTreeMap;
use std::fmt;

use crate::gindex::{GeneralizedIndex, helper_indices};
use crate::hash::{Hash256, hash_pair};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    BranchLength { expected: usize, got: usize },
    LeafCount { indices: usize, leaves: usize },
    DuplicateIndex(GeneralizedIndex),
    NestedIndex(GeneralizedIndex),
    Incomplete,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BranchLength { expected, got } => {
                write!(f, "branch has {got} nodes, generalized index needs {expected}")
            }
            Self::LeafCount { indices, leaves } => {
                write!(f, "{leaves} leaves supplied for {indices} indices")
            }
            Self::DuplicateIndex(g) => write!(f, "generalized index {g} appears more than once"),
            Self::NestedIndex(g) => write!(f, "generalized index {g} is an ancestor of another proven index"),
            Self::Incomplete => write!(f, "proof does not determine the root"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Recomputes the root from a leaf and its branch (leaf level first).
pub fn calculate_merkle_root(
    leaf: &Hash256,
    branch: &[Hash256],
    index: GeneralizedIndex,
) -> Result<Hash256, ProofError> {
    let depth = index.depth() as usize;
    if branch.len() != depth {
        return Err(ProofError::BranchLength { expected: depth, got: branch.len() });
    }
    let mut node = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        node = if index.bit(i as u32) { hash_pair(sibling, &node) } else { hash_pair(&node, sibling) };
    }
    Ok(node)
}

pub fn verify_merkle_proof(
    leaf: &Hash256,
    branch: &[Hash256],
    index: GeneralizedIndex,
    root: &Hash256,
) -> bool {
    calculate_merkle_root(leaf, branch, index).is_ok_and(|r| r == *root)
}

/// Recomputes the root from several leaves and the helper nodes returned by
/// [`helper_indices`] (spec: `calculate_multi_merkle_root`).
///
/// Unlike the reference algorithm this rejects duplicate indices and indices
/// that are ancestors of other indices, which would otherwise let a proof
/// assert two different values for the same node.
pub fn calculate_multi_merkle_root(
    leaves: &[Hash256],
    proof: &[Hash256],
    indices: &[GeneralizedIndex],
) -> Result<Hash256, ProofError> {
    if leaves.len() != indices.len() {
        return Err(ProofError::LeafCount { indices: indices.len(), leaves: leaves.len() });
    }
    let helpers = helper_indices(indices);
    if proof.len() != helpers.len() {
        return Err(ProofError::BranchLength { expected: helpers.len(), got: proof.len() });
    }

    let mut nodes = BTreeMap::new();
    for (&index, leaf) in indices.iter().zip(leaves) {
        if nodes.insert(index.get(), *leaf).is_some() {
            return Err(ProofError::DuplicateIndex(index));
        }
    }
    for &a in indices {
        if indices.iter().any(|&b| b != a && b.is_descendant_of(a)) {
            return Err(ProofError::NestedIndex(a));
        }
    }
    for (index, node) in helpers.iter().zip(proof) {
        nodes.insert(index.get(), *node);
    }

    // The largest key is always among the deepest nodes, so its sibling can
    // never still be waiting to be computed.
    while let Some((&k, _)) = nodes.last_key_value() {
        if k == 1 {
            break;
        }
        let (Some(left), Some(right)) = (nodes.remove(&(k & !1)), nodes.remove(&(k | 1))) else {
            return Err(ProofError::Incomplete);
        };
        if nodes.insert(k / 2, hash_pair(&left, &right)).is_some() {
            return Err(ProofError::Incomplete);
        }
    }
    nodes.remove(&1).ok_or(ProofError::Incomplete)
}

pub fn verify_merkle_multiproof(
    leaves: &[Hash256],
    proof: &[Hash256],
    indices: &[GeneralizedIndex],
    root: &Hash256,
) -> bool {
    calculate_multi_merkle_root(leaves, proof, indices).is_ok_and(|r| r == *root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::merkleize;

    fn g(i: u64) -> GeneralizedIndex {
        GeneralizedIndex::new(i).unwrap()
    }

    fn leaves() -> Vec<Hash256> {
        (0..8u8).map(|i| [i + 1; 32]).collect()
    }

    // Full 8-leaf tree as a 1-indexed array: node i at position i.
    fn tree() -> Vec<Hash256> {
        let mut t = vec![[0u8; 32]; 16];
        t[8..].copy_from_slice(&leaves());
        for i in (1..8).rev() {
            t[i] = hash_pair(&t[2 * i], &t[2 * i + 1]);
        }
        t
    }

    #[test]
    fn single_proofs_for_every_node() {
        let t = tree();
        assert_eq!(t[1], merkleize(&leaves(), None));
        for i in 1..16u64 {
            let index = g(i);
            let branch: Vec<_> = index.branch_indices().iter().map(|b| t[b.get() as usize]).collect();
            assert!(verify_merkle_proof(&t[i as usize], &branch, index, &t[1]), "node {i}");
            let mut bad = t[i as usize];
            bad[0] ^= 1;
            assert!(!verify_merkle_proof(&bad, &branch, index, &t[1]));
        }
    }

    #[test]
    fn wrong_branch_length_rejected() {
        let t = tree();
        let err = calculate_merkle_root(&t[9], &[t[8]], g(9)).unwrap_err();
        assert_eq!(err, ProofError::BranchLength { expected: 3, got: 1 });
    }

    #[test]
    fn multiproof_round_trip() {
        let t = tree();
        let indices = [g(8), g(9), g(14)];
        let helpers = helper_indices(&indices);
        let proof: Vec<_> = helpers.iter().map(|h| t[h.get() as usize]).collect();
        let leaves: Vec<_> = indices.iter().map(|i| t[i.get() as usize]).collect();
        assert!(verify_merkle_multiproof(&leaves, &proof, &indices, &t[1]));

        let mut wrong = leaves.clone();
        wrong[2][5] ^= 1;
        assert!(!verify_merkle_multiproof(&wrong, &proof, &indices, &t[1]));

        // Mixed depths: an internal node plus a leaf in the other half.
        let indices = [g(2), g(13)];
        let helpers = helper_indices(&indices);
        let proof: Vec<_> = helpers.iter().map(|h| t[h.get() as usize]).collect();
        let leaves: Vec<_> = indices.iter().map(|i| t[i.get() as usize]).collect();
        assert!(verify_merkle_multiproof(&leaves, &proof, &indices, &t[1]));
    }

    #[test]
    fn multiproof_rejects_malformed_inputs() {
        let t = tree();
        assert!(matches!(
            calculate_multi_merkle_root(&[t[8], t[8]], &[], &[g(8), g(8)]),
            Err(ProofError::DuplicateIndex(_)) | Err(ProofError::BranchLength { .. })
        ));
        let indices = [g(4), g(9)];
        let helpers = helper_indices(&indices);
        let proof: Vec<_> = helpers.iter().map(|h| t[h.get() as usize]).collect();
        assert_eq!(
            calculate_multi_merkle_root(&[t[4], t[9]], &proof, &indices),
            Err(ProofError::NestedIndex(g(4)))
        );
        assert!(matches!(
            calculate_multi_merkle_root(&[t[8]], &[], &[g(8), g(9)]),
            Err(ProofError::LeafCount { .. })
        ));
    }

    #[test]
    fn single_proof_is_a_multiproof() {
        let t = tree();
        let index = g(13);
        let branch: Vec<_> = index.branch_indices().iter().map(|b| t[b.get() as usize]).collect();
        assert!(verify_merkle_multiproof(&[t[13]], &branch, &[index], &t[1]));
    }
}
