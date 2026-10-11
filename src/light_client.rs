use crate::gindex::GeneralizedIndex;
use crate::hash::Hash256;
use crate::proof::verify_merkle_proof;

const fn gindex(index: u64) -> GeneralizedIndex {
    match GeneralizedIndex::new(index) {
        Some(g) => g,
        None => panic!("generalized index 0"),
    }
}

/// `BeaconState.finalized_checkpoint.root`, Altair to Deneb.
pub const FINALIZED_ROOT_GINDEX: GeneralizedIndex = gindex(105);
/// `BeaconState.current_sync_committee`, Altair to Deneb.
pub const CURRENT_SYNC_COMMITTEE_GINDEX: GeneralizedIndex = gindex(54);
/// `BeaconState.next_sync_committee`, Altair to Deneb.
pub const NEXT_SYNC_COMMITTEE_GINDEX: GeneralizedIndex = gindex(55);
/// `BeaconBlockBody.execution_payload`, Capella onwards.
pub const EXECUTION_PAYLOAD_GINDEX: GeneralizedIndex = gindex(25);
/// `BeaconState.finalized_checkpoint.root`, Electra onwards.
pub const FINALIZED_ROOT_GINDEX_ELECTRA: GeneralizedIndex = gindex(169);
/// `BeaconState.current_sync_committee`, Electra onwards.
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: GeneralizedIndex = gindex(86);
/// `BeaconState.next_sync_committee`, Electra onwards.
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: GeneralizedIndex = gindex(87);

/// The consensus-specs `is_valid_merkle_branch`: `branch` must hold `depth`
/// nodes, and `index` is the leaf position within its level.
pub fn is_valid_merkle_branch(
    leaf: &Hash256,
    branch: &[Hash256],
    depth: u32,
    index: u64,
    root: &Hash256,
) -> bool {
    if branch.len() != depth as usize || depth >= 64 || index >> depth != 0 {
        return false;
    }
    let gindex = GeneralizedIndex::new((1 << depth) | index).expect("non-zero");
    verify_merkle_proof(leaf, branch, gindex, root)
}

/// The consensus-specs `is_valid_normalized_merkle_branch` (Electra): a
/// branch may be longer than the depth of `gindex`, as long as the extra
/// leading nodes are zero. Light clients use this to accept proofs built
/// for a deeper state layout across a fork.
pub fn is_valid_normalized_merkle_branch(
    leaf: &Hash256,
    branch: &[Hash256],
    gindex: GeneralizedIndex,
    root: &Hash256,
) -> bool {
    let depth = gindex.depth() as usize;
    let Some(extra) = branch.len().checked_sub(depth) else {
        return false;
    };
    branch[..extra].iter().all(|n| *n == [0u8; 32])
        && verify_merkle_proof(leaf, &branch[extra..], gindex, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deneb::BeaconBlockBody;
    use crate::prelude::*;
    use crate::schema::{Schema, parse_path};
    use crate::{Ssz, Tree, prove};

    fn container(name: &'static str, fields: &[&'static str]) -> Schema {
        let checkpoint = Schema::Container {
            name: "Checkpoint",
            fields: vec![("epoch", Schema::Basic { size: 8 }), ("root", Schema::Basic { size: 32 })],
        };
        Schema::Container {
            name,
            fields: fields
                .iter()
                .map(|&f| {
                    (
                        f,
                        if f.ends_with("checkpoint") {
                            checkpoint.clone()
                        } else {
                            Schema::Basic { size: 8 }
                        },
                    )
                })
                .collect(),
        }
    }

    const ALTAIR: &[&str] = &[
        "genesis_time",
        "genesis_validators_root",
        "slot",
        "fork",
        "latest_block_header",
        "block_roots",
        "state_roots",
        "historical_roots",
        "eth1_data",
        "eth1_data_votes",
        "eth1_deposit_index",
        "validators",
        "balances",
        "randao_mixes",
        "slashings",
        "previous_epoch_participation",
        "current_epoch_participation",
        "justification_bits",
        "previous_justified_checkpoint",
        "current_justified_checkpoint",
        "finalized_checkpoint",
        "inactivity_scores",
        "current_sync_committee",
        "next_sync_committee",
    ];

    const LATER: &[&str] = &[
        "latest_execution_payload_header",
        "next_withdrawal_index",
        "next_withdrawal_validator_index",
        "historical_summaries",
        "deposit_requests_start_index",
        "deposit_balance_to_consume",
        "exit_balance_to_consume",
        "earliest_exit_epoch",
        "consolidation_balance_to_consume",
        "earliest_consolidation_epoch",
        "pending_deposits",
        "pending_partial_withdrawals",
        "pending_consolidations",
    ];

    fn gi(s: &Schema, path: &str) -> GeneralizedIndex {
        s.generalized_index(&parse_path(path)).unwrap()
    }

    #[test]
    fn constants_match_beacon_state_layouts() {
        let altair = container("BeaconState", ALTAIR);
        assert_eq!(gi(&altair, "finalized_checkpoint.root"), FINALIZED_ROOT_GINDEX);
        assert_eq!(gi(&altair, "current_sync_committee"), CURRENT_SYNC_COMMITTEE_GINDEX);
        assert_eq!(gi(&altair, "next_sync_committee"), NEXT_SYNC_COMMITTEE_GINDEX);

        // Deneb has 28 fields, still within 32 leaves: same indices.
        let deneb: Vec<_> = ALTAIR.iter().chain(&LATER[..4]).copied().collect();
        assert_eq!(gi(&container("BeaconState", &deneb), "finalized_checkpoint.root"), FINALIZED_ROOT_GINDEX);

        // Electra has 37 fields, so the state tree grows a level.
        let electra: Vec<_> = ALTAIR.iter().chain(LATER).copied().collect();
        let electra = container("BeaconState", &electra);
        assert_eq!(gi(&electra, "finalized_checkpoint.root"), FINALIZED_ROOT_GINDEX_ELECTRA);
        assert_eq!(gi(&electra, "current_sync_committee"), CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA);
        assert_eq!(gi(&electra, "next_sync_committee"), NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA);

        assert_eq!(
            BeaconBlockBody::schema().generalized_index(&parse_path("execution_payload")),
            Ok(EXECUTION_PAYLOAD_GINDEX)
        );
    }

    fn sample_tree() -> Tree {
        let leaves: Vec<Hash256> = (0..64u8).map(|i| [i; 32]).collect();
        Tree::from_chunks(&leaves, 64)
    }

    #[test]
    fn spec_branch_check() {
        let body = BeaconBlockBody::default();
        let p = prove(&body, &parse_path("execution_payload")).unwrap();
        let root = body.hash_tree_root();
        assert!(is_valid_merkle_branch(&p.leaf, &p.branch, p.depth(), p.subtree_index(), &root));
        assert!(!is_valid_merkle_branch(&p.leaf, &p.branch, p.depth(), p.subtree_index() + 1, &root));
        assert!(!is_valid_merkle_branch(&p.leaf, &p.branch[1..], p.depth(), p.subtree_index(), &root));
        assert!(!is_valid_merkle_branch(&p.leaf, &p.branch, p.depth(), 1 << p.depth(), &root));
    }

    #[test]
    fn normalized_branches() {
        let tree = sample_tree();
        let root = tree.root();
        let g = gindex(64 + 21);
        let leaf = tree.node_root(g).unwrap();
        let branch = tree.prove(g).unwrap();
        assert!(is_valid_normalized_merkle_branch(&leaf, &branch, g, &root));

        let mut padded = vec![[0u8; 32]; 2];
        padded.extend_from_slice(&branch);
        assert!(is_valid_normalized_merkle_branch(&leaf, &padded, g, &root));

        padded[1][0] = 1;
        assert!(!is_valid_normalized_merkle_branch(&leaf, &padded, g, &root));
        assert!(!is_valid_normalized_merkle_branch(&leaf, &branch[1..], g, &root));
    }
}
