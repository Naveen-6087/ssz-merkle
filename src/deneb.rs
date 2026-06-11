use crate::{Bitlist, Bitvector, ByteList, ByteVector, List, U256, Vector, ssz_container};

pub type Slot = u64;
pub type Epoch = u64;
pub type ValidatorIndex = u64;
pub type CommitteeIndex = u64;
pub type Gwei = u64;
pub type Root = ByteVector<32>;
pub type Bytes32 = ByteVector<32>;
pub type Hash32 = ByteVector<32>;
pub type BLSPubkey = ByteVector<48>;
pub type BLSSignature = ByteVector<96>;
pub type KZGCommitment = ByteVector<48>;
pub type ExecutionAddress = ByteVector<20>;
pub type Transaction = ByteList<MAX_BYTES_PER_TRANSACTION>;

pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
pub const MAX_PROPOSER_SLASHINGS: usize = 16;
pub const MAX_ATTESTER_SLASHINGS: usize = 2;
pub const MAX_ATTESTATIONS: usize = 128;
pub const MAX_DEPOSITS: usize = 16;
pub const MAX_VOLUNTARY_EXITS: usize = 16;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const DEPOSIT_PROOF_LENGTH: usize = 33;
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;
pub const MAX_BYTES_PER_TRANSACTION: usize = 1 << 30;
pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1 << 20;
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Eth1Data {
        pub deposit_root: Root,
        pub deposit_count: u64,
        pub block_hash: Hash32,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BeaconBlockHeader {
        pub slot: Slot,
        pub proposer_index: ValidatorIndex,
        pub parent_root: Root,
        pub state_root: Root,
        pub body_root: Root,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SignedBeaconBlockHeader {
        pub message: BeaconBlockHeader,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProposerSlashing {
        pub signed_header_1: SignedBeaconBlockHeader,
        pub signed_header_2: SignedBeaconBlockHeader,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Checkpoint {
        pub epoch: Epoch,
        pub root: Root,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct AttestationData {
        pub slot: Slot,
        pub index: CommitteeIndex,
        pub beacon_block_root: Root,
        pub source: Checkpoint,
        pub target: Checkpoint,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct IndexedAttestation {
        pub attesting_indices: List<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
        pub data: AttestationData,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct AttesterSlashing {
        pub attestation_1: IndexedAttestation,
        pub attestation_2: IndexedAttestation,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Attestation {
        pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
        pub data: AttestationData,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct DepositData {
        pub pubkey: BLSPubkey,
        pub withdrawal_credentials: Bytes32,
        pub amount: Gwei,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Deposit {
        pub proof: Vector<Bytes32, DEPOSIT_PROOF_LENGTH>,
        pub data: DepositData,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct VoluntaryExit {
        pub epoch: Epoch,
        pub validator_index: ValidatorIndex,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SignedVoluntaryExit {
        pub message: VoluntaryExit,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SyncAggregate {
        pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
        pub sync_committee_signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Withdrawal {
        pub index: u64,
        pub validator_index: ValidatorIndex,
        pub address: ExecutionAddress,
        pub amount: Gwei,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ExecutionPayload {
        pub parent_hash: Hash32,
        pub fee_recipient: ExecutionAddress,
        pub state_root: Bytes32,
        pub receipts_root: Bytes32,
        pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
        pub prev_randao: Bytes32,
        pub block_number: u64,
        pub gas_limit: u64,
        pub gas_used: u64,
        pub timestamp: u64,
        pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
        pub base_fee_per_gas: U256,
        pub block_hash: Hash32,
        pub transactions: List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>,
        pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
        pub blob_gas_used: u64,
        pub excess_blob_gas: u64,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BLSToExecutionChange {
        pub validator_index: ValidatorIndex,
        pub from_bls_pubkey: BLSPubkey,
        pub to_execution_address: ExecutionAddress,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SignedBLSToExecutionChange {
        pub message: BLSToExecutionChange,
        pub signature: BLSSignature,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BeaconBlockBody {
        pub randao_reveal: BLSSignature,
        pub eth1_data: Eth1Data,
        pub graffiti: Bytes32,
        pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
        pub attester_slashings: List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
        pub attestations: List<Attestation, MAX_ATTESTATIONS>,
        pub deposits: List<Deposit, MAX_DEPOSITS>,
        pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
        pub sync_aggregate: SyncAggregate,
        pub execution_payload: ExecutionPayload,
        pub bls_to_execution_changes: List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
        pub blob_kzg_commitments: List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BeaconBlock {
        pub slot: Slot,
        pub proposer_index: ValidatorIndex,
        pub parent_root: Root,
        pub state_root: Root,
        pub body: BeaconBlockBody,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PathElem, Ssz};

    fn path(p: &[&str]) -> Vec<PathElem> {
        p.iter().map(|s| PathElem::parse(s)).collect()
    }

    #[test]
    fn known_generalized_indices() {
        let body = BeaconBlockBody::schema();
        // Used by blob sidecar inclusion proofs (KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = 17).
        let g = body.generalized_index(&path(&["blob_kzg_commitments", "0"])).unwrap();
        assert_eq!(g.get(), 221_184);
        assert_eq!(g.depth(), 17);
        // EXECUTION_PAYLOAD_GINDEX = 25 in the Capella light client spec.
        assert_eq!(body.generalized_index(&path(&["execution_payload"])).unwrap().get(), 25);
    }

    #[test]
    fn header_body_root_matches_body() {
        let body = BeaconBlockBody::default();
        let block = BeaconBlock { slot: 7, body: body.clone(), ..Default::default() };
        let header = BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root.clone(),
            state_root: block.state_root.clone(),
            body_root: ByteVector::from(body.hash_tree_root()),
        };
        assert_eq!(header.hash_tree_root(), block.hash_tree_root());
    }
}
