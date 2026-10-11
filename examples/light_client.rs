use ssz_merkle::deneb::{BeaconBlockBody, BeaconBlockHeader, ExecutionPayload};
use ssz_merkle::light_client::{EXECUTION_PAYLOAD_GINDEX, is_valid_merkle_branch};
use ssz_merkle::{ByteVector, Ssz, hex, parse_path, prove};

// A light client trusts a block header (for example through a sync committee
// signature) and wants the execution block hash without downloading the body.
fn main() {
    let body = BeaconBlockBody {
        execution_payload: ExecutionPayload {
            block_number: 21_000_000,
            block_hash: ByteVector::new(vec![0xab; 32]).unwrap(),
            ..Default::default()
        },
        ..Default::default()
    };
    let header = BeaconBlockHeader {
        slot: 10_500_000,
        body_root: ByteVector::from(body.hash_tree_root()),
        ..Default::default()
    };

    // Full node side: prove the payload root inside the body.
    let proof = prove(&body, &parse_path("execution_payload")).unwrap();
    assert_eq!(proof.gindex, EXECUTION_PAYLOAD_GINDEX);

    // Light client side: the gindex comes from the spec, not from the prover.
    let trusted_body_root: [u8; 32] = header.body_root.as_bytes().try_into().unwrap();
    let ok = is_valid_merkle_branch(
        &proof.leaf,
        &proof.branch,
        EXECUTION_PAYLOAD_GINDEX.depth(),
        EXECUTION_PAYLOAD_GINDEX.subtree_index(),
        &trusted_body_root,
    );
    println!("execution payload root {} verified: {ok}", hex::encode(proof.leaf));
    assert!(ok);

    // Then a second proof, from the payload root down to the block hash.
    let inner = prove(&body.execution_payload, &parse_path("block_hash")).unwrap();
    assert!(inner.verify(&proof.leaf));
    println!("block hash {} at payload gindex {}", hex::encode(inner.leaf), inner.gindex);
}
