use std::path::Path;

use ssz_merkle::deneb::{BeaconBlockBody, BeaconBlockHeader};
use ssz_merkle::{ByteVector, PathElem, Ssz, prove, verify_merkle_proof};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/consensus-spec-tests/merkle_proof/BeaconBlockBody")
        .join("blob_kzg_commitment_merkle_proof__random_block_1/object.ssz_snappy");
    let compressed = std::fs::read(&file).expect("vendored test vector");
    let bytes = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy");
    let body = BeaconBlockBody::from_ssz(&bytes).expect("valid Deneb block body");

    let header = BeaconBlockHeader {
        slot: 1,
        proposer_index: 7,
        body_root: ByteVector::from(body.hash_tree_root()),
        ..Default::default()
    };

    // Commitment -> body root, then body root -> header root.
    let in_body = prove(&body, &[PathElem::parse("blob_kzg_commitments"), PathElem::Index(0)]).unwrap();
    let in_header = prove(&header, &[PathElem::parse("body_root")]).unwrap();

    let gindex = in_header.gindex.concat(in_body.gindex).expect("fits in 64 bits");
    let branch: Vec<_> = in_body.branch.iter().chain(&in_header.branch).copied().collect();
    let root = header.hash_tree_root();

    println!("commitment:      0x{}", hex(&body.blob_kzg_commitments[0]));
    println!("leaf (htr):      0x{}", hex(&in_body.leaf));
    println!("body gindex:     {} (depth {})", in_body.gindex, in_body.gindex.depth());
    println!("header gindex:   {gindex} (depth {})", gindex.depth());
    println!("header root:     0x{}", hex(&root));
    println!("proof valid:     {}", verify_merkle_proof(&in_body.leaf, &branch, gindex, &root));
}
