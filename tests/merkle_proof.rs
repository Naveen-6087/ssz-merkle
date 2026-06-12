mod common;

use common::{cases, hex, parse_hex32, read_snappy, read_yaml, spec_tests_dir};
use ssz_merkle::deneb::BeaconBlockBody;
use ssz_merkle::{GeneralizedIndex, PathElem, Ssz, calculate_merkle_root, prove};

#[test]
fn deneb_blob_kzg_commitment_inclusion_proofs() {
    let suite = spec_tests_dir().join("merkle_proof/BeaconBlockBody");
    let dirs = cases(&suite).expect("merkle_proof vectors are vendored in the repository");
    assert_eq!(dirs.len(), 4);

    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = read_snappy(&dir.join("object.ssz_snappy"));
        let body = BeaconBlockBody::from_ssz(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(body.to_ssz(), bytes, "{name}: re-encoding differs");

        let expected = read_yaml(&dir.join("proof.yaml"));
        let leaf = parse_hex32(expected["leaf"].as_str().unwrap());
        let gindex = GeneralizedIndex::new(expected["leaf_index"].as_i64().unwrap() as u64).unwrap();
        let branch: Vec<_> =
            expected["branch"].as_vec().unwrap().iter().map(|h| parse_hex32(h.as_str().unwrap())).collect();

        let path = [PathElem::parse("blob_kzg_commitments"), PathElem::Index(0)];
        let proof = prove(&body, &path).unwrap();
        assert_eq!(proof.gindex, gindex, "{name}: generalized index");
        assert_eq!(proof.leaf, leaf, "{name}: leaf");
        assert_eq!(proof.leaf, body.blob_kzg_commitments[0].hash_tree_root(), "{name}: leaf root");
        assert_eq!(
            proof.branch.iter().map(|h| hex(h)).collect::<Vec<_>>(),
            branch.iter().map(|h| hex(h)).collect::<Vec<_>>(),
            "{name}: branch"
        );

        let root = body.hash_tree_root();
        assert_eq!(calculate_merkle_root(&leaf, &branch, gindex), Ok(root), "{name}: root");
        assert!(proof.verify(&root));
        assert_eq!(body.tree().root(), root);

        let mut tampered = branch.clone();
        tampered[3][0] ^= 1;
        assert_ne!(calculate_merkle_root(&leaf, &tampered, gindex), Ok(root));
    }
}
