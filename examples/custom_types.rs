use ssz_merkle::{Bitlist, ByteVector, List, Ssz, hex, parse_path, prove, prove_multi, ssz_container};

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Validator {
        pub pubkey: ByteVector<48>,
        pub effective_balance: u64,
        pub slashed: bool,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Registry {
        pub epoch: u64,
        pub validators: List<Validator, 1048576>,
        pub participation: Bitlist<1048576>,
    }
}

fn main() {
    let validators = (0..1000u64)
        .map(|i| Validator {
            pubkey: ByteVector::new(vec![i as u8; 48]).unwrap(),
            effective_balance: 32_000_000_000,
            slashed: i == 42,
        })
        .collect();
    let registry = Registry {
        epoch: 1234,
        validators: List::new(validators).unwrap(),
        participation: Bitlist::from_bools(&[true; 1000]).unwrap(),
    };

    let bytes = registry.to_ssz();
    assert_eq!(Registry::from_ssz(&bytes).unwrap(), registry);
    let root = registry.hash_tree_root();
    println!("{} bytes, root {}", bytes.len(), hex::encode(root));

    let path = parse_path("validators.42.slashed");
    let proof = prove(&registry, &path).unwrap();
    println!("validators[42].slashed: gindex {}, {} branch nodes", proof.gindex, proof.branch.len());
    assert!(proof.verify_path::<Registry>(&path, &root));

    let paths = ["epoch", "validators.__len__", "validators.42.slashed", "validators.999.effective_balance"]
        .map(parse_path);
    let multi = prove_multi(&registry, &paths).unwrap();
    let separate: usize = paths.iter().map(|p| prove(&registry, p).unwrap().branch.len()).sum();
    println!("multiproof: {} helper nodes instead of {separate}", multi.helpers.len());
    assert!(multi.verify_paths::<Registry, _>(&paths, &root));
}
