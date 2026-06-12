use proptest::prelude::*;
use ssz_merkle::hash::hash_pair;
use ssz_merkle::merkle::{merkleize, next_pow_of_two};
use ssz_merkle::proof::calculate_multi_merkle_root;
use ssz_merkle::{
    Bitlist, Bitvector, ByteList, GeneralizedIndex, Hash256, List, PathElem, ProgressiveList, Ssz, Vector,
    prove, ssz_container, verify_merkle_proof,
};

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Inner {
        pub id: u32,
        pub tags: List<u16, 16>,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Outer {
        pub slot: u64,
        pub flags: Bitvector<12>,
        pub votes: Bitlist<300>,
        pub data: ByteList<100>,
        pub fixed: Vector<u64, 5>,
        pub inners: List<Inner, 8>,
        pub history: ProgressiveList<u32>,
    }
}

fn inner() -> impl Strategy<Value = Inner> {
    (any::<u32>(), prop::collection::vec(any::<u16>(), 0..=16))
        .prop_map(|(id, tags)| Inner { id, tags: List::new(tags).unwrap() })
}

fn outer() -> impl Strategy<Value = Outer> {
    (
        any::<u64>(),
        prop::collection::vec(any::<bool>(), 12),
        prop::collection::vec(any::<bool>(), 0..=300),
        prop::collection::vec(any::<u8>(), 0..=100),
        prop::collection::vec(any::<u64>(), 5),
        prop::collection::vec(inner(), 0..=8),
        prop::collection::vec(any::<u32>(), 0..=40),
    )
        .prop_map(|(slot, flags, votes, data, fixed, inners, history)| Outer {
            slot,
            flags: Bitvector::from_bools(&flags).unwrap(),
            votes: Bitlist::from_bools(&votes).unwrap(),
            data: ByteList::new(data).unwrap(),
            fixed: Vector::new(fixed).unwrap(),
            inners: List::new(inners).unwrap(),
            history: ProgressiveList::from(history),
        })
}

fn naive_merkleize(chunks: &[Hash256], limit: usize) -> Hash256 {
    let mut layer = chunks.to_vec();
    layer.resize(next_pow_of_two(limit), [0u8; 32]);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
    }
    layer[0]
}

fn path(parts: &[&str]) -> Vec<PathElem> {
    parts.iter().map(|p| PathElem::parse(p)).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn round_trip_and_tree_root(value in outer()) {
        let bytes = value.to_ssz();
        prop_assert_eq!(bytes.len(), value.encoded_len());
        prop_assert_eq!(Outer::from_ssz(&bytes).unwrap(), value.clone());
        prop_assert_eq!(value.tree().root(), value.hash_tree_root());
    }

    #[test]
    fn every_field_has_a_valid_proof(value in outer()) {
        let root = value.hash_tree_root();
        for field in ["slot", "flags", "votes", "data", "fixed", "inners", "history"] {
            let proof = prove(&value, &path(&[field])).unwrap();
            prop_assert!(proof.verify(&root), "field {}", field);
            let mut bad = proof.clone();
            bad.leaf[31] ^= 1;
            prop_assert!(!bad.verify(&root));
        }
        let slot = prove(&value, &path(&["slot"])).unwrap();
        prop_assert_eq!(slot.leaf, value.slot.hash_tree_root());
        let inners = prove(&value, &path(&["inners"])).unwrap();
        prop_assert_eq!(inners.leaf, value.inners.hash_tree_root());
    }

    #[test]
    fn nested_and_length_proofs(value in outer()) {
        let root = value.hash_tree_root();
        let len = prove(&value, &path(&["inners", "__len__"])).unwrap();
        prop_assert_eq!(&len.leaf[..8], &(value.inners.len() as u64).to_le_bytes()[..]);
        prop_assert!(len.verify(&root));
        for (i, inner) in value.inners.iter().enumerate() {
            let p = prove(&value, &path(&["inners", &i.to_string(), "id"])).unwrap();
            prop_assert_eq!(p.leaf, inner.id.hash_tree_root());
            prop_assert!(p.verify(&root));
        }
        // Element i of a packed uint64 vector lives in chunk i / 4 at byte offset 8 * (i % 4).
        for (i, v) in value.fixed.iter().enumerate() {
            let p = prove(&value, &path(&["fixed", &i.to_string()])).unwrap();
            let at = 8 * (i % 4);
            prop_assert_eq!(&p.leaf[at..at + 8], &v.to_le_bytes()[..]);
            prop_assert!(p.verify(&root));
        }
        // Progressive list elements: packed uint32s, 8 per chunk.
        for (i, v) in value.history.iter().enumerate() {
            let p = prove(&value, &path(&["history", &i.to_string()])).unwrap();
            let at = 4 * (i % 8);
            prop_assert_eq!(&p.leaf[at..at + 4], &v.to_le_bytes()[..]);
            prop_assert!(p.verify(&root));
        }
    }

    #[test]
    fn multiproof_for_random_fields(value in outer(), picks in prop::collection::btree_set(0usize..7, 1..=7)) {
        let fields = ["slot", "flags", "votes", "data", "fixed", "inners", "history"];
        let tree = value.tree();
        let schema = Outer::schema();
        let indices: Vec<GeneralizedIndex> =
            picks.iter().map(|&i| schema.generalized_index(&path(&[fields[i]])).unwrap()).collect();
        let leaves: Vec<Hash256> = indices.iter().map(|&g| tree.node_root(g).unwrap()).collect();
        let helpers = tree.multiproof(&indices).unwrap();
        prop_assert_eq!(calculate_multi_merkle_root(&leaves, &helpers, &indices), Ok(value.hash_tree_root()));
    }

    #[test]
    fn decoding_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        // Whatever decodes must re-encode to exactly the same bytes.
        if let Ok(v) = Outer::from_ssz(&bytes) {
            prop_assert_eq!(v.to_ssz(), bytes);
        }
    }

    #[test]
    fn mutated_encodings_never_panic(value in outer(), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut bytes = value.to_ssz();
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(v) = Outer::from_ssz(&bytes) {
            prop_assert_eq!(v.to_ssz(), bytes);
        }
    }
}

proptest! {
    #[test]
    fn merkleize_matches_naive(n in 0usize..70, extra in 0usize..70) {
        let chunks: Vec<Hash256> = (0..n).map(|i| [i as u8; 32]).collect();
        let limit = n + extra;
        prop_assert_eq!(merkleize(&chunks, Some(limit)), naive_merkleize(&chunks, limit));
    }

    #[test]
    fn single_proofs_on_large_lists(values in prop::collection::vec(any::<u64>(), 1..200), pick in any::<prop::sample::Index>()) {
        let list: List<u64, { 1 << 30 }> = List::new(values.clone()).unwrap();
        let i = pick.index(values.len());
        let p = prove(&list, &[PathElem::Index(i as u64)]).unwrap();
        prop_assert!(verify_merkle_proof(&p.leaf, &p.branch, p.gindex, &list.hash_tree_root()));
        prop_assert_eq!(p.branch.len(), 1 + 28); // length mix-in + log2(2^30 * 8 / 32)
    }

    #[test]
    fn gindex_concat_inverts_relative(a in 1u64..1 << 20, b in 1u64..1 << 20) {
        let (a, b) = (GeneralizedIndex::new(a).unwrap(), GeneralizedIndex::new(b).unwrap());
        let c = a.concat(b).unwrap();
        prop_assert_eq!(c.relative_to(a), Some(b));
        prop_assert!(c.is_descendant_of(a));
        prop_assert_eq!(c.depth(), a.depth() + b.depth());
    }
}
