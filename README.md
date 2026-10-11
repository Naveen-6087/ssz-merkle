# ssz-merkle

[![crates.io](https://img.shields.io/crates/v/ssz-merkle.svg)](https://crates.io/crates/ssz-merkle)
[![docs.rs](https://docs.rs/ssz-merkle/badge.svg)](https://docs.rs/ssz-merkle)
[![CI](https://github.com/Naveen-6087/ssz-merkle/actions/workflows/ci.yml/badge.svg)](https://github.com/Naveen-6087/ssz-merkle/actions/workflows/ci.yml)
[![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/)

SSZ serialization, `hash_tree_root`, generalized indices and Merkle proofs for
Ethereum consensus types, in Rust.

The crate has three jobs:

1. Turning SSZ objects into bytes and back.
2. Computing their Merkle roots.
3. Proving that one value sits at a given position under a root. This is
   the check that light clients, blob sidecars, bridges and zk coprocessors
   run instead of downloading whole blocks or states.

It passes all 4,624 official `ssz_generic` reference tests (consensus-specs
v1.6.1), and reproduces the official Deneb blob-inclusion proofs byte for
byte.

- **Every SSZ type.** This includes EIP-7916 progressive lists and EIP-7495
  progressive containers.
- **Proofs from a path.** A dotted path such as
  `"body.blob_kzg_commitments.0"` becomes a generalized index, and from there
  a single proof or one multiproof covering several paths.
- **Light-client helpers.** The spec's gindex constants, `is_valid_merkle_branch`
  and `is_valid_normalized_merkle_branch`.
- **`no_std` + `alloc`.** It runs in embedded targets and zkVM guests, and
  its only required dependency is `sha2`.
- **Optional extras.** `serde` support for proofs, and a CLI.

## Install

```toml
[dependencies]
ssz-merkle = "0.1"
```

| Feature | Default | What it adds |
|---------|---------|--------------|
| `serde` | no | `Serialize`/`Deserialize` for `Proof`, `Multiproof` and `GeneralizedIndex` (hashes as `0x` hex) |
| `cli` | no | The `ssz-merkle` binary: `cargo install ssz-merkle --features cli` |

The library is always `#![no_std]` and uses `alloc`. Hashing goes through
the [`sha2`](https://crates.io/crates/sha2) crate. zkVMs that accelerate
SHA-256 by patching `sha2` (as SP1 and RISC Zero do) therefore speed this
crate up with no code changes.

## Quick start

Declare your types with the container macro. Fields are serialized and
merkleized in declaration order, exactly as the SSZ spec defines containers:

```rust
use ssz_merkle::{Bitlist, ByteVector, List, Ssz, ssz_container};

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

let registry = Registry {
    epoch: 7,
    validators: List::new(vec![Validator::default(); 3]).unwrap(),
    participation: Bitlist::from_bools(&[true, false, true]).unwrap(),
};

let bytes = registry.to_ssz();
assert_eq!(Registry::from_ssz(&bytes).unwrap(), registry);
let root: [u8; 32] = registry.hash_tree_root();
```

### Prove a value

```rust
# use ssz_merkle::{List, Ssz, ssz_container};
# ssz_container! {
#     #[derive(Clone, Debug, Default, PartialEq, Eq)]
#     pub struct Registry { pub epoch: u64, pub balances: List<u64, 1024> }
# }
# let registry = Registry { epoch: 7, balances: List::new(vec![32; 100]).unwrap() };
use ssz_merkle::{parse_path, prove};

let root = registry.hash_tree_root();
let path = parse_path("balances.42");
let proof = prove(&registry, &path).unwrap();     // gindex, leaf, branch

// The verifier recomputes the gindex from its own copy of the type, so a
// prover cannot pass off a branch for a different field.
assert!(proof.verify_path::<Registry>(&path, &root));
```

### Prove several values at once

A multiproof shares every node that the individual branches have in common:

```rust
# use ssz_merkle::{List, Ssz, ssz_container, parse_path};
# ssz_container! {
#     #[derive(Clone, Debug, Default, PartialEq, Eq)]
#     pub struct Registry { pub epoch: u64, pub balances: List<u64, 1024> }
# }
# let registry = Registry { epoch: 7, balances: List::new(vec![32; 100]).unwrap() };
use ssz_merkle::prove_multi;

let paths = ["epoch", "balances.__len__", "balances.42", "balances.99"].map(parse_path);
let multi = prove_multi(&registry, &paths).unwrap();
assert!(multi.verify_paths::<Registry, _>(&paths, &registry.hash_tree_root()));
```

### Generalized indices without a value

```rust
use ssz_merkle::deneb::{BeaconBlock, BeaconBlockBody};
use ssz_merkle::{Ssz, parse_path};

let g = BeaconBlockBody::generalized_index(&parse_path("blob_kzg_commitments.0")).unwrap();
assert_eq!((g.get(), g.depth()), (221_184, 17)); // as in Deneb blob sidecars

let g = BeaconBlock::generalized_index(&parse_path("body.execution_payload.block_hash")).unwrap();
assert_eq!(g.get(), 6444);
```

### Light clients

```rust
use ssz_merkle::deneb::BeaconBlockBody;
use ssz_merkle::light_client::{EXECUTION_PAYLOAD_GINDEX, is_valid_merkle_branch};
use ssz_merkle::{Ssz, parse_path, prove};

let body = BeaconBlockBody::default();
let body_root = body.hash_tree_root(); // in practice: from a trusted header
let proof = prove(&body, &parse_path("execution_payload")).unwrap();

let g = EXECUTION_PAYLOAD_GINDEX;
assert!(is_valid_merkle_branch(&proof.leaf, &proof.branch, g.depth(), g.subtree_index(), &body_root));
```

`light_client` also exports `FINALIZED_ROOT_GINDEX`,
`CURRENT_SYNC_COMMITTEE_GINDEX` and `NEXT_SYNC_COMMITTEE_GINDEX`, in their
Altair and `_ELECTRA` variants. The tests check each of them against the
`BeaconState` field layout of its fork. `is_valid_normalized_merkle_branch`
accepts branches built for a deeper state, as the Electra light-client
protocol requires.

### Serde

With the `serde` feature, proofs serialize to plain JSON:

```text
{"gindex":221184,"leaf":"0xc7b8...","branch":["0x0000...", "0xf5a5...", ...]}
```

## What's inside

| Module | Contents |
|--------|----------|
| crate root | `Ssz` trait, `prove`, `prove_multi`, `Proof`, `Multiproof`, `parse_path` |
| `collections`, `bits` | `Vector`, `List`, `ByteVector`, `ByteList`, `Bitvector`, `Bitlist`, `ProgressiveList`, `ProgressiveBitlist` |
| `ssz_container!`, `ssz_progressive_container!` | Containers and EIP-7495 progressive containers |
| `gindex` | `GeneralizedIndex` arithmetic: `concat`, `relative_to`, `branch_indices`, `helper_indices` |
| `proof` | `verify_merkle_proof`, `calculate_multi_merkle_root` and friends |
| `tree` | `Tree`, an explicit Merkle tree with virtual zero subtrees |
| `schema` | Type shapes and path → gindex resolution |
| `light_client` | Spec gindex constants and branch checks |
| `deneb` | Deneb mainnet types (`BeaconBlock`, `BeaconBlockBody`, `ExecutionPayload`, ...) |
| `hex` | `encode`, `decode`, `decode_hash` |

Basic types are `u8`, `u16`, `u32`, `u64`, `u128`, `U256` and `bool`.

### How it works

- **Two Merkleization paths, cross-checked.** `hash_tree_root` hashes layer
  by layer without allocating nodes. `tree()` builds the explicit tree that
  proofs are read from. The reference tests and property tests assert that
  both give the same root.
- **Virtual zero padding.** All-zero subtrees cost O(1). A
  `List<u64, 2^40>` with 1,000 elements hashes only what it holds, and a
  proof deep inside the padding costs the same as anywhere else.
- **Schemas are values.** `T::schema()` describes the type's shape, and
  gindex resolution walks it with checked 64-bit arithmetic: overflow is an
  error, never a silent wrap.
- **Strict multiproofs.** Verification follows the spec, but also rejects
  duplicate indices and indices nested inside other proven indices. Either
  would let a proof claim two values for one node.

## CLI

```console
$ cargo install ssz-merkle --features cli

$ ssz-merkle gindex BeaconBlockBody blob_kzg_commitments.0
{"gindex":221184,"depth":17,"type":"Vector[uint8, 48]"}

$ ssz-merkle root  BeaconBlockBody block.ssz_snappy
$ ssz-merkle prove BeaconBlockBody block.ssz_snappy blob_kzg_commitments.0
$ ssz-merkle multiproof BeaconBlockBody block.ssz_snappy blob_kzg_commitments.0 execution_payload.block_hash
$ ssz-merkle verify <root> <leaf> <gindex> <branch...>
$ ssz-merkle json  BeaconBlockBody block.ssz_snappy
```

Input files hold raw SSZ, or snappy-compressed SSZ when the name ends in
`.ssz_snappy`. Output is JSON. The exit status is 0 on success, 1 for an
invalid proof, and 2 for usage or input errors.

## Examples

```sh
cargo run --example custom_types           # containers, proofs, multiproofs
cargo run --example light_client           # header -> execution payload -> block hash
cargo run --example blob_inclusion_proof   # a real Deneb blob commitment into a block header
```

## Testing

```sh
bash scripts/fetch-spec-tests.sh   # consensus-specs v1.6.1 ssz_generic, checksum verified
cargo test --all-features
```

| Suite | Checks |
|-------|--------|
| `ssz_generic` (4,624 cases) | Decode, byte-exact re-encode, both Merkleization paths against the expected root, and the decoded value against `value.yaml`. Every invalid case must fail to decode. |
| Deneb `merkle_proof` | The generated proof for `blob_kzg_commitments[0]` equals the official gindex, leaf and 17-node branch. |
| Property tests | Round trips; the tree root equals `hash_tree_root`; proofs and multiproofs for every field, element and length; decoding is canonical; mutated input never panics. |
| Unit and doc tests | Spec examples, light-client gindices against the `BeaconState` layouts, serde round trips, and the examples in this README. |
| CI | fmt, clippy, tests, MSRV 1.85, a `no_std` build for `thumbv7m-none-eabi` (including a downstream crate that uses the macros), docs, `cargo package` and `cargo audit`. |

## Benchmarks

`cargo bench --bench merkle`. One run on an Intel Core i5-12500H gave these
Criterion medians:

| Operation | Time |
|-----------|------|
| `merkleize` 65,536 chunks | 7.2 ms |
| `hash_tree_root` of `List<u64, 2^40>` with 100,000 elements | 3.3 ms |
| Deneb block body (36 KB): decode / encode / `hash_tree_root` | 85 µs / 12 µs / 321 µs |
| Prove `blob_kzg_commitments[0]` (tree build included) / verify | 814 µs / 2.6 µs |
| Resolve a gindex from a path | 36 ns |

## Security

- Decoding is strict. Bad offsets, wrong lengths, over-limit lists,
  missing bitlist delimiters, non-zero padding bits and invalid booleans are
  all rejected, and whatever decodes re-encodes to the same bytes.
- Always derive the gindex from the type you trust (`verify_path`,
  `verify_paths`, or the `light_client` constants), never from the prover.
- Hashing is not constant time. The inputs are public consensus data.
- The crate has not been audited.

## Limitations

- `Union` and `CompatibleUnion` are not implemented.
- Only Deneb mainnet types are bundled. Types for other forks are a few
  lines each with the macros.
- `tree()` materializes every non-zero node, so proving into a whole
  `BeaconState` uses memory proportional to the state.
- Generalized indices are 64-bit, which limits paths to 63 levels.

## References

- [SSZ specification](https://github.com/ethereum/consensus-specs/blob/v1.6.1/ssz/simple-serialize.md) and [Merkle proof formats](https://github.com/ethereum/consensus-specs/blob/v1.6.1/ssz/merkle-proofs.md)
- [EIP-7916 ProgressiveList](https://eips.ethereum.org/EIPS/eip-7916) and [EIP-7495 ProgressiveContainer](https://eips.ethereum.org/EIPS/eip-7495)
- [Altair light client sync protocol](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/altair/light-client/sync-protocol.md)

## License

MIT
