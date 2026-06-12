# ssz-merkle

SSZ serialization, Merkleization, generalized indices and Merkle proofs for
Ethereum consensus types, in Rust. The crate passes the official
`ssz_generic` reference tests (4,624 cases from consensus-specs v1.6.1),
including the EIP-7916 progressive lists and EIP-7495 progressive
containers. It also reproduces, byte for byte, the official Deneb blob
KZG-commitment inclusion proofs for real `BeaconBlockBody` objects.

```rust
use ssz_merkle::deneb::BeaconBlockBody;
use ssz_merkle::{PathElem, Ssz, prove};

let body = BeaconBlockBody::from_ssz(&bytes)?;
let proof = prove(&body, &[PathElem::parse("blob_kzg_commitments"), PathElem::Index(0)])?;
assert_eq!(proof.gindex.get(), 221_184); // depth 17, as in blob sidecars
assert!(proof.verify(&body.hash_tree_root()));
```

## Why

Every object in Ethereum's consensus layer is identified by its SSZ
`hash_tree_root`. Light clients, blob sidecars, bridges and zk coprocessors
never download whole objects. Instead they check that a single value sits at
a known position under a trusted root. That position is a **generalized
index** (gindex), and the check is a **Merkle branch**.

Getting these right means reproducing the exact tree shape the spec defines:
chunk packing, virtual zero padding up to list limits, length mix-ins,
bitfield delimiters, and now the progressive shapes of EIP-7916 and EIP-7495.
This crate makes those shapes explicit. Each type knows its schema, so a
path like `body.execution_payload.block_hash` becomes a gindex. Each value
can build its full tree, so the branch for that gindex can be extracted and
verified.

## Features

- **Serialization** of every SSZ type: `uint8`–`uint256`, `boolean`,
  `Vector`, `List`, `ByteVector`, `ByteList`, `Bitvector`, `Bitlist`,
  containers, EIP-7916 `ProgressiveList` / `ProgressiveBitlist`, and EIP-7495
  progressive containers. Decoding is hardened: offsets, limits, delimiters,
  padding bits and trailing bytes are all checked.
- **Merkleization**: `hash_tree_root` with virtual zero padding, so a
  `List<u64, 2^40>` holding 1,000 elements hashes only what it holds.
- **Generalized indices**: the spec's `get_generalized_index`, extended to
  bitfields and progressive types, plus `concat`, `relative_to`,
  `branch_indices`, `path_indices` and `helper_indices`.
- **Proofs**: single-item and multi-item proofs from an explicit `Tree`, plus
  `verify_merkle_proof` and `verify_merkle_multiproof`.
- **Types**: the `ssz_container!` and `ssz_progressive_container!` macros,
  and the Deneb consensus types (`BeaconBlockBody`, `ExecutionPayload`, ...)
  for the mainnet preset.
- **Canonical JSON** via `Ssz::to_value().to_json()`.
- **CLI**: `ssz-merkle`, for computing gindices, roots, proofs and JSON from
  SSZ files.

## Architecture

```
            ssz-merkle (CLI)          deneb (consensus types)
                    \                     /
     ssz_container! / ssz_progressive_container!
                              |
     Ssz trait: encode | decode | hash_tree_root | tree | schema | to_value
        |              |                  |              |
     codec       merkle (pack,      tree (explicit    schema (paths ->
   (offsets,     merkleize,         Merkle tree,      generalized
    limits)      progressive)       proofs)           indices)
                       \                 |
                        hash (SHA-256, zero hashes)   gindex, proof
```

| Module | Responsibility |
|--------|----------------|
| `ssz` | The `Ssz` trait and impls for basic types |
| `collections`, `bits` | Vectors, lists, byte types, bitfields, progressive variants |
| `container` | The container macros and progressive-container hashing |
| `codec` | Offset tables, element counts, strict decoding errors |
| `merkle` | `pack`, `merkleize`, `merkleize_progressive`, mix-ins |
| `tree` | `Tree` with virtual zero subtrees: node lookup, branches, multiproofs |
| `schema` | Static type shapes and path → gindex resolution |
| `gindex`, `proof` | Generalized index arithmetic and proof verification |
| `deneb` | Deneb mainnet consensus types |

### Design decisions

- **Two Merkleization paths, cross-checked.** `hash_tree_root` merkleizes
  directly, layer by layer, without building nodes. `tree()` builds an
  explicit tree for proofs. Every reference vector and property test asserts
  that the two give the same root.
- **Virtual padding.** `Tree::Zero(depth)` represents an all-zero subtree in
  O(1), so proofs into `List[Transaction, 2^20]` or deep inside zero padding
  cost the same as anywhere else.
- **Schemas are values.** `T::schema()` returns a `Schema` tree, and gindex
  resolution runs over it with checked 64-bit arithmetic (overflow is an
  error, not a wrap).
- **Distinct byte types.** `ByteVector`/`ByteList` share the SSZ and hashing
  of `Vector[uint8]`/`List[uint8]` but render as hex, matching the
  canonical JSON mapping and the test vectors.
- **Strict multiproofs.** `calculate_multi_merkle_root` follows the spec,
  but also rejects duplicate indices and indices nested inside other proven
  indices, which could otherwise claim two values for one node.
- **No `unsafe`, one runtime dependency** (`sha2`). `snap` is only pulled in
  by the default `cli` feature.

### Progressive types

EIP-7916 lists merkleize as `hash(rest, first)`. Level *k* holds 4ᵏ chunks
in its right subtree, and the remaining levels hang off the left. The gindex
of chunk *p* therefore walks left once per full level, then indexes into the
right subtree. EIP-7495 containers place each field at the position of the
matching `1` in `active_fields`, merkleize progressively, and mix in the
packed `active_fields` bits. The spec's `get_generalized_index` predates both
EIPs, so this extension is this crate's own and is checked against the tree
by the property tests.

## Usage

```toml
[dependencies]
ssz-merkle = { git = "https://github.com/Naveen-6087/ssz-merkle" }
# library only, without the CLI's snappy dependency:
# ssz-merkle = { git = "...", default-features = false }
```

Defining types:

```rust
use ssz_merkle::{Bitlist, List, Ssz, ssz_container};

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Vote {
        pub slot: u64,
        pub voters: Bitlist<2048>,
        pub roots: List<u64, 16>,
    }
}

let vote = Vote::default();
let bytes = vote.to_ssz();
assert_eq!(Vote::from_ssz(&bytes).unwrap(), vote);
let root = vote.hash_tree_root();
```

Proving and verifying:

```rust
use ssz_merkle::{GeneralizedIndex, PathElem, Ssz, prove, verify_merkle_proof};

let path = [PathElem::parse("roots"), PathElem::Index(3)];
let proof = prove(&vote, &path)?;                 // leaf, branch, gindex
assert!(verify_merkle_proof(&proof.leaf, &proof.branch, proof.gindex, &root));

let gindex = Vote::schema().generalized_index(&path)?;  // no value needed
```

`cargo run --example blob_inclusion_proof` chains two proofs: a blob KZG
commitment into a real Deneb block body, then the body into a block header
(gindex `12 ⊕ 221184 = 1662976`, depth 20). That is what a light client
checks for a blob sidecar.

## CLI

```
ssz-merkle types                              list the built-in Deneb types
ssz-merkle gindex <type> [path...]            generalized index of a path
ssz-merkle root   <type> <file>               hash_tree_root of an SSZ object
ssz-merkle json   <type> <file>               canonical JSON
ssz-merkle prove  <type> <file> [path...]     Merkle proof for a path
ssz-merkle verify <root> <leaf> <gindex> [branch...]
```

Files hold raw SSZ, or snappy-compressed SSZ if the name ends in
`.ssz_snappy`. Output is JSON. The exit status is `0` on success, `1` for an
invalid proof and `2` for usage or input errors.

```console
$ ssz-merkle gindex BeaconBlockBody blob_kzg_commitments 0
{"gindex":221184,"depth":17,"type":"Vector[uint8, 48]"}

$ ssz-merkle gindex BeaconBlock body execution_payload block_hash
{"gindex":6444,"depth":12,"type":"Vector[uint8, 32]"}

$ BODY=testdata/consensus-spec-tests/merkle_proof/BeaconBlockBody/blob_kzg_commitment_merkle_proof__random_block_1/object.ssz_snappy
$ ssz-merkle root BeaconBlockBody $BODY
{"root":"0x4393548ea4bf4f5625079f98d40ed403cc2b250438a0c8ee953752f8297a9537"}

$ ssz-merkle prove BeaconBlockBody $BODY blob_kzg_commitments 0
{"root":"0x4393...9537","gindex":221184,"leaf":"0xc7b8...c3ac","branch":["0x0000...0000", ...17 nodes]}
```

(Hashes are abbreviated above; the CLI prints them in full.)

## Testing

```sh
bash scripts/fetch-spec-tests.sh   # consensus-specs v1.6.1 ssz_generic (~170 MB download, checksum verified)
cargo test --all-features
```

| Suite | Cases | Checks |
|-------|------:|--------|
| `ssz_generic` (v1.6.1) | 4,624 | Valid cases: decode, re-encode byte-exact, `hash_tree_root` and `tree().root()` against the expected root, decoded value against `value.yaml`. Invalid cases: decoding must fail. Covers `uints` 66, `boolean` 6, `bitvector` 85, `bitlist` 494, `basic_vector` 1,157, `basic_progressive_list` 887, `progressive_bitlist` 703, `containers` 701, `progressive_containers` 525 |
| Deneb `merkle_proof` | 4 | Real block bodies decode and re-encode; the generated proof for `blob_kzg_commitments[0]` equals the official gindex, leaf and 17-node branch |
| Property tests (proptest) | 9 | Round trips; tree root equals `hash_tree_root`; proofs for every field, nested field, length and packed basic element; multiproofs; merkleize vs naive padding; decoding is canonical (whatever decodes re-encodes to the same bytes); mutated encodings never panic; gindex `concat`/`relative_to` inverses |
| Unit tests | 39 | Spec examples (helper indices, `{x, y}` paths), known gindices (221184, `EXECUTION_PAYLOAD_GINDEX` 25), progressive layouts, edge cases |
| CLI and doc tests | 6 | End-to-end prove → verify, exit codes, JSON output |

Without the downloaded suites, the `ssz_generic` tests are skipped. Set
`SSZ_REQUIRE_SPEC_TESTS=1` to make that a failure, as CI does.

## Benchmarks

```sh
cargo bench --bench merkle
```

One local sample (Windows, Intel Core i5-12500H, `cargo bench`, Criterion
median). Treat these as orders of magnitude only:

| Benchmark | Time |
|-----------|------|
| `merkleize` 1,024 chunks / 65,536 chunks | 118 µs / 7.2 ms |
| `merkleize_progressive` 1,024 / 65,536 chunks | 111 µs / 7.6 ms |
| `hash_tree_root` of `List<u64, 2^40>` with 1,000 / 100,000 elements | 32 µs / 3.3 ms |
| Deneb block body (36 KB): decode / encode | 85 µs / 12 µs |
| Deneb block body: `hash_tree_root` / full `tree()` | 321 µs / 726 µs |
| Prove `blob_kzg_commitments[0]` (tree build included) / verify | 814 µs / 2.6 µs |
| Resolve a gindex from a path | 36 ns |

The `Benchmarks` workflow reruns the suite on GitHub's runners and uploads
Criterion's reports as an artifact.

## Security considerations

- Decoding is consensus-critical and strict. The reference invalid cases
  exercise malformed offsets, wrong lengths, over-limit lists and bitlists,
  missing delimiters, non-zero bitvector padding, and invalid booleans. The
  property tests check that any accepted encoding is canonical.
- A Merkle proof only proves what its gindex means for the expected schema.
  Callers must derive the gindex from the type they trust, not take it from
  the prover.
- Hashing is not constant time. Inputs here are public consensus data.
- This crate has not been audited. For production consensus clients, prefer
  battle-tested crates such as `ethereum_ssz` / `tree_hash` (Lighthouse) or
  `ssz_rs`.

## Limitations

- `Union` and the newer `CompatibleUnion` (`compatible_unions` suite) are not
  implemented.
- Only Deneb mainnet types are bundled. Other forks' types can be declared
  with the macros.
- `Tree` materializes every non-zero node, so proving into very large
  objects (a full `BeaconState`) uses memory proportional to the object.
- Generalized indices are 64-bit. Paths deeper than 63 levels return
  `PathError::Overflow`.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo +1.85 check --all-targets --all-features   # MSRV
cargo audit
```

## References

- [SSZ specification](https://github.com/ethereum/consensus-specs/blob/v1.6.1/ssz/simple-serialize.md)
  and [Merkle proof formats](https://github.com/ethereum/consensus-specs/blob/v1.6.1/ssz/merkle-proofs.md)
- [EIP-7916: SSZ ProgressiveList](https://eips.ethereum.org/EIPS/eip-7916)
- [EIP-7495: SSZ ProgressiveContainer](https://eips.ethereum.org/EIPS/eip-7495)
- [Deneb p2p: blob sidecar inclusion proofs](https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/deneb/p2p-interface.md)

## License

MIT, see [LICENSE](LICENSE). Reference test data is CC0; see
[testdata/README.md](testdata/README.md).
