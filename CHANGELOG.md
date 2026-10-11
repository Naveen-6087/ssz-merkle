# Changelog

## 0.1.0

First release.

- SSZ serialization and `hash_tree_root` for every SSZ type, including
  EIP-7916 progressive lists and EIP-7495 progressive containers, through the
  `Ssz` trait and the `ssz_container!` / `ssz_progressive_container!` macros.
- Generalized index resolution from typed paths, with `parse_path` for
  dotted strings and `Ssz::generalized_index`.
- Single proofs (`prove`, `Proof`), multiproofs (`prove_multi`, `Multiproof`)
  and schema-checked verification (`verify_path`, `verify_paths`).
- `light_client`: gindex constants for Altair and Electra state layouts,
  `is_valid_merkle_branch` and `is_valid_normalized_merkle_branch`.
- `#![no_std]` with `alloc`; `sha2` is the only required dependency.
- Optional `serde` support for proofs and generalized indices.
- Deneb mainnet consensus types.
- `hex` helpers.
- The `ssz-merkle` CLI behind the `cli` feature.
