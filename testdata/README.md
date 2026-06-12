# Test data

The repository's code is MIT licensed. The reference tests below come from
the Ethereum consensus specifications and are dedicated to the public domain
(CC0-1.0).

| Path | Source |
|------|--------|
| `consensus-spec-tests/merkle_proof/BeaconBlockBody/` | [ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests) `tests/mainnet/deneb/merkle_proof/single_merkle_proof/BeaconBlockBody` at commit `bc5c1a7fb2a8871aaffd4b16ee4dd9c72bb81908` (v1.6.0-beta.0) |
| `consensus-spec-tests/ssz_generic/` (downloaded) | `tests/general/phase0/ssz_generic` from the [consensus-specs v1.6.1](https://github.com/ethereum/consensus-specs/releases/tag/v1.6.1) `general.tar.gz` release asset, SHA-256 `87898ba7a3fa16bc66b08c88b4ccab008833a517a7602cf421c6ce79734e07e9` |

Only the merkle_proof vectors (85 KB) are committed. `scripts/fetch-spec-tests.sh`
downloads the ssz_generic suites (about 300 MB unpacked), verifies the archive
checksum and the number of cases in each suite.

`*.ssz_snappy` files are binary: `.gitattributes` marks them so Git never
rewrites their line endings.
