use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub type Hash256 = [u8; 32];

pub const BYTES_PER_CHUNK: usize = 32;
pub const MAX_DEPTH: usize = 64;

pub fn hash(data: &[u8]) -> Hash256 {
    Sha256::digest(data).into()
}

pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of a fully zeroed subtree with `2^depth` leaves.
pub fn zero_hash(depth: usize) -> Hash256 {
    static ZERO_HASHES: OnceLock<[Hash256; MAX_DEPTH + 1]> = OnceLock::new();
    let table = ZERO_HASHES.get_or_init(|| {
        let mut table = [[0u8; 32]; MAX_DEPTH + 1];
        for d in 1..=MAX_DEPTH {
            table[d] = hash_pair(&table[d - 1], &table[d - 1]);
        }
        table
    });
    table[depth]
}

pub(crate) fn length_chunk(len: u64) -> Hash256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&len.to_le_bytes());
    chunk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash256) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        assert_eq!(hex(&hash(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&zero_hash(1)), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    }

    #[test]
    fn zero_hashes_chain() {
        assert_eq!(zero_hash(0), [0u8; 32]);
        for d in 1..=MAX_DEPTH {
            assert_eq!(zero_hash(d), hash_pair(&zero_hash(d - 1), &zero_hash(d - 1)));
        }
    }
}
