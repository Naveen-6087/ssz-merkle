use crate::hash::{BYTES_PER_CHUNK, Hash256, hash_pair, length_chunk, zero_hash};
use crate::prelude::*;

pub fn next_pow_of_two(n: usize) -> usize {
    n.max(1).next_power_of_two()
}

pub(crate) fn depth_for(leaves: usize) -> usize {
    next_pow_of_two(leaves).trailing_zeros() as usize
}

/// Splits serialized basic values into zero-padded 32-byte chunks.
pub fn pack(bytes: &[u8]) -> Vec<Hash256> {
    bytes
        .chunks(BYTES_PER_CHUNK)
        .map(|c| {
            let mut chunk = [0u8; 32];
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect()
}

/// Merkleizes chunks padded virtually to `next_pow_of_two(limit)` leaves
/// (or `next_pow_of_two(chunks.len())` without a limit).
///
/// # Panics
///
/// Panics if `chunks.len()` exceeds `limit`; callers enforce type limits
/// before merkleizing.
pub fn merkleize(chunks: &[Hash256], limit: Option<usize>) -> Hash256 {
    let leaves = limit.unwrap_or(chunks.len());
    assert!(chunks.len() <= leaves, "merkleize: {} chunks exceed limit {leaves}", chunks.len());
    let depth = depth_for(leaves);
    if chunks.is_empty() {
        return zero_hash(depth);
    }
    let mut layer = chunks.to_vec();
    for d in 0..depth {
        let next_len = layer.len().div_ceil(2);
        for i in 0..next_len {
            let left = layer[2 * i];
            let right = layer.get(2 * i + 1).copied().unwrap_or_else(|| zero_hash(d));
            layer[i] = hash_pair(&left, &right);
        }
        layer.truncate(next_len);
    }
    layer[0]
}

/// EIP-7916: `hash(merkleize_progressive(rest, 4n), merkleize(first n, n))`.
pub fn merkleize_progressive(chunks: &[Hash256]) -> Hash256 {
    fn go(chunks: &[Hash256], num_leaves: usize) -> Hash256 {
        if chunks.is_empty() {
            return [0u8; 32];
        }
        let split = num_leaves.min(chunks.len());
        let rest = go(&chunks[split..], num_leaves * 4);
        let first = merkleize(&chunks[..split], Some(num_leaves));
        hash_pair(&rest, &first)
    }
    go(chunks, 1)
}

pub fn mix_in_length(root: &Hash256, len: u64) -> Hash256 {
    hash_pair(root, &length_chunk(len))
}

pub fn mix_in_selector(root: &Hash256, selector: u8) -> Hash256 {
    hash_pair(root, &length_chunk(u64::from(selector)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(b: u8) -> Hash256 {
        [b; 32]
    }

    // Reference implementation: materialize every padding chunk.
    fn naive(chunks: &[Hash256], limit: Option<usize>) -> Hash256 {
        let width = next_pow_of_two(limit.unwrap_or(chunks.len()));
        let mut layer = chunks.to_vec();
        layer.resize(width, [0u8; 32]);
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        }
        layer[0]
    }

    #[test]
    fn matches_naive_padding() {
        for n in 0..20u8 {
            let chunks: Vec<_> = (0..n).map(chunk).collect();
            assert_eq!(merkleize(&chunks, None), naive(&chunks, None), "n={n}");
            for limit in [n as usize, 32, 100] {
                if (n as usize) <= limit {
                    assert_eq!(merkleize(&chunks, Some(limit)), naive(&chunks, Some(limit)));
                }
            }
        }
    }

    #[test]
    fn single_chunk_is_root() {
        assert_eq!(merkleize(&[chunk(7)], None), chunk(7));
        assert_eq!(merkleize(&[], None), [0u8; 32]);
        assert_eq!(merkleize(&[], Some(4)), zero_hash(2));
    }

    #[test]
    #[should_panic(expected = "exceed limit")]
    fn over_limit_panics() {
        merkleize(&[chunk(1), chunk(2)], Some(1));
    }

    #[test]
    fn progressive_layout() {
        let z = [0u8; 32];
        let c: Vec<_> = (1..=6).map(chunk).collect();
        assert_eq!(merkleize_progressive(&[]), z);
        assert_eq!(merkleize_progressive(&c[..1]), hash_pair(&z, &c[0]));

        let second_level = merkleize(&c[1..5], Some(4));
        let five = hash_pair(&hash_pair(&z, &second_level), &c[0]);
        assert_eq!(merkleize_progressive(&c[..5]), five);

        let third_level = hash_pair(&z, &merkleize(&c[5..], Some(16)));
        let six = hash_pair(&hash_pair(&third_level, &second_level), &c[0]);
        assert_eq!(merkleize_progressive(&c), six);
    }

    #[test]
    fn pack_pads() {
        assert!(pack(&[]).is_empty());
        let p = pack(&[1u8; 33]);
        assert_eq!(p.len(), 2);
        assert_eq!(p[1][0], 1);
        assert_eq!(p[1][1..], [0u8; 31]);
    }
}
