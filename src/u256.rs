use crate::prelude::*;
use core::fmt;

/// 256-bit unsigned integer stored as 32 little-endian bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0; 32]);
    pub const MAX: Self = Self([0xff; 32]);

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Parses a decimal string; returns `None` on invalid digits or overflow.
    pub fn from_dec_str(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        let mut limbs = [0u64; 4];
        for c in s.bytes() {
            let digit = u64::from(c.checked_sub(b'0').filter(|d| *d < 10)?);
            let mut carry = u128::from(digit);
            for limb in &mut limbs {
                let v = u128::from(*limb) * 10 + carry;
                *limb = v as u64;
                carry = v >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        let mut out = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        Some(Self(out))
    }
}

impl From<u64> for U256 {
    fn from(v: u64) -> Self {
        Self::from(u128::from(v))
    }
}

impl From<u128> for U256 {
    fn from(v: u128) -> Self {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&v.to_le_bytes());
        Self(out)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut limbs: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(self.0[i * 8..(i + 1) * 8].try_into().expect("8 bytes"))
        });
        if limbs == [0; 4] {
            return f.write_str("0");
        }
        let mut digits = Vec::new();
        while limbs != [0; 4] {
            let mut rem = 0u128;
            for limb in limbs.iter_mut().rev() {
                let v = (rem << 64) | u128::from(*limb);
                *limb = (v / 10) as u64;
                rem = v % 10;
            }
            digits.push(b'0' + rem as u8);
        }
        digits.reverse();
        f.write_str(core::str::from_utf8(&digits).expect("ascii digits"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_round_trip() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::MAX.to_string(), max);
        assert_eq!(U256::from_dec_str(max), Some(U256::MAX));
        assert_eq!(U256::ZERO.to_string(), "0");
        assert_eq!(U256::from(u128::MAX).to_string(), u128::MAX.to_string());
        assert_eq!(
            U256::from_dec_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            ),
            None
        );
        assert_eq!(U256::from_dec_str("12a"), None);
        assert_eq!(U256::from_dec_str(""), None);
    }
}
