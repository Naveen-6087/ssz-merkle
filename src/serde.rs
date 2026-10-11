use serde::de::{Error as _, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::gindex::GeneralizedIndex;
use crate::hash::Hash256;
use crate::hex;
use crate::prelude::*;

impl Serialize for GeneralizedIndex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for GeneralizedIndex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u64::deserialize(d)?;
        GeneralizedIndex::new(v).ok_or_else(|| D::Error::custom("generalized index must be non-zero"))
    }
}

/// `0x`-prefixed hex for a single 32-byte node.
pub(crate) mod hash {
    use super::*;

    pub fn serialize<S: Serializer>(h: &Hash256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash256, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode_hash(&s).map_err(D::Error::custom)
    }
}

/// A list of `0x`-prefixed 32-byte nodes.
pub(crate) mod hashes {
    use super::*;

    pub fn serialize<S: Serializer>(hs: &[Hash256], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(hs.len()))?;
        for h in hs {
            seq.serialize_element(&hex::encode(h))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Hash256>, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Vec<Hash256>;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a list of 32-byte hex strings")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64));
                while let Some(s) = seq.next_element::<String>()? {
                    out.push(hex::decode_hash(&s).map_err(A::Error::custom)?);
                }
                Ok(out)
            }
        }

        d.deserialize_seq(V)
    }
}
