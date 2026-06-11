use std::fmt;

use crate::gindex::GeneralizedIndex;

/// Static shape of an SSZ type, used to turn paths into generalized indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Schema {
    Basic { size: usize },
    Vector { elem: Box<Schema>, len: usize },
    List { elem: Box<Schema>, limit: usize },
    ProgressiveList { elem: Box<Schema> },
    Bitvector { len: usize },
    Bitlist { limit: usize },
    ProgressiveBitlist,
    Container { name: &'static str, fields: Vec<(&'static str, Schema)> },
    ProgressiveContainer { name: &'static str, active_fields: Vec<bool>, fields: Vec<(&'static str, Schema)> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathElem {
    Field(String),
    Index(u64),
    Length,
}

impl PathElem {
    /// `"__len__"` is the length, all-digit strings are indices, anything
    /// else is a field name.
    pub fn parse(s: &str) -> Self {
        if s == "__len__" {
            Self::Length
        } else if let Ok(i) = s.parse() {
            Self::Index(i)
        } else {
            Self::Field(s.to_owned())
        }
    }
}

impl fmt::Display for PathElem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(name) => f.write_str(name),
            Self::Index(i) => write!(f, "{i}"),
            Self::Length => f.write_str("__len__"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    IntoBasic(PathElem),
    NoSuchField { container: &'static str, field: String },
    IndexOutOfRange { index: u64, bound: usize },
    NotIndexable(PathElem),
    NoLength,
    Overflow,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntoBasic(p) => write!(f, "cannot descend into a basic value with `{p}`"),
            Self::NoSuchField { container, field } => write!(f, "{container} has no field `{field}`"),
            Self::IndexOutOfRange { index, bound } => {
                write!(f, "index {index} is out of range (bound {bound})")
            }
            Self::NotIndexable(p) => write!(f, "`{p}` does not apply to this type"),
            Self::NoLength => write!(f, "`__len__` only applies to lists"),
            Self::Overflow => write!(f, "generalized index does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for PathError {}

impl fmt::Display for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Schema::Basic { size: 0 } => f.write_str("bit"),
            Schema::Basic { size } => write!(f, "uint{}", size * 8),
            Schema::Vector { elem, len } => write!(f, "Vector[{elem}, {len}]"),
            Schema::List { elem, limit } => write!(f, "List[{elem}, {limit}]"),
            Schema::ProgressiveList { elem } => write!(f, "ProgressiveList[{elem}]"),
            Schema::Bitvector { len } => write!(f, "Bitvector[{len}]"),
            Schema::Bitlist { limit } => write!(f, "Bitlist[{limit}]"),
            Schema::ProgressiveBitlist => f.write_str("ProgressiveBitlist"),
            Schema::Container { name, .. } | Schema::ProgressiveContainer { name, .. } => f.write_str(name),
        }
    }
}

const UINT64: Schema = Schema::Basic { size: 8 };
const BIT: Schema = Schema::Basic { size: 0 };

impl Schema {
    pub fn is_basic(&self) -> bool {
        matches!(self, Schema::Basic { .. })
    }

    /// Bytes per element when packed: the basic size, or 32 for a root.
    pub fn item_length(&self) -> usize {
        match self {
            Schema::Basic { size } => *size,
            _ => 32,
        }
    }

    pub fn chunk_count(&self) -> usize {
        match self {
            Schema::Basic { .. } => 1,
            Schema::Vector { elem, len: n } | Schema::List { elem, limit: n } => {
                ((*n as u128 * elem.item_length() as u128).div_ceil(32)) as usize
            }
            Schema::Bitvector { len: n } | Schema::Bitlist { limit: n } => n.div_ceil(256),
            Schema::Container { fields, .. } => fields.len(),
            Schema::ProgressiveList { .. }
            | Schema::ProgressiveBitlist
            | Schema::ProgressiveContainer { .. } => 0,
        }
    }

    pub fn generalized_index(&self, path: &[PathElem]) -> Result<GeneralizedIndex, PathError> {
        self.resolve(path).map(|(g, _)| g)
    }

    /// Generalized index of `path` and the schema of the value it reaches
    /// (spec: `get_generalized_index`, extended to bitfields and EIP-7916
    /// progressive lists).
    pub fn resolve(&self, path: &[PathElem]) -> Result<(GeneralizedIndex, &Schema), PathError> {
        let mut root: u64 = 1;
        let mut typ = self;
        for p in path {
            let (next, elem) = match (typ, p) {
                (Schema::Basic { .. }, _) => return Err(PathError::IntoBasic(p.clone())),
                (
                    Schema::List { .. }
                    | Schema::Bitlist { .. }
                    | Schema::ProgressiveList { .. }
                    | Schema::ProgressiveBitlist,
                    PathElem::Length,
                ) => (mul_add(root, 2, 1)?, &UINT64),
                (_, PathElem::Length) => return Err(PathError::NoLength),
                (Schema::Container { name, fields }, PathElem::Field(field)) => {
                    let pos = fields
                        .iter()
                        .position(|(n, _)| n == field)
                        .ok_or_else(|| PathError::NoSuchField { container: name, field: field.clone() })?;
                    (fixed_leaf(root, fields.len(), pos as u64)?, &fields[pos].1)
                }
                (Schema::ProgressiveContainer { name, active_fields, fields }, PathElem::Field(field)) => {
                    let pos = fields
                        .iter()
                        .position(|(n, _)| n == field)
                        .ok_or_else(|| PathError::NoSuchField { container: name, field: field.clone() })?;
                    let slot = active_fields
                        .iter()
                        .enumerate()
                        .filter(|(_, active)| **active)
                        .nth(pos)
                        .map(|(slot, _)| slot as u64)
                        .expect("one active slot per field");
                    let data = root.checked_mul(2).ok_or(PathError::Overflow)?;
                    (progressive_leaf(data, slot)?, &fields[pos].1)
                }
                (Schema::Vector { elem, len }, PathElem::Index(i)) => {
                    bounded(*i, *len)?;
                    (fixed_leaf(root, typ.chunk_count(), chunk_of(*i, elem))?, &**elem)
                }
                (Schema::List { elem, limit }, PathElem::Index(i)) => {
                    bounded(*i, *limit)?;
                    let data = root.checked_mul(2).ok_or(PathError::Overflow)?;
                    (fixed_leaf(data, typ.chunk_count(), chunk_of(*i, elem))?, &**elem)
                }
                (Schema::Bitvector { len }, PathElem::Index(i)) => {
                    bounded(*i, *len)?;
                    (fixed_leaf(root, typ.chunk_count(), i / 256)?, &BIT)
                }
                (Schema::Bitlist { limit }, PathElem::Index(i)) => {
                    bounded(*i, *limit)?;
                    let data = root.checked_mul(2).ok_or(PathError::Overflow)?;
                    (fixed_leaf(data, typ.chunk_count(), i / 256)?, &BIT)
                }
                (Schema::ProgressiveList { elem }, PathElem::Index(i)) => {
                    let data = root.checked_mul(2).ok_or(PathError::Overflow)?;
                    (progressive_leaf(data, chunk_of(*i, elem))?, &**elem)
                }
                (Schema::ProgressiveBitlist, PathElem::Index(i)) => {
                    let data = root.checked_mul(2).ok_or(PathError::Overflow)?;
                    (progressive_leaf(data, i / 256)?, &BIT)
                }
                _ => return Err(PathError::NotIndexable(p.clone())),
            };
            root = next;
            typ = elem;
        }
        Ok((GeneralizedIndex::new(root).expect("non-zero"), typ))
    }
}

fn bounded(index: u64, bound: usize) -> Result<(), PathError> {
    if index < bound as u64 { Ok(()) } else { Err(PathError::IndexOutOfRange { index, bound }) }
}

fn chunk_of(index: u64, elem: &Schema) -> u64 {
    (u128::from(index) * elem.item_length() as u128 / 32) as u64
}

fn mul_add(a: u64, b: u64, c: u64) -> Result<u64, PathError> {
    a.checked_mul(b).and_then(|v| v.checked_add(c)).ok_or(PathError::Overflow)
}

fn fixed_leaf(subtree_root: u64, chunks: usize, pos: u64) -> Result<u64, PathError> {
    let width = (chunks.max(1) as u64).checked_next_power_of_two().ok_or(PathError::Overflow)?;
    mul_add(subtree_root, width, pos)
}

/// Leaf `pos` of a progressive subtree: level k (k = 0, 1, ...) holds 4^k
/// leaves in the right child, and the remaining levels hang off the left.
fn progressive_leaf(data_root: u64, mut pos: u64) -> Result<u64, PathError> {
    let mut node = data_root;
    let mut width: u64 = 1;
    loop {
        if pos < width {
            let first = mul_add(node, 2, 1)?;
            return mul_add(first, width, pos);
        }
        pos -= width;
        node = node.checked_mul(2).ok_or(PathError::Overflow)?;
        width = width.checked_mul(4).ok_or(PathError::Overflow)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &[&str]) -> Vec<PathElem> {
        p.iter().map(|s| PathElem::parse(s)).collect()
    }

    fn container() -> Schema {
        // {x: Bytes32, y: List[uint64, 32]} from the merkle-proofs spec.
        Schema::Container {
            name: "Foo",
            fields: vec![
                ("x", Schema::Vector { elem: Box::new(Schema::Basic { size: 1 }), len: 32 }),
                ("y", Schema::List { elem: Box::new(UINT64), limit: 32 }),
            ],
        }
    }

    #[test]
    fn spec_style_paths() {
        let s = container();
        let gi = |p: &[&str]| s.generalized_index(&path(p)).map(GeneralizedIndex::get);
        assert_eq!(gi(&[]), Ok(1));
        assert_eq!(gi(&["x"]), Ok(2));
        assert_eq!(gi(&["y"]), Ok(3));
        assert_eq!(gi(&["y", "__len__"]), Ok(7));
        // y data root is 6; 32 uint64s pack into 8 chunks; element 5 is in chunk 1.
        assert_eq!(gi(&["y", "5"]), Ok(6 * 8 + 1));
        assert_eq!(gi(&["x", "31"]), Ok(2));
    }

    #[test]
    fn path_errors() {
        let s = container();
        assert!(matches!(s.generalized_index(&path(&["z"])), Err(PathError::NoSuchField { .. })));
        assert!(matches!(s.generalized_index(&path(&["y", "32"])), Err(PathError::IndexOutOfRange { .. })));
        assert_eq!(s.generalized_index(&path(&["x", "__len__"])), Err(PathError::NoLength));
        assert!(matches!(s.generalized_index(&path(&["y", "1", "0"])), Err(PathError::IntoBasic(_))));
        assert!(matches!(s.generalized_index(&path(&["0"])), Err(PathError::NotIndexable(_))));
        let inner = Schema::List { elem: Box::new(Schema::Basic { size: 32 }), limit: 1 << 40 };
        let deep = Schema::List { elem: Box::new(inner), limit: 1 << 40 };
        assert_eq!(deep.generalized_index(&path(&["0", "0"])), Err(PathError::Overflow));
    }

    #[test]
    fn progressive_positions() {
        // data root 2; level 0 leaf 0 -> (2*2+1)*1+0 = 5; level 1 leaves 1..4
        // under node 4 -> (4*2+1)*4 + (i-1).
        let s = Schema::ProgressiveList { elem: Box::new(Schema::Basic { size: 32 }) };
        let gi = |i: u64| s.generalized_index(&[PathElem::Index(i)]).unwrap().get();
        assert_eq!(gi(0), 5);
        assert_eq!(gi(1), 36);
        assert_eq!(gi(4), 39);
        assert_eq!(gi(5), (8 * 2 + 1) * 16);
    }
}
