use crate::hash::{Hash256, hash_pair};
use crate::merkle::{merkleize_progressive, pack};
use crate::prelude::*;
use crate::tree::Tree;

/// Declares a struct and implements [`Ssz`](crate::Ssz) for it as an SSZ
/// container whose fields are serialized and merkleized in declaration order.
///
/// ```
/// use ssz_merkle::{List, Ssz, ssz_container};
///
/// ssz_container! {
///     #[derive(Clone, Debug, Default, PartialEq, Eq)]
///     pub struct Checkpoint {
///         pub epoch: u64,
///         pub roots: List<u64, 8>,
///     }
/// }
///
/// let c = Checkpoint { epoch: 3, roots: List::new(vec![1, 2]).unwrap() };
/// assert_eq!(Checkpoint::from_ssz(&c.to_ssz()).unwrap(), c);
/// ```
#[macro_export]
macro_rules! ssz_container {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fmeta:meta])* $fvis:vis $field:ident : $ty:ty ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $(#[$fmeta])* $fvis $field: $ty ),+
        }

        impl $crate::Ssz for $name {
            $crate::__ssz_codec_methods!($( $field: $ty ),+);

            fn hash_tree_root(&self) -> $crate::Hash256 {
                $crate::merkle::merkleize(&[ $( $crate::Ssz::hash_tree_root(&self.$field) ),+ ], None)
            }

            fn tree(&self) -> $crate::Tree {
                let subtrees = $crate::__private::vec![ $( $crate::Ssz::tree(&self.$field) ),+ ];
                let n = subtrees.len();
                $crate::Tree::from_subtrees(subtrees, n)
            }

            fn schema() -> $crate::Schema {
                $crate::Schema::Container {
                    name: stringify!($name),
                    fields: $crate::__private::vec![ $( (stringify!($field), <$ty as $crate::Ssz>::schema()) ),+ ],
                }
            }

            fn to_value(&self) -> $crate::Value {
                $crate::Value::Container($crate::__private::vec![ $( (stringify!($field), $crate::Ssz::to_value(&self.$field)) ),+ ])
            }
        }
    };
}

/// Declares an EIP-7495 progressive container. The bit list after the name
/// is `active_fields`: fields are merkleized at the positions of its ones.
///
/// ```
/// use ssz_merkle::{Ssz, ssz_progressive_container};
///
/// ssz_progressive_container! {
///     #[derive(Clone, Debug, Default, PartialEq, Eq)]
///     pub struct Square: [1, 0, 1] {
///         pub side: u16,
///         pub color: u8,
///     }
/// }
///
/// let s = Square { side: 4, color: 1 };
/// assert_eq!(Square::from_ssz(&s.to_ssz()).unwrap(), s);
/// ```
#[macro_export]
macro_rules! ssz_progressive_container {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident : [ $($bit:literal),+ $(,)? ] {
            $( $(#[$fmeta:meta])* $fvis:vis $field:ident : $ty:ty ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $(#[$fmeta])* $fvis $field: $ty ),+
        }

        impl $name {
            pub const ACTIVE_FIELDS: &'static [u8] = &[ $($bit),+ ];
            const _VALID: () = $crate::container::check_active_fields(
                Self::ACTIVE_FIELDS,
                [ $( stringify!($field) ),+ ].len(),
            );
        }

        impl $crate::Ssz for $name {
            $crate::__ssz_codec_methods!($( $field: $ty ),+);

            fn hash_tree_root(&self) -> $crate::Hash256 {
                let () = Self::_VALID;
                $crate::container::progressive_root(
                    Self::ACTIVE_FIELDS,
                    &[ $( $crate::Ssz::hash_tree_root(&self.$field) ),+ ],
                )
            }

            fn tree(&self) -> $crate::Tree {
                let () = Self::_VALID;
                $crate::container::progressive_tree(
                    Self::ACTIVE_FIELDS,
                    $crate::__private::vec![ $( $crate::Ssz::tree(&self.$field) ),+ ],
                )
            }

            fn schema() -> $crate::Schema {
                $crate::Schema::ProgressiveContainer {
                    name: stringify!($name),
                    active_fields: Self::ACTIVE_FIELDS.iter().map(|&b| b == 1).collect(),
                    fields: $crate::__private::vec![ $( (stringify!($field), <$ty as $crate::Ssz>::schema()) ),+ ],
                }
            }

            fn to_value(&self) -> $crate::Value {
                $crate::Value::Container($crate::__private::vec![ $( (stringify!($field), $crate::Ssz::to_value(&self.$field)) ),+ ])
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ssz_codec_methods {
    ($( $field:ident : $ty:ty ),+) => {
        fn fixed_size() -> Option<usize> {
            let mut total = 0usize;
            $( total += <$ty as $crate::Ssz>::fixed_size()?; )+
            Some(total)
        }

        fn encoded_len(&self) -> usize {
            0 $( + match <$ty as $crate::Ssz>::fixed_size() {
                Some(size) => size,
                None => $crate::codec::OFFSET_LEN + $crate::Ssz::encoded_len(&self.$field),
            } )+
        }

        fn encode_into(&self, out: &mut $crate::__private::Vec<u8>) {
            let fixed_len = 0 $( + <$ty as $crate::Ssz>::fixed_size().unwrap_or($crate::codec::OFFSET_LEN) )+;
            let mut variable = $crate::__private::Vec::new();
            $(
                if <$ty as $crate::Ssz>::fixed_size().is_some() {
                    $crate::Ssz::encode_into(&self.$field, out);
                } else {
                    $crate::codec::write_offset(out, fixed_len + variable.len());
                    $crate::Ssz::encode_into(&self.$field, &mut variable);
                }
            )+
            out.extend_from_slice(&variable);
        }

        fn from_ssz(bytes: &[u8]) -> Result<Self, $crate::DecodeError> {
            let sizes = [ $( <$ty as $crate::Ssz>::fixed_size() ),+ ];
            let mut parts = $crate::codec::split_container(bytes, &sizes)?.into_iter();
            Ok(Self {
                $( $field: <$ty as $crate::Ssz>::from_ssz(parts.next().expect("one part per field"))
                    .map_err(|e| e.in_field(stringify!($field)))?, )+
            })
        }
    };
}

#[doc(hidden)]
pub const fn check_active_fields(active: &[u8], fields: usize) {
    assert!(!active.is_empty() && active.len() <= 256, "active_fields must have 1..=256 entries");
    assert!(active[active.len() - 1] == 1, "active_fields must not end in 0");
    let mut ones = 0;
    let mut i = 0;
    while i < active.len() {
        assert!(active[i] <= 1, "active_fields entries must be 0 or 1");
        ones += active[i] as usize;
        i += 1;
    }
    assert!(ones == fields, "active_fields must have one 1 per field");
}

fn active_fields_chunk(active: &[u8]) -> Hash256 {
    let mut bytes = vec![0u8; active.len().div_ceil(8)];
    for (i, &bit) in active.iter().enumerate() {
        bytes[i / 8] |= bit << (i % 8);
    }
    pack(&bytes)[0]
}

fn spread<T>(active: &[u8], items: Vec<T>, zero: impl Fn() -> T) -> Vec<T> {
    let mut items = items.into_iter();
    active
        .iter()
        .map(|&bit| if bit == 1 { items.next().expect("one item per active field") } else { zero() })
        .collect()
}

#[doc(hidden)]
pub fn progressive_root(active: &[u8], roots: &[Hash256]) -> Hash256 {
    let chunks = spread(active, roots.to_vec(), || [0u8; 32]);
    hash_pair(&merkleize_progressive(&chunks), &active_fields_chunk(active))
}

#[doc(hidden)]
pub fn progressive_tree(active: &[u8], subtrees: Vec<Tree>) -> Tree {
    let leaves = spread(active, subtrees, || Tree::Zero(0));
    Tree::node(Tree::progressive(leaves), Tree::Leaf(active_fields_chunk(active)))
}
