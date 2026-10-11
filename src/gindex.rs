use crate::prelude::*;
use core::fmt;

/// Position of a node in a binary Merkle tree: the root is 1 and the
/// children of `i` are `2i` and `2i + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GeneralizedIndex(u64);

impl GeneralizedIndex {
    pub const ROOT: Self = Self(1);

    pub const fn new(index: u64) -> Option<Self> {
        if index == 0 { None } else { Some(Self(index)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Number of edges between this node and the root.
    pub const fn depth(self) -> u32 {
        63 - self.0.leading_zeros()
    }

    /// Position within its level, counted from the left (`get_subtree_index`).
    pub fn subtree_index(self) -> u64 {
        self.0 - (1 << self.depth())
    }

    pub fn bit(self, position: u32) -> bool {
        position < 64 && self.0 & (1 << position) != 0
    }

    pub fn sibling(self) -> Self {
        Self(self.0 ^ 1)
    }

    pub fn parent(self) -> Self {
        Self((self.0 / 2).max(1))
    }

    pub fn child(self, right: bool) -> Option<Self> {
        self.0.checked_mul(2)?.checked_add(u64::from(right)).map(Self)
    }

    pub fn is_root(self) -> bool {
        self.0 == 1
    }

    /// Whether `self` lies in the subtree rooted at `ancestor` (inclusive).
    pub fn is_descendant_of(self, ancestor: Self) -> bool {
        let shift = self.depth().checked_sub(ancestor.depth());
        shift.is_some_and(|s| self.0 >> s == ancestor.0)
    }

    /// Index of `self` within the subtree rooted at `inner`, i.e. the
    /// generalized index `g` such that `concat(inner, g) == self`.
    pub fn relative_to(self, inner: Self) -> Option<Self> {
        let shift = self.depth().checked_sub(inner.depth())?;
        (self.0 >> shift == inner.0).then(|| Self((1 << shift) | (self.0 & ((1u64 << shift) - 1))))
    }

    /// Composes paths: the node at `inner` inside the subtree at `self`.
    pub fn concat(self, inner: Self) -> Option<Self> {
        let d = inner.depth();
        let base = self.0.checked_mul(1u64.checked_shl(d)?)?;
        base.checked_add(inner.0 - (1 << d)).map(Self)
    }

    /// Siblings of the nodes on the path to the root, leaf level first.
    pub fn branch_indices(self) -> Vec<Self> {
        let mut out = Vec::with_capacity(self.depth() as usize);
        let mut g = self;
        while !g.is_root() {
            out.push(g.sibling());
            g = g.parent();
        }
        out
    }

    /// Nodes on the path to the root (excluding the root), leaf first.
    pub fn path_indices(self) -> Vec<Self> {
        let mut out = Vec::with_capacity(self.depth() as usize);
        let mut g = self;
        while !g.is_root() {
            out.push(g);
            g = g.parent();
        }
        out
    }
}

impl fmt::Display for GeneralizedIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Generalized indices of every extra node needed to prove `indices`,
/// sorted in decreasing order (spec: `get_helper_indices`).
pub fn helper_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
    let mut helpers = alloc::collections::BTreeSet::new();
    let mut paths = alloc::collections::BTreeSet::new();
    for &index in indices {
        helpers.extend(index.branch_indices());
        paths.extend(index.path_indices());
    }
    let mut out: Vec<_> = helpers.difference(&paths).copied().collect();
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(i: u64) -> GeneralizedIndex {
        GeneralizedIndex::new(i).unwrap()
    }

    #[test]
    fn navigation() {
        assert_eq!(GeneralizedIndex::new(0), None);
        assert_eq!(g(1).depth(), 0);
        assert_eq!(g(8).depth(), 3);
        assert_eq!(g(15).depth(), 3);
        assert_eq!(g(9).sibling(), g(8));
        assert_eq!(g(9).subtree_index(), 1);
        assert_eq!(g(1).subtree_index(), 0);
        assert_eq!(g(9).parent(), g(4));
        assert_eq!(g(4).child(true), Some(g(9)));
        assert_eq!(g(u64::MAX).child(false), None);
        assert!(g(9).bit(0) && !g(9).bit(1) && g(9).bit(3) && !g(9).bit(64));
    }

    #[test]
    fn concat_and_relative() {
        // Field 3 of an 8-field container (gindex 11) then element 2 of a
        // 4-leaf vector inside it (gindex 6).
        assert_eq!(g(11).concat(g(6)), Some(g(46)));
        assert_eq!(g(46).relative_to(g(11)), Some(g(6)));
        assert_eq!(g(46).relative_to(g(10)), None);
        assert_eq!(g(1).concat(g(46)), Some(g(46)));
        assert_eq!(g(46).concat(g(1)), Some(g(46)));
        assert!(g(46).is_descendant_of(g(5)));
        assert!(!g(46).is_descendant_of(g(4)));
        assert_eq!(g(1 << 62).concat(g(4)), None);
    }

    #[test]
    fn branch_and_path() {
        assert_eq!(g(9).branch_indices(), vec![g(8), g(5), g(3)]);
        assert_eq!(g(9).path_indices(), vec![g(9), g(4), g(2)]);
        assert!(g(1).branch_indices().is_empty());
    }

    #[test]
    fn helper_indices_spec_example() {
        // Spec example: proving leaves 8, 9 and 14 of an 8-leaf tree needs
        // nodes 15, 6 and 5.
        assert_eq!(helper_indices(&[g(8), g(9), g(14)]), vec![g(15), g(6), g(5)]);
        // A single index degenerates to its branch.
        assert_eq!(helper_indices(&[g(9)]), g(9).branch_indices());
    }
}
