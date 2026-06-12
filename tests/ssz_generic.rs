#![allow(non_snake_case)]

mod common;

use std::path::Path;

use common::{cases, check, spec_tests_dir};
use ssz_merkle::{
    Bitlist, Bitvector, ByteList, List, ProgressiveBitlist, ProgressiveList, Ssz, U256, Vector,
    ssz_container, ssz_progressive_container,
};

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SingleFieldTestStruct { pub A: u8 }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SmallTestStruct { pub A: u16, pub B: u16 }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct FixedTestStruct { pub A: u8, pub B: u64, pub C: u32 }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct VarTestStruct { pub A: u16, pub B: List<u16, 1024>, pub C: u8 }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ComplexTestStruct {
        pub A: u16,
        pub B: List<u16, 128>,
        pub C: u8,
        pub D: ByteList<256>,
        pub E: VarTestStruct,
        pub F: Vector<FixedTestStruct, 4>,
        pub G: Vector<VarTestStruct, 2>,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveTestStruct {
        pub A: ProgressiveList<u8>,
        pub B: ProgressiveList<u64>,
        pub C: ProgressiveList<SmallTestStruct>,
        pub D: ProgressiveList<ProgressiveList<VarTestStruct>>,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BitsStruct {
        pub A: Bitlist<5>,
        pub B: Bitvector<2>,
        pub C: Bitvector<1>,
        pub D: Bitlist<6>,
        pub E: Bitvector<8>,
    }
}

ssz_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveBitsStruct {
        pub A: Bitvector<256>,
        pub B: Bitlist<256>,
        pub C: ProgressiveBitlist,
        pub D: Bitvector<257>,
        pub E: Bitlist<257>,
        pub F: ProgressiveBitlist,
        pub G: Bitvector<1280>,
        pub H: Bitlist<1280>,
        pub I: ProgressiveBitlist,
        pub J: Bitvector<1281>,
        pub K: Bitlist<1281>,
        pub L: ProgressiveBitlist,
    }
}

ssz_progressive_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveSingleFieldContainerTestStruct: [1] { pub A: u8 }
}

ssz_progressive_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveSingleListContainerTestStruct: [0, 0, 0, 0, 1] { pub C: ProgressiveBitlist }
}

ssz_progressive_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveVarTestStruct: [1, 0, 1, 0, 1] {
        pub A: u8,
        pub B: List<u16, 123>,
        pub C: ProgressiveBitlist,
    }
}

ssz_progressive_container! {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ProgressiveComplexTestStruct:
        [1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
    {
        pub A: u8,
        pub B: List<u16, 123>,
        pub C: ProgressiveBitlist,
        pub D: ProgressiveList<u64>,
        pub E: ProgressiveList<SmallTestStruct>,
        pub F: ProgressiveList<ProgressiveList<VarTestStruct>>,
        pub G: List<ProgressiveSingleFieldContainerTestStruct, 10>,
        pub H: ProgressiveList<ProgressiveVarTestStruct>,
    }
}

type Dispatch = fn(&str, &Path, bool) -> Result<(), String>;

fn run_suite(suite: &str, dispatch: Dispatch) {
    let base = spec_tests_dir().join("ssz_generic").join(suite);
    let mut ran = 0;
    let mut failures = Vec::new();
    for (kind, valid) in [("valid", true), ("invalid", false)] {
        let Some(dirs) = cases(&base.join(kind)) else { return };
        for dir in dirs {
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            let result = std::panic::catch_unwind(|| dispatch(&name, &dir, valid))
                .unwrap_or_else(|_| Err("panicked".into()));
            if let Err(e) = result {
                failures.push(format!("{kind}/{name}: {e}"));
            }
            ran += 1;
        }
    }
    eprintln!("{suite}: {ran} cases, {} failures", failures.len());
    assert!(failures.is_empty(), "{} of {ran} cases failed:\n{}", failures.len(), failures.join("\n"));
}

/// The number following `prefix` in a case name, e.g. 16 in `vec_uint8_16_max`.
fn number_after(name: &str, prefix: &str) -> Option<usize> {
    name.strip_prefix(prefix)?.split('_').next()?.parse().ok()
}

macro_rules! by_length {
    ($n:expr, [$($len:literal),+], $make:ident) => {
        match $n {
            $( $len => $make!($len), )+
            n => Err(format!("no type instantiated for length {n}")),
        }
    };
}

fn vector_of<T: Ssz>(len: usize, dir: &Path, valid: bool) -> Result<(), String> {
    macro_rules! vector {
        ($l:literal) => {
            check::<Vector<T, $l>>(dir, valid)
        };
    }
    by_length!(len, [0, 1, 2, 3, 4, 5, 8, 16, 31, 512, 513], vector)
}

macro_rules! by_elem {
    ($name:expr, $f:ident, $($args:expr),*) => {
        match $name {
            "bool" => $f::<bool>($($args),*),
            "uint8" => $f::<u8>($($args),*),
            "uint16" => $f::<u16>($($args),*),
            "uint32" => $f::<u32>($($args),*),
            "uint64" => $f::<u64>($($args),*),
            "uint128" => $f::<u128>($($args),*),
            "uint256" => $f::<U256>($($args),*),
            other => Err(format!("unknown element type {other}")),
        }
    };
}

fn progressive_list_of<T: Ssz>(dir: &Path, valid: bool) -> Result<(), String> {
    check::<ProgressiveList<T>>(dir, valid)
}

#[test]
fn uints() {
    run_suite("uints", |name, dir, valid| match number_after(name, "uint_") {
        Some(8) => check::<u8>(dir, valid),
        Some(16) => check::<u16>(dir, valid),
        Some(32) => check::<u32>(dir, valid),
        Some(64) => check::<u64>(dir, valid),
        Some(128) => check::<u128>(dir, valid),
        Some(256) => check::<U256>(dir, valid),
        _ => Err("unknown uint size".into()),
    });
}

#[test]
fn boolean() {
    run_suite("boolean", |_, dir, valid| check::<bool>(dir, valid));
}

#[test]
fn bitvector() {
    run_suite("bitvector", |name, dir, valid| {
        macro_rules! bitvector {
            ($l:literal) => {
                check::<Bitvector<$l>>(dir, valid)
            };
        }
        let n = number_after(name, "bitvec_").ok_or("bad name")?;
        by_length!(n, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 511, 512, 513], bitvector)
    });
}

#[test]
fn bitlist() {
    run_suite("bitlist", |name, dir, valid| {
        macro_rules! bitlist {
            ($l:literal) => {
                check::<Bitlist<$l>>(dir, valid)
            };
        }
        match number_after(name, "bitlist_") {
            Some(n) => {
                by_length!(n, [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 511, 512, 513], bitlist)
            }
            // Undelimited inputs are invalid for every limit.
            None => check::<Bitlist<4096>>(dir, valid),
        }
    });
}

#[test]
fn basic_vector() {
    run_suite("basic_vector", |name, dir, valid| {
        let rest = name.strip_prefix("vec_").ok_or("bad name")?;
        let (elem, tail) = rest.split_once('_').ok_or("bad name")?;
        let len: usize = tail.split('_').next().and_then(|n| n.parse().ok()).ok_or("bad length")?;
        by_elem!(elem, vector_of, len, dir, valid)
    });
}

#[test]
fn basic_progressive_list() {
    run_suite("basic_progressive_list", |name, dir, valid| {
        let rest = name.strip_prefix("proglist_").ok_or("bad name")?;
        let elem = rest.split('_').next().ok_or("bad name")?;
        by_elem!(elem, progressive_list_of, dir, valid)
    });
}

#[test]
fn progressive_bitlist() {
    run_suite("progressive_bitlist", |_, dir, valid| check::<ProgressiveBitlist>(dir, valid));
}

#[test]
fn containers() {
    run_suite("containers", |name, dir, valid| {
        let ty = name.split('_').next().unwrap_or_default();
        match ty {
            "SingleFieldTestStruct" => check::<SingleFieldTestStruct>(dir, valid),
            "SmallTestStruct" => check::<SmallTestStruct>(dir, valid),
            "FixedTestStruct" => check::<FixedTestStruct>(dir, valid),
            "VarTestStruct" => check::<VarTestStruct>(dir, valid),
            "ComplexTestStruct" => check::<ComplexTestStruct>(dir, valid),
            "ProgressiveTestStruct" => check::<ProgressiveTestStruct>(dir, valid),
            "BitsStruct" => check::<BitsStruct>(dir, valid),
            "ProgressiveBitsStruct" => check::<ProgressiveBitsStruct>(dir, valid),
            other => Err(format!("unknown container {other}")),
        }
    });
}

#[test]
fn progressive_containers() {
    run_suite("progressive_containers", |name, dir, valid| {
        let ty = name.split('_').next().unwrap_or_default();
        match ty {
            "ProgressiveSingleFieldContainerTestStruct" => {
                check::<ProgressiveSingleFieldContainerTestStruct>(dir, valid)
            }
            "ProgressiveSingleListContainerTestStruct" => {
                check::<ProgressiveSingleListContainerTestStruct>(dir, valid)
            }
            "ProgressiveVarTestStruct" => check::<ProgressiveVarTestStruct>(dir, valid),
            "ProgressiveComplexTestStruct" => check::<ProgressiveComplexTestStruct>(dir, valid),
            other => Err(format!("unknown container {other}")),
        }
    });
}
