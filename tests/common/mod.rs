#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ssz_merkle::{Ssz, Value};
use yaml_rust2::{Yaml, YamlLoader};

pub fn spec_tests_dir() -> PathBuf {
    std::env::var_os("SSZ_SPEC_TESTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/consensus-spec-tests"))
}

/// Case directories of a suite, or `None` (or a panic when
/// `SSZ_REQUIRE_SPEC_TESTS=1`) if it has not been downloaded.
pub fn cases(suite: &Path) -> Option<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = match std::fs::read_dir(suite) {
        Ok(entries) => entries.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_dir()).collect(),
        Err(_) => Vec::new(),
    };
    if out.is_empty() {
        let msg = format!("missing reference tests in {} (run scripts/fetch-spec-tests.sh)", suite.display());
        if std::env::var("SSZ_REQUIRE_SPEC_TESTS").as_deref() == Ok("1") {
            panic!("{msg}");
        }
        eprintln!("skipping: {msg}");
        return None;
    }
    out.sort();
    Some(out)
}

pub fn read_snappy(path: &Path) -> Vec<u8> {
    let compressed = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::raw::Decoder::new().decompress_vec(&compressed).expect("valid snappy block")
}

pub fn read_yaml(path: &Path) -> Yaml {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    YamlLoader::load_from_str(&text).expect("valid yaml").into_iter().next().unwrap_or(Yaml::Null)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn parse_hex32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

/// Compares a decoded value with its YAML form from the test vectors.
pub fn compare(value: &Value, yaml: &Yaml, at: &str) -> Result<(), String> {
    let mismatch = || Err(format!("{at}: {value:?} does not match {yaml:?}"));
    match (value, yaml) {
        (Value::Uint(n), Yaml::Integer(i)) if *n == i.to_string() => Ok(()),
        (Value::Uint(n), Yaml::String(s) | Yaml::Real(s)) if n == s => Ok(()),
        (Value::Bool(b), Yaml::Boolean(y)) if b == y => Ok(()),
        (Value::Bytes(b), Yaml::String(s)) if hex(b) == *s => Ok(()),
        (Value::List(items), Yaml::Array(ys)) if items.len() == ys.len() => {
            items.iter().zip(ys).enumerate().try_for_each(|(i, (v, y))| compare(v, y, &format!("{at}[{i}]")))
        }
        (Value::Container(fields), Yaml::Hash(map)) if fields.len() == map.len() => {
            fields.iter().zip(map).try_for_each(|((name, v), (k, y))| {
                if k.as_str() != Some(name) {
                    return Err(format!("{at}: field {name} vs key {k:?}"));
                }
                compare(v, y, &format!("{at}.{name}"))
            })
        }
        _ => mismatch(),
    }
}

/// Runs one `valid` case: decode, re-encode, hash-tree-root (directly and
/// via the explicit tree) and value comparison.
pub fn check_valid<T: Ssz>(dir: &Path) -> Result<(), String> {
    let serialized = read_snappy(&dir.join("serialized.ssz_snappy"));
    let value = T::from_ssz(&serialized).map_err(|e| format!("decode failed: {e}"))?;
    if value.to_ssz() != serialized {
        return Err("re-encoding differs".into());
    }
    if value.encoded_len() != serialized.len() {
        return Err("encoded_len differs".into());
    }
    let meta = read_yaml(&dir.join("meta.yaml"));
    let root = meta["root"].as_str().ok_or("meta.yaml has no root")?;
    if hex(&value.hash_tree_root()) != root {
        return Err(format!("root {} != {root}", hex(&value.hash_tree_root())));
    }
    if hex(&value.tree().root()) != root {
        return Err("tree root differs from hash_tree_root".into());
    }
    compare(&value.to_value(), &read_yaml(&dir.join("value.yaml")), "value")
}

pub fn check_invalid<T: Ssz>(dir: &Path) -> Result<(), String> {
    let serialized = read_snappy(&dir.join("serialized.ssz_snappy"));
    match T::from_ssz(&serialized) {
        Ok(_) => Err("invalid input decoded successfully".into()),
        Err(_) => Ok(()),
    }
}

pub fn check<T: Ssz>(dir: &Path, valid: bool) -> Result<(), String> {
    if valid { check_valid::<T>(dir) } else { check_invalid::<T>(dir) }
}
