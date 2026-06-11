use std::path::Path;
use std::process::ExitCode;

use ssz_merkle::deneb::{
    Attestation, BeaconBlock, BeaconBlockBody, BeaconBlockHeader, ExecutionPayload, SignedBeaconBlockHeader,
};
use ssz_merkle::{GeneralizedIndex, Hash256, PathElem, Ssz, calculate_merkle_root, prove};

const USAGE: &str = "usage: ssz-merkle <command> [args]

commands:
  types                              list the built-in Deneb types
  gindex <type> [path...]            generalized index of a path, e.g. blob_kzg_commitments 0
  root   <type> <file>               hash_tree_root of an SSZ object
  json   <type> <file>               the object in canonical JSON form
  prove  <type> <file> [path...]     Merkle proof for a path inside the object
  verify <root> <leaf> <gindex> [branch...]
                                     check a proof (branch nodes leaf level first)

<file> holds raw SSZ bytes; files ending in .ssz_snappy are snappy-decompressed.
Paths use field names, list indices and __len__. Exit status: 0 ok, 1 invalid
proof, 2 usage or input error.";

const TYPES: &[&str] = &[
    "BeaconBlock",
    "BeaconBlockBody",
    "BeaconBlockHeader",
    "SignedBeaconBlockHeader",
    "ExecutionPayload",
    "Attestation",
];

macro_rules! with_type {
    ($name:expr, $f:ident ( $($arg:expr),* )) => {
        match $name {
            "BeaconBlock" => $f::<BeaconBlock>($($arg),*),
            "BeaconBlockBody" => $f::<BeaconBlockBody>($($arg),*),
            "BeaconBlockHeader" => $f::<BeaconBlockHeader>($($arg),*),
            "SignedBeaconBlockHeader" => $f::<SignedBeaconBlockHeader>($($arg),*),
            "ExecutionPayload" => $f::<ExecutionPayload>($($arg),*),
            "Attestation" => $f::<Attestation>($($arg),*),
            other => Err(format!("unknown type `{other}` (see `ssz-merkle types`)")),
        }
    };
}

enum Failure {
    Usage(String),
    Invalid,
}

impl From<String> for Failure {
    fn from(msg: String) -> Self {
        Failure::Usage(msg)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(Failure::Invalid) => {
            println!("{{\"valid\":false}}");
            ExitCode::from(1)
        }
        Err(Failure::Usage(msg)) => {
            eprintln!("ssz-merkle: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<String, Failure> {
    let (cmd, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
    match (cmd.as_str(), rest) {
        ("-h" | "--help" | "help", _) => Ok(USAGE.to_string()),
        ("types", []) => Ok(json_array(TYPES.iter().map(|t| format!("\"{t}\"")))),
        ("gindex", [ty, path @ ..]) => Ok(with_type!(ty.as_str(), gindex(path))?),
        ("root", [ty, file]) => Ok(with_type!(ty.as_str(), root(Path::new(file)))?),
        ("json", [ty, file]) => Ok(with_type!(ty.as_str(), to_json(Path::new(file)))?),
        ("prove", [ty, file, path @ ..]) => Ok(with_type!(ty.as_str(), proof(Path::new(file), path))?),
        ("verify", [root, leaf, gindex, branch @ ..]) => verify(root, leaf, gindex, branch),
        _ => Err(Failure::Usage(format!("invalid arguments\n\n{USAGE}"))),
    }
}

fn parse_path(path: &[String]) -> Vec<PathElem> {
    path.iter().map(|p| PathElem::parse(p)).collect()
}

fn load<T: Ssz>(file: &Path) -> Result<T, String> {
    let raw = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let bytes = if file.extension().is_some_and(|e| e == "ssz_snappy") {
        snap::raw::Decoder::new()
            .decompress_vec(&raw)
            .map_err(|e| format!("{}: snappy: {e}", file.display()))?
    } else {
        raw
    };
    T::from_ssz(&bytes).map_err(|e| format!("{}: {e}", file.display()))
}

fn gindex<T: Ssz>(path: &[String]) -> Result<String, String> {
    let schema = T::schema();
    let (g, leaf) = schema.resolve(&parse_path(path)).map_err(|e| e.to_string())?;
    Ok(format!("{{\"gindex\":{g},\"depth\":{},\"type\":\"{leaf}\"}}", g.depth()))
}

fn root<T: Ssz>(file: &Path) -> Result<String, String> {
    let value: T = load(file)?;
    Ok(format!("{{\"root\":\"{}\"}}", hex(&value.hash_tree_root())))
}

fn to_json<T: Ssz>(file: &Path) -> Result<String, String> {
    let value: T = load(file)?;
    Ok(value.to_value().to_json())
}

fn proof<T: Ssz>(file: &Path, path: &[String]) -> Result<String, String> {
    let value: T = load(file)?;
    let p = prove(&value, &parse_path(path)).map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"root\":\"{}\",\"gindex\":{},\"leaf\":\"{}\",\"branch\":{}}}",
        hex(&value.hash_tree_root()),
        p.gindex,
        hex(&p.leaf),
        json_array(p.branch.iter().map(|h| format!("\"{}\"", hex(h))))
    ))
}

fn verify(root: &str, leaf: &str, gindex: &str, branch: &[String]) -> Result<String, Failure> {
    let root = parse_hash(root)?;
    let leaf = parse_hash(leaf)?;
    let gindex = gindex
        .parse()
        .ok()
        .and_then(GeneralizedIndex::new)
        .ok_or_else(|| format!("invalid generalized index `{gindex}`"))?;
    let branch = branch.iter().map(|h| parse_hash(h)).collect::<Result<Vec<_>, _>>()?;
    let computed = calculate_merkle_root(&leaf, &branch, gindex).map_err(|e| e.to_string())?;
    if computed == root { Ok("{\"valid\":true}".into()) } else { Err(Failure::Invalid) }
}

fn parse_hash(s: &str) -> Result<Hash256, String> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("`{s}` is not a 32-byte hex value"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).expect("validated hex");
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn json_array(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(","))
}
