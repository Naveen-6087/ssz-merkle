#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssz-merkle")).args(args).output().expect("binary runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn block_body() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/consensus-spec-tests/merkle_proof/BeaconBlockBody")
        .join("blob_kzg_commitment_merkle_proof__random_block_1/object.ssz_snappy")
        .to_string_lossy()
        .into_owned()
}

/// Pulls `"key":"value"` or `"key":value` out of the CLI's flat JSON output.
fn field(json: &str, key: &str) -> String {
    let start = json.find(&format!("\"{key}\":")).expect("key present") + key.len() + 3;
    let rest = &json[start..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    rest.chars().take_while(|c| !matches!(c, '"' | ',' | '}')).collect()
}

#[test]
fn gindex_command() {
    let out = run(&["gindex", "BeaconBlockBody", "blob_kzg_commitments", "0"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out), r#"{"gindex":221184,"depth":17,"type":"Vector[uint8, 48]"}"#);

    let out = run(&["gindex", "BeaconBlock", "body", "execution_payload", "block_hash"]);
    assert_eq!(field(&stdout(&out), "gindex"), "6444");
}

#[test]
fn prove_then_verify() {
    let body = block_body();
    let out = run(&["prove", "BeaconBlockBody", &body, "blob_kzg_commitments", "0"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let json = stdout(&out);
    let root = field(&json, "root");
    let leaf = field(&json, "leaf");
    let branch: Vec<String> = json[json.find('[').unwrap() + 1..json.rfind(']').unwrap()]
        .split(',')
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    assert_eq!(branch.len(), 17);

    let mut args = vec!["verify", root.as_str(), leaf.as_str(), "221184"];
    args.extend(branch.iter().map(String::as_str));
    let out = run(&args);
    assert!(out.status.success());
    assert_eq!(stdout(&out), r#"{"valid":true}"#);

    args[3] = "221185";
    let out = run(&args);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), r#"{"valid":false}"#);

    let root_out = run(&["root", "BeaconBlockBody", &body]);
    assert_eq!(field(&stdout(&root_out), "root"), root);
}

#[test]
fn json_output_is_canonical_mapping() {
    let out = run(&["json", "BeaconBlockBody", &block_body()]);
    assert!(out.status.success());
    let json = stdout(&out);
    assert!(json.starts_with(r#"{"randao_reveal":"0x"#));
    assert!(json.contains(r#""deposit_count":""#), "integers are strings");
}

#[test]
fn errors_exit_with_code_two() {
    for args in [
        vec![],
        vec!["gindex", "NoSuchType"],
        vec!["gindex", "BeaconBlockBody", "nope"],
        vec!["root", "BeaconBlockBody", "missing-file.ssz"],
        vec!["verify", "0x12", "0x34", "5"],
        vec!["verify", &"00".repeat(32), &"00".repeat(32), "0"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
    assert!(run(&["types"]).status.success());
    assert!(run(&["--help"]).status.success());
}

#[test]
fn dotted_paths_and_multiproof() {
    let out = run(&["gindex", "BeaconBlockBody", "blob_kzg_commitments.0"]);
    assert_eq!(field(&stdout(&out), "gindex"), "221184");

    let body = block_body();
    let out = run(&[
        "multiproof",
        "BeaconBlockBody",
        &body,
        "blob_kzg_commitments.0",
        "execution_payload.block_hash",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let json = stdout(&out);
    assert!(json.contains(r#""gindices":[221184,"#), "{json}");
    assert!(json.contains(r#""helpers":["0x"#));

    let out = run(&["multiproof", "BeaconBlockBody", &body]);
    assert_eq!(out.status.code(), Some(2));
}
