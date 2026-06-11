use std::hint::black_box;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ssz_merkle::deneb::BeaconBlockBody;
use ssz_merkle::merkle::{merkleize, merkleize_progressive};
use ssz_merkle::{GeneralizedIndex, Hash256, List, PathElem, Ssz, prove, verify_merkle_proof};

fn chunks(n: usize) -> Vec<Hash256> {
    (0..n).map(|i| [(i % 251) as u8; 32]).collect()
}

fn block_body() -> (Vec<u8>, BeaconBlockBody) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/consensus-spec-tests/merkle_proof/BeaconBlockBody")
        .join("blob_kzg_commitment_merkle_proof__random_block_3/object.ssz_snappy");
    let compressed = std::fs::read(path).expect("vendored vector");
    let bytes = snap::raw::Decoder::new().decompress_vec(&compressed).expect("snappy");
    let body = BeaconBlockBody::from_ssz(&bytes).expect("valid body");
    (bytes, body)
}

fn merkleization(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkleize");
    for n in [1usize << 10, 1 << 16] {
        let input = chunks(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("binary", n), &input, |b, input| {
            b.iter(|| merkleize(black_box(input), None));
        });
        group.bench_with_input(BenchmarkId::new("progressive", n), &input, |b, input| {
            b.iter(|| merkleize_progressive(black_box(input)));
        });
    }
    group.finish();
}

fn lists(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_u64_limit_2^40");
    for n in [1_000usize, 100_000] {
        let list: List<u64, { 1 << 40 }> = List::new((0..n as u64).collect()).unwrap();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("hash_tree_root", n), &list, |b, list| {
            b.iter(|| black_box(list).hash_tree_root());
        });
    }
    group.finish();
}

fn beacon_block_body(c: &mut Criterion) {
    let (bytes, body) = block_body();
    let mut group = c.benchmark_group("deneb_block_body");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("decode", |b| b.iter(|| BeaconBlockBody::from_ssz(black_box(&bytes)).unwrap()));
    group.bench_function("encode", |b| b.iter(|| black_box(&body).to_ssz()));
    group.bench_function("hash_tree_root", |b| b.iter(|| black_box(&body).hash_tree_root()));
    group.bench_function("tree", |b| b.iter(|| black_box(&body).tree()));

    let path = [PathElem::parse("blob_kzg_commitments"), PathElem::Index(0)];
    group.bench_function("prove_blob_commitment", |b| b.iter(|| prove(black_box(&body), &path).unwrap()));

    let proof = prove(&body, &path).unwrap();
    let root = body.hash_tree_root();
    group.bench_function("verify_blob_commitment", |b| {
        b.iter(|| verify_merkle_proof(&proof.leaf, &proof.branch, proof.gindex, black_box(&root)))
    });
    group.finish();

    let schema = BeaconBlockBody::schema();
    c.bench_function("gindex/blob_kzg_commitments.0", |b| {
        b.iter(|| -> GeneralizedIndex { schema.generalized_index(black_box(&path)).unwrap() })
    });
}

criterion_group!(benches, merkleization, lists, beacon_block_body);
criterion_main!(benches);
