use core::hash::{Hash, Hasher};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rs_ssl::{Sha1Hasher, Sha224Hasher, Sha256Hasher, Sha384Hasher, Sha512Hasher, Sha512_224Hasher, Sha512_256Hasher};

const FUNCTIONS_BENCH_COMPARISON: &str = "Compare different SHA functions execution time";

fn compare_sha_impls(c: &mut Criterion) {
    let mut b_group = c.benchmark_group(FUNCTIONS_BENCH_COMPARISON);

    b_group.bench_function("SHA-1", |b| {
        b.iter(|| {
            let mut sha1hasher = Sha1Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha1hasher);
            sha1hasher.finish();
        })
    });

    b_group.bench_function("SHA-224", |b| {
        b.iter(|| {
            let mut sha224hasher = Sha224Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha224hasher);
            sha224hasher.finish();
        })
    });

    b_group.bench_function("SHA-256", |b| {
        b.iter(|| {
            let mut sha256hasher = Sha256Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha256hasher);
            sha256hasher.finish();
        })
    });

    b_group.bench_function("SHA-384", |b| {
        b.iter(|| {
            let mut sha384hasher = Sha384Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha384hasher);
            sha384hasher.finish();
        })
    });

    b_group.bench_function("SHA-512", |b| {
        b.iter(|| {
            let mut sha512hasher = Sha512Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512hasher);
            sha512hasher.finish();
        })
    });

    b_group.bench_function("SHA-512/224", |b| {
        b.iter(|| {
            let mut sha512_224hasher = Sha512_224Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512_224hasher);
            sha512_224hasher.finish();
        })
    });

    b_group.bench_function("SHA-512/256", |b| {
        b.iter(|| {
            let mut sha512_256hasher = Sha512_256Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512_256hasher);
            sha512_256hasher.finish();
        })
    });

    b_group.finish();
}

criterion_group!(benches, compare_sha_impls,);
criterion_main!(benches);
