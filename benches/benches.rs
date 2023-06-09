use core::hash::{Hash, Hasher};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rs_shield::{
    Sha1Hasher, Sha224Hasher, Sha256Hasher, Sha384Hasher, Sha3_224Hasher, Sha3_256Hasher, Sha3_384Hasher,
    Sha3_512Hasher, Sha512Hasher, Sha512_224Hasher, Sha512_256Hasher, Shake128Hasher, Shake256Hasher,
};

const FUNCTIONS_BENCH_COMPARISON: &str = "Compare different SHA functions execution time";

fn compare_sha_impls(c: &mut Criterion) {
    let mut b_group = c.benchmark_group(FUNCTIONS_BENCH_COMPARISON);

    b_group.bench_function("SHA-1", |b| {
        b.iter(|| {
            let mut sha1hasher = Sha1Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha1hasher);
            let _ = sha1hasher.finish();
        })
    });

    b_group.bench_function("SHA-224", |b| {
        b.iter(|| {
            let mut sha224hasher = Sha224Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha224hasher);
            let _ = sha224hasher.finish();
        })
    });

    b_group.bench_function("SHA-256", |b| {
        b.iter(|| {
            let mut sha256hasher = Sha256Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha256hasher);
            let _ = sha256hasher.finish();
        })
    });

    b_group.bench_function("SHA-384", |b| {
        b.iter(|| {
            let mut sha384hasher = Sha384Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha384hasher);
            let _ = sha384hasher.finish();
        })
    });

    b_group.bench_function("SHA-512", |b| {
        b.iter(|| {
            let mut sha512hasher = Sha512Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512hasher);
            let _ = sha512hasher.finish();
        })
    });

    b_group.bench_function("SHA-512/224", |b| {
        b.iter(|| {
            let mut sha512_224hasher = Sha512_224Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512_224hasher);
            let _ = sha512_224hasher.finish();
        })
    });

    b_group.bench_function("SHA-512/256", |b| {
        b.iter(|| {
            let mut sha512_256hasher = Sha512_256Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha512_256hasher);
            let _ = sha512_256hasher.finish();
        })
    });

    b_group.bench_function("SHA3-224", |b| {
        b.iter(|| {
            let mut sha3_224hasher = Sha3_224Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha3_224hasher);
            let _ = sha3_224hasher.finish();
        })
    });

    b_group.bench_function("SHA3-256", |b| {
        b.iter(|| {
            let mut sha3_256hasher = Sha3_256Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha3_256hasher);
            let _ = sha3_256hasher.finish();
        })
    });

    b_group.bench_function("SHA3-384", |b| {
        b.iter(|| {
            let mut sha3_384hasher = Sha3_384Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha3_384hasher);
            let _ = sha3_384hasher.finish();
        })
    });

    b_group.bench_function("SHA3-512", |b| {
        b.iter(|| {
            let mut sha3_512hasher = Sha3_512Hasher::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut sha3_512hasher);
            let _ = sha3_512hasher.finish();
        })
    });

    b_group.bench_function("SHAKE128", |b| {
        b.iter(|| {
            let mut shake128hasher = Shake128Hasher::<20>::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut shake128hasher);
            let _ = shake128hasher.finish();
        })
    });

    b_group.bench_function("SHAKE256", |b| {
        b.iter(|| {
            let mut shake256hasher = Shake256Hasher::<20>::default();
            black_box(FUNCTIONS_BENCH_COMPARISON).hash(&mut shake256hasher);
            let _ = shake256hasher.finish();
        })
    });

    b_group.finish();
}

criterion_group!(benches, compare_sha_impls,);
criterion_main!(benches);
