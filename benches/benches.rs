use core::hash::{BuildHasher, Hash, Hasher};
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};

// #[cfg(feature = "comparator_build")]
// use comparison_benchmark::{
//     compare_simple_digestion_of_different_implementations,
//     compare_simple_digestion_with_hash_producing_of_different_implementations,
// };
use rs_sha1::Sha1Hasher;
use rs_sha224::Sha224Hasher;
use rs_sha256::Sha256Hasher;
use rs_sha384::Sha384Hasher;

#[cfg(feature = "comparator_build")]
mod comparison_benchmark;

const FUNCTIONS_BENCH_COMPARISON: &str = "Compare different SHA functions execution time";

fn compare_sha_functions(c: &mut Criterion) {
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

    b_group.finish();
}

// #[cfg(feature = "criterion")]
criterion_group!(benches, compare_sha_functions,);

// #[cfg(feature = "comparator_build")]
// criterion_group!(
//     benches,
//     compare_simple_digestion_of_different_implementations,
//     compare_simple_digestion_with_hash_producing_of_different_implementations,
// );

criterion_main!(benches);
