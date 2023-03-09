use core::hash::{BuildHasher, Hash, Hasher};
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use hash_ctx_lib::HasherContext;

#[cfg(feature = "comparator_build")]
use comparison_benchmark::{
    compare_simple_digestion_of_different_implementations,
    compare_simple_digestion_with_hash_producing_of_different_implementations,
};
use rs_sha1_lib::Sha1Hasher;

#[cfg(feature = "comparator_build")]
mod comparison_benchmark;

fn test(c: &mut Criterion) {
    c.bench_function("dasd", |b| {
        b.iter(|| {
            let mut sha1hasher = Sha1Hasher::default();
            // black_box("abc").hash(&mut sha1hasher);
            "abc".hash(&mut sha1hasher);
            HasherContext::finish(&mut sha1hasher);
        })
    });
}

// #[cfg(feature = "criterion")]
criterion_group!(benches, test,);

// #[cfg(feature = "comparator_build")]
// criterion_group!(
//     benches,
//     compare_simple_digestion_of_different_implementations,
//     compare_simple_digestion_with_hash_producing_of_different_implementations,
// );

criterion_main!(benches);
