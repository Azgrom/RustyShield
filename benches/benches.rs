extern crate criterion;
extern crate hashes_sha1;
extern crate openssl as ossl_sha1;

use core::hash::{BuildHasher, Hash, Hasher};
use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use hash_ctx_lib::HasherContext;
use rs_sha1_lib::Sha1State;

const BASE_INPUT_SIZE: usize = 4_096;
const SIXTEEN_KB_BASE_INPUT: [u8; BASE_INPUT_SIZE] = [0x80; BASE_INPUT_SIZE];

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn this_impl_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let sha1_default_state = Sha1State::default();
        let mut sha1hasher = sha1_default_state.build_hasher();
        input.hash(&mut sha1hasher);
        let _result = sha1hasher.finish();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn openssl_bind_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = ossl_sha1::sha::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finish();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn rust_crypto_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    use hashes_sha1::Digest;
    b.iter(|| {
        let mut sha1_ctx = hashes_sha1::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finalize();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn this_impl_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let sha1_default_state = Sha1State::default();
        let mut sha1hasher = sha1_default_state.build_hasher();
        input.hash(&mut sha1hasher);
        let _result = HasherContext::finish(&mut sha1hasher);
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn openssl_bind_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = ossl_sha1::sha::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finish();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn rust_crypto_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    use hashes_sha1::Digest;
    b.iter(|| {
        let mut sha1_ctx = hashes_sha1::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finalize();
    })
}

#[cfg(feature = "comparator_build")]
fn compare_simple_digestion_of_different_implementations(c: &mut Criterion) {
    let mut benchmark_different_messages_lengths_impact = c.benchmark_group(
        "Compare messages from 0 to 4 kilobytes simple digestion of different implementations",
    );

    for current_size in (0..=BASE_INPUT_SIZE).step_by(1024) {
        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("This impl", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            this_impl_sha1_simple_digestion_with_given_input_size,
        );

        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("OpenSSL bind", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            openssl_bind_sha1_simple_digestion_with_given_input_size,
        );

        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("RustCrypto", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            rust_crypto_sha1_simple_digestion_with_given_input_size,
        );
    }

    benchmark_different_messages_lengths_impact.finish();
}

#[cfg(feature = "comparator_build")]
fn compare_simple_digestion_with_hash_producing_of_different_implementations(c: &mut Criterion) {
    let mut benchmark_different_messages_lengths_impact =
        c.benchmark_group("Compare messages from 0 to 4 kilobytes simple digestion, with final hash computing, of different implementations");

    for current_size in (0..=BASE_INPUT_SIZE).step_by(1024) {
        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("This impl", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            this_impl_sha1_digestion_with_given_input_size,
        );

        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("OpenSSL bind", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            openssl_bind_sha1_digestion_with_given_input_size,
        );

        benchmark_different_messages_lengths_impact.bench_with_input(
            BenchmarkId::new("RustCrypto", current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            rust_crypto_sha1_digestion_with_given_input_size,
        );
    }

    benchmark_different_messages_lengths_impact.finish();
}

#[cfg(feature = "criterion")]
criterion_group!(benches, bit_rotation,);

#[cfg(feature = "comparator_build")]
criterion_group!(
    benches,
    compare_simple_digestion_of_different_implementations,
    compare_simple_digestion_with_hash_producing_of_different_implementations,
);

criterion_main!(benches);
