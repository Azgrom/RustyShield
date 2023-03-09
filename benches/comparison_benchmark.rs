extern crate hashes_sha1;
extern crate openssl as ossl_sha1;
use criterion::{Bencher, BenchmarkId, Criterion};
use rs_ssl::{HasherContext, Sha1State};
use std::hash::{BuildHasher, Hash, Hasher};

const BASE_INPUT_SIZE: usize = 4_096;
const SIXTEEN_KB_BASE_INPUT: [u8; BASE_INPUT_SIZE] = [0x80; BASE_INPUT_SIZE];

fn this_impl_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let sha1_default_state = Sha1State::default();
        let mut sha1hasher = sha1_default_state.build_hasher();
        input.hash(&mut sha1hasher);
        let _result = HasherContext::finish(&mut sha1hasher);
    })
}

fn openssl_bind_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = ossl_sha1::sha::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finish();
    })
}

fn rust_crypto_sha1_simple_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    use hashes_sha1::Digest;
    b.iter(|| {
        let mut sha1_ctx = hashes_sha1::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finalize();
    })
}

fn this_impl_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let sha1_default_state = Sha1State::default();
        let mut sha1hasher = sha1_default_state.build_hasher();
        input.hash(&mut sha1hasher);
        let _result = HasherContext::finish(&mut sha1hasher);
    })
}

fn openssl_bind_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = ossl_sha1::sha::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finish();
    })
}

fn rust_crypto_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    use hashes_sha1::Digest;
    b.iter(|| {
        let mut sha1_ctx = hashes_sha1::Sha1::new();
        sha1_ctx.update(input);
        let _result = sha1_ctx.finalize();
    })
}

pub(crate) fn compare_simple_digestion_of_different_implementations(c: &mut Criterion) {
    let mut benchmark_different_messages_lengths_impact =
        c.benchmark_group("Compare messages from 0 to 4 kilobytes simple digestion of different implementations");

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

pub(crate) fn compare_simple_digestion_with_hash_producing_of_different_implementations(c: &mut Criterion) {
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
