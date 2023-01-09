use core::ops::{BitOr, Shl, Shr};
use std::hash::{BuildHasher, Hash};

use criterion::{Bencher, BenchmarkId, Criterion, criterion_group, criterion_main};
use lib::HashContext;
use openssl::sha::Sha1 as ossl_sha1;
use sha1::{Digest, Sha1 as rsc_sha1};
use lib::sha1_hasher::Sha1Hasher;
use lib::sha1_state::Sha1State;

const HASH_SIZE: u32 = 20;
const ROTATION: u32 = 2;
const BASE_INPUT_SIZE: usize = 16_384;
const SIXTEEN_KB_BASE_INPUT: [u8; BASE_INPUT_SIZE] = [0x80; BASE_INPUT_SIZE];

#[inline]
fn rotate<R>(x: R, l: R, r: R) -> R
where
    R: BitOr<Output = R> + Shl<Output = R> + Shr<Output = R> + Copy + Sized,
{
    (x << l) | (x >> r)
}

fn rotate_left(x: u32, n: u32) -> u32 {
    rotate(x, n, 32 - n)
}

fn rotate_right(x: u32, n: u32) -> u32 {
    rotate(x, 32 - n, n)
}

#[cfg(feature = "criterion")]
pub fn bit_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rotation study");

    group.bench_function("std rotate left", |b| {
        b.iter(|| HASH_SIZE.rotate_left(ROTATION))
    });
    group.bench_function("custom rotate left", |b| {
        b.iter(|| rotate_left(HASH_SIZE, ROTATION))
    });

    group.bench_function("std rotate right", |b| {
        b.iter(|| HASH_SIZE.rotate_right(ROTATION))
    });
    group.bench_function("custom rotate right", |b| {
        b.iter(|| rotate_right(HASH_SIZE, ROTATION))
    });

    group.finish();
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn this_impl_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let sha1_default_state = Sha1State::default();
        let mut sha1hasher = sha1_default_state.build_hasher();
        input.hash(&mut sha1hasher);
        sha1hasher.to_hex_string();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn openssl_bind_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = ossl_sha1::new();
        sha1_ctx.update(input);
        sha1_ctx
            .finish()
            .iter().map(|b| format!("{:02x}", b)).collect::<String>();
    })
}

#[inline(always)]
#[cfg(feature = "comparator_build")]
fn rust_crypto_sha1_digestion_with_given_input_size(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = rsc_sha1::new();
        sha1_ctx.update(input);
        let array = sha1_ctx.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    })
}

#[cfg(feature = "comparator_build")]
fn this_implementation_through_different_input_lengths(c: &mut Criterion) {
    let mut benchmark_different_messages_lengths_impact =
        c.benchmark_group("Bench messages from 0 to 16 kilobytes");

    for current_size in (0..=BASE_INPUT_SIZE).step_by(512) {
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
criterion_group!(benches, this_implementation_through_different_input_lengths,);

criterion_main!(benches);
