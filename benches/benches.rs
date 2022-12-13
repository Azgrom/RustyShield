use core::ops::{BitOr, Shl, Shr};
use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};
use openssl::sha::{Sha1, sha1};
use lib::Sha1Context;
use sha1::{Digest, Sha1 as rust_crypto_Sha1};

const HASH_SIZE: u32 = 20;
const ROTATION: u32 = 2;

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

// #[inline]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

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

pub fn f_0_19(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("Bench F_0_19 implementations");

    benchmark_group.bench_function("Implemented ch -> F_0_19", |b| {
        b.iter(|| Sha1Context::ch(black_box(1000), black_box(2001), black_box(3002)))
    });
    benchmark_group.bench_function("Original ch -> F_0_19", |b| {
        b.iter(|| ch(black_box(1000), black_box(2001), black_box(3002)))
    });
}

#[inline]
fn single_byte_message_bench(bencher: &mut Bencher) {
    bencher.iter(|| {
        let mut sha1_context = Sha1Context::default();
        sha1_context.write(&[0x80]);
        sha1_context.finish();
        sha1_context.hex_hash();
    })
}

#[inline]
fn double_byte_message_bench(bencher: &mut Bencher) {
    bencher.iter(|| {
        let mut sha1_context = Sha1Context::default();
        sha1_context.write(&[0x80; 2]);
        sha1_context.finish();
        sha1_context.hex_hash();
    })
}

fn different_message_lengths_comparison(c: &mut Criterion) {
    let mut benchmark_different_messages_impact =
        c.benchmark_group("Bench messages from single byte to 64 bytes");

    benchmark_different_messages_impact
        .bench_function("Single Byte Message", single_byte_message_bench);
    benchmark_different_messages_impact
        .bench_function("Double Byte Message", double_byte_message_bench);
}

fn rust_crypto_sha1_bench(bencher: &mut Bencher) {
    bencher.iter(|| {
        let mut sha1 = rust_crypto_Sha1::new();
        sha1.update(&[0x80]);
        sha1.finalize()[..]
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect::<String>();
    });
}

fn openssl_binded_sha1_bench(bencher: &mut Bencher) {
    bencher.iter(|| {
        hex::encode(sha1(&[0x80]))
    })
}

fn different_sha1_implementations(c: &mut Criterion) {
    let mut group = c.benchmark_group(
        "Bench time necessary to digest the same message between different implementations",
    );

    group.bench_function("This crate very implementation", single_byte_message_bench);
    group.bench_function("Rust Crypto Sha1 implementation", rust_crypto_sha1_bench);
    group.bench_function("OpenSSL Rust binded Sha1 implementation", openssl_binded_sha1_bench);
}

criterion_group!(
    benches,
    bit_rotation,
    f_0_19,
    different_message_lengths_comparison,
    different_sha1_implementations
);
criterion_main!(benches);
