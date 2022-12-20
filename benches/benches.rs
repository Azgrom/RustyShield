use core::ops::{BitOr, Shl, Shr};
use criterion::{black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use lib::Sha1Context;
use std::fmt::format;

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

#[inline]
fn compare_sha1_digestion_with_different_input_sizes(b: &mut Bencher, input: &[u8]) {
    b.iter(|| {
        let mut sha1_ctx = Sha1Context::default();
        sha1_ctx.write(&input);
        sha1_ctx.finish();
        sha1_ctx.hex_hash();
    })
}

fn different_message_lengths_comparison(c: &mut Criterion) {
    let mut benchmark_different_messages_impact =
        c.benchmark_group("Bench messages from 0 to 16 kilobytes");

    for current_size in (0..=BASE_INPUT_SIZE).step_by(1024) {
        benchmark_different_messages_impact.bench_with_input(
            BenchmarkId::from_parameter(current_size),
            &SIXTEEN_KB_BASE_INPUT[..current_size],
            compare_sha1_digestion_with_different_input_sizes,
        );
    }
}

criterion_group!(benches, bit_rotation, different_message_lengths_comparison,);
criterion_main!(benches);
