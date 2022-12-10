use core::ops::{BitOr, Shl, Shr};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lib::{Sha1Context};

const HASH_SIZE: u32 = 20;
const ROTATION: u32 = 2;

#[inline]
fn rotate<R>(x: R, l: R, r: R) -> R
where
    R: BitOr<Output = R> + Shl<Output = R> + Shr<Output = R> + Copy + Sized,
{
    (x << l) | (x >> r)
}

#[inline]
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

criterion_group!(benches, bit_rotation, f_0_19);
criterion_main!(benches);
