use criterion::{black_box, Criterion, criterion_group, criterion_main};

const HASH_SIZE: u32 = 20;
const ROTATION: u32 = 2;

trait ShiftSideways: core::ops::Shl<Output = Self> + core::ops::Shr<Output = Self> + Copy + Sized {}

impl ShiftSideways for u32 {

}

#[inline]
fn rotate<R>(x: R, l: R, r: R) -> R
    where R: ShiftSideways + core::ops::BitOr<Output = R>
{
    (x << l) | (x >> r)
}

fn rotate_left(x: u32, n: u32) -> u32 {
    rotate(x, n, 32 - n)
}

fn rotate_right(x: u32, n: u32) -> u32 {
    rotate(x, 32 - n, n)
}

fn get_be(value: u32) -> u32 {
    let b = value / 256;
    let c = b / 256;
    let d = c / 256;
    (value << 24) | (b << 16) | (c << 8) | d
}

pub fn bit_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rotation study");

    group.bench_function("std rotate left", |b| b.iter(|| HASH_SIZE.rotate_left(ROTATION)));
    group.bench_function("custom rotate left", |b| b.iter(|| rotate_left(HASH_SIZE, ROTATION)));

    group.bench_function("std rotate right", |b| b.iter(|| HASH_SIZE.rotate_right(ROTATION)));
    group.bench_function("custom rotate right", |b| b.iter(|| rotate_right(HASH_SIZE, ROTATION)));

    group.finish();
}

pub fn convert_to_big_endian(c: &mut Criterion) {
    let mut group = c.benchmark_group("u32 conversion to Big Endian");

    group.bench_function("std to big endian", |b| b.iter(|| HASH_SIZE.to_be()));
    group.bench_function("cus to big endian", |b| b.iter(|| get_be(HASH_SIZE)));

    group.finish();
}

criterion_group!(benches, bit_rotation, convert_to_big_endian);
criterion_main!(benches);
