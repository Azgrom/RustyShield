use crate::implmementations::{FirstImplementationOfGF2ToThe8, SecondImplementationOfGF2ToThe8};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const X: u8 = 131;
const Y: u8 = 137;

mod implmementations;

fn gf2to_the8comparison(c: &mut Criterion) {
    let mut b_group = c.benchmark_group("GaloisField(2^8) bench");

    b_group.bench_function("First Implementation", |b| {
        b.iter(|| {
            let _ =
                FirstImplementationOfGF2ToThe8::from(black_box(X)) * FirstImplementationOfGF2ToThe8::from(black_box(Y));
        })
    });

    b_group.bench_function("Second Implementation", |b| {
        b.iter(|| {
            let _ = SecondImplementationOfGF2ToThe8::from(black_box(X))
                * SecondImplementationOfGF2ToThe8::from(black_box(Y));
        })
    });

    b_group.finish();
}

criterion_group!(benches, gf2to_the8comparison,);
criterion_main!(benches);
