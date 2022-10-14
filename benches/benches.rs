use criterion::{black_box, Criterion, criterion_group, criterion_main};

const HASH_SIZE: usize = 20;
const DEMO_HASH: [u8; HASH_SIZE] = [
    10, 179, 229, 95, 211, 211, 209, 95, 236, 5, 106, 173, 76, 17, 122, 198, 142, 157, 113, 97,
];

fn to_string_wth_iterator(hash: &[u8; HASH_SIZE]) -> String {
    hash.iter().map(|x| format!("{:02x}", x)).collect()
}

fn to_string_with_for_loop(hash: &[u8; HASH_SIZE]) -> String {
    let mut buf = String::with_capacity(4 * HASH_SIZE);

    for h in hash {
        buf.push_str(&format!("{:02x}", h));
    }

    buf
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("To String");

    group.bench_function("to_string_wth_iterator", |b| b.iter(|| to_string_wth_iterator(black_box(&DEMO_HASH))));
    group.bench_function("to_string_with_for_loop", |b| b.iter(|| to_string_with_for_loop(black_box(&DEMO_HASH))));

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
