use crate::iteration_definitions::{HmacHashersComparison, SimpleHashersComparison};
use criterion::{criterion_group, criterion_main, Criterion};

mod iteration_definitions;

fn compare_sha_impls(c: &mut Criterion) {
    const FUNCTIONS_BENCH_COMPARISON: &str = "Compare different SHA functions execution time";
    let mut b_group = c.benchmark_group(FUNCTIONS_BENCH_COMPARISON);

    b_group.bench_function("SHA-1", SimpleHashersComparison::sha1_iteration);
    b_group.bench_function("SHA-224", SimpleHashersComparison::sha224_iteration);
    b_group.bench_function("SHA-256", SimpleHashersComparison::sha256_iteration);
    b_group.bench_function("SHA-384", SimpleHashersComparison::sha384_iteration);
    b_group.bench_function("SHA-512", SimpleHashersComparison::sha512_iteration);
    b_group.bench_function("SHA-512/224", SimpleHashersComparison::sha512_224_iteration);
    b_group.bench_function("SHA-512/256", SimpleHashersComparison::sha512_256_iteration);
    b_group.bench_function("SHA3-224", SimpleHashersComparison::sha3_224_iteration);
    b_group.bench_function("SHA3-256", SimpleHashersComparison::sha3_256_iteration);
    b_group.bench_function("SHA3-384", SimpleHashersComparison::sha3_384_iteration);
    b_group.bench_function("SHA3-512", SimpleHashersComparison::sha3_512_iteration);
    b_group.bench_function("SHAKE128", SimpleHashersComparison::shake128_iteration);
    b_group.bench_function("SHAKE256", SimpleHashersComparison::shake256_iteration);

    b_group.finish();
}

fn compare_hmac_impls(c: &mut Criterion) {
    let mut b_group = c.benchmark_group("Compare HMAC with different Hasher execution time with");

    b_group.bench_function("SHA-1 HMAC", HmacHashersComparison::hmac_sha1_iteration);
    b_group.bench_function("SHA-224 HMAC", HmacHashersComparison::hmac_sha224_iteration);
    b_group.bench_function("SHA-256 HMAC", HmacHashersComparison::hmac_sha256_iteration);
    b_group.bench_function("SHA-384 HMAC", HmacHashersComparison::hmac_sha384_iteration);
    b_group.bench_function("SHA-512 HMAC", HmacHashersComparison::hmac_sha512_iteration);
    b_group.bench_function("SHA-512/224 HMAC", HmacHashersComparison::hmac_sha512_224_iteration);
    b_group.bench_function("SHA-512/256 HMAC", HmacHashersComparison::hmac_sha512_256_iteration);
    b_group.bench_function("SHA3-224 HMAC", HmacHashersComparison::hmac_sha3_224_iteration);
    b_group.bench_function("SHA3-256 HMAC", HmacHashersComparison::hmac_sha3_256_iteration);
    b_group.bench_function("SHA3-384 HMAC", HmacHashersComparison::hmac_sha3_384_iteration);
    b_group.bench_function("SHA3-512 HMAC", HmacHashersComparison::hmac_sha3_512_iteration);
    b_group.bench_function("SHAKE128 HMAC", HmacHashersComparison::hmac_shake128_64bytes_output_iteration);
    b_group.bench_function("SHAKE256 HMAC", HmacHashersComparison::hmac_shake256_64bytes_output_iteration);
    b_group.bench_function(
        "200bit Keccak HMAC with 8 lanes of rate",
        HmacHashersComparison::hmac_200bits_keccak_8lanes_rate_64bytes_output_iteration,
    );
    b_group.bench_function(
        "400bit Keccak HMAC with 8 lanes of rate",
        HmacHashersComparison::hmac_400bits_keccak_8lanes_rate_64bytes_output_iteration,
    );
    b_group.bench_function(
        "800bit Keccak HMAC with 8 lanes of rate",
        HmacHashersComparison::hmac_800bits_keccak_8lanes_rate_64bytes_output_iteration,
    );
    b_group.bench_function(
        "1600bit Keccak HMAC with 8 lanes of rate",
        HmacHashersComparison::hmac_1600bits_keccak_8lanes_rate_64bytes_output_iteration,
    );

    b_group.finish()
}

criterion_group!(benches, compare_sha_impls, compare_hmac_impls);
criterion_main!(benches);
