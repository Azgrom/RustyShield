# `rs_sha512_224`

`rs_sha512_224` is a Rust crate offering the SHA-512/224 cryptographic hash algorithm. This package is designed to function in a `#![no_std]` context, compatible with Rust's libcore, and caters to applications where the exclusive use of SHA-512/224 is desired. Additionally, it adheres to a `#![no_std]`, `#![no_alloc]` environment, making it appropriate for systems where dynamic memory allocation is not feasible.

Compliant with the Federal Information Processing Standards (FIPS) Publication 180-4, the SHA-512/224 implementation provided here is recommended by NIST for the following use cases:

- Creation of digital signatures in a Public Key Infrastructure (PKI).
- Computation of a hash-based message authentication code (HMAC).
- Use in hash functions in Hash-based Quantum-resistant Cryptography.
- Generation of checksums to guarantee data integrity during transmission or storage.

`rs_sha512_224` is also part of the `rs_ssl` library bundle, where it is available alongside a wide range of cryptographic functions.

According to the NIST, SHA-512/224 is anticipated to remain suitable for most cryptographic applications beyond the year 2030.

## More Information

For more details about `rs_sha512_224`, the range of cryptographic functions offered, and the overarching `rs_ssl` project, please visit the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
For anyone interested in contributing, please check the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on the project's GitHub page.

## License
This project is licensed under GPL-2.0-only.
