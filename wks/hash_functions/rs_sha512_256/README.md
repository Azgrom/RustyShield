# `rs_sha512_256`

`rs_sha512_256` is a Rust crate offering the SHA-512/256 cryptographic hash algorithm. This package is designed to function in a `#![no_std]` context, compatible with Rust's libcore, and caters to applications where the exclusive use of SHA-512/256 is desired. Furthermore, it is suitable for a `#![no_std]`, `#![no_alloc]` environment, making it ideal for systems where dynamic memory allocation is not an option.

In accordance with the Federal Information Processing Standards (FIPS) Publication 180-4, the SHA-512/256 implementation provided here is endorsed by NIST for the following applications:

- Creation of digital signatures as part of a Public Key Infrastructure (PKI).
- Computation of a hash-based message authentication code (HMAC).
- Use in hash functions for Hash-based Quantum-resistant Cryptography.
- Generation of checksums to ensure data integrity during transmission or storage.

`rs_sha512_256` is also integrated into the `rs_ssl` library bundle, where it is available in combination with a wide range of cryptographic functions.

As projected by the NIST, SHA-512/256 is anticipated to remain suitable for most cryptographic applications beyond the year 2030.

## More Information

For more detailed information about `rs_sha512_256`, the spectrum of cryptographic functions provided, and the wider `rs_ssl` project, please visit the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
If you are interested in contributing, kindly refer to the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) available on the project's GitHub page.

## License
This project is licensed under GPL-2.0-only.
