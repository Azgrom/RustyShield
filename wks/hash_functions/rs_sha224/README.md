# `rs_sha224`

`rs_sha224` is a Rust crate providing the SHA-224 cryptographic hash algorithm. It operates in a `#![no_std]` context, compatible with Rust's libcore, and serves as a standalone crate for focused use cases. Furthermore, it aligns with the `#![no_std]`, `#![no_alloc]` environment, making it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-224 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4. Yet, in accordance with NIST recommendations, SHA-224 is currently advised for the following use cases:

- Secure password hashing with a salt in a database.
- Computation of a hash-based message authentication code (HMAC).
- Generation of a checksum to ensure data integrity during transmission or storage.

`rs_sha224` also integrates into the `rs_ssl` library bundle, providing users with a wide array of cryptographic functions.

According to the NIST, SHA-224 is expected to remain adequate for most cryptographic applications until at least 2030.

## More Information

For additional information about `rs_sha224`, other available cryptographic functions, and the broader `rs_ssl` project, please visit the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
For those interested in contributing, please refer to the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on the project's GitHub page.

## License
This project is licensed under GPL-2.0-only.
