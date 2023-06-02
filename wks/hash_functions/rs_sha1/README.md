# `rs_sha1`

`rs_sha1` is a Rust crate providing the SHA-1 cryptographic hash algorithm. It operates in a `#![no_std]` context, compatible with Rust's libcore, and serves as a standalone crate for focused use cases. Furthermore, it aligns with the `#![no_std]`, `#![no_alloc]` environment, making it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-1 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4. Yet, in accordance with NIST recommendations, SHA-1 is currently advised for the following use cases:

- Generation of a commit identifier in software versioning systems.
- Computation of a hash-based message authentication code (HMAC).
- Any non-cryptographic hash use case that requires a balance of performance and collision resistance.

`rs_sha1` also integrates into the `rs_ssl` library bundle, providing users with a wide array of cryptographic functions.

## More Information

For additional information about `rs_sha1`, other available cryptographic functions, and the broader `rs_ssl` project, please visit the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
For those interested in contributing, please refer to the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on the project's GitHub page.

## License
This project is licensed under GPL-2.0-only.
