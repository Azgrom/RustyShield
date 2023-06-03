# `rs_sha3_256`

`rs_sha3_256` is a Rust crate implementing the SHA-3_256 cryptographic hash algorithm. This permutation-based hash algorithm is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-3_256 is compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. As per the National Institute of Standards and Technology (NIST) guidelines, SHA-3_256 is recommended for several use cases:

> "SHA-3 provides security strengths against preimage, second preimage and collision attacks [...] at the 128-bit security level."

Given this advice, NIST recommendations imply that SHA-3_256 is suitable for the following contexts:

- Digital signatures that require 128 bits of security.
- Cryptographic hash functions in systems and protocols requiring 128 bits of security.
- Authentication methods that necessitate 128 bits of security.

Beyond these specific recommendations, SHA-3_256 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].
- Key derivation functions or in generation of random numbers[^6].

These points should be carefully considered, given your overall security objectives and risk tolerance.

For access to a comprehensive range of cryptographic functions, `rs_sha3_256` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_sha3_256` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha3_256 = "0.1.*"
    ```
   _Please replace `"0.1"` with the version number you intend to use._

2. Import `rs_sha3_256` in your Rust source file:

    ```rust
    extern crate rs_sha3_256;
    ```

3. Use the functions provided by the `rs_sha3_256` module in your code. Here's an example of how to create a SHA-3_256 hash from a string:

    ```rust
    use rs_sha3_256::{HasherContext, Sha3_256Hasher};

    let mut sha3_256hasher = Sha3_256Hasher::default();
    sha3_256hasher.write(b"your string here");

    let output = HasherContext::finish(&mut sha3_256hasher);
    println!("{:x}", output);
    ```

## More Information

For a more detailed exploration of `rs_sha3_256`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). SHA-3 Standard: Permutation-Based Hash and Extendable-
