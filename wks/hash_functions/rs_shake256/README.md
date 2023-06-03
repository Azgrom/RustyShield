# `rs_shake256`

`rs_shake256` is a Rust crate implementing the SHAKE256 Extendable-Output Function (XOF). This permutation-based function is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHAKE256 is compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. As per the National Institute of Standards and Technology (NIST) guidelines, SHAKE256 is recommended for various use cases:

> "SHAKE128 and SHAKE256 are extendable-output functions (XOFs), which can output a hash of variable length, are approved for all applications using hash functions that can benefit from variable-length output."

Given this advice, NIST recommendations imply that SHAKE256 is suitable for the following contexts:

- Digital signatures that require variable bits of security.
- Cryptographic hash functions in systems and protocols requiring variable bits of security.
- Authentication methods that necessitate variable bits of security.
- Applications where the output length is not fixed.

Beyond these specific recommendations, SHAKE256 could also find application in:

- Generation of unique identifiers in distributed systems[^2].
- Data integrity checks in Merkle Trees[^4].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- Key derivation functions or in generation of random numbers[^6].

These points should be carefully considered, given your overall security objectives and risk tolerance.

For access to a comprehensive range of cryptographic functions, `rs_shake256` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_shake256` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_shake256 = "0.1.*"
    ```
   _Please replace `"0.1"` with the version number you intend to use.

2. Import `rs_shake256` in your Rust source file:

    ```rust
    extern crate rs_shake256;
    ```

3. Use the functions provided by the `rs_shake256` module in your code. Here's an example of how to create a SHAKE256 hash from a string:

    ```rust
    use rs_shake256::{HasherContext, Shake256Hasher};

    let mut shake256hasher = Shake256Hasher::default();
    shake256hasher.write(b"your string here");

    let output = HasherContext::finish(& mut shake256hasher);
    println!("{:x}", output);
    ```

## More Information

For a more detailed exploration of `rs_shake256`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

[^2]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)

[^3]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)

[^4]: Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function. [Link](https://link.springer.com/content/pdf/10.1007/3-540-45961-8_24.pdf)

[^6]: National Institute of Standards and Technology. (2012). Recommendation for Key Derivation through Extraction-then-Expansion. [SP 800-56C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf)

---
**Note**: The references have been provided as per the best knowledge as of May 17, 2023.
