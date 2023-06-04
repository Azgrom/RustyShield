# `rs_sha3_224`

`rs_sha3_224` is a Rust crate implementing the SHA-3_224 cryptographic hash algorithm. This permutation-based hash algorithm is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-3_224 is compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. As per the National Institute of Standards and Technology (NIST) guidelines, SHA-3_224 is recommended for several use cases:

> "SHA-3 provides security strengths against preimage, second preimage and collision attacks [...] at the 112-bit security level."

Given this advice, NIST recommendations imply that SHA-3_224 is suitable for the following contexts:

- Digital signatures that require 112 bits of security.
- Cryptographic hash functions in systems and protocols requiring 112 bits of security.
- Authentication methods that necessitate 112 bits of security.

Beyond these specific recommendations, SHA-3_224 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].
- Key derivation functions or in generation of random numbers[^6].

These points should be carefully considered, given your overall security objectives and risk tolerance.

For access to a comprehensive range of cryptographic functions, `rs_sha3_224` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_sha3_224` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

   ```toml
   rs_sha3_224 = "0.1.*"
   ```

3. Use the functions provided by the `rs_sha3_224` module in your code. Here's an example of how to create a SHA-3_224 hash from a string:

    ```rust
    use rs_sha3_224::{HasherContext, Sha3_224Hasher};
    
    let mut sha3_224hasher = Sha3_224Hasher::default();
    sha3_224hasher.write(b"your string here");
    
    let u64result = sha3_224hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_224hasher);
    assert_eq!(u64result, 0xDDF2FCD38ED7C536);
    assert_eq!(format!("{bytes_result:02x}"), "ddf2fcd38ed7c536146be476795619b9232eee08d83a94d40ebd9f79");
    assert_eq!(format!("{bytes_result:02X}"), "DDF2FCD38ED7C536146BE476795619B9232EEE08D83A94D40EBD9F79");
    assert_eq!(
        bytes_result,
        [
            0xDD, 0xF2, 0xFC, 0xD3, 0x8E, 0xD7, 0xC5, 0x36, 0x14, 0x6B, 0xE4, 0x76, 0x79, 0x56,
            0x19, 0xB9, 0x23, 0x2E, 0xEE, 0x08, 0xD8, 0x3A, 0x94, 0xD4, 0x0E, 0xBD, 0x9F, 0x79
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha3_224`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

[^2]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)

[^3]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)

[^4]: Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function. [Link](https://link.springer.com/content/pdf/10.1007/3-540-45961-8_24.pdf)

[^5]: Bloom, B. H. (1970). Space/time trade-offs in hash coding with allowable errors. Communications of the ACM, 13(7), 422-426. [DOI:10.1145/362686.362692](https://doi.org/10.1145/362686.362692)

[^6]: National Institute of Standards and Technology. (2012). Recommendation for Key Derivation Using Pseudorandom Functions. [NIST Special Publication 800-108](https://doi.org/10.6028/NIST.SP.800-108)

---
**Note**: The references have been provided as per the best knowledge as of Jun 02, 2023.
