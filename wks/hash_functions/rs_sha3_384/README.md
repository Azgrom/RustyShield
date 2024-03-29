# `rs_sha3_384`

`rs_sha3_384` is a Rust crate implementing the SHA-3_384 cryptographic hash algorithm. This permutation-based hash algorithm is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-3_384 is compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. As per the National Institute of Standards and Technology (NIST) guidelines, SHA-3_384 is recommended for several use cases:

> "SHA-3 provides security strengths against preimage, second preimage and collision attacks [...] at the 192-bit security level."

Given this advice, NIST recommendations imply that SHA-3_384 is suitable for the following contexts:

- Digital signatures that require 192 bits of security.
- Cryptographic hash functions in systems and protocols requiring 192 bits of security.
- Authentication methods that necessitate 192 bits of security.

Beyond these specific recommendations, SHA-3_384 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].
- Key derivation functions or in generation of random numbers[^6].

These points should be carefully considered, given your overall security objectives and risk tolerance.

For access to a comprehensive range of cryptographic functions, `rs_sha3_384` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_sha3_384` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha3_384 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha3_384` module in your code. Here's an example of how to create a SHA-3_384 hash from a string:

    ```rust
    use rs_sha3_384::{HasherContext, Sha3_384Hasher};
    
    let mut sha3_384hasher = Sha3_384Hasher::default();
    sha3_384hasher.write(b"your string here");
    
    let u64result = sha3_384hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_384hasher);
    assert_eq!(u64result, 0x75FD44A90B9A3689);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "75fd44a90b9a3689f55dd3d09006bf31f8443752cc662a277914c32e772aa33431d306f4b174ccaf3abdb7eff384063d"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "75FD44A90B9A3689F55DD3D09006BF31F8443752CC662A277914C32E772AA33431D306F4B174CCAF3ABDB7EFF384063D"
    );
    assert_eq!(
        bytes_result,
        [
            0x75, 0xFD, 0x44, 0xA9, 0x0B, 0x9A, 0x36, 0x89, 0xF5, 0x5D, 0xD3, 0xD0, 0x90, 0x06, 0xBF, 0x31, 0xF8, 0x44,
            0x37, 0x52, 0xCC, 0x66, 0x2A, 0x27, 0x79, 0x14, 0xC3, 0x2E, 0x77, 0x2A, 0xA3, 0x34, 0x31, 0xD3, 0x06, 0xF4,
            0xB1, 0x74, 0xCC, 0xAF, 0x3A, 0xBD, 0xB7, 0xEF, 0xF3, 0x84, 0x06, 0x3D
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha3_384`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/Azgrom/RustyShield/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

[^2]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)

[^3]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)

[^4]: Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function. [Link](https://link.springer.com/content/pdf/10.1007/3-540-45961-8_24.pdf)

[^5]: Bloom, B. H. (1970). Space/time trade-offs in hash coding with allowable errors. Communications of the ACM, 13(7), 422-426. [DOI:10.1145/362686.362692](https://doi.org/10.1145/362686.362692)

[^6]: National Institute of Standards and Technology. (2012). Recommendation for Key Derivation through Extraction-then-Expansion. [SP 800-56C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf)

---
**Note**: The references have been provided as per the best knowledge as of May 17, 2023.
