# `rs_sha3_512`

`rs_sha3_512` is a Rust crate implementing the SHA-3_512 cryptographic hash algorithm. This permutation-based hash algorithm is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of SHA-3_512 is compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. As per the National Institute of Standards and Technology (NIST) guidelines, SHA-3_512 is recommended for several use cases:

> "SHA-3 provides security strengths against preimage, second preimage and collision attacks [...] at the 256-bit security level."

Given this advice, NIST recommendations imply that SHA-3_512 is suitable for the following contexts:

- Digital signatures that require 256 bits of security.
- Cryptographic hash functions in systems and protocols requiring 256 bits of security.
- Authentication methods that necessitate 256 bits of security.

Beyond these specific recommendations, SHA-3_512 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].
- Key derivation functions or in generation of random numbers[^6].

These points should be carefully considered, given your overall security objectives and risk tolerance.

For access to a comprehensive range of cryptographic functions, `rs_sha3_512` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_sha3_512` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha3_512 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha3_512` module in your code. Here's an example of how to create a SHA-3_512 hash from a string:

    ```rust
    use rs_sha3_512::{HasherContext, Sha3_512Hasher};
    
    let mut sha3_512hasher = Sha3_512Hasher::default();
    sha3_512hasher.write(b"your string here");
    
    let u64result = sha3_512hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_512hasher);
    assert_eq!(u64result, 0x8FB6BC7A78EA3DDD);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "8fb6bc7a78ea3ddd267454718826f2b01b373dac4f947a2c7e0e0e27360392a58065e399062d837b53ed0413239d555fc5eac5b8a43c4c37684d1d6d30cb7fa3"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "8FB6BC7A78EA3DDD267454718826F2B01B373DAC4F947A2C7E0E0E27360392A58065E399062D837B53ED0413239D555FC5EAC5B8A43C4C37684D1D6D30CB7FA3"
    );
    assert_eq!(
        bytes_result,
        [
            0x8F, 0xB6, 0xBC, 0x7A, 0x78, 0xEA, 0x3D, 0xDD, 0x26, 0x74, 0x54, 0x71, 0x88, 0x26, 0xF2, 0xB0, 0x1B, 0x37,
            0x3D, 0xAC, 0x4F, 0x94, 0x7A, 0x2C, 0x7E, 0x0E, 0x0E, 0x27, 0x36, 0x03, 0x92, 0xA5, 0x80, 0x65, 0xE3, 0x99,
            0x06, 0x2D, 0x83, 0x7B, 0x53, 0xED, 0x04, 0x13, 0x23, 0x9D, 0x55, 0x5F, 0xC5, 0xEA, 0xC5, 0xB8, 0xA4, 0x3C,
            0x4C, 0x37, 0x68, 0x4D, 0x1D, 0x6D, 0x30, 0xCB, 0x7F, 0xA3
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha3_512`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

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
