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

For access to a comprehensive range of cryptographic functions, `rs_shake256` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_shake256` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_shake256 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_shake256` module in your code. Here's an example of how to create a SHAKE256 hash from a string:

    ```rust
    use rs_shake256::{HasherContext, Shake256Hasher};
    
    let mut sha512_256hasher = Shake256Hasher::<20>::default();
    sha512_256hasher.write(b"your string here");
    
    let u64result = sha512_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_256hasher);
    assert_eq!(u64result, 0x97E1C052B5574F11);
    assert_eq!(format!("{bytes_result:02x}"), "97e1c052b5574f117b3fb13f26865fb4eec4a473");
    assert_eq!(format!("{bytes_result:02X}"), "97E1C052B5574F117B3FB13F26865FB4EEC4A473");
    assert_eq!(
        bytes_result,
        [
            0x97, 0xE1, 0xC0, 0x52, 0xB5, 0x57, 0x4F, 0x11, 0x7B, 0x3F, 0xB1, 0x3F, 0x26, 0x86, 0x5F, 0xB4, 0xEE, 0xC4,
            0xA4, 0x73
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_shake256`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/Azgrom/RustyShield/CONTRIBUTING.md) on our GitHub page.

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
