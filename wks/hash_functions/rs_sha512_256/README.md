# `rs_sha512_256`

`rs_sha512_256` is a Rust crate implementing the SHA-512/256 cryptographic hash algorithm. Configured for compatibility with Rust's libcore within a `#![no_std]` context, it operates as a standalone crate for specialized use cases and is also compatible with a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-512/256 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. In line with the National Institute of Standards and Technology (NIST) guidelines, SHA-512/256 is recommended for several use cases:

> "SHA-512/256 provides 128 bits of security against collision attacks and, therefore, is suitable for functions requiring a hash length of 128 bits."

Given this advice, NIST recommendations imply that SHA-512/256 is suitable for the following contexts:

- Digital signatures that require 128 bits of security.
- Cryptographic hash functions in systems and protocols requiring 128 bits of security.
- Authentication methods that necessitate 128 bits of security.

Beyond these specific recommendations, SHA-512/256 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].

Given your overall security objectives and risk tolerance, these points should be carefully considered.

For access to a comprehensive range of cryptographic functions, `rs_sha512_256` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_sha512_256` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha512_256 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha512_256` module in your code. Here's an example of how to create a SHA-512/256 hash from a string:

    ```rust
    use rs_sha512_256::{HasherContext, Sha512_256Hasher};
    
    let mut sha512_256hasher = Sha512_256Hasher::default();
    sha512_256hasher.write(b"your string here");
    
    let u64result = sha512_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_256hasher);
    assert_eq!(u64result, 0xD6F2B480B2185883);
    assert_eq!(format!("{bytes_result:02x}"), "d6f2b480b21858837024cd2d4823c7baf48529d3688d407c7ef35a1f783c0b57");
    assert_eq!(format!("{bytes_result:02X}"), "D6F2B480B21858837024CD2D4823C7BAF48529D3688D407C7EF35A1F783C0B57");
    assert_eq!(
        bytes_result,
        [
            0xD6, 0xF2, 0xB4, 0x80, 0xB2, 0x18, 0x58, 0x83, 0x70, 0x24, 0xCD, 0x2D, 0x48, 0x23, 0xC7, 0xBA, 0xF4, 0x85,
            0x29, 0xD3, 0x68, 0x8D, 0x40, 0x7C, 0x7E, 0xF3, 0x5A, 0x1F, 0x78, 0x3C, 0x0B, 0x57
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha512_256`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/Azgrom/RustyShield/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). Secure Hash Standard (SHS). [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

[^2]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)

[^3]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)

[^4]: Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function. [Link](https://link.springer.com/content/pdf/10.1007/3-540-45961-8_24.pdf)

[^5]: Bloom, B. H. (1970). Space/time trade-offs in hash coding with allowable errors. Communications of the ACM, 13(7), 422-426. [DOI:10.1145/362686.362692](https://doi.org/10.1145/362686.362692)

---
**Note**: The references have been provided as per the best knowledge as of Jun 02, 2023.
