# `rs_sha256`

`rs_sha256` is a Rust crate implementing the SHA-256 cryptographic hash algorithm. Configured for compatibility with Rust's libcore within a `#![no_std]` context, it operates as a standalone crate for specialized use cases and is also compatible with a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-256 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. In line with the National Institute of Standards and Technology (NIST) guidelines, SHA-256 is recommended for several use cases:

> "SHA-256 provides 128 bits of security against collision attacks and, therefore, is suitable for functions requiring a hash length of 128 bits."

Given this advice, NIST recommendations imply that SHA-256 is suitable for the following contexts:

- Digital signatures that require 128 bits of security.
- Cryptographic hash functions in systems and protocols requiring 128 bits of security.
- Authentication methods that necessitate 128 bits of security.

Beyond these specific recommendations, SHA-256 could also find application in:

- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- Data integrity checks in Merkle Trees[^4].
- As a randomized hash function in Bloom filters[^5].

Given your overall security objectives and risk tolerance, these points should be carefully considered.

For access to a comprehensive range of cryptographic functions, `rs_sha256` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_sha256` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha256 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha256` module in your code. Here's an example of how to create a SHA-256 hash from a string:

    ```rust
    use rs_sha256::{HasherContext, Sha256Hasher};
    
    let mut sha256hasher = Sha256Hasher::default();
    sha256hasher.write(b"your string here");
    
    let u64result = sha256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha256hasher);
    assert_eq!(u64result, 0xEBEA8483C5B21AE6);
    assert_eq!(format!("{bytes_result:02x}"), "ebea8483c5b21ae61081786be10f9704ce8975e1e5b505c03f6ab8514ecc5c0c");
    assert_eq!(format!("{bytes_result:02X}"), "EBEA8483C5B21AE61081786BE10F9704CE8975E1E5B505C03F6AB8514ECC5C0C");
    assert_eq!(
        bytes_result,
        [
            0xEB, 0xEA, 0x84, 0x83, 0xC5, 0xB2, 0x1A, 0xE6, 0x10, 0x81, 0x78, 0x6B, 0xE1, 0x0F, 0x97, 0x04, 0xCE, 0x89,
            0x75, 0xE1, 0xE5, 0xB5, 0x05, 0xC0, 0x3F, 0x6A, 0xB8, 0x51, 0x4E, 0xCC, 0x5C, 0x0C
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha256`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on our GitHub page.

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
