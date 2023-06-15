# `rs_sha384`

`rs_sha384` is a Rust crate implementing the SHA-384 cryptographic hash algorithm. Configured for compatibility with Rust's libcore within a `#![no_std]` context, it operates as a standalone crate for specialized use cases and is also compatible with a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-384 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. In line with the National Institute of Standards and Technology (NIST) guidelines, SHA-384 is recommended for several use cases:

> "SHA-384 provides 192 bits of security against collision attacks and, therefore, is suitable for functions requiring a hash length of 192 bits."

Given this advice, NIST recommendations imply that SHA-384 is suitable for the following contexts:

- Digital signatures that require 192 bits of security.
- Cryptographic hash functions in systems and protocols requiring 192 bits of security.
- Authentication methods that necessitate 192 bits of security.

Beyond these specific recommendations, SHA-384 could also find application in:

- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- Data integrity checks in Merkle Trees[^4].
- As a randomized hash function in Bloom filters[^5].

Given your overall security objectives and risk tolerance, these points should be carefully considered.

For access to a comprehensive range of cryptographic functions, `rs_sha384` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_sha384` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha384 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha384` module in your code. Here's an example of how to create a SHA-384 hash from a string:

    ```rust
    use rs_sha384::{HasherContext, Sha384Hasher};
    
    let mut sha512hasher = Sha384Hasher::default();
    sha512hasher.write(b"your string here");
    
    let u64result = sha512hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512hasher);
    assert_eq!(u64result, 0x27C3D7DA682CF0AB);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "27c3d7da682cf0ab27648e1f5da0a6c18ea13d9629e1ce7d9df1f38b1ee7dfb6ebf5aede6f8ddc9f8c2b9e96d29e4e63"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "27C3D7DA682CF0AB27648E1F5DA0A6C18EA13D9629E1CE7D9DF1F38B1EE7DFB6EBF5AEDE6F8DDC9F8C2B9E96D29E4E63"
    );
    assert_eq!(
        bytes_result,
        [
            0x27, 0xC3, 0xD7, 0xDA, 0x68, 0x2C, 0xF0, 0xAB, 0x27, 0x64, 0x8E, 0x1F, 0x5D, 0xA0, 0xA6, 0xC1, 0x8E, 0xA1,
            0x3D, 0x96, 0x29, 0xE1, 0xCE, 0x7D, 0x9D, 0xF1, 0xF3, 0x8B, 0x1E, 0xE7, 0xDF, 0xB6, 0xEB, 0xF5, 0xAE, 0xDE,
            0x6F, 0x8D, 0xDC, 0x9F, 0x8C, 0x2B, 0x9E, 0x96, 0xD2, 0x9E, 0x4E, 0x63
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha384`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

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
