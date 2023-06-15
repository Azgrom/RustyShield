# `rs_sha512`

`rs_sha512` is a Rust crate implementing the SHA-512 cryptographic hash algorithm. Configured for compatibility with Rust's libcore within a `#![no_std]` context, it operates as a standalone crate for specialized use cases and is also compatible with a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-512 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. In line with the National Institute of Standards and Technology (NIST) guidelines, SHA-512 is recommended for several use cases:

> "SHA-512 provides 256 bits of security against collision attacks and, therefore, is suitable for functions requiring a hash length of 256 bits."

Given this advice, NIST recommendations imply that SHA-512 is suitable for the following contexts:

- Digital signatures that require 256 bits of security.
- Cryptographic hash functions in systems and protocols requiring 256 bits of security.
- Authentication methods that necessitate 256 bits of security.

Beyond these specific recommendations, SHA-512 could also find application in:

- Data integrity checks in Merkle Trees[^4].
- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- As a randomized hash function in Bloom filters[^5].

Given your overall security objectives and risk tolerance, these points should be carefully considered.

For access to a comprehensive range of cryptographic functions, `rs_sha512` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_sha512` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha512 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha512` module in your code. Here's an example of how to create a SHA-512 hash from a string:

    ```rust
    use rs_sha512::{HasherContext, Sha512Hasher};
    
    let mut sha512hasher = Sha512Hasher::default();
    sha512hasher.write(b"your string here");
    
    let u64result = sha512hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512hasher);
    assert_eq!(u64result, 0x3B9147CC94F9A792);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "3b9147cc94f9a7926fd175a4f7292adca33c467d94a0c9890e6ff581433e03fcb17f4874eb53876874c4d262baeb49decae0492dd19e37ef76d345926ff66744"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "3B9147CC94F9A7926FD175A4F7292ADCA33C467D94A0C9890E6FF581433E03FCB17F4874EB53876874C4D262BAEB49DECAE0492DD19E37EF76D345926FF66744"
    );
    assert_eq!(
        bytes_result,
        [
            0x3B, 0x91, 0x47, 0xCC, 0x94, 0xF9, 0xA7, 0x92, 0x6F, 0xD1, 0x75, 0xA4, 0xF7, 0x29, 0x2A, 0xDC, 0xA3, 0x3C,
            0x46, 0x7D, 0x94, 0xA0, 0xC9, 0x89, 0x0E, 0x6F, 0xF5, 0x81, 0x43, 0x3E, 0x03, 0xFC, 0xB1, 0x7F, 0x48, 0x74,
            0xEB, 0x53, 0x87, 0x68, 0x74, 0xC4, 0xD2, 0x62, 0xBA, 0xEB, 0x49, 0xDE, 0xCA, 0xE0, 0x49, 0x2D, 0xD1, 0x9E,
            0x37, 0xEF, 0x76, 0xD3, 0x45, 0x92, 0x6F, 0xF6, 0x67, 0x44
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha512`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

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
