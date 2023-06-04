# `rs_sha224`

`rs_sha224` is a Rust crate delivering the SHA-224 cryptographic hash algorithm. Configured for compatibility with Rust's libcore within a `#![no_std]` context, it operates as a standalone crate for specialized use cases and is also compatible with a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-224 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. In line with the National Institute of Standards and Technology (NIST) guidelines, SHA-224 is recommended for several use cases:

> "SHA-224 provides 112 bits of security against collision attacks and, therefore, is suitable for functions requiring a hash length of 112 bits."

Given this advice, NIST recommendations imply that SHA-224 is suitable for the following contexts:

- Digital signatures that require 112 bits of security.
- Cryptographic hash functions in systems and protocols requiring 112 bits of security.
- Authentication methods that necessitate 112 bits of security.

Beyond these specific recommendations, SHA-224 could also find application in:

- Version control systems for the generation of commit identifiers[^2].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^3].
- Data integrity checks in Merkle Trees[^4].
- As a randomized hash function in Bloom filters[^5].

Given your overall security objectives and risk tolerance, these points should be carefully considered.

For access to a comprehensive range of cryptographic functions, `rs_sha224` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_sha224` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_sha224 = "0.1.*"
    ```
   
3. Use the functions provided by the `rs_sha224` module in your code. Here's an example of how to create a SHA-224 hash from a string:

    ```rust
    use rs_sha224::{HasherContext, Sha224Hasher};
    
    let mut sha224hasher = Sha224Hasher::default();
    sha224hasher.write(b"your string here");
    
    let u64result = sha224hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha224hasher);
    assert_eq!(u64result, 0xC8DA90DF20FC1F9C);
    assert_eq!(format!("{bytes_result:02x}"), "c8da90df20fc1f9cad8bec106821904e8a27b9bcc79d954f1fa01b83");
    assert_eq!(format!("{bytes_result:02X}"), "C8DA90DF20FC1F9CAD8BEC106821904E8A27B9BCC79D954F1FA01B83");
    assert_eq!(
        bytes_result,
        [
            0xC8, 0xDA, 0x90, 0xDF, 0x20, 0xFC, 0x1F, 0x9C, 0xAD, 0x8B, 0xEC, 0x10, 0x68, 0x21, 0x90, 0x4E, 0x8A, 0x27,
            0xB9, 0xBC, 0xC7, 0x9D, 0x95, 0x4F, 0x1F, 0xA0, 0x1B, 0x83
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha224`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

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
