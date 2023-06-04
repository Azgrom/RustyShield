# `rs_sha1`

`rs_sha1` is a Rust crate offering the SHA-1 cryptographic hash algorithm. Designed for compatibility with Rust's libcore in a `#![no_std]` context, it operates as a standalone crate for specialized use cases and can also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is untenable.

This implementation of SHA-1 is compliant with the Federal Information Processing Standards (FIPS) Publication 180-4[^1]. However, due to the nature of SHA-1's vulnerability to collision attacks, it is not recommended by the National Institute of Standards and Technology (NIST) for any application that requires collision resistance. This aligns with the guidance from NIST Special Publication 800-107:

> "Federal agencies should stop using SHA-1 for [...] applications that require collision resistance as soon as practical, and must use the SHA-2 family of hash functions for these applications after 2010."

Given the above, NIST recommendations imply that SHA-1 should not be used in the following contexts:

- Cryptographic security applications requiring collision resistance.
- Generation of digital signatures and certificates.
- Cryptographic hash functions in new systems and protocols.

Yet, SHA-1 may still be utilized for non-security-critical applications, such as:

- Generation of a commit identifier in software versioning systems[^2].
- Computation of a hash-based message authentication code (HMAC), when collision resistance is not a requirement[^3].
- Data integrity checks in Merkle Trees[^4].
- Randomized hash function in a Bloom filter[^5].

Please, consider these points with care, given the overall security objectives and risk tolerance of your application.

For access to a comprehensive range of cryptographic functions, `rs_sha1` can be utilized as part of the `rs_ssl` library bundle.

## How To Use

Below are steps to use the `rs_sha1` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

   ```toml
   rs_sha1 = "0.1.*"
   ```

3. Use the functions provided by the `rs_sha1` module in your code. Here's an example of how to create a SHA-1 hash from a string:

    ```rust
    use rs_sha1::{HasherContext, Sha1Hasher};
    
    let mut sha1hasher = Sha1Hasher::default();
    
    sha1hasher.write(b"your string here");
    
    let u64result = sha1hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha1hasher);
    assert_eq!(u64result, 0x7D2C170805790AFA);
    assert_eq!(format!("{bytes_result:02x}"), "7d2c170805790afac408349a9c266a123d1961be");
    assert_eq!(format!("{bytes_result:02X}"), "7D2C170805790AFAC408349A9C266A123D1961BE");
    assert_eq!(
        bytes_result,
        [
            0x7D, 0x2C, 0x17, 0x08, 0x05, 0x79, 0x0A, 0xFA, 0xC4, 0x08, 0x34, 0x9A, 0x9C, 0x26, 0x6A, 0x12, 0x3D, 0x19, 0x61, 0xBE
        ]
    )
    ```

## More Information

For a more detailed exploration of `rs_sha1`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

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
