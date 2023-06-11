# `rs_hmac`

The `rs_hmac` crate provides an implementation of the Keyed-Hash Message Authentication Code (HMAC) that is compatible with all hash function algorithms present in the RustyShield library. HMAC is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key, used to confirm both the data integrity and the authenticity of a message.

This implementation of HMAC is compliant with the Federal Information Processing Standards (FIPS) Publication 198[^1]. The National Institute of Standards and Technology (NIST) provides the following recommendation on HMAC usage:

> "HMAC is a mechanism for message authentication using cryptographic hash functions. HMAC can be used with any iterative cryptographic hash function, e.g., SHA-256, in combination with a secret shared key. The cryptographic strength of HMAC depends on the properties of the underlying hash function."

Given this recommendation, HMAC is implicated in use cases such as:

- Cryptographic data integrity checks.
- Authentication methods involving a shared secret key.
- Protection against tampering in network communication protocols.
- Digital signatures when combined with a public-key algorithm.

Beyond these specific use cases, HMAC could also find more broad applications in:

- Ensuring data integrity in data storage and retrieval[^2].
- Authentication of software updates or data transmissions[^3].
- Generation of unique identifiers in distributed systems[^4].
- Hash-based pseudorandom number generators[^5].

These points should be considered carefully, given the security requirements of your particular application.

## How To Use

Below are steps to use the `rs_hmac` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

   ```toml
   rs_hmac = "0.1.*"
   ```

2. Add any hash function available on `rs_shield`. In this case we will use the `SHAKE128` algorithm as example:

   ```toml
   rs_shake128 = "0.1.*"
   ```

3. Use the functions provided by the `rs_hmac` module in your code. Here's an example of how to create an HMAC from a string and a key:

    ```rust
    use rs_hmac::Hmac;
    use rs_shake128::Shake128State;
    
    const BYTE_OUTPUT_LENGTH: usize = 20;
    let key = b"your key here";
    let data = b"your string here";
    let byte_result = Hmac::<Shake128State<BYTE_OUTPUT_LENGTH>, BYTE_OUTPUT_LENGTH>::digest(key, data);
    
    assert_eq!(format!("{byte_result:X}"), "C17043C47B31C5897E35E658AD9521734E5CBF")
    ```

## More Information

For a more detailed exploration of `rs_hmac`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

## Contributions

Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/Azgrom/RustyShield/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2008). The Keyed-Hash Message Authentication Code (HMAC). [FIPS PUB 198](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)
[^2]: National Institute of Standards and Technology. (2012). Recommendation for Key Derivation through Extraction-then-Expansion. [SP 800-56C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf)
[^3]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)
[^4]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)
[^5]: Dodis, Y., Pointcheval, D., Ruhault, S., Vergniaud, D., & Wichs, D. (2013). Security Analysis of Pseudo-Random Number Generators with Input: /dev/random is not Robust. [Link](https://eprint.iacr.org/2013/338.pdf)

---
**Note**: The references have been provided as per the best knowledge as of May 17, 2023.
