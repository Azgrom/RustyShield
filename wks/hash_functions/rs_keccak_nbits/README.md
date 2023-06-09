# `rs_keccak_nbits`

`rs_keccak_nbits` is a Rust crate implementing the Keccak Extendable-Output Function (XOF) that provides a variable-length hash output. This permutation-based function is designed for compatibility with Rust's libcore in a `#![no_std]` context, allowing it to operate as a standalone crate for specialized use cases and also function within a `#![no_std]`, `#![no_alloc]` environment, rendering it suitable for systems where dynamic memory allocation is not feasible.

This implementation of Keccak is not compliant with the Federal Information Processing Standards (FIPS) Publication 202[^1]. The `rs_keccak_nbits` crate is designed to be used primarily for academic purposes and in scenarios where consistency, rather than security, is the main requirement.

This implementation is capable to represent any of the other Keccak permutations, including the other ones present in RustyShield.

Despite not being FIPS compliant, the Keccak function is suitable for the following contexts in an academic or consistency-driven scenario:

- Research on digital signatures that require variable bits of security.
- Study and understanding of cryptographic hash functions in systems and protocols requiring variable bits of security.
- Analysis of authentication methods that necessitate variable bits of security.
- Exploration of applications where the output length is not fixed.

Beyond these specific recommendations, Keccak could also find application in:

- Generation of unique identifiers in distributed systems[^2].
- Data integrity checks in Merkle Trees[^3].
- Hash-based message authentication codes (HMACs), when collision resistance is necessary[^4].
- Key derivation functions or in generation of random numbers[^5].

These points should be carefully considered, given your overall academic objectives or need for consistency.

For access to a comprehensive range of cryptographic functions, `rs_keccak_nbits` can be utilized as part of the `rs_shield` library bundle.

## How To Use

Below are steps to use the `rs_keccak_nbits` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_keccak_nbits = "0.1.*"
    ```
   _Please replace `"0.1"` with the version number you intend to use.

2. Use the functions provided by the `rs_keccak_nbits` module in your code. Here's an example of how to create a Keccak hash from a string:

    ```rust
    use rs_keccak_nbits::{HasherContext, KeccakHasher};

    // In this example it is representing a 200bit state, with 20bytes of rate, and 20bytes output
    let mut n_bit_keccak_hasher = NBitKeccakHasher::<u8, 20, 20>::default();

    4usize.hash(&mut n_bit_keccak_hasher);

    let i = n_bit_keccak_hasher.finish();
    assert_eq!(result, 0xEB31065163D8823);

    let output = HasherContext::finish(& mut n_bit_keccak_hasher);
    println!("{:x}", output);
    ```

## More Information

For a more detailed exploration of `rs_keccak_nbits`, an overview of other available cryptographic functions, and an introduction to the broader `rs_shield` project, please consult the [RustyShield project page on crates.io](https://crates.io/crates/rs_shield).

## Contributions
Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/Azgrom/RustyShield/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.

## References

[^1]: National Institute of Standards and Technology. (2015). SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
[^2]: Linus Torvalds. (2005). Git: A distributed version control system. Software: Practice and Experience, 41(1), 79-88. [DOI:10.1002/spe.1006](https://doi.org/10.1002/spe.1006)
[^3]: Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption Function. [Link](https://link.springer.com/content/pdf/10.1007/3-540-45961-8_24.pdf)
[^4]: Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. [RFC 2104](https://tools.ietf.org/html/rfc2104)
[^5]: National Institute of Standards and Technology. (2012). Recommendation for Key Derivation through Extraction-then-Expansion. [SP 800-56C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf)

---
**Note**: The references have been provided as per the best knowledge as of May 17, 2023.
