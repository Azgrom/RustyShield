# rs_shake128

`rs_shake128` is a Rust crate offering the SHAKE128 cryptographic hash algorithm. This package is designed to function in a `#![no_std]` context, compatible with Rust's libcore, and caters to applications where the exclusive use of SHAKE128 is desired. Furthermore, it is suitable for a `#![no_std]`, `#![no_alloc]` environment, making it ideal for systems where dynamic memory allocation is not an option.

In accordance with the Federal Information Processing Standards (FIPS) 202, which defines the permutation-based hash and extendable-output functions (SHAKE), the SHAKE128 implementation provided here is endorsed by NIST for a variety of applications:

- Hash functions for Hash-based Quantum-resistant Cryptography ([source](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)).
- Computation of a hash-based message authentication code (HMAC) ([source](https://tools.ietf.org/html/rfc2104)).
- Random bit generation ([source](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)).
- Digital signatures, including the RSA signature scheme with Appendix – Probabilistic Signature Scheme (RSASSA-PSS) ([source](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-107r1.pdf)).
- Key derivation functions, such as those used in the generation and management of symmetric keys ([source](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf)).
- Data integrity verification and password storage, for instance, in PBKDF2 ([source](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-132.pdf)).

`rs_shake128` is also integrated into the `rs_ssl` library bundle, where it is available in combination with a wide range of cryptographic functions.

As projected by the NIST, SHAKE128 is anticipated to remain suitable for most cryptographic applications beyond the year 2030.

## More Information

For more detailed information about `rs_shake128`, the spectrum of cryptographic functions provided, and the wider `rs_ssl` project, visit the [RustySSL project page on GitHub](https://github.com/RustySSL/rs_ssl) or the [RustySSL crate on crates.io](https://crates.io/crates/rs_ssl).

## Contributions
Interested contributors are encouraged to follow the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) available on the project's GitHub page.

## License
This project is licensed under GPL-2.0-only.
