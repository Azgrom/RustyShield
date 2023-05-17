<!-- Allow this file to not have a first line heading -->
<!-- markdownlint-disable-file MD041 -->
<!-- Disable warning on emphasis after first heading -->
<!-- markdownlint-disable-file MD036 -->

<!-- inline html -->
<!-- markdownlint-disable-file MD033 -->

<div align="center">

# RustySSL `rs-ssl`

**An OpenSSL inspired Rust based encryption library** 

[![Documentation](https://img.shields.io/badge/docs-API-blue)](https://crates.io/)
[![GitHub Workflow Status](https://github.com/Azgrom/RustySSL/workflows/Cargo%20Build%20&%20Test/badge.svg?branch=master)](https://github.com/Azgrom/RustySSL/actions)

</div>

## Vision

RustySSL seeks to establish the Rust language self-sufficency by offering an API that is fully compatible with [*Rust's core library*](https://doc.rust-lang.org/stable/core/index.html) , although not restricted to it. RustySSL aims to provide a reliable, user-friendly, standards-compliant, and platform-agnostic suite of  encryption tools.

## How To Use

See the implementation documentation for examples.

## RoadMap

1. The initial objective of RustySSL is to port all OpenSSL algorithms to the Rust ecosystem.
2. Following the port, RustySSL will continue to expand and incorporate additional cryptographic algorithms.
3. Although the current implementations are not the fastest, there is considerable room for improvement.  There will probably a competitive performance boost once the [SIMD module](https://doc.rust-lang.org/core/simd/index.html) stabilizes;

At this moment the objective is to provide all OpenSSL's current set of algorithms. After that I plan to implement some cryptocurrencies hashing algorithms like [Equihash](https://en.wikipedia.org/wiki/Equihash), [Ethereum's Keccak-256](https://ethereum.org/en/developers/docs/consensus-mechanisms/pow/mining-algorithms/ethash/) and others.

## Why This Project?

The benefits of RustySSL include:

- **Minimal Dependencies and Supply Chain Security**: By relying solely on Rust's core library, RustySSL minimizes the risk of dependency-related issues and provides an increased level of supply chain security. Trust is only required in the Rust core library team;
- **No `alloc` extern crate and Platform-Agnostic**: RustySSL avoids the `alloc` crate, enabling it to function without assuming the host has a heap allocator and enabling more embedded applications and kernel-level use saces. Additionally, leveraging Rust's libcore ensures cross-platform reliability, reducing complexity for the end-user;
- **Consolidated Design Pattern**: By adhering to the [`Hash`, `Hasher`, and `BuildHasher` design pattern from Rust's core library](https://doc.rust-lang.org/core/hash/index.html), users can interchangeably use any algorithm with a basic understanding of these traits;
- **Ecosystem Self-Sufficiency**: The project strengthens the Rust ecosystem's self-sufficiency by relying on its own implementations, reducing reliance on external variables through FFI calls.

## Philosophy

Inspired by the Unix philosophy, but adapting to the purpose of this project:

1. **Do One Thing Well**: Each implementation should focus on a single responsibility. If responsibilities diverge, a new crate should be created.
2. **Avoid Dependency Breakage**: Changing implementations should not break dependencies. If new traits are required, they should benefit all project implementations.
3. **Self-Support**: Implementations should be able to function solely with Rust's libcore and be backward compatible with it.
4. **Clarity Over Efficiency**: Clear, understandable code is prioritized over highly optimized but obscure solutions.

## Supported Algorithms

|            Ciphers            |                    Hashing Functions                     |                 Public-key                  |
| :---------------------------: | :------------------------------------------------------: | :-----------------------------------------: |
|      AES - `coming soon`      |                    SHA-1 - `rs_sha1`                     |             RSA - `coming soon`             |
|   Blowfish - `coming soon`    |                  SHA-224  - `rs_sha224`                  |             DSA - `coming soon`             |
|   Camellia - `coming soon`    |                  SHA-256 - `rs_sha256`                   | Diffie-Hellman key exchange - `coming soon` |
|   Chacha20 - `coming soon`    |                  SHA-384 - `rs_sha384`                   |       Elliptic curve - `coming soon`        |
|   Poly1305 - `coming soon`    |                  SHA-512 - `rs_sha512`                   |           X25519 - `coming soon`            |
|     SEED - `coming soon`      |              SHA-512/224 - `rs_sha512_224`               |           Ed25519 - `coming soon`           |
|   CAST-128 - `coming soon`    |              SHA-512/256 - `rs_sha512_256`               |            X448 - `coming soon`             |
|      DES - `coming soon`      |                 SHA3-224 - `rs_sha3_224`                 |            Ed448 - `coming soon`            |
|     IDEA - `coming soon`      |                 SHA3-256 - `rs_sha3_256`                 |      GOST R 34.10-2001 - `coming soon`      |
|      RC2 - `coming soon`      |                 SHA3-384 - `rs_sha3_384`                 |             SM2 - `coming soon`             |
|      RC4 - `coming soon`      |                 SHA3-512 - `rs_sha3_512`                 |                                             |
|      RC5 - `coming soon`      |                 SHAKE128 - `rs_shake128`                 |                                             |
|  Triple DES - `coming soon`   |                 SHAKE256 - `rs_shake256`                 |                                             |
| GOST 28147-89 - `coming soon` |                     HMAC - `rs_hmac`                     |                                             |
|      SM4 - `coming soon`      | Generic Keccak {200, 400, 800, 1600} - `rs_keccak_nbits` |                                             |
|                               |                  BLAKE2 - `coming soon`                  |                                             |
|                               |             GOST R 34.11-94 - `coming soon`              |                                             |
|                               |                   MD2 - `coming soon`                    |                                             |
|                               |                   MD4 - `coming soon`                    |                                             |
|                               |                   MD5 - `coming soon`                    |                                             |
|                               |                  MDC-2 - `coming soon`                   |                                             |
|                               |                RIPEMD-160 - `coming soon`                |                                             |
|                               |                   SM3 - `coming soon`                    |                                             |
|                               |                Whirlpool - `coming soon`                 |                                             |

## Contributing

Contributions will very much welcomed contributions from everyone. 

If you have a suggestion of an algorithm that you want to see included in this project, please open an issue proposing it.

To contribute, please follow the [contribution guidelines](./CONTRIBUTING.md).

## License

RustySSL is licensed under GPL-2.0-only. 

In plain English, this means you are free to use, modify, and distribute the software, provided that any modification must also be licensed under GPL-2.0-only. Or, if more convenient, for a modification that is an improvement and conforms to the [contribution guidelines](,/CONTRIBUTING.md) to bring it to the project.
