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

- **Minimal Dependencies and Supply Chain Security**: By relying solely on Rust's core library, RustySSL minimizes the risk of dependency-related issues and provides an increased level of supply chain security. Trust is only required in the Rust core library team.
- **No `alloc` extern crate and Platform-Agnostic**: RustySSL avoids the `alloc` crate, enabling it to function without assuming the host has a heap allocator and enabling more embedded applications and kernel-level use saces. Additionally, leveraging Rust's libcore ensures cross-platform reliability, reducing complexity for the end-user.
- **Consolidated Design Pattern**: By adhering to the [`Hash`, `Hasher`, and `BuildHasher` design pattern from Rust's core library](https://doc.rust-lang.org/core/hash/index.html), users can interchangeably use any algorithm with a basic understanding of these traits.
- **Ecosystem Self-Sufficiency**: The project strengthens the Rust ecosystem's self-sufficiency by relying on its own implementations, reducing reliance on external variables through FFI calls.

## Philosophy

Inspired by the Unix philosophy, but adapting to the purpose of this project:

1. **Do One Thing Well**: Each implementation should focus on a single responsibility. If responsibilities diverge, a new crate should be created.
2. **Avoid Dependency Breakage**: Changing implementations should not break dependencies. If new traits are required, they should benefit all project implementations.
3. **Self-Support**: Implementations should be able to function solely with Rust's libcore.
4. **Clarity Over Efficiency**: Clear, understandable code is prioritized over highly optimized but obscure solutions.

## Current Algorithms

| Name                                 |       Crate       |      |
| :----------------------------------- | :---------------: | ---- |
| SHA-1                                |     `rs_sha1`     |      |
| SHA-224                              |    `rs_sha224`    |      |
| SHA-256                              |    `rs_sha256`    |      |
| SHA-384                              |    `rs_sha384`    |      |
| SHA-512                              |    `rs_sha512`    |      |
| SHA-512/224                          |  `rs_sha512_224`  |      |
| SHA-512/256                          |  `rs_sha512_256`  |      |
| SHA3-224                             |   `rs_sha3_224`   |      |
| SHA3-256                             |   `rs_sha3_256`   |      |
| SHA3-384                             |   `rs_sha3_384`   |      |
| SHA3-512                             |   `rs_sha3_512`   |      |
| SHAKE128                             |   `rs_shake128`   |      |
| SHAKE256                             |   `rs_shake256`   |      |
| HMAC                                 |     `rs_hmac`     |      |
| Generic Keccak {200, 400, 800, 1600} | `rs_keccak_nbits` |      |

### Coming Soon

If anyone would like to see another algorithm not included here, I would love to hear about it!

| Ciphers       | Hashing Functions |         Public-key          |
| ------------- | :---------------- | :-------------------------: |
| AES           | BLAKE2            |             RSA             |
| Blowfish      | GOST R 34.11-94   |             DSA             |
| Camellia      | MD2               | Diffie-Hellman key exchange |
| Chacha20      | MD4               |       Elliptic curve        |
| Poly1305      | MD5               |           X25519            |
| SEED          | MDC-2             |           Ed25519           |
| CAST-128      | RIPEMD-160        |            X448             |
| DES           | SM3               |            Ed448            |
| IDEA          | Whirlpool         |      GOST R 34.10-2001      |
| RC2           |                   |             SM2             |
| RC4           |                   |                             |
| RC5           |                   |                             |
| Triple DES    |                   |                             |
| GOST 28147-89 |                   |                             |
| SM4           |                   |                             |
