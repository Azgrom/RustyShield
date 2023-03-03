<!-- Allow this file to not have a first line heading -->
<!-- markdownlint-disable-file MD041 -->
<!-- Disable warning on emphasis after first heading -->
<!-- markdownlint-disable-file MD036 -->

<!-- inline html -->
<!-- markdownlint-disable-file MD033 -->

<div align="center">
# RustySSL `rs-ssl`

------

**An OpenSSL inspired Rust set of reliable, easy to use, standards compliant and `no_std` encryption tools** 

[![Documentation](https://img.shields.io/badge/docs-API-blue)](https://crates.io/)
[![GitHub Workflow Status](https://github.com/Azgrom/RustySSL/workflows/Cargo%20Build%20&%20Test/badge.svg?branch=master)](https://github.com/Azgrom/RustySSL/actions)

</div>

## Vision

This project objective is to expand [Rust's core library](https://doc.rust-lang.org/stable/core/index.html) by providing a platform-agnostic set of cryptographic APIs while also complying to the proposed design patterns found in [libcore generic hashing support](https://doc.rust-lang.org/core/hash/index.html) primitive traits coupling.

## How to use

```rust
use rs_ssl::Sha1State;

fn main(){
    let sha1_default_state = Sha1State::default();
    let mut sha1_hasher = sha1_default_state.build_hasher();
    let quick_brown_fox: &str = "The quick brown fox jumps over the lazy dog";

    sha1_hasher.write(quick_brown_fox.as_ref());
    let quick_brown_fox_sha1_result = sha1_hasher.finish();

    println!("Quick brown fox SHA1 u64 hex result: {:08x}", quick_brown_fox_sha1_result);
}
```

> Default SHA1 hasher u64 hex result: 2fd4e1c67a2d28fc

As [Rust's Hash trait implementation for the `str`](https://doc.rust-lang.org/core/hash/trait.Hash.html#prefix-collisions) primitive tries to ensure prefix collisions resiliency for any  type that implements the [Hasher trait](https://doc.rust-lang.org/core/hash/trait.Hasher.html), it should be noted that unless you pass a reference of `[u8]` instead of `str` or `String` it will pass an extra `0xFF` byte to the `Hasher` so that the [resulting state of `["ab", "c"]` be completely different from `["a", "bc"]`](https://doc.rust-lang.org/core/hash/trait.Hash.html#prefix-collisions).

Because of that, the `.as_ref()` from the example above conveniently casts the `quick_brown_fox` string to a byte array.

As shown below using the collision-free routine ends up being more idiomatic, as it passes to require that a given type implements the [`Hash`](https://doc.rust-lang.org/core/hash/trait.Hash.html#) trait to be hashed. BUT this feature may cause confusion and corruption if not properly standardized by a consumer of this library.

```rust
use rs_ssl::Sha1State;

fn main() {
    let sha1_default_state = Sha1State::default();
    let mut sha1_hasher = sha1_default_state.build_hasher();
    let quick_brown_fox: &str = "The quick brown fox jumps over the lazy dog";

    quick_brown_fox.hash(&mut sha1_hasher);
    let quick_brown_fox_sha1_result = sha1_hasher.finish();

    println!("Quick brown fox with 0xFF SHA1 u64 hex result: {:08x}", quick_brown_fox_sha1_result);
}
```

> Quick brown fox with 0xFF SHA1 u64 hex result: 8ce3a5582cfaa886

## Roadmap

At this moment the objective is to provide all OpenSSL's current set of algorithms. After that I plan to implement some cryptocurrencies hashing algorithms like [Equihash](https://en.wikipedia.org/wiki/Equihash), [Ethereum's Keccak-256](https://ethereum.org/en/developers/docs/consensus-mechanisms/pow/mining-algorithms/ethash/) and others.

## Why to make this project?

It is not a second-system syndrome. The point is:

- Until now there were no standardized Rust implementations following a common underlying abstraction;
- The Rust core library already provides all the necessary building blocks to develop hashing algorithms;
- A set of `#![no_std]` hashing function implementations would not only to compile relatively fast, but would also be considerably easy to:
  - Port on any platform; 
  - Switch algorithms between themselves;
  - And abstract away the cross-platform reliability assurance to the libcore;

- Even though an OpenSSL FFI call serves pretty well it still is an external dependency that would mostly not be directly compiled and optimized but used the one already present on the OS. This could compromise some niche and important optimization, reliability on other platforms and potentially ship some dead weight to the final application;
- Although the current implementations are not the fastest, there is considerable room for improvement.  I believe we might see a competitive performance boost once the [SIMD module](https://doc.rust-lang.org/core/simd/index.html) stabilizes;

So I hope this project may contribute to the Rust ecosystem maturity by facilitating further development with Rust as a platform-agnostic, [self-sufficient](https://doc.rust-lang.org/stable/embedded-book/intro/no-std.html), consistent, lean, reliable and performatic language.

### Hash functions

| Name        |      Crate      |      |
| :---------- | :-------------: | ---- |
| SHA-1       |    `rs_sha1`    |      |
| SHA-224     |   `rs_sha224`   |      |
| SHA-256     |   `rs_sha256`   |      |
| SHA-384     |   `rs_sha384`   |      |
| SHA-512     |   `rs_sha512`   |      |
| SHA-512/224 | `rs_sha512_224` |      |
| SHA-512/256 | `rs_sha512_256` |      |

### Public-key

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
| DES           | SHA3-224          |            Ed448            |
| IDEA          | SHA3-256          |      GOST R 34.10-2001      |
| RC2           | SHA3-384          |             SM2             |
| RC4           | SHA3-512          |                             |
| RC5           | SHAKE128          |                             |
| Triple DES    | SHAKE256          |                             |
| GOST 28147-89 | SM3               |                             |
| SM4           | Whirlpool         |                             |
