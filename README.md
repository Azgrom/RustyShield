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

This project objective is to expand [Rust's core library](https://doc.rust-lang.org/stable/core/index.html) by providing a platform-agnostic set of cryptographic APIs all while also complying to the proposed design patterns found in [libcore generic hashing support](https://doc.rust-lang.org/core/hash/index.html) primitive traits coupling.

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

As shown below using the collision-free routine ends up being more idiomatic, as it passes to only to require that a given type implements the [`Hash`](https://doc.rust-lang.org/core/hash/trait.Hash.html#) trait to be hashed. BUT this feature may cause confusion and corruption if not properly standardized by a consumer of this library.

```rust
use rs_ssl::Sha1State;

fn main(){
    let sha1_default_state = Sha1State::default();
    let mut sha1_hasher = sha1_default_state.build_hasher();
    let quick_brown_fox: &str = "The quick brown fox jumps over the lazy dog";

    quick_brown_fox.hash(&mut sha1_hasher);
    let quick_brown_fox_sha1_result = sha1_hasher.finish();

    println!("Quick brown fox with 0xFF SHA1 u64 hex result: {:08x}", quick_brown_fox_sha1_result);
}
```

> Quick brown fox with 0xFF SHA1 u64 hex result: 8ce3a5582cfaa886

