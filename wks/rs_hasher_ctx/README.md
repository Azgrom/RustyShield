# `rs_hasher_ctx`

The `rs_hasher_ctx` crate provides the `HasherContext` trait, including a redefinition of `Hasher::finish()`. This crate is considered as an internal trait of `rs_ssl`, and it is primarily intended to streamline the dependencies in the broader RustySSL project.

While `rs_hasher_ctx` can be used independently, its primary purpose is to offer a consistent and shared context for all cryptographic hash function crates in the RustySSL library. Each hash function that makes use of `rs_hasher_ctx` is able to export the `HasherContext` trait, which in turn minimizes the number of dependency declarations required in any given crate.

## How To Use

Here are the steps to use the `rs_hasher_ctx` crate in your Rust projects:

1. Add the following line to your `Cargo.toml` under the `[dependencies]` section:

    ```toml
    rs_hasher_ctx = "0.1.*"
    ```
   
3. Use the `HasherContext` trait in your code as follows:

    ```rust
    use rs_hasher_ctx::HasherContext;
    ```

## More Information

For a more detailed exploration of `rs_hasher_ctx`, an overview of other available cryptographic functions, and an introduction to the broader `rs_ssl` project, please consult the [RustySSL project page on crates.io](https://crates.io/crates/rs_ssl).

## Contributions

Potential contributors are encouraged to consult the [contribution guidelines](https://github.com/RustySSL/rs_ssl/CONTRIBUTING.md) on our GitHub page.

## License

This project is licensed under GPL-2.0-only.
