//! # Blowfish - `rs_blowfish` - Symmetric Key Block Cipher
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! This crate, `rs_blowfish`, is part of the RustyShield project. The intent of the RustyShield project is to provide comprehensive cryptographic functionality for the Rust programming language, expanding upon Rust's core library abstractions.
//!
//! The `rs_blowfish` crate specifically aims to implement Blowfish, a symmetric-key block cipher that was invented by Bruce Schneier in 1993. Blowfish provides a good encryption rate in software and no effective cryptanalysis of it has been found to date.
//!
//! Blowfish is a symmetric key algorithm, which means the same key is used for encrypting and decrypting the data. It is suitable for applications where the key does not change often, like a communications link or an automatic file encryptor.

#![no_std]

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
