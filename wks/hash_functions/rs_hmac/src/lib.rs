//! # HMAC `rs-hmac` - Hash-based Message Authentication Code
//!
//! This HMAC implementation is a specific type of message authentication code (MAC) involving a cryptographic hash
//! function in combination with a secret cryptographic key. It was developed by the National Institute of Standards and
//! Technology (NIST).
//!
//! The HMAC function implemented in this crate is compatible with any hash function present in the encompassing
//! project.
//!
//! HMAC is suitable for a range of cryptographic purposes, including verifying the data integrity and the authenticity
//! of a message. It is typically used in data communications and is crucial for many protocols to ensure data hasn't
//! been tampered with during transmission.
//!
//! ## Usage
//!
//! The crate provides a straightforward API. Users can create a new HMAC instance, update it with input data, and
//! finalize to get the resultant MAC.
//!
//! ### Example
//!
//! Here is an example of how to use the HMAC function with SHA3-256 in Rust:
//!
//! ```rust
//! # use std::hash::Hasher;
//! # use rs_hmac::Hmac;
//! # use rs_sha3_256::Sha3_256State;
//! let mut hmac = Hmac::<Sha3_256State, 32>::new(b"my secret and secure key");
//! hmac.write(b"hello world");
//! let result = hmac.finish();
//! assert_eq!(result, 0xF9C0C982D2F30FE5);
//! ```
//!
//! ## Use Cases
//!
//! HMAC is recommended for a variety of tasks, including:
//!
//! - Ensuring data integrity and authenticity in data communications.
//! - Authenticating API requests.
//! - Secure password storage.
//!
//! [NIST](https://www.nist.gov/) recommends HMAC for ensuring data integrity and authenticity, particularly when it is
//! crucial to verify that data has not been tampered with during communication.
//!

#![no_std]

use core::hash::{Hash, Hasher};
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::{HashAlgorithm, LenPad};
use internal_state::BytesLen;

const INNER_PAD: u8 = 0x36;
const OUTER_PAD: u8 = 0x5c;

/// `Hmac<H: Default + HashAlgorithm, const OUTPUT_SIZE: usize>` is a generic struct that provides the HMAC (Hash-based
/// Message Authentication Code) in Rust.
///
/// In the context of cryptographic hashing, HMAC is an algorithm that combines a specified Hash function (`H`) and a
/// secret cryptographic key to convert input data into a fixed-size sequence of bytes. The HMAC is responsible for
/// maintaining the internal state of the hashing process and providing methods to add more data and retrieve the
/// resultant Message Authentication Code (MAC).
///
/// The `Hmac` struct is implemented using any hash function available in this crate, making it a flexible choice for
/// HMAC operations.
///
/// ## Examples
///
/// The following examples demonstrate using `Hmac` with both `Hash` and `Hasher`, and illustrate the difference between
/// these approaches:
///
///```rust
/// # use std::hash::{Hash, Hasher};
/// # use rs_hmac::Hmac;
/// use rs_sha3_512::Sha3_512State;
/// let data = b"hello";
/// let key = b"my secret and secure key";
///
/// // Using Hash
/// let mut hmac_hash = Hmac::<Sha3_512State, 64>::new(key);
/// data.hash(&mut hmac_hash);
/// let result_via_hash = hmac_hash.finish();
///
/// // Using Hasher
/// let mut hmac_hasher = Hmac::<Sha3_512State, 64>::new(key);
/// hmac_hasher.write(data);
/// let result_via_hasher = hmac_hasher.finish();
///
/// // Simulating the Hash inners
/// let mut hmac_simulate = Hmac::<Sha3_512State, 64>::new(key);
/// hmac_simulate.write_usize(data.len());
/// hmac_simulate.write(data);
/// let simulated_hash_result = hmac_simulate.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
///
/// Note that in the context of HMAC, the hash operation applies a different set of operations than the hasher's
/// `write`, which results in different outcomes.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Hmac<H: Default + HashAlgorithm, const OUTPUT_SIZE: usize> {
    inner_hasher: GenericHasher<H, OUTPUT_SIZE>,
    outer_hasher: GenericHasher<H, OUTPUT_SIZE>,
}

impl<H, const OUTPUT_SIZE: usize> Hmac<H, OUTPUT_SIZE>
where
    H: BytesLen + Default + HashAlgorithm<Output = ByteArrayWrapper<OUTPUT_SIZE>>,
    <H as HashAlgorithm>::Output: From<H>,
    ByteArrayWrapper<OUTPUT_SIZE>: From<H>,
{
    /// Creates a new HMAC context with the given key.
    ///
    /// This method initializes a new HMAC context using the provided key. If the key is longer than the block size
    /// of the hash algorithm, it is hashed, and the hash is used as the key. If the key is shorter than the block
    /// size of the hash algorithm, it is padded with zeros.
    ///
    /// The key is split into two halves - one for the inner hash and one for the outer hash. The inner hash is padded
    /// with `0x36` and the outer hash is padded with `0x5c`.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice that holds the key.
    ///
    /// # Returns
    ///
    /// A new HMAC context.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::hash::Hasher;
    /// use hash_ctx_lib::HasherContext;
    /// use rs_hmac::Hmac;
    /// use rs_sha3_384::Sha3_384State;
    ///
    /// let key = b"my secret and secure key";
    /// let mut hmac = Hmac::<Sha3_384State, 48>::new(key);
    ///
    /// hmac.write(b"data");
    /// let u64result = hmac.finish();
    /// let bytes_result = HasherContext::finish(&mut hmac);
    ///
    /// assert_eq!(u64result, 0x122C8376A6EB06CD);
    /// assert_eq!(
    ///     bytes_result,
    ///     [
    ///         0xC1, 0x4C, 0x21, 0xF6, 0x5A, 0xCA, 0x45, 0x19, 0x91, 0xF3, 0xAB, 0x87, 0x76, 0x6E, 0x7C, 0xDF, 0xC4, 0x50,
    ///         0x6A, 0x18, 0xE7, 0x08, 0xA4, 0x64, 0xFA, 0x0E, 0xCD, 0x4C, 0xC0, 0x97, 0x32, 0xFA, 0x5F, 0x8A, 0x8A, 0x33,
    ///         0x26, 0x0F, 0xE2, 0x65, 0x9C, 0xC3, 0xBF, 0x6E, 0xD1, 0x5E, 0x16, 0xEB
    ///     ]
    /// );
    /// ```
    pub fn new(key: &[u8]) -> Self {
        let mut inner_key = H::Padding::default();
        let mut outer_key = H::Padding::default();

        if key.len() > H::Padding::len() {
            let mut hasher: GenericHasher<H, OUTPUT_SIZE> = GenericHasher::default();
            hasher.write(key);
            let bytes_output: ByteArrayWrapper<OUTPUT_SIZE> = HasherContext::finish(&mut hasher).into();

            inner_key.as_mut()[..H::len()].clone_from_slice(bytes_output.as_ref());
            outer_key.as_mut()[..H::len()].clone_from_slice(bytes_output.as_ref());
        } else {
            inner_key.as_mut()[..key.len()].clone_from_slice(key);
            outer_key.as_mut()[..key.len()].clone_from_slice(key);
        }

        for (i, o) in inner_key.as_mut().iter_mut().zip(outer_key.as_mut().iter_mut()) {
            *i ^= INNER_PAD;
            *o ^= OUTER_PAD;
        }

        let mut inner_hasher = GenericHasher::default();
        let mut outer_hasher = GenericHasher::default();

        inner_hasher.write(inner_key.as_ref());
        outer_hasher.write(outer_key.as_ref());

        Self {
            inner_hasher,
            outer_hasher,
        }
    }

    /// Computes the HMAC of a message with a key.
    ///
    /// This method calculates the HMAC of the provided message using the key from the HMAC context.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice that holds the key.
    /// * `msg` - A byte slice that holds the message.
    ///
    /// # Returns
    ///
    /// The HMAC of the message as a byte array wrapper.
    ///
    /// # Example
    ///
    /// ```
    /// use rs_hmac::Hmac;
    /// use rs_sha1::{Sha1Hasher, Sha1State};
    ///
    /// let key = b"key";
    /// let  msg = b"The quick brown fox jumps over the lazy dog";
    /// let resulting_sha1state = Hmac::<Sha1State, 20>::digest(key, msg);
    ///
    /// assert_eq!(format!("{:02x}", resulting_sha1state), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    /// ```
    pub fn digest(key: &[u8], msg: &[u8]) -> ByteArrayWrapper<OUTPUT_SIZE> {
        let mut hmac = Self::new(key);
        hmac.write(msg);
        HasherContext::finish(&mut hmac)
    }
}

impl<H, const OUTPUT_SIZE: usize> Hasher for Hmac<H, OUTPUT_SIZE>
where
    H: Default + HashAlgorithm,
    <H as HashAlgorithm>::Output: From<H>,
    ByteArrayWrapper<OUTPUT_SIZE>: From<H>,
{
    fn finish(&self) -> u64 {
        Hasher::finish(&self.inner_hasher)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.inner_hasher.write(bytes)
    }
}

impl<H, const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE> for Hmac<H, OUTPUT_SIZE>
where
    H: Default + HashAlgorithm,
    <H as HashAlgorithm>::Output: From<H>,
    ByteArrayWrapper<OUTPUT_SIZE>: From<H>,
{
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        let inner_result: ByteArrayWrapper<OUTPUT_SIZE> = HasherContext::finish(&mut self.inner_hasher).into();

        self.outer_hasher.write(inner_result.as_ref());
        HasherContext::finish(&mut self.outer_hasher).into()
    }
}
