#![no_std]

use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, NewHasherContext};
use internal_hasher::{HashAlgorithm, LenPad};
use internal_state::BytesLen;

const INNER_PAD: u8 = 0x36;
const OUTER_PAD: u8 = 0x5c;

/// HMAC context.
/// This context can be used to compute a HMAC.
///
/// # Example
/// ```
/// use rs_hmac::Hmac;
/// use rs_sha1::Sha1State;
/// ```
pub struct Hmac<H: HashAlgorithm> {
    inner_hasher: GenericHasher<H>,
    outer_hasher: GenericHasher<H>,
}

impl<H> Hmac<H>
where
    H: BytesLen + Default + HashAlgorithm,
    <H as HashAlgorithm>::Output: From<H>,
{
    /// Create a new HMAC context with the given key.
    /// If the key is longer than the block size of the hash algorithm,
    /// it will be hashed and the hash will be used as the key.
    /// If the key is shorter than the block size of the hash algorithm,
    /// it will be padded with zeros.
    /// The key will be split into two halves, one for the inner hash and one for the outer hash.
    /// The inner hash will be padded with `0x36` and the outer hash will be padded with `0x5c`.
    /// Give me a key and I'll give you a HMAC context.
    ///
    /// # Example:
    /// ```
    /// use rs_hmac::Hmac;
    /// ```
    pub fn new(key: &[u8]) -> Self {
        let mut inner_key = H::Padding::default();
        let mut outer_key = H::Padding::default();

        if key.len() > H::Padding::len() {
            let mut hasher: GenericHasher<H> = GenericHasher::default();
            hasher.write(key);
            let bytes_output: H::Output = NewHasherContext::finish(&mut hasher).into();

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

    /// Compute the HMAC of a message with a key.
    /// # Example:
    /// ```
    /// use rs_hmac::Hmac;
    /// use rs_sha1::Sha1State;
    ///
    /// let key = b"key";
    /// let  msg = b"The quick brown fox jumps over the lazy dog";
    /// let resulting_sha1state = Hmac::<Sha1State>::digest(key, msg);
    ///
    /// assert_eq!(format!("{resulting_sha1state:08x}"), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    /// ```
    pub fn digest(key: &[u8], msg: &[u8]) -> H {
        let mut hmac = Self::new(key);
        hmac.write(msg);
        NewHasherContext::finish(&mut hmac)
    }
}

impl<H> Default for Hmac<H>
where
    H: BytesLen + Default + HashAlgorithm,
    <H as HashAlgorithm>::Output: From<H>,
{
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<H: HashAlgorithm> Hasher for Hmac<H> {
    fn finish(&self) -> u64 {
        self.clone().inner_hasher.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.inner_hasher.write(bytes)
    }
}

impl<H> NewHasherContext for Hmac<H>
where
    H: HashAlgorithm,
    <H as HashAlgorithm>::Output: From<H>,
{
    type State = H;

    fn finish(&mut self) -> Self::State {
        let inner_result: H::Output = NewHasherContext::finish(&mut self.inner_hasher).into();

        self.outer_hasher.write(inner_result.as_ref());
        NewHasherContext::finish(&mut self.outer_hasher)
    }
}
