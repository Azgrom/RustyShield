#![no_std]

use core::hash::Hasher;
use core::mem::size_of;
use hash_ctx_lib::{GenericHasher, NewHasherContext};
use internal_hasher::{HashAlgorithm, LenPad};

pub struct Hmac<H: HashAlgorithm> {
    inner_hasher: GenericHasher<H>,
    outer_hasher: GenericHasher<H>,
}

impl<H> Hmac<H> where H: HashAlgorithm + Default {
    pub fn new(key: &[u8]) -> Self {
        let mut inner_key = Self::inner_key();
        let mut outer_key = Self::outer_key();

        if key.len() > H::Padding::len() {
            let mut hasher: GenericHasher<H> = GenericHasher::default();
            hasher.write(key);
            inner_key.as_mut().copy_from_slice(&hasher.finish().to_be_bytes()[..H::Padding::len()]);
        } else {
            inner_key.as_mut()[..key.len()].copy_from_slice(key);
        }

        outer_key.as_mut().copy_from_slice(inner_key.as_ref());

        for byte in inner_key.as_mut().iter_mut() {
            *byte ^= 0x36;
        }

        for byte in outer_key.as_mut().iter_mut() {
            *byte ^= 0x5c;
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

    pub fn write(&mut self, input: &[u8]) {
        self.inner_hasher.write(input);
    }

    fn inner_key() -> H::Padding {
        let mut inner_key = H::Padding::default();
        inner_key.as_mut().fill(0x36);
        inner_key
    }

    fn outer_key() -> H::Padding {
        let mut outer_key = H::Padding::default();
        outer_key.as_mut().fill(0x5c);
        outer_key
    }
}

impl<H> Default for Hmac<H> where H: HashAlgorithm + Default {
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

impl<H: HashAlgorithm> NewHasherContext for Hmac<H> {
    type State = H;

    fn finish(&mut self) -> Self::State {
        let inner_result = self.inner_hasher.finish();
        self.outer_hasher.write(&inner_result.to_be_bytes());
        NewHasherContext::finish(&mut self.outer_hasher)
    }
}
