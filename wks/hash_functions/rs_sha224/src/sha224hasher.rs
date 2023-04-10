use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, NewHasherContext};
use crate::Sha224State;

/// The SHA-224 Hasher
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha224Hasher(GenericHasher<Sha224State>);

impl Default for Sha224Hasher {
    fn default() -> Self {
        Self(GenericHasher::default())
    }
}

impl Hasher for Sha224Hasher {
    /// Finish the hash and return the hash value as a `u64`.
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    /// Write a byte array to the hasher.
    /// This hasher can digest up to `u64::MAX` bytes. If more bytes are written, the hasher will panic.
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl NewHasherContext for Sha224Hasher {
    type State = Sha224State;

    fn finish(&mut self) -> Self::State {
        NewHasherContext::finish(&mut self.0)
    }
}
