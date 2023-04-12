use crate::Sha1State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, NewHasherContext};

/// The SHA-1 Hasher
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha1Hasher(GenericHasher<Sha1State>);

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self(GenericHasher::default())
    }
}

impl Hasher for Sha1Hasher {
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

impl NewHasherContext for Sha1Hasher {
    type State = Sha1State;

    fn finish(&mut self) -> Self::State {
        NewHasherContext::finish(&mut self.0)
    }
}
