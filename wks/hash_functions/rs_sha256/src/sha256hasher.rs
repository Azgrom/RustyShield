use crate::Sha256State;
use core::hash::Hasher;
use hash_ctx_lib::{U64MaxGenericHasher, HasherContext};

/// The SHA-256 Hasher
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Hasher(U64MaxGenericHasher<Sha256State>);

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self(U64MaxGenericHasher::default())
    }
}

impl Hasher for Sha256Hasher {
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

impl HasherContext for Sha256Hasher {
    type State = Sha256State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}
