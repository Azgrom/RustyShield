use crate::Sha1State;
use core::hash::Hasher;
use hash_ctx_lib::{U64MaxGenericHasher, HasherContext};
use internal_hasher::HasherPadOps;

/// The SHA-1 Hasher
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha1Hasher(U64MaxGenericHasher<Sha1State>);

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self(U64MaxGenericHasher::default())
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

impl HasherContext for Sha1Hasher {
    type State = Sha1State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}

impl HasherPadOps for Sha1Hasher {
    fn size_mod_pad(&self) -> usize {
        self.0.size_mod_pad()
    }

    fn zeros_pad(&self) -> usize {
        self.0.zeros_pad()
    }
}
