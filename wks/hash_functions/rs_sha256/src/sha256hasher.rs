use crate::{Sha256State, BYTES_LEN};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

/// The SHA-256 Hasher
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha256Hasher(GenericHasher<Sha256State, BYTES_LEN>);

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

impl HasherContext<BYTES_LEN> for Sha256Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).into()
    }
}
