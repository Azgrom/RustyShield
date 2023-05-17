use crate::{Sha1State, BYTES_LEN};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

/// The SHA-1 Hasher
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha1Hasher(GenericHasher<Sha1State, BYTES_LEN>);

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

impl HasherContext<BYTES_LEN> for Sha1Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
