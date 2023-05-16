use crate::{Sha512_256State, BYTES_LEN};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

#[derive(Clone, Debug, Default)]
pub struct Sha512_256Hasher(GenericHasher<Sha512_256State, BYTES_LEN>);

impl Hasher for Sha512_256Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha512_256Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
