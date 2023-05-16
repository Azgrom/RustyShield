use crate::{Sha512_224State, BYTES_LEN};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

#[derive(Clone, Debug, Default)]
pub struct Sha512_224Hasher(GenericHasher<Sha512_224State, BYTES_LEN>);

impl Hasher for Sha512_224Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha512_224Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).into()
    }
}
