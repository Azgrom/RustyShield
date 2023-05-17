use crate::{Sha3_256State, OUTPUT_SIZE};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_state::ExtendedOutputFunction;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_256Hasher(GenericHasher<Sha3_256State, OUTPUT_SIZE>);

impl Hasher for Sha3_256Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_256Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
