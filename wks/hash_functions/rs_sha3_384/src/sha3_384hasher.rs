use crate::{Sha3_384State, OUTPUT_SIZE};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_state::ExtendedOutputFunction;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_384Hasher(GenericHasher<Sha3_384State, OUTPUT_SIZE>);

impl Hasher for Sha3_384Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_384Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
