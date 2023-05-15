use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;
use crate::Sha3_512State;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_512Hasher(GenericHasher<Sha3_512State>);

impl Hasher for Sha3_512Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha3_512Hasher {
    type State = <Sha3_512State as HashAlgorithm>::Output;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}
