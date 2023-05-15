use crate::Sha3_256State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_256Hasher(GenericHasher<Sha3_256State>);

impl Hasher for Sha3_256Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha3_256Hasher {
    type State = <Sha3_256State as HashAlgorithm>::Output;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}
