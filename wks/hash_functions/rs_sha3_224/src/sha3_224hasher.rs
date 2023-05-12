use core::hash::{Hash, Hasher};
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use crate::Sha3_224State;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Sha3_224Hasher(GenericHasher<Sha3_224State>);

impl Default for Sha3_224Hasher {
    fn default() -> Self {
        Self(GenericHasher::default())
    }
}

impl Hasher for Sha3_224Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha3_224Hasher {
    type State = <Sha3_224State as HashAlgorithm>::Output;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}
