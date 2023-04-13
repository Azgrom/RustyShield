use crate::Sha512State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};

#[derive(Clone, Debug)]
pub struct Sha512Hasher(GenericHasher<Sha512State>);

impl Default for Sha512Hasher {
    fn default() -> Self {
        Self(GenericHasher::default())
    }
}

impl Hasher for Sha512Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha512Hasher {
    type State = Sha512State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}
