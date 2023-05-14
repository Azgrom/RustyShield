use crate::Sha512_224State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};

#[derive(Clone, Debug, Default)]
pub struct Sha512_224Hasher(GenericHasher<Sha512_224State>);

impl Hasher for Sha512_224Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha512_224Hasher {
    type State = Sha512_224State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}
