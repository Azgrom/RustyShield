use crate::Sha512_224State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, NewHasherContext};

#[derive(Clone, Debug)]
pub struct Sha512_224Hasher(GenericHasher<Sha512_224State>);

impl Default for Sha512_224Hasher {
    fn default() -> Self {
        Self(GenericHasher::default())
    }
}

impl Hasher for Sha512_224Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl NewHasherContext for Sha512_224Hasher {
    type State = Sha512_224State;

    fn finish(&mut self) -> Self::State {
        NewHasherContext::finish(&mut self.0)
    }
}
