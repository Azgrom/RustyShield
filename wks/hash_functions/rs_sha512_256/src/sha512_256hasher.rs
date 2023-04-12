use crate::Sha512_256State;
use core::hash::Hasher;
use hash_ctx_lib::{U128MaxGenericHasher, HasherContext};

#[derive(Clone, Debug)]
pub struct Sha512_256Hasher(U128MaxGenericHasher<Sha512_256State>);

impl Default for Sha512_256Hasher {
    fn default() -> Self {
        Self(U128MaxGenericHasher::default())
    }
}

impl Hasher for Sha512_256Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha512_256Hasher {
    type State = Sha512_256State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}
