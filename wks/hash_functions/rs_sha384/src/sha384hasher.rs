use crate::Sha384State;
use core::hash::Hasher;
use hash_ctx_lib::{U128MaxGenericHasher, HasherContext};

#[derive(Clone, Debug)]
pub struct Sha384Hasher(U128MaxGenericHasher<Sha384State>);

impl Default for Sha384Hasher {
    fn default() -> Self {
        Self(U128MaxGenericHasher::default())
    }
}

impl Hasher for Sha384Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext for Sha384Hasher {
    type State = Sha384State;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0)
    }
}
