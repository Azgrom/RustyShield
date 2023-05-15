use crate::Shake256State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_state::ExtendedOutputFunction;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake256State<OUTPUT_SIZE>>);

impl<const OUTPUT_SIZE: usize> Hasher for Shake256Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext for Shake256Hasher<OUTPUT_SIZE> {
    type State = [u8; OUTPUT_SIZE];

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}
