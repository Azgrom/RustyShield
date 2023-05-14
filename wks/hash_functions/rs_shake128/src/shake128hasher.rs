use crate::Shake128State;
use core::hash::Hasher;
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_state::ExtendedOutputFunction;

#[derive(Default)]
pub struct Shake128Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake128State<OUTPUT_SIZE>>);

impl<const OUTPUT_SIZE: usize> Hasher for Shake128Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext for Shake128Hasher<OUTPUT_SIZE> {
    type State = [u8; OUTPUT_SIZE];

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}
