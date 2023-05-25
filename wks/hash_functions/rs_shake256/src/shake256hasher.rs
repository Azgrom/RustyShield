use crate::Shake256State;
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_state::ExtendedOutputFunction;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake256State<OUTPUT_SIZE>, OUTPUT_SIZE>);

impl<const OUTPUT_SIZE: usize> Hasher for Shake256Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE> for Shake256Hasher<OUTPUT_SIZE> {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
