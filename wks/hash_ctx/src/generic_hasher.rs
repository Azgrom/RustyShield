use crate::{ByteArrayWrapper, HasherContext};
use core::hash::Hasher;
use internal_hasher::{DigestThroughPad, HashAlgorithm};

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct GenericHasher<H: Default + HashAlgorithm, const OUTPUT_LEN: usize> {
    pub padding: H::Padding,
    pub state: H,
}

impl<H: Default + HashAlgorithm, const OUTPUT_LEN: usize> Hasher for GenericHasher<H, OUTPUT_LEN>
where
    ByteArrayWrapper<OUTPUT_LEN>: From<H>,
{
    fn finish(&self) -> u64 {
        let mut hasher = self.clone();
        HasherContext::<OUTPUT_LEN>::finish(&mut hasher).state_to_u64()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.padding.write(&mut self.state, bytes)
    }
}

impl<H: Default + HashAlgorithm, const OUTPUT_LEN: usize> HasherContext<OUTPUT_LEN> for GenericHasher<H, OUTPUT_LEN>
where
    ByteArrayWrapper<OUTPUT_LEN>: From<H>,
{
    type Output = H;

    fn finish(&mut self) -> Self::Output {
        self.padding.finish(&mut self.state);
        self.state.clone()
    }
}
