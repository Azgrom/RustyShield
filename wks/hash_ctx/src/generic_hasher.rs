use crate::HasherContext;
use core::hash::Hasher;
use internal_hasher::{DigestThroughPad, HashAlgorithm};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GenericHasher<H: HashAlgorithm> {
    pub padding: H::Padding,
    pub state: H,
}

impl<H: HashAlgorithm + Default> Default for GenericHasher<H> {
    fn default() -> Self {
        Self {
            padding: H::Padding::default(),
            state: H::default(),
        }
    }
}

impl<H: HashAlgorithm> Hasher for GenericHasher<H> {
    fn finish(&self) -> u64 {
        let mut hasher = self.clone();
        HasherContext::finish(&mut hasher).state_to_u64()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.padding.write(&mut self.state, bytes)
    }
}

impl<H: HashAlgorithm> HasherContext for GenericHasher<H> {
    type State = H;

    fn finish(&mut self) -> Self::State {
        self.padding.finish(&mut self.state);
        self.state.clone()
    }
}
