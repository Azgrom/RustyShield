use core::hash::Hasher;
use internal_hasher::{BytePad, HashAlgorithm, HasherPadOps, LenPad};
use crate::NewHasherContext;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct GenericHasher<H: HashAlgorithm> {
    pub padding: H::Padding,
    pub state: H,
    pub size: u64,
}

impl<H: HashAlgorithm> HasherPadOps for GenericHasher<H>{
    fn size_mod_pad(&self) -> usize {
        (self.size & self.padding.last_index() as u64) as usize
    }

    fn zeros_pad(&self) -> usize {
        1 + (self.padding.last_index() & (self.padding.offset().wrapping_sub(self.size_mod_pad())))
    }
}

impl<H: HashAlgorithm + Default> Default for GenericHasher<H> {
    fn default() -> Self {
        Self{
            padding: H::Padding::default(),
            state: H::default(),
            size: u64::MIN,
        }
    }
}

impl<H: HashAlgorithm> NewHasherContext for GenericHasher<H> {
    type State = H;

    fn finish(&mut self) -> Self::State {
        let zeros_pad = self.zeros_pad();
        let mut offset = H::Padding::default();
        offset[0] = 0x80;

        let len = (self.size * 8).to_be_bytes();
        self.write(&offset[..zeros_pad]);
        self.write(&len);

        self.state.clone()
    }
}

impl<H: HashAlgorithm> Hasher for GenericHasher<H> {
    fn finish(&self) -> u64 {
        let mut hasher = self.clone();
        NewHasherContext::finish(&mut hasher).state_to_u64()
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let lw = self.size_mod_pad();
        self.size += bytes.len() as u64;

        if lw != 0 {
            let mut left = H::Padding::len() - lw;
            if left > bytes.len() {
                left = bytes.len();
            }

            self.padding.as_mut()[lw..lw + left].clone_from_slice(&bytes[..left]);

            if (lw + left) & self.padding.last_index() != 0 {
                return;
            }

            self.state.hash_block(self.padding.as_ref());
            bytes = &bytes[left..];
        }

        while bytes.len() >= H::Padding::len() {
            self.state.hash_block(&bytes[..H::Padding::len()]);
            bytes = &bytes[H::Padding::len()..];
        }

        if !bytes.is_empty() {
            self.padding.as_mut()[..bytes.len()].clone_from_slice(&bytes[..]);
        }
    }
}
