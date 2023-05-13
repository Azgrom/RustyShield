use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, KeccakSponge};
use crate::Sha3_224Hasher;

const RATE: usize = 1152;
const OUTPUT_SIZE: usize = 28;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_224State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl Sha3_224State {
    /// Squeezes the output data from the sponge
    pub fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_224State {
    type Hasher = Sha3_224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_224Hasher::default()
    }
}

impl BytesLen for Sha3_224State {
    fn len() -> usize {
        RATE
    }
}

impl HashAlgorithm for Sha3_224State {
    type Padding = GenericPad<KeccakU128Size, {RATE / u8::BITS as usize}, 0x06>;
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        todo!()
    }
}
