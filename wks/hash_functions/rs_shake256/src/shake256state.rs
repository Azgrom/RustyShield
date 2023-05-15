use crate::Shake256Hasher;
use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};

const RATE: usize = 136;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256State<const OUTPUT_SIZE: usize> {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl<const OUTPUT_SIZE: usize> BuildHasher for Shake256State<OUTPUT_SIZE> {
    type Hasher = Shake256Hasher<OUTPUT_SIZE>;

    fn build_hasher(&self) -> Self::Hasher {
        Shake256Hasher::default()
    }
}

impl<const OUTPUT_SIZE: usize> BytesLen for Shake256State<OUTPUT_SIZE> {
    fn len() -> usize {
        RATE
    }
}

impl<const OUTPUT_SIZE: usize> ExtendedOutputFunction<OUTPUT_SIZE> for Shake256State<OUTPUT_SIZE> {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl<const OUTPUT_SIZE: usize> HashAlgorithm for Shake256State<OUTPUT_SIZE> {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x1F>;
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
