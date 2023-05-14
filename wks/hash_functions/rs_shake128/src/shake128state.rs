use crate::Shake128Hasher;
use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};

const RATE: usize = 168;

// Example of how to use KeccakSponge in SHAKE128
#[derive(Clone, Debug, Default)]
pub struct Shake128State<const OUTPUT_SIZE: usize> {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl<const OUTPUT_SIZE: usize> BuildHasher for Shake128State<OUTPUT_SIZE> {
    type Hasher = Shake128Hasher<OUTPUT_SIZE>;

    fn build_hasher(&self) -> Self::Hasher {
        Shake128Hasher::default()
    }
}

impl<const OUTPUT_SIZE: usize> BytesLen for Shake128State<OUTPUT_SIZE> {
    fn len() -> usize {
        RATE
    }
}

impl<const OUTPUT_SIZE: usize> ExtendedOutputFunction<OUTPUT_SIZE> for Shake128State<OUTPUT_SIZE> {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl<const OUTPUT_SIZE: usize> HashAlgorithm for Shake128State<OUTPUT_SIZE> {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x1F>;
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes);
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
