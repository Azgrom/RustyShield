use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use crate::Sha3_384Hasher;

const RATE: usize = 104;
const OUTPUT_SIZE: usize = 48;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_384State{
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_384State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_384State {
    type Hasher = Sha3_384Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_384Hasher::default()
    }
}

impl BytesLen for Sha3_384State {
    fn len() -> usize {
        RATE
    }
}

impl HashAlgorithm for Sha3_384State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
