use crate::{Sha3_512Hasher, OUTPUT_SIZE};
use core::hash::BuildHasher;
use hash_ctx_lib::ByteArrayWrapper;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};

const RATE: usize = 72;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_512State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_512State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_512State {
    type Hasher = Sha3_512Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_512Hasher::default()
    }
}

impl BytesLen for Sha3_512State {
    fn len() -> usize {
        RATE
    }
}

impl From<Sha3_512State> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(value: Sha3_512State) -> Self {
        value.sponge.into()
    }
}

impl HashAlgorithm for Sha3_512State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}