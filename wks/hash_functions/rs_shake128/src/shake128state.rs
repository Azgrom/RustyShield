use internal_hasher::{HashAlgorithm, GenericPad, KeccakU128Size};
use internal_state::{BytesLen, KeccakSponge};

const RATE: usize = 1344;

// Example of how to use KeccakSponge in SHAKE128
#[derive(Clone, Debug)]
pub struct Shake128State<const OUTPUT_SIZE: usize> {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl<const OUTPUT_SIZE: usize> Shake128State<OUTPUT_SIZE> {
    /// Squeezes the output data from the sponge
    pub fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl<const OUTPUT_SIZE: usize> BytesLen for Shake128State<OUTPUT_SIZE> {
    fn len() -> usize {
        RATE
    }
}

impl<const OUTPUT_SIZE: usize> Default for Shake128State<OUTPUT_SIZE> {
    fn default() -> Self {
        Self {
            sponge: KeccakSponge::new(),
        }
    }
}

impl<const OUTPUT_SIZE: usize> HashAlgorithm for Shake128State<OUTPUT_SIZE> {
    type Padding = GenericPad<KeccakU128Size, { RATE / u8::BITS as usize }, 0x1F>;
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes);
    }

    fn state_to_u64(&self) -> u64 {
        todo!()
    }
}
