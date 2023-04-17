use internal_state::{BytesLen, KeccakSponge};

const RATE: usize = 1344;

// Example of how to use KeccakSponge in SHAKE128
pub struct Shake128State {
    sponge: KeccakSponge<u64, RATE>,
}

impl BytesLen for Shake128State {
    fn len() -> usize {
        RATE
    }
}

impl Default for Shake128State {
    fn default() -> Self {
        Self {
            sponge: KeccakSponge::new(0x1F),
        }
    }
}
