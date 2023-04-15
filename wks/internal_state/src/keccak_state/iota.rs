use crate::keccak_state::{KeccakState, RC};

pub(crate) trait Iota {
    fn iota(&mut self, round: usize);
}
