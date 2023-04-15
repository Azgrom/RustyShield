use n_bit_words_lib::TSize;
use crate::keccak_state::KeccakState;

pub(crate) trait Rho {
    fn rho(&mut self);
}
