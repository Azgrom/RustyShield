use n_bit_words_lib::{NBitWord, TSize};
use crate::keccak_state::KeccakState;

pub(crate) trait Theta {
    fn theta(&mut self);
}
