use crate::keccak_state::KeccakState;

pub(crate) trait Chi {
    fn chi(&mut self);
}
