use crate::keccak::chi::Chi;
use crate::keccak::iota::Iota;
use crate::keccak::pi::Pi;
use crate::keccak::rho::Rho;
use crate::keccak::state::KeccakState;
use crate::keccak::theta::Theta;
use core::ops::{BitAnd, BitOr, BitXor, BitXorAssign, Not, Sub};
use n_bit_words_lib::{NBitWord, Rotate, TSize};

pub(crate) mod chi;
pub(crate) mod iota;
pub(crate) mod pi;
pub(crate) mod rho;
pub(crate) mod state;
pub(crate) mod theta;

pub(crate) const WIDTH: usize = 5;
pub(crate) const HEIGHT: usize = 5;
const LANES: usize = WIDTH * HEIGHT;
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub struct KeccakSponge<T, const RATE: usize>
where
    T: Default + Copy,
{
    state: KeccakState<T>,
    capacity: usize,
    delimiter: u8,
}

impl<T, const RATE: usize> KeccakSponge<T, RATE>
where
    T: BitAnd
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    pub fn new(capacity: usize, delimiter: u8) -> Self {
        let state = KeccakState::default();
        KeccakSponge {
            state,
            capacity,
            delimiter,
        }
    }

    pub fn absorb(&mut self, input: &[u8; RATE]) {
        // Absorb the input
    }

    pub fn squeeze(&mut self, output: &mut [u8; RATE]) {
        // Squeeze the output
    }

    fn pad(&self, input: &[u8; RATE]) -> [u8; RATE] {
        // Apply the padding
        [0; RATE]
    }

    fn rnd(&mut self, i: usize) {
        // Apply the Keccak permutation
        self.state.theta();
        self.state.rho();
        self.state.pi();
        self.state.chi();
        self.state.iota(i);
    }
}
