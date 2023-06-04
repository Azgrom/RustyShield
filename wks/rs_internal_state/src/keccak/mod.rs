use crate::keccak::state::{KeccakState, KeccakStateIter, KeccakStateIterMut};
use crate::keccak::xof::ExtendedOutputFunction;
use alloc::borrow::ToOwned;
use core::mem::size_of;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};

pub(crate) mod chi;
mod from_bytes;
pub(crate) mod iota;
pub(crate) mod pi;
pub(crate) mod plane;
pub(crate) mod rho;
pub(crate) mod state;
pub(crate) mod theta;
pub(crate) mod xof;

pub(crate) const WIDTH: usize = 5;
pub(crate) const HEIGHT: usize = 5;

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

/// The `KeccakSponge` struct implements a generic sponge construction based on the Keccak permutation.
/// # Sponge construction
///
/// The sponge construction is a cryptographic primitive that can be used to build hash functions,
/// stream ciphers, and more. It is based on an internal state and two operations: absorbing and
/// squeezing. The internal state is divided into two parts: a public part called the rate and a
/// secret part called the capacity. The Keccak sponge construction uses the Keccak-f permutation as
/// its underlying function.
///
/// The Keccak-f permutation is a family of permutations parameterized by the width of the state.
/// The most commonly used instance is Keccak-f[1600], with a state width of 1600 bits.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct KeccakSponge<T, const RATE: usize, const OUTPUT_SIZE: usize>
where
    T: Default + Copy,
{
    /// The internal state of the sponge, which holds a Keccak state of generic type `T` (e.g., u64 for Keccak-f[1600])
    state: KeccakState<T>,
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> KeccakSponge<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    /// Absorbs the input data into the sponge
    /// The absorb method takes an input byte slice and processes it through the sponge construction.
    /// It first pads the input using the padding rule, then divides the padded input into blocks of
    /// size `N`. Each block is XORed with the rate portion of the state, followed by the application of
    /// the Keccak-f permutation
    pub fn absorb(&mut self, input: &[u8]) {
        let lanes_to_fulfill = RATE / (size_of::<T>());
        for (lane, byte) in
            KeccakStateIterMut::new(&mut self.state).take(lanes_to_fulfill).zip(input.chunks_exact(size_of::<T>()))
        {
            *lane ^= NBitWord::<T>::from_le_bytes(byte);
        }

        self.state.apply_f();
    }

    fn words_to_take(t_size: usize) -> usize {
        return if RATE % t_size != 0 {
            1 + RATE / t_size
        } else {
            RATE / t_size
        };
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> ExtendedOutputFunction<OUTPUT_SIZE>
    for KeccakSponge<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn squeeze_u64(&self) -> u64 {
        const BYTE_COUNT_IN_U64: usize = 8;
        let t_size = size_of::<T>();
        let bytes_in_rate = RATE / (t_size);
        let mut u64_le_bytes = [0u8; BYTE_COUNT_IN_U64];
        let mut completed_bytes = 0;

        let mut state = self.state.clone();

        while BYTE_COUNT_IN_U64 > completed_bytes {
            for (le_bytes, lane) in u64_le_bytes.iter_mut().skip(completed_bytes).zip(
                KeccakStateIter::new(&state)
                    .take(bytes_in_rate)
                    .flat_map(|lane| lane.to_le_bytes().as_ref().to_owned()),
            ) {
                *le_bytes = lane;
            }

            completed_bytes += bytes_in_rate;

            if BYTE_COUNT_IN_U64 > completed_bytes {
                state.apply_f();
            }
        }

        u64::from_be_bytes(u64_le_bytes)
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        let t_size = size_of::<T>();
        let words_to_tale = KeccakSponge::<T, RATE, OUTPUT_SIZE>::words_to_take(t_size);
        let mut output = [0u8; OUTPUT_SIZE];
        let mut completed_bytes = 0;

        while OUTPUT_SIZE > completed_bytes {
            for (le_bytes, lane) in output
                .chunks_mut(t_size)
                .skip(completed_bytes / t_size)
                .zip(KeccakStateIter::new(&self.state).take(words_to_tale))
            {
                le_bytes.clone_from_slice(&lane.to_le_bytes().as_ref()[..le_bytes.len()])
            }

            completed_bytes += RATE;

            if OUTPUT_SIZE > completed_bytes {
                self.state.apply_f();
            }
        }

        output
    }
}
