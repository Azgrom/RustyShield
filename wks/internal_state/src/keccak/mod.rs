use crate::keccak::chi::Chi;
use crate::keccak::iota::Iota;
use crate::keccak::pi::Pi;
use crate::keccak::rho::Rho;
use crate::keccak::state::KeccakState;
use crate::keccak::theta::Theta;
use core::mem::size_of;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use core::slice::ChunksExact;
use n_bit_words_lib::{FromLittleEndianBytes, NBitWord, Rotate, TSize};
use crate::keccak::from_bytes::FromBytes;

pub(crate) mod chi;
mod from_bytes;
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
pub struct KeccakSponge<T, const RATE: usize>
where
    T: Default + Copy,
{
    /// The internal state of the sponge, which holds a Keccak state of generic type `T` (e.g., u64 for Keccak-f[1600])
    state: KeccakState<T>,
    /// A delimiter byte used in the padding rule to distinguish different applications of the sponge construction
    delimiter: u8,
}

impl<T, const RATE: usize> KeccakSponge<T, RATE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + FromLittleEndianBytes + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    /// Creates a new Keccak sponge with the specified rate and capacity
    /// * `N`: The block size, in bytes, of the sponge construction. It is equal to the rate divided by 8.
    /// * `d`: The delimiter byte used in the padding rule, which is unique to each specific application
    ///   of the sponge construction
    pub fn new(delimiter: u8) -> Self {
        KeccakSponge {
            state: KeccakState::default(),
            delimiter,
        }
    }

    /// Absorbs the input data into the sponge
    /// The absorb method takes an input byte slice and processes it through the sponge construction.
    /// It first pads the input using the padding rule, then divides the padded input into blocks of
    /// size `N`. Each block is XORed with the rate portion of the state, followed by the application of
    /// the Keccak-f permutation
    pub fn absorb(&mut self, input: &[u8]) {
        let keccak_chunk = RATE / u8::BITS as usize;
        let rate_chunk = keccak_chunk / size_of::<T>();
        let mut rate_part_chunks = input.chunks_exact(keccak_chunk);

        while let Some(rate_part_chunk) = rate_part_chunks.next(){
            for (i, le_bytes) in rate_part_chunk.chunks(size_of::<T>()).enumerate() {
                self.state.write_into(i, le_bytes);
            }

            self.state.apply_f();
        }

        let x = rate_part_chunks.remainder();
        if !x.is_empty() {

        }
    }

    /// Squeezes the output data from the sponge
    pub fn squeeze(&mut self, output: &mut [u8; RATE]) {
        // let mut offset = 0;
        // let block_size = RATE / 8;
        //
        // while offset < output.len() {
        //     let remaining = output.len() - offset;
        //     let to_copy = usize::min(block_size, remaining);
        //     self.state.copy_block(&mut output[offset..offset + to_copy]);
        //     self.state.apply_f();
        //
        //     offset += block_size;
        // }
    }

    // /// The padding rule, denoted as pad, is used to pad the input data before absorbing it into the
    // /// sponge. It appends a delimiter byte `d`, followed by a series of zero bytes, and finally a `1` byte
    // fn pad(&self, input: &mut ChunksExact<u8>) -> [u8; RATE / u8::BITS as usize] {
    //     let mut pad = [0u8; RATE / u8::BITS as usize];
    //
    //     if let Some(input_chunk) = input.next() {
    //         pad.clone_from_slice(input_chunk);
    //         return pad;
    //     }
    //
    //
    // }
}
