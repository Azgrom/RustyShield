use core::array::IntoIter;
use crate::{keccak::chi::Chi, keccak::iota::Iota, keccak::pi::Pi, keccak::rho::Rho, keccak::theta::Theta, keccak::{HEIGHT, RC, WIDTH}, KeccakSponge};
use core::iter::Flatten;
use core::mem::size_of;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use core::slice::{Iter, IterMut};
use n_bit_words_lib::{LittleEndianBytes, NBitWord, Rotate, TSize};
use crate::keccak::from_bytes::FromBytes;

type Plane<T> = [NBitWord<T>; WIDTH];

/// `KeccakState<T>` represents the internal state of the Keccak-based permutations with a variable width.
/// It is used as the foundation for various NIST-validated hash algorithms and other Keccak-based constructions.
///
/// This implementation is designed to support multiple widths by varying the `T` type parameter, which corresponds to
/// the following bit widths:
/// - `u8`: 200-bit permutation
/// - `u16`: 400-bit permutation
/// - `u32`: 800-bit permutation
/// - `u64`: 1600-bit permutation
///
/// The 1600-bit permutation (`KeccakState<u64>`) is the basis for the following NIST-validated hash algorithms:
///
/// - SHA-3 family of hash functions:
///   - SHA3-224
///   - SHA3-256
///   - SHA3-384
///   - SHA3-512
///
/// - Extendable-output functions (XOFs):
///   - SHAKE128
///   - SHAKE256
///
/// - RawSHAKE variants:
///   - RawSHAKE128
///   - RawSHAKE256
///
/// Please note that the NIST-validated hash algorithms are specifically based on the 1600-bit permutation (`KeccakState<u64>`).
/// The other permutations (`KeccakState<u8>`, `KeccakState<u16>`, and `KeccakState<u32>`) can be used for other
/// Keccak-based constructions or research purposes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakState<T: Default + Copy> {
    state: [Plane<T>; HEIGHT],
}

pub struct KeccakStateIter<'a, T> {
    iter: Flatten<Iter<'a, Plane<T>>>,
}

impl<'a, T: Default + Copy> KeccakStateIter<'a, T> {
    pub(crate) fn new(src: &'a KeccakState<T>) -> Self {
        Self {
            iter: src.state.iter().flatten(),
        }
    }
}

impl<'a, T> ExactSizeIterator for KeccakStateIter<'a, T> {}

impl<'a, T> Iterator for KeccakStateIter<'a, T> {
    type Item = &'a NBitWord<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct KeccakStateIterMut<'a, T>{
    iter: Flatten<IterMut<'a, Plane<T>>>,
}

impl<'a, T: Default + Copy> KeccakStateIterMut<'a, T> {
    pub(crate) fn new(src: &'a mut KeccakState<T>) -> Self {
        Self {
            iter: src.state.iter_mut().flatten(),
        }
    }
}

impl<'a, T> Iterator for KeccakStateIterMut<'a, T> {
    type Item = &'a mut NBitWord<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a, T> ExactSizeIterator for KeccakStateIterMut<'a, T> {}

impl<T> KeccakState<T>
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
    pub fn apply_f(&mut self) {
        for i in 0..24 {
            self.theta();
            self.rho();
            self.pi();
            self.chi();
            self.iota(i);
        }
    }
}

impl<T> Chi for KeccakState<T>
    where
        T: BitAnd + BitOr<NBitWord<T>, Output = NBitWord<T>> + Copy + Default + Not<Output = T>,
        NBitWord<T>: BitOr<NBitWord<T>> + TSize<T>,
        u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn chi(&mut self) {
        let mut temp_state = Self::default();

        for x in 0..5 {
            for y in 0..5 {
                temp_state.state[x][y] =
                    self.state[x][y] ^ ((!self.state[(x + 1) % 5][y]) & self.state[(x + 2) % 5][y]);
            }
        }

        self.state = temp_state.state;
    }
}

impl<T: Copy + Default> Default for KeccakState<T> {
    fn default() -> Self {
        Self {
            state: [[NBitWord::default(); WIDTH]; HEIGHT],
        }
    }
}

impl From<[[u64; WIDTH]; HEIGHT]> for KeccakState<u64> {
    fn from(lanes: [[u64; WIDTH]; HEIGHT]) -> Self {
        let mut state = Self::default();

        for x in 0..5 {
            for y in 0..5 {
                state.state[x][y] = lanes[x][y].into();
            }
        }

        state
    }
}

impl<'a, T> IntoIterator for &'a mut KeccakState<T>
    where T: Copy + Default
{
    type Item = &'a mut NBitWord<T>;
    type IntoIter = Flatten<IterMut<'a, Plane<T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.state.iter_mut().flatten()
    }
}

impl<T> Iota for KeccakState<T>
    where
        T: Copy + Default + BitXorAssign,
        NBitWord<T>: From<u64>,
{
    fn iota(&mut self, round: usize) {
        self.state[0][0] ^= RC[round].into()
    }
}

impl<T> Pi for KeccakState<T>
    where
        T: Default + Copy,
{
    fn pi(&mut self) {
        let mut temp_state = Self::default();

        for x in 0..5 {
            for y in 0..5 {
                let nx = y;
                let ny = (2 * x + 3 * y) % 5;
                temp_state.state[nx][ny] = self.state[x][y];
            }
        }

        self.state = temp_state.state;
    }
}

impl<T> Rho for KeccakState<T>
    where
        T: BitOr<NBitWord<T>, Output = NBitWord<T>> + Copy + Default,
        NBitWord<T>: Rotate + TSize<T>,
        u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn rho(&mut self) {
        for x in 0..5 {
            for y in 0..5 {
                let t = x + y * 5;
                let x1 = NBitWord::new((t * (t + 1)) / 2).into();
                self.state[x][y] = self.state[x][y].rotate_left(x1);
            }
        }
    }
}

impl<T> Theta for KeccakState<T>
where
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor<Output = T> + BitXorAssign + Copy + Default,
    NBitWord<T>: Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn theta(&mut self) {
        let mut c: [NBitWord<T>; 5] = [NBitWord::default(); 5];

        for x in 0..5 {
            c[x] = self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^ self.state[x][3] ^ self.state[x][4];
        }

        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(NBitWord::new(1).into());
            for y in 0..5 {
                self.state[x][y] ^= d;
            }
        }
    }
}
