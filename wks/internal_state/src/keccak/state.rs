use crate::{
    keccak::chi::Chi,
    keccak::iota::Iota,
    keccak::pi::Pi,
    keccak::rho::Rho,
    keccak::theta::Theta,
    keccak::{HEIGHT, RC, WIDTH},
};
use core::iter::Flatten;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Index, IndexMut, Not, Sub};
use core::slice::{Iter, IterMut};
use n_bit_words_lib::{LittleEndianBytes, NBitWord, Rotate, TSize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Plane<T> {
    lanes: [NBitWord<T>; WIDTH],
}

impl<T: Copy> Plane<T> {
    fn deconstruct(&self) -> [NBitWord<T>; WIDTH] {
        self.lanes
    }
}

impl<T: Copy + Default> Default for Plane<T> {
    fn default() -> Self {
        Self {
            lanes: [NBitWord::default(); WIDTH],
        }
    }
}

impl<T> Index<usize> for Plane<T> {
    type Output = NBitWord<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.lanes[index]
    }
}

impl<T> IndexMut<usize> for Plane<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.lanes[index]
    }
}

impl<'a, T> IntoIterator for &'a Plane<T> {
    type Item = &'a NBitWord<T>;
    type IntoIter = Iter<'a, NBitWord<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.lanes.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Plane<T> {
    type Item = &'a mut NBitWord<T>;
    type IntoIter = IterMut<'a, NBitWord<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.lanes.iter_mut()
    }
}

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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeccakState<T: Default + Copy> {
    planes: [Plane<T>; HEIGHT],
}

impl<T> KeccakState<T>
where
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor<Output = T> + BitXorAssign + Copy + Default,
    NBitWord<T>: Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    #[inline(always)]
    fn bit_xor_lanes(&self, y: usize) -> NBitWord<T> {
        self.planes[0][y] ^ self.planes[1][y] ^ self.planes[2][y] ^ self.planes[3][y] ^ self.planes[4][y]
    }
}

pub struct KeccakStateIter<'a, T> {
    iter: Flatten<Iter<'a, Plane<T>>>,
}

impl<'a, T: Default + Copy> KeccakStateIter<'a, T> {
    pub(crate) fn new(src: &'a KeccakState<T>) -> Self {
        Self {
            iter: src.planes.iter().flatten(),
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

pub struct KeccakStateIterMut<'a, T> {
    iter: Flatten<IterMut<'a, Plane<T>>>,
}

impl<'a, T: Default + Copy> KeccakStateIterMut<'a, T> {
    pub(crate) fn new(src: &'a mut KeccakState<T>) -> Self {
        Self {
            iter: src.planes.iter_mut().flatten(),
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

impl<T> Chi for Plane<T>
where
    T: Copy,
    NBitWord<T>: BitAnd<Output = NBitWord<T>> + BitXorAssign + Not<Output = NBitWord<T>>,
{
    fn chi(&mut self) {
        let [lane0, lane1, lane2, lane3, lane4] = self.deconstruct();

        self[0] ^= !lane1 & lane2;
        self[1] ^= !lane2 & lane3;
        self[2] ^= !lane3 & lane4;
        self[3] ^= !lane4 & lane0;
        self[4] ^= !lane0 & lane1;
    }
}

impl<T> Chi for KeccakState<T>
where
    T: Copy + Default,
    NBitWord<T>: BitAnd<Output = NBitWord<T>> + BitXorAssign + Not<Output = NBitWord<T>>,
{
    fn chi(&mut self) {
        let mut lane0: NBitWord<T>;
        let mut lane1: NBitWord<T>;
        let mut lane2: NBitWord<T>;
        let mut lane3: NBitWord<T>;
        let mut lane4: NBitWord<T>;

        for x in 0..5 {
            lane0 = self.planes[x][0];
            lane1 = self.planes[x][1];
            lane2 = self.planes[x][2];
            lane3 = self.planes[x][3];
            lane4 = self.planes[x][4];

            self.planes[x][0] ^= !lane1 & lane2;
            self.planes[x][1] ^= !lane2 & lane3;
            self.planes[x][2] ^= !lane3 & lane4;
            self.planes[x][3] ^= !lane4 & lane0;
            self.planes[x][4] ^= !lane0 & lane1;
        }
    }
}

impl<T: Copy + Default> Default for KeccakState<T> {
    fn default() -> Self {
        Self {
            planes: [Plane::<T>::default(); HEIGHT],
        }
    }
}

impl From<[[u64; WIDTH]; HEIGHT]> for KeccakState<u64> {
    fn from(lanes: [[u64; WIDTH]; HEIGHT]) -> Self {
        let mut state = Self::default();

        for x in 0..5 {
            for y in 0..5 {
                state.planes[x][y] = lanes[x][y].into();
            }
        }

        state
    }
}

impl<T> Iota for KeccakState<T>
where
    T: Copy + Default + BitXorAssign,
    NBitWord<T>: From<u64>,
{
    fn iota(&mut self, round: usize) {
        self.planes[0][0] ^= RC[round].into()
    }
}

impl<T> Pi for KeccakState<T>
where
    T: Default + Copy,
{
    fn pi(&mut self) {
        let lane1 = self.planes[0][1];
        self.planes[0][1] = self.planes[1][1];
        self.planes[1][1] = self.planes[1][4];
        self.planes[1][4] = self.planes[4][2];
        self.planes[4][2] = self.planes[2][4];
        self.planes[2][4] = self.planes[4][0];
        self.planes[4][0] = self.planes[0][2];
        self.planes[0][2] = self.planes[2][2];
        self.planes[2][2] = self.planes[2][3];
        self.planes[2][3] = self.planes[3][4];
        self.planes[3][4] = self.planes[4][3];
        self.planes[4][3] = self.planes[3][0];
        self.planes[3][0] = self.planes[0][4];
        self.planes[0][4] = self.planes[4][4];
        self.planes[4][4] = self.planes[4][1];
        self.planes[4][1] = self.planes[1][3];
        self.planes[1][3] = self.planes[3][1];
        self.planes[3][1] = self.planes[1][0];
        self.planes[1][0] = self.planes[0][3];
        self.planes[0][3] = self.planes[3][3];
        self.planes[3][3] = self.planes[3][2];
        self.planes[3][2] = self.planes[2][1];
        self.planes[2][1] = self.planes[1][2];
        self.planes[1][2] = self.planes[2][0];
        self.planes[2][0] = lane1;
    }
}

impl<T> Rho for KeccakState<T>
where
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + Copy + Default,
    NBitWord<T>: Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn rho(&mut self) {
        self.planes[0][1] = self.planes[0][1].rotate_left(1);
        self.planes[0][2] = self.planes[0][2].rotate_left(62);
        self.planes[0][3] = self.planes[0][3].rotate_left(28);
        self.planes[0][4] = self.planes[0][4].rotate_left(27);
        self.planes[1][0] = self.planes[1][0].rotate_left(36);
        self.planes[1][1] = self.planes[1][1].rotate_left(44);
        self.planes[1][2] = self.planes[1][2].rotate_left(6);
        self.planes[1][3] = self.planes[1][3].rotate_left(55);
        self.planes[1][4] = self.planes[1][4].rotate_left(20);
        self.planes[2][0] = self.planes[2][0].rotate_left(3);
        self.planes[2][1] = self.planes[2][1].rotate_left(10);
        self.planes[2][2] = self.planes[2][2].rotate_left(43);
        self.planes[2][3] = self.planes[2][3].rotate_left(25);
        self.planes[2][4] = self.planes[2][4].rotate_left(39);
        self.planes[3][0] = self.planes[3][0].rotate_left(41);
        self.planes[3][1] = self.planes[3][1].rotate_left(45);
        self.planes[3][2] = self.planes[3][2].rotate_left(15);
        self.planes[3][3] = self.planes[3][3].rotate_left(21);
        self.planes[3][4] = self.planes[3][4].rotate_left(8);
        self.planes[4][0] = self.planes[4][0].rotate_left(18);
        self.planes[4][1] = self.planes[4][1].rotate_left(2);
        self.planes[4][2] = self.planes[4][2].rotate_left(61);
        self.planes[4][3] = self.planes[4][3].rotate_left(56);
        self.planes[4][4] = self.planes[4][4].rotate_left(14);
    }
}

impl<T> Theta for KeccakState<T>
where
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor<Output = T> + BitXorAssign + Copy + Default,
    NBitWord<T>: Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn theta(&mut self) {
        let c: [NBitWord<T>; 5] = [
            self.bit_xor_lanes(0),
            self.bit_xor_lanes(1),
            self.bit_xor_lanes(2),
            self.bit_xor_lanes(3),
            self.bit_xor_lanes(4),
        ];

        let mut t: NBitWord<T>;
        for y in 0..5 {
            t = c[(y + 4) % 5] ^ c[(y + 1) % 5].rotate_left(1);

            self.planes[0][y] ^= t;
            self.planes[1][y] ^= t;
            self.planes[2][y] ^= t;
            self.planes[3][y] ^= t;
            self.planes[4][y] ^= t;
        }
    }
}
