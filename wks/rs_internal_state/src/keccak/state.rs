use crate::{
    keccak::chi::Chi,
    keccak::iota::Iota,
    keccak::pi::Pi,
    keccak::plane::Plane,
    keccak::rho::Rho,
    keccak::theta::Theta,
    keccak::{HEIGHT, RC, WIDTH},
};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};

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
    pub(crate) planes: [Plane<T>; HEIGHT],
}

impl<T> KeccakState<T>
where
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default,
    NBitWord<T>: Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    #[inline(always)]
    fn bit_xor_lanes(&self, y: usize) -> NBitWord<T> {
        self.planes[0][y] ^ self.planes[1][y] ^ self.planes[2][y] ^ self.planes[3][y] ^ self.planes[4][y]
    }
}

impl<T> KeccakState<T>
where
    T: BitAnd + BitAndAssign + BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default + Not,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    pub fn apply_f(&mut self) {
        (0..24).fold(self, |state, i| {
            state.theta();
            state.rho();
            state.pi();
            state.chi();
            state.iota(i);

            state
        });
    }
}

impl<T> Chi for KeccakState<T>
where
    T: Copy + Default,
    NBitWord<T>: BitAnd<Output = NBitWord<T>> + BitXorAssign + Not<Output = NBitWord<T>>,
{
    fn chi(&mut self) {
        (0..5).fold(&mut self.planes, |planes, x| {
            let lane0: NBitWord<T> = planes[x][0];
            let lane1: NBitWord<T> = planes[x][1];
            let lane2: NBitWord<T> = planes[x][2];
            let lane3: NBitWord<T> = planes[x][3];
            let lane4: NBitWord<T> = planes[x][4];

            planes[x][0] ^= !lane1 & lane2;
            planes[x][1] ^= !lane2 & lane3;
            planes[x][2] ^= !lane3 & lane4;
            planes[x][3] ^= !lane4 & lane0;
            planes[x][4] ^= !lane0 & lane1;

            planes
        });
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
    fn from(planes: [[u64; WIDTH]; HEIGHT]) -> Self {
        let mut state = Self::default();

        for (self_plane, from_plane) in state.planes.iter_mut().zip(planes.iter()) {
            for (self_lane, from_lane) in self_plane.into_iter().zip(from_plane.iter()) {
                *self_lane = (*from_lane).into();
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
    T: BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default,
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

        (0..5).fold(&mut self.planes, |planes, y| {
            let t: NBitWord<T> = c[(y + 4) % 5] ^ c[(y + 1) % 5].rotate_left(1);

            planes[0][y] ^= t;
            planes[1][y] ^= t;
            planes[2][y] ^= t;
            planes[3][y] ^= t;
            planes[4][y] ^= t;

            planes
        });
    }
}
