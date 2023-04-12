use crate::Sha224Hasher;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::BuildHasher,
    ops::AddAssign
};
use internal_hasher::{HashAlgorithm, U32Pad};
use internal_state::{BytesLen, DWords, NewGenericStateHasher, Sha256BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};
use n_bit_words_lib::NBitWord;

const H0: u32 = 0xC1059ED8;
const H1: u32 = 0x367CD507;
const H2: u32 = 0x3070DD17;
const H3: u32 = 0xF70E5939;
const H4: u32 = 0xFFC00B31;
const H5: u32 = 0x68581511;
const H6: u32 = 0x64F98FA7;
const H7: u32 = 0xBEFA4FA4;

const HX: [u32; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];
const BYTES_LEN: usize = 28;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha224State(
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
);

impl AddAssign<Sha256BitsState> for Sha224State {
    fn add_assign(&mut self, rhs: Sha256BitsState) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
        self.5 += rhs.5;
        self.6 += rhs.6;
        self.7 += rhs.7;
    }
}

impl BuildHasher for Sha224State {
    type Hasher = Sha224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha224State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha224State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u32; 8]> for Sha224State {
    fn from(v: [u32; 8]) -> Self {
        Self(
            NBitWord::from(v[0]),
            NBitWord::from(v[1]),
            NBitWord::from(v[2]),
            NBitWord::from(v[3]),
            NBitWord::from(v[4]),
            NBitWord::from(v[5]),
            NBitWord::from(v[6]),
            NBitWord::from(v[7]),
        )
    }
}

impl From<Sha224State> for [u8; BYTES_LEN] {
    fn from(value: Sha224State) -> Self {
        let a = u32::to_be_bytes(value.0.into());
        let b = u32::to_be_bytes(value.1.into());
        let c = u32::to_be_bytes(value.2.into());
        let d = u32::to_be_bytes(value.3.into());
        let e = u32::to_be_bytes(value.4.into());
        let f = u32::to_be_bytes(value.5.into());
        let g = u32::to_be_bytes(value.6.into());

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3], e[0], e[1],
            e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3],
        ]
    }
}

impl HashAlgorithm for Sha224State {
    type Padding = U32Pad;
    type Output = [u8; BYTES_LEN];

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut state = Sha256BitsState(
            self.0,
            self.1,
            self.2,
            self.3,
            self.4,
            self.5,
            self.6,
            self.7,
            DWords::<u32>::from(<&[u8; 64]>::try_from(bytes).unwrap()),
        );

        state.block_00_15();
        state.block_16_31();
        state.block_32_47();
        state.block_48_63();

        *self += state;
    }

    fn state_to_u64(&self) -> u64 {
        Into::<u64>::into(self.0) << 32 | Into::<u64>::into(self.1)
    }
}

impl LowerHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.5, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.6, f)
    }
}

impl UpperHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.5, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.6, f)
    }
}
