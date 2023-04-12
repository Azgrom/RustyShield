use crate::Sha384Hasher;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::BuildHasher,
    ops::AddAssign,
};
use internal_hasher::{HashAlgorithm, U64Pad};
use internal_state::{BytesLen, DWords, NewGenericStateHasher, Sha512BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};
use n_bit_words_lib::NBitWord;

const H0: u64 = 0xCBBB9D5DC1059ED8;
const H1: u64 = 0x629A292A367CD507;
const H2: u64 = 0x9159015A3070DD17;
const H3: u64 = 0x152FECD8F70E5939;
const H4: u64 = 0x67332667FFC00B31;
const H5: u64 = 0x8EB44A8768581511;
const H6: u64 = 0xDB0C2E0D64F98FA7;
const H7: u64 = 0x47B5481DBEFA4FA4;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];
const BYTES_LEN: usize = 48;

#[derive(Clone, Debug)]
pub struct Sha384State(
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
);

impl AddAssign<Sha512BitsState> for Sha384State {
    fn add_assign(&mut self, rhs: Sha512BitsState) {
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

impl BuildHasher for Sha384State {
    type Hasher = Sha384Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha384State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha384State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u64; 8]> for Sha384State {
    fn from(v: [u64; 8]) -> Self {
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

impl From<Sha384State> for [u8; BYTES_LEN] {
    fn from(value: Sha384State) -> Self {
        let a = u64::to_be_bytes(value.0.into());
        let b = u64::to_be_bytes(value.1.into());
        let c = u64::to_be_bytes(value.2.into());
        let d = u64::to_be_bytes(value.3.into());
        let e = u64::to_be_bytes(value.4.into());
        let f = u64::to_be_bytes(value.5.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[5], e[0], e[1], e[2], e[3],
            e[4], e[5], e[6], e[7], f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
        ]
    }
}

impl HashAlgorithm for Sha384State {
    type Padding = U64Pad;
    type Output = [u8; BYTES_LEN];

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut state = Sha512BitsState(
            self.0,
            self.1,
            self.2,
            self.3,
            self.4,
            self.5,
            self.6,
            self.7,
            DWords::<u64>::from(<&[u8; 128]>::try_from(bytes).unwrap()),
        );

        state.block_00_15();
        state.block_16_31();
        state.block_32_47();
        state.block_48_63();
        state.block_64_79();

        *self += state;
    }

    fn state_to_u64(&self) -> u64 {
        Into::<u64>::into(self.0) << 32 | Into::<u64>::into(self.1)
    }
}

impl LowerHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.5, f)
    }
}

impl UpperHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.5, f)
    }
}
