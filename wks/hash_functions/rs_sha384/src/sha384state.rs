use crate::{sha384hasher::Sha384Hasher, sha384words::Sha384Words, SHA384PADDING_SIZE};
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::BuildHasher,
    hash::{Hash, Hasher},
    ops::AddAssign,
};
use internal_state::Sha512BitsState;
use n_bit_words_lib::U64Word;

const H0: u64 = 0xCBBB9D5DC1059ED8;
const H1: u64 = 0x629A292A367CD507;
const H2: u64 = 0x9159015A3070DD17;
const H3: u64 = 0x152FECD8F70E5939;
const H4: u64 = 0x67332667FFC00B31;
const H5: u64 = 0x8EB44A8768581511;
const H6: u64 = 0xDB0C2E0D64F98FA7;
const H7: u64 = 0x47B5481DBEFA4FA4;

#[derive(Clone)]
pub struct Sha384State(pub(crate) Sha512BitsState);

impl Sha384State {
    pub(crate) fn block_00_15(&mut self, w: &[U64Word; 16]) {
        self.0.block_00_15(w)
    }

    pub(crate) fn block_16_31(&mut self, w: &mut [U64Word; 16]) {
        self.0.block_16_31(w)
    }

    pub(crate) fn block_32_47(&mut self, w: &mut [U64Word; 16]) {
        self.0.block_32_47(w)
    }

    pub(crate) fn block_48_63(&mut self, w: &mut [U64Word; 16]) {
        self.0.block_48_63(w)
    }

    pub(crate) fn block_64_79(&mut self, w: &mut [U64Word; 16]) {
        self.0.block_64_79(w)
    }
}

impl AddAssign for Sha384State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl BuildHasher for Sha384State {
    type Hasher = Sha384Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha384Hasher {
            size: u128::MIN,
            state: self.clone(),
            words: Sha384Words::default(),
        }
    }
}

impl Default for Sha384State {
    fn default() -> Self {
        Self(Sha512BitsState(
            H0.into(),
            H1.into(),
            H2.into(),
            H3.into(),
            H4.into(),
            H5.into(),
            H6.into(),
            H7.into(),
        ))
    }
}

impl From<Sha384State> for [u8; SHA384PADDING_SIZE as usize] {
    fn from(value: Sha384State) -> Self {
        let a = value.0 .0.to_be_bytes();
        let b = value.0 .1.to_be_bytes();
        let c = value.0 .2.to_be_bytes();
        let d = value.0 .3.to_be_bytes();
        let e = value.0 .4.to_be_bytes();
        let f = value.0 .5.to_be_bytes();

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5],
            b[6], b[7], c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3],
            d[4], d[5], d[6], d[5], e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7], f[0], f[1],
            f[2], f[3], f[4], f[5], f[6], f[7],
        ]
    }
}

impl Hash for Sha384State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .5, f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";

impl UpperHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .5, f)
    }
}
