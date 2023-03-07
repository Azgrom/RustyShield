use crate::{sha256hasher::Sha256Hasher, sha256words::Sha256Words};
use core::ops::AddAssign;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
};
use internal_state::Sha256BitsState;
use n_bit_words_lib::U32Word;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

#[derive(Clone, Debug)]
pub struct Sha256State(pub(crate) Sha256BitsState);

impl Sha256State {
    pub(crate) fn block_00_15(&mut self, w: &[U32Word; 16]) {
        self.0.block_00_15(w)
    }

    pub(crate) fn block_16_31(&mut self, w: &mut [U32Word; 16]) {
        self.0.block_16_31(w)
    }

    pub(crate) fn block_32_47(&mut self, w: &mut [U32Word; 16]) {
        self.0.block_32_47(w)
    }

    pub(crate) fn block_48_63(&mut self, w: &mut [U32Word; 16]) {
        self.0.block_48_63(w)
    }
}

impl AddAssign for Sha256State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha256Hasher {
            size: u64::MIN,
            state: self.clone(),
            words: Sha256Words::default(),
        }
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self(Sha256BitsState(
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

impl From<Sha256State> for [u8; 32] {
    fn from(value: Sha256State) -> Self {
        let a = value.0 .0.to_be_bytes();
        let b = value.0 .1.to_be_bytes();
        let c = value.0 .2.to_be_bytes();
        let d = value.0 .3.to_be_bytes();
        let e = value.0 .4.to_be_bytes();
        let f = value.0 .5.to_be_bytes();
        let g = value.0 .6.to_be_bytes();
        let h = value.0 .7.to_be_bytes();

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1],
            d[2], d[3], e[0], e[1], e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3],
            h[0], h[1], h[2], h[3],
        ]
    }
}

impl Hash for Sha256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .5, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .6, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .7, f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .5, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .6, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .7, f)
    }
}
