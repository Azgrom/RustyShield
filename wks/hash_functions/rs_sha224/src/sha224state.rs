use crate::{sha224hasher::Sha224Hasher, sha224words::Sha224Words};
use core::ops::AddAssign;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
};
use internal_state::Sha256BitsState;
use n_bit_words_lib::U32Word;

const H0: u32 = 0xC1059ED8;
const H1: u32 = 0x367CD507;
const H2: u32 = 0x3070DD17;
const H3: u32 = 0xF70E5939;
const H4: u32 = 0xFFC00B31;
const H5: u32 = 0x68581511;
const H6: u32 = 0x64F98FA7;
const H7: u32 = 0xBEFA4FA4;

#[derive(Clone)]
pub struct Sha224State(pub(crate) Sha256BitsState);

impl Sha224State {
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

impl AddAssign for Sha224State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl BuildHasher for Sha224State {
    type Hasher = Sha224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha224Hasher {
            size: u64::MIN,
            state: self.clone(),
            words: Sha224Words::default(),
        }
    }
}

impl Default for Sha224State {
    fn default() -> Self {
        Self(
            Sha256BitsState(H0.into(),
                            H1.into(),
                            H2.into(),
                            H3.into(),
                            H4.into(),
                            H5.into(),
                            H6.into(),
                            H7.into(),)
        )
    }
}

impl From<Sha224State> for [u8; 28] {
    fn from(value: Sha224State) -> Self {
        let a = value.0.0.to_be_bytes();
        let b = value.0.1.to_be_bytes();
        let c = value.0.2.to_be_bytes();
        let d = value.0.3.to_be_bytes();
        let e = value.0.4.to_be_bytes();
        let f = value.0.5.to_be_bytes();
        let g = value.0.6.to_be_bytes();

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3], e[0], e[1],
            e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3],
        ]
    }
}

impl Hash for Sha224State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.5, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0.6, f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.5, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0.6, f)
    }
}
