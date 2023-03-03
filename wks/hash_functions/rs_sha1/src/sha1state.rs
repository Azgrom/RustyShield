use crate::sha1comp::Sha1Comp;
use crate::{sha1hasher::Sha1Hasher, sha1words::Sha1Padding, SHA1_WORD_COUNT};
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::AddAssign,
};
use n_bit_words_lib::U32Word;

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

#[derive(Clone, Debug)]
pub struct Sha1State(pub U32Word, pub U32Word, pub U32Word, pub U32Word, pub U32Word);

impl Sha1State {
    pub(crate) fn block_00_15(&mut self, words: &[U32Word; SHA1_WORD_COUNT as usize]) {
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[0]).rounds_00_19();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[1]).rounds_00_19();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[2]).rounds_00_19();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[3]).rounds_00_19();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[4]).rounds_00_19();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[5]).rounds_00_19();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[6]).rounds_00_19();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[7]).rounds_00_19();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[8]).rounds_00_19();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[9]).rounds_00_19();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[10]).rounds_00_19();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[11]).rounds_00_19();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[12]).rounds_00_19();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[13]).rounds_00_19();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[14]).rounds_00_19();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[15]).rounds_00_19();
    }

    pub(crate) fn block_16_31(&mut self, words: &mut [U32Word; SHA1_WORD_COUNT as usize]) {
        words[0] = (words[0] ^ words[2] ^ words[8] ^ words[13]).rotate_left(1);
        words[1] = (words[1] ^ words[3] ^ words[9] ^ words[14]).rotate_left(1);
        words[2] = (words[2] ^ words[4] ^ words[10] ^ words[15]).rotate_left(1);
        words[3] = (words[3] ^ words[5] ^ words[11] ^ words[0]).rotate_left(1);
        words[4] = (words[4] ^ words[6] ^ words[12] ^ words[1]).rotate_left(1);
        words[5] = (words[5] ^ words[7] ^ words[13] ^ words[2]).rotate_left(1);
        words[6] = (words[6] ^ words[8] ^ words[14] ^ words[3]).rotate_left(1);
        words[7] = (words[7] ^ words[9] ^ words[15] ^ words[4]).rotate_left(1);
        words[8] = (words[8] ^ words[10] ^ words[0] ^ words[5]).rotate_left(1);
        words[9] = (words[9] ^ words[11] ^ words[1] ^ words[6]).rotate_left(1);
        words[10] = (words[10] ^ words[12] ^ words[2] ^ words[7]).rotate_left(1);
        words[11] = (words[11] ^ words[13] ^ words[3] ^ words[8]).rotate_left(1);
        words[12] = (words[12] ^ words[14] ^ words[4] ^ words[9]).rotate_left(1);
        words[13] = (words[13] ^ words[15] ^ words[5] ^ words[10]).rotate_left(1);
        words[14] = (words[14] ^ words[0] ^ words[6] ^ words[11]).rotate_left(1);
        words[15] = (words[15] ^ words[1] ^ words[7] ^ words[12]).rotate_left(1);

        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[0]).rounds_00_19();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[1]).rounds_00_19();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[2]).rounds_00_19();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[3]).rounds_00_19();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[4]).rounds_20_39();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[5]).rounds_20_39();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[6]).rounds_20_39();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[7]).rounds_20_39();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[8]).rounds_20_39();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[9]).rounds_20_39();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[10]).rounds_20_39();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[11]).rounds_20_39();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[12]).rounds_20_39();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[13]).rounds_20_39();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[14]).rounds_20_39();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[15]).rounds_20_39();
    }

    pub(crate) fn block_32_47(&mut self, words: &mut [U32Word; SHA1_WORD_COUNT as usize]) {
        words[0] = (words[0] ^ words[2] ^ words[8] ^ words[13]).rotate_left(1);
        words[1] = (words[1] ^ words[3] ^ words[9] ^ words[14]).rotate_left(1);
        words[2] = (words[2] ^ words[4] ^ words[10] ^ words[15]).rotate_left(1);
        words[3] = (words[3] ^ words[5] ^ words[11] ^ words[0]).rotate_left(1);
        words[4] = (words[4] ^ words[6] ^ words[12] ^ words[1]).rotate_left(1);
        words[5] = (words[5] ^ words[7] ^ words[13] ^ words[2]).rotate_left(1);
        words[6] = (words[6] ^ words[8] ^ words[14] ^ words[3]).rotate_left(1);
        words[7] = (words[7] ^ words[9] ^ words[15] ^ words[4]).rotate_left(1);
        words[8] = (words[8] ^ words[10] ^ words[0] ^ words[5]).rotate_left(1);
        words[9] = (words[9] ^ words[11] ^ words[1] ^ words[6]).rotate_left(1);
        words[10] = (words[10] ^ words[12] ^ words[2] ^ words[7]).rotate_left(1);
        words[11] = (words[11] ^ words[13] ^ words[3] ^ words[8]).rotate_left(1);
        words[12] = (words[12] ^ words[14] ^ words[4] ^ words[9]).rotate_left(1);
        words[13] = (words[13] ^ words[15] ^ words[5] ^ words[10]).rotate_left(1);
        words[14] = (words[14] ^ words[0] ^ words[6] ^ words[11]).rotate_left(1);
        words[15] = (words[15] ^ words[1] ^ words[7] ^ words[12]).rotate_left(1);
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[0]).rounds_20_39();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[1]).rounds_20_39();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[2]).rounds_20_39();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[3]).rounds_20_39();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[4]).rounds_20_39();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[5]).rounds_20_39();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[6]).rounds_20_39();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[7]).rounds_20_39();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[8]).rounds_40_59();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[9]).rounds_40_59();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[10]).rounds_40_59();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[11]).rounds_40_59();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[12]).rounds_40_59();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[13]).rounds_40_59();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[14]).rounds_40_59();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[15]).rounds_40_59();
    }

    pub(crate) fn block_48_63(&mut self, words: &mut [U32Word; SHA1_WORD_COUNT as usize]) {
        words[0] = (words[0] ^ words[2] ^ words[8] ^ words[13]).rotate_left(1);
        words[1] = (words[1] ^ words[3] ^ words[9] ^ words[14]).rotate_left(1);
        words[2] = (words[2] ^ words[4] ^ words[10] ^ words[15]).rotate_left(1);
        words[3] = (words[3] ^ words[5] ^ words[11] ^ words[0]).rotate_left(1);
        words[4] = (words[4] ^ words[6] ^ words[12] ^ words[1]).rotate_left(1);
        words[5] = (words[5] ^ words[7] ^ words[13] ^ words[2]).rotate_left(1);
        words[6] = (words[6] ^ words[8] ^ words[14] ^ words[3]).rotate_left(1);
        words[7] = (words[7] ^ words[9] ^ words[15] ^ words[4]).rotate_left(1);
        words[8] = (words[8] ^ words[10] ^ words[0] ^ words[5]).rotate_left(1);
        words[9] = (words[9] ^ words[11] ^ words[1] ^ words[6]).rotate_left(1);
        words[10] = (words[10] ^ words[12] ^ words[2] ^ words[7]).rotate_left(1);
        words[11] = (words[11] ^ words[13] ^ words[3] ^ words[8]).rotate_left(1);
        words[12] = (words[12] ^ words[14] ^ words[4] ^ words[9]).rotate_left(1);
        words[13] = (words[13] ^ words[15] ^ words[5] ^ words[10]).rotate_left(1);
        words[14] = (words[14] ^ words[0] ^ words[6] ^ words[11]).rotate_left(1);
        words[15] = (words[15] ^ words[1] ^ words[7] ^ words[12]).rotate_left(1);

        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[0]).rounds_40_59();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[1]).rounds_40_59();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[2]).rounds_40_59();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[3]).rounds_40_59();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[4]).rounds_40_59();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[5]).rounds_40_59();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[6]).rounds_40_59();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[7]).rounds_40_59();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[8]).rounds_40_59();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[9]).rounds_40_59();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[10]).rounds_40_59();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[11]).rounds_40_59();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[12]).rounds_60_79();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[13]).rounds_60_79();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[14]).rounds_60_79();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[15]).rounds_60_79();
    }

    pub(crate) fn block_64_79(&mut self, words: &mut [U32Word; SHA1_WORD_COUNT as usize]) {
        words[0] = (words[0] ^ words[2] ^ words[8] ^ words[13]).rotate_left(1);
        words[1] = (words[1] ^ words[3] ^ words[9] ^ words[14]).rotate_left(1);
        words[2] = (words[2] ^ words[4] ^ words[10] ^ words[15]).rotate_left(1);
        words[3] = (words[3] ^ words[5] ^ words[11] ^ words[0]).rotate_left(1);
        words[4] = (words[4] ^ words[6] ^ words[12] ^ words[1]).rotate_left(1);
        words[5] = (words[5] ^ words[7] ^ words[13] ^ words[2]).rotate_left(1);
        words[6] = (words[6] ^ words[8] ^ words[14] ^ words[3]).rotate_left(1);
        words[7] = (words[7] ^ words[9] ^ words[15] ^ words[4]).rotate_left(1);
        words[8] = (words[8] ^ words[10] ^ words[0] ^ words[5]).rotate_left(1);
        words[9] = (words[9] ^ words[11] ^ words[1] ^ words[6]).rotate_left(1);
        words[10] = (words[10] ^ words[12] ^ words[2] ^ words[7]).rotate_left(1);
        words[11] = (words[11] ^ words[13] ^ words[3] ^ words[8]).rotate_left(1);
        words[12] = (words[12] ^ words[14] ^ words[4] ^ words[9]).rotate_left(1);
        words[13] = (words[13] ^ words[15] ^ words[5] ^ words[10]).rotate_left(1);
        words[14] = (words[14] ^ words[0] ^ words[6] ^ words[11]).rotate_left(1);
        words[15] = (words[15] ^ words[1] ^ words[7] ^ words[12]).rotate_left(1);

        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[0]).rounds_60_79();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[1]).rounds_60_79();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[2]).rounds_60_79();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[3]).rounds_60_79();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[4]).rounds_60_79();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[5]).rounds_60_79();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[6]).rounds_60_79();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[7]).rounds_60_79();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[8]).rounds_60_79();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[9]).rounds_60_79();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[10]).rounds_60_79();
        Sha1Comp(self.0, &mut self.1, self.2, self.3, &mut self.4, words[11]).rounds_60_79();
        Sha1Comp(self.4, &mut self.0, self.1, self.2, &mut self.3, words[12]).rounds_60_79();
        Sha1Comp(self.3, &mut self.4, self.0, self.1, &mut self.2, words[13]).rounds_60_79();
        Sha1Comp(self.2, &mut self.3, self.4, self.0, &mut self.1, words[14]).rounds_60_79();
        Sha1Comp(self.1, &mut self.2, self.3, self.4, &mut self.0, words[15]).rounds_60_79();
    }
}

impl AddAssign for Sha1State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
    }
}

impl BuildHasher for Sha1State {
    type Hasher = Sha1Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha1Hasher {
            size: u64::default(),
            state: self.clone(),
            words: Sha1Padding::default(),
        }
    }
}

impl Default for Sha1State {
    fn default() -> Self {
        Self(H0.into(), H1.into(), H2.into(), H3.into(), H4.into())
    }
}

impl From<Sha1State> for [u8; 20] {
    fn from(value: Sha1State) -> Self {
        let x = value.0.to_be_bytes();
        let y = value.1.to_be_bytes();
        let z = value.2.to_be_bytes();
        let w = value.3.to_be_bytes();
        let t = value.4.to_be_bytes();

        [
            x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3], z[0], z[1], z[2], z[3], w[0], w[1], w[2], w[3], t[0], t[1],
            t[2], t[3],
        ]
    }
}

impl Hash for Sha1State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2.hash(state);
        self.3.hash(state);
        self.4.hash(state);
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.4, f)
    }
}

impl PartialEq for Sha1State {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3 && self.4 == other.4
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.4, f)
    }
}
