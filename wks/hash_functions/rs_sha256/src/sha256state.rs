use crate::sha256comp::Sha256Comp;
use crate::{sha256hasher::Sha256Hasher, sha256words::Sha256Words};
use core::ops::AddAssign;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
};
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
pub struct Sha256State(
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
);

impl Sha256State {
    pub(crate) fn block_00_15(&mut self, w: &[U32Word; 16]) {
        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U32Word::K00);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U32Word::K01);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U32Word::K02);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U32Word::K03);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U32Word::K04);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U32Word::K05);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U32Word::K06);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U32Word::K07);
        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U32Word::K08);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U32Word::K09);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U32Word::K10);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U32Word::K11);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U32Word::K12);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U32Word::K13);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U32Word::K14);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U32Word::K15);
    }

    pub(crate) fn block_16_31(&mut self, w: &mut [U32Word; 16]) {
        w[0] = w[0] + w[1].gamma0() + w[9] + w[14].gamma1();
        w[1] = w[1] + w[2].gamma0() + w[10] + w[15].gamma1();
        w[2] = w[2] + w[3].gamma0() + w[11] + w[0].gamma1();
        w[3] = w[3] + w[4].gamma0() + w[12] + w[1].gamma1();
        w[4] = w[4] + w[5].gamma0() + w[13] + w[2].gamma1();
        w[5] = w[5] + w[6].gamma0() + w[14] + w[3].gamma1();
        w[6] = w[6] + w[7].gamma0() + w[15] + w[4].gamma1();
        w[7] = w[7] + w[8].gamma0() + w[0] + w[5].gamma1();
        w[8] = w[8] + w[9].gamma0() + w[1] + w[6].gamma1();
        w[9] = w[9] + w[10].gamma0() + w[2] + w[7].gamma1();
        w[10] = w[10] + w[11].gamma0() + w[3] + w[8].gamma1();
        w[11] = w[11] + w[12].gamma0() + w[4] + w[9].gamma1();
        w[12] = w[12] + w[13].gamma0() + w[5] + w[10].gamma1();
        w[13] = w[13] + w[14].gamma0() + w[6] + w[11].gamma1();
        w[14] = w[14] + w[15].gamma0() + w[7] + w[12].gamma1();
        w[15] = w[15] + w[0].gamma0() + w[8] + w[13].gamma1();

        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U32Word::K16);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U32Word::K17);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U32Word::K18);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U32Word::K19);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U32Word::K20);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U32Word::K21);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U32Word::K22);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U32Word::K23);
        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U32Word::K24);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U32Word::K25);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U32Word::K26);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U32Word::K27);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U32Word::K28);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U32Word::K29);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U32Word::K30);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U32Word::K31);
    }

    pub(crate) fn block_32_47(&mut self, w: &mut [U32Word; 16]) {
        w[0] = w[0] + w[1].gamma0() + w[9] + w[14].gamma1();
        w[1] = w[1] + w[2].gamma0() + w[10] + w[15].gamma1();
        w[2] = w[2] + w[3].gamma0() + w[11] + w[0].gamma1();
        w[3] = w[3] + w[4].gamma0() + w[12] + w[1].gamma1();
        w[4] = w[4] + w[5].gamma0() + w[13] + w[2].gamma1();
        w[5] = w[5] + w[6].gamma0() + w[14] + w[3].gamma1();
        w[6] = w[6] + w[7].gamma0() + w[15] + w[4].gamma1();
        w[7] = w[7] + w[8].gamma0() + w[0] + w[5].gamma1();
        w[8] = w[8] + w[9].gamma0() + w[1] + w[6].gamma1();
        w[9] = w[9] + w[10].gamma0() + w[2] + w[7].gamma1();
        w[10] = w[10] + w[11].gamma0() + w[3] + w[8].gamma1();
        w[11] = w[11] + w[12].gamma0() + w[4] + w[9].gamma1();
        w[12] = w[12] + w[13].gamma0() + w[5] + w[10].gamma1();
        w[13] = w[13] + w[14].gamma0() + w[6] + w[11].gamma1();
        w[14] = w[14] + w[15].gamma0() + w[7] + w[12].gamma1();
        w[15] = w[15] + w[0].gamma0() + w[8] + w[13].gamma1();

        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U32Word::K32);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U32Word::K33);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U32Word::K34);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U32Word::K35);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U32Word::K36);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U32Word::K37);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U32Word::K38);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U32Word::K39);
        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U32Word::K40);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U32Word::K41);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U32Word::K42);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U32Word::K43);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U32Word::K44);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U32Word::K45);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U32Word::K46);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U32Word::K47);
    }

    pub(crate) fn block_48_63(&mut self, w: &mut [U32Word; 16]) {
        w[0] = w[0] + w[1].gamma0() + w[9] + w[14].gamma1();
        w[1] = w[1] + w[2].gamma0() + w[10] + w[15].gamma1();
        w[2] = w[2] + w[3].gamma0() + w[11] + w[0].gamma1();
        w[3] = w[3] + w[4].gamma0() + w[12] + w[1].gamma1();
        w[4] = w[4] + w[5].gamma0() + w[13] + w[2].gamma1();
        w[5] = w[5] + w[6].gamma0() + w[14] + w[3].gamma1();
        w[6] = w[6] + w[7].gamma0() + w[15] + w[4].gamma1();
        w[7] = w[7] + w[8].gamma0() + w[0] + w[5].gamma1();
        w[8] = w[8] + w[9].gamma0() + w[1] + w[6].gamma1();
        w[9] = w[9] + w[10].gamma0() + w[2] + w[7].gamma1();
        w[10] = w[10] + w[11].gamma0() + w[3] + w[8].gamma1();
        w[11] = w[11] + w[12].gamma0() + w[4] + w[9].gamma1();
        w[12] = w[12] + w[13].gamma0() + w[5] + w[10].gamma1();
        w[13] = w[13] + w[14].gamma0() + w[6] + w[11].gamma1();
        w[14] = w[14] + w[15].gamma0() + w[7] + w[12].gamma1();
        w[15] = w[15] + w[0].gamma0() + w[8] + w[13].gamma1();

        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U32Word::K48);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U32Word::K49);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U32Word::K50);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U32Word::K51);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U32Word::K52);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U32Word::K53);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U32Word::K54);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U32Word::K55);
        Sha256Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U32Word::K56);
        Sha256Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U32Word::K57);
        Sha256Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U32Word::K58);
        Sha256Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U32Word::K59);
        Sha256Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U32Word::K60);
        Sha256Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U32Word::K61);
        Sha256Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U32Word::K62);
        Sha256Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U32Word::K63);
    }
}

impl AddAssign for Sha256State {
    fn add_assign(&mut self, rhs: Self) {
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
        Self(
            H0.into(),
            H1.into(),
            H2.into(),
            H3.into(),
            H4.into(),
            H5.into(),
            H6.into(),
            H7.into(),
        )
    }
}

impl From<Sha256State> for [u8; 32] {
    fn from(value: Sha256State) -> Self {
        let a = value.0.to_be_bytes();
        let b = value.1.to_be_bytes();
        let c = value.2.to_be_bytes();
        let d = value.3.to_be_bytes();
        let e = value.4.to_be_bytes();
        let f = value.5.to_be_bytes();
        let g = value.6.to_be_bytes();
        let h = value.7.to_be_bytes();

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3], e[0], e[1],
            e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3], h[0], h[1], h[2], h[3],
        ]
    }
}

impl Hash for Sha256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2.hash(state);
        self.3.hash(state);
        self.4.hash(state);
        self.5.hash(state);
        self.6.hash(state);
        self.7.hash(state);
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.5, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.6, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.7, f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.5, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.6, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.7, f)
    }
}
