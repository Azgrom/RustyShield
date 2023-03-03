use crate::sha384comp::Sha384Comp;
use crate::{sha384hasher::Sha384Hasher, sha384words::Sha384Words, SHA384PADDING_SIZE};
use core::hash::BuildHasher;
use core::ops::AddAssign;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{Hash, Hasher},
};
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
pub struct Sha384State(
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
);

impl Sha384State {
    pub(crate) fn block_00_15(&mut self, w: &[U64Word; 16]) {
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U64Word::K00);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U64Word::K01);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U64Word::K02);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U64Word::K03);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U64Word::K04);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U64Word::K05);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U64Word::K06);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U64Word::K07);
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U64Word::K08);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U64Word::K09);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U64Word::K10);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U64Word::K11);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U64Word::K12);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U64Word::K13);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U64Word::K14);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U64Word::K15);
    }

    pub(crate) fn block_16_31(&mut self, w: &mut [U64Word; 16]) {
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

        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U64Word::K16);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U64Word::K17);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U64Word::K18);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U64Word::K19);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U64Word::K20);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U64Word::K21);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U64Word::K22);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U64Word::K23);
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U64Word::K24);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U64Word::K25);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U64Word::K26);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U64Word::K27);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U64Word::K28);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U64Word::K29);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U64Word::K30);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U64Word::K31);
    }

    pub(crate) fn block_32_47(&mut self, w: &mut [U64Word; 16]) {
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

        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U64Word::K32);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U64Word::K33);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U64Word::K34);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U64Word::K35);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U64Word::K36);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U64Word::K37);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U64Word::K38);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U64Word::K39);
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U64Word::K40);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U64Word::K41);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U64Word::K42);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U64Word::K43);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U64Word::K44);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U64Word::K45);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U64Word::K46);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U64Word::K47);
    }

    pub(crate) fn block_48_63(&mut self, w: &mut [U64Word; 16]) {
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

        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U64Word::K48);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U64Word::K49);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U64Word::K50);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U64Word::K51);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U64Word::K52);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U64Word::K53);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U64Word::K54);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U64Word::K55);
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U64Word::K56);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U64Word::K57);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U64Word::K58);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U64Word::K59);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U64Word::K60);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U64Word::K61);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U64Word::K62);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U64Word::K63);
    }

    pub(crate) fn block_64_79(&mut self, w: &mut [U64Word; 16]) {
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

        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[0], U64Word::K64);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[1], U64Word::K65);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[2], U64Word::K66);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[3], U64Word::K67);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[4], U64Word::K68);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[5], U64Word::K69);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[6], U64Word::K70);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[7], U64Word::K71);
        Sha384Comp(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7).rnd(w[8], U64Word::K72);
        Sha384Comp(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6).rnd(w[9], U64Word::K73);
        Sha384Comp(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5).rnd(w[10], U64Word::K74);
        Sha384Comp(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4).rnd(w[11], U64Word::K75);
        Sha384Comp(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3).rnd(w[12], U64Word::K76);
        Sha384Comp(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2).rnd(w[13], U64Word::K77);
        Sha384Comp(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1).rnd(w[14], U64Word::K78);
        Sha384Comp(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0).rnd(w[15], U64Word::K79);
    }
}

impl AddAssign for Sha384State {
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

impl From<Sha384State> for [u8; SHA384PADDING_SIZE as usize] {
    fn from(value: Sha384State) -> Self {
        let a = value.0.to_be_bytes();
        let b = value.1.to_be_bytes();
        let c = value.2.to_be_bytes();
        let d = value.3.to_be_bytes();
        let e = value.4.to_be_bytes();
        let f = value.5.to_be_bytes();

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[5], e[0], e[1], e[2], e[3],
            e[4], e[5], e[6], e[7], f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
        ]
    }
}

impl Hash for Sha384State {
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

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";

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
