use crate::rotors::sha256rotor::Sha256Rotor as Rotor;
use core::{
    hash::{Hash, Hasher},
    ops::AddAssign,
};
use n_bit_words_lib::{NBitWord, TSize};

type U32Word = NBitWord<u32>;

#[derive(Clone, Debug)]
pub struct Sha256BitsState(
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
);

impl Sha256BitsState {
    fn next_words(w: &mut [U32Word; 16]) {
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
    }

    pub fn block_00_15(&mut self, w: &[U32Word; 16]) {
        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[0],
        )
        .rnd(Self::K00.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[1],
        )
        .rnd(Self::K01.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[2],
        )
        .rnd(Self::K02.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[3],
        )
        .rnd(Self::K03.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[4],
        )
        .rnd(Self::K04.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[5],
        )
        .rnd(Self::K05.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[6],
        )
        .rnd(Self::K06.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[7],
        )
        .rnd(Self::K07.into());
        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[8],
        )
        .rnd(Self::K08.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[9],
        )
        .rnd(Self::K09.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[10],
        )
        .rnd(Self::K10.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[11],
        )
        .rnd(Self::K11.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[12],
        )
        .rnd(Self::K12.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[13],
        )
        .rnd(Self::K13.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[14],
        )
        .rnd(Self::K14.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[15],
        )
        .rnd(Self::K15.into());
    }

    pub fn block_16_31(&mut self, w: &mut [U32Word; 16]) {
        Self::next_words(w);

        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[0],
        )
        .rnd(Self::K16.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[1],
        )
        .rnd(Self::K17.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[2],
        )
        .rnd(Self::K18.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[3],
        )
        .rnd(Self::K19.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[4],
        )
        .rnd(Self::K20.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[5],
        )
        .rnd(Self::K21.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[6],
        )
        .rnd(Self::K22.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[7],
        )
        .rnd(Self::K23.into());
        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[8],
        )
        .rnd(Self::K24.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[9],
        )
        .rnd(Self::K25.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[10],
        )
        .rnd(Self::K26.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[11],
        )
        .rnd(Self::K27.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[12],
        )
        .rnd(Self::K28.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[13],
        )
        .rnd(Self::K29.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[14],
        )
        .rnd(Self::K30.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[15],
        )
        .rnd(Self::K31.into());
    }

    pub fn block_32_47(&mut self, w: &mut [U32Word; 16]) {
        Self::next_words(w);

        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[0],
        )
        .rnd(Self::K32.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[1],
        )
        .rnd(Self::K33.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[2],
        )
        .rnd(Self::K34.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[3],
        )
        .rnd(Self::K35.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[4],
        )
        .rnd(Self::K36.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[5],
        )
        .rnd(Self::K37.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[6],
        )
        .rnd(Self::K38.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[7],
        )
        .rnd(Self::K39.into());
        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[8],
        )
        .rnd(Self::K40.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[9],
        )
        .rnd(Self::K41.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[10],
        )
        .rnd(Self::K42.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[11],
        )
        .rnd(Self::K43.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[12],
        )
        .rnd(Self::K44.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[13],
        )
        .rnd(Self::K45.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[14],
        )
        .rnd(Self::K46.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[15],
        )
        .rnd(Self::K47.into());
    }

    pub fn block_48_63(&mut self, w: &mut [U32Word; 16]) {
        Self::next_words(w);

        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[0],
        )
        .rnd(Self::K48.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[1],
        )
        .rnd(Self::K49.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[2],
        )
        .rnd(Self::K50.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[3],
        )
        .rnd(Self::K51.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[4],
        )
        .rnd(Self::K52.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[5],
        )
        .rnd(Self::K53.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[6],
        )
        .rnd(Self::K54.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[7],
        )
        .rnd(Self::K55.into());
        Rotor(
            self.0,
            self.1,
            self.2,
            &mut self.3,
            self.4,
            self.5,
            self.6,
            &mut self.7,
            w[8],
        )
        .rnd(Self::K56.into());
        Rotor(
            self.7,
            self.0,
            self.1,
            &mut self.2,
            self.3,
            self.4,
            self.5,
            &mut self.6,
            w[9],
        )
        .rnd(Self::K57.into());
        Rotor(
            self.6,
            self.7,
            self.0,
            &mut self.1,
            self.2,
            self.3,
            self.4,
            &mut self.5,
            w[10],
        )
        .rnd(Self::K58.into());
        Rotor(
            self.5,
            self.6,
            self.7,
            &mut self.0,
            self.1,
            self.2,
            self.3,
            &mut self.4,
            w[11],
        )
        .rnd(Self::K59.into());
        Rotor(
            self.4,
            self.5,
            self.6,
            &mut self.7,
            self.0,
            self.1,
            self.2,
            &mut self.3,
            w[12],
        )
        .rnd(Self::K60.into());
        Rotor(
            self.3,
            self.4,
            self.5,
            &mut self.6,
            self.7,
            self.0,
            self.1,
            &mut self.2,
            w[13],
        )
        .rnd(Self::K61.into());
        Rotor(
            self.2,
            self.3,
            self.4,
            &mut self.5,
            self.6,
            self.7,
            self.0,
            &mut self.1,
            w[14],
        )
        .rnd(Self::K62.into());
        Rotor(
            self.1,
            self.2,
            self.3,
            &mut self.4,
            self.5,
            self.6,
            self.7,
            &mut self.0,
            w[15],
        )
        .rnd(Self::K63.into());
    }
}

impl Sha256BitsState {
    const K00: u32 = 0x428A2F98;
    const K01: u32 = 0x71374491;
    const K02: u32 = 0xB5C0FBCF;
    const K03: u32 = 0xE9B5DBA5;
    const K04: u32 = 0x3956C25B;
    const K05: u32 = 0x59F111F1;
    const K06: u32 = 0x923F82A4;
    const K07: u32 = 0xAB1C5ED5;
    const K08: u32 = 0xD807AA98;
    const K09: u32 = 0x12835B01;
    const K10: u32 = 0x243185BE;
    const K11: u32 = 0x550C7DC3;
    const K12: u32 = 0x72BE5D74;
    const K13: u32 = 0x80DEB1FE;
    const K14: u32 = 0x9BDC06A7;
    const K15: u32 = 0xC19BF174;
    const K16: u32 = 0xE49B69C1;
    const K17: u32 = 0xEFBE4786;
    const K18: u32 = 0x0FC19DC6;
    const K19: u32 = 0x240CA1CC;
    const K20: u32 = 0x2DE92C6F;
    const K21: u32 = 0x4A7484AA;
    const K22: u32 = 0x5CB0A9DC;
    const K23: u32 = 0x76F988DA;
    const K24: u32 = 0x983E5152;
    const K25: u32 = 0xA831C66D;
    const K26: u32 = 0xB00327C8;
    const K27: u32 = 0xBF597FC7;
    const K28: u32 = 0xC6E00BF3;
    const K29: u32 = 0xD5A79147;
    const K30: u32 = 0x06CA6351;
    const K31: u32 = 0x14292967;
    const K32: u32 = 0x27B70A85;
    const K33: u32 = 0x2E1B2138;
    const K34: u32 = 0x4D2C6DFC;
    const K35: u32 = 0x53380D13;
    const K36: u32 = 0x650A7354;
    const K37: u32 = 0x766A0ABB;
    const K38: u32 = 0x81C2C92E;
    const K39: u32 = 0x92722C85;
    const K40: u32 = 0xA2BFE8A1;
    const K41: u32 = 0xA81A664B;
    const K42: u32 = 0xC24B8B70;
    const K43: u32 = 0xC76C51A3;
    const K44: u32 = 0xD192E819;
    const K45: u32 = 0xD6990624;
    const K46: u32 = 0xF40E3585;
    const K47: u32 = 0x106AA070;
    const K48: u32 = 0x19A4C116;
    const K49: u32 = 0x1E376C08;
    const K50: u32 = 0x2748774C;
    const K51: u32 = 0x34B0BCB5;
    const K52: u32 = 0x391C0CB3;
    const K53: u32 = 0x4ED8AA4A;
    const K54: u32 = 0x5B9CCA4F;
    const K55: u32 = 0x682E6FF3;
    const K56: u32 = 0x748F82EE;
    const K57: u32 = 0x78A5636F;
    const K58: u32 = 0x84C87814;
    const K59: u32 = 0x8CC70208;
    const K60: u32 = 0x90BEFFFA;
    const K61: u32 = 0xA4506CEB;
    const K62: u32 = 0xBEF9A3F7;
    const K63: u32 = 0xC67178F2;
}

impl AddAssign for Sha256BitsState {
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

impl Hash for Sha256BitsState {
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
