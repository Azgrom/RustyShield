use crate::rotors::sha256rotor::Sha256Rotor as Rotor;
use core::{
    hash::{Hash, Hasher},
    ops::AddAssign,
};
use n_bit_words_lib::U32Word;

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
        .rnd(U32Word::K00);
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
        .rnd(U32Word::K01);
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
        .rnd(U32Word::K02);
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
        .rnd(U32Word::K03);
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
        .rnd(U32Word::K04);
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
        .rnd(U32Word::K05);
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
        .rnd(U32Word::K06);
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
        .rnd(U32Word::K07);
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
        .rnd(U32Word::K08);
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
        .rnd(U32Word::K09);
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
        .rnd(U32Word::K10);
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
        .rnd(U32Word::K11);
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
        .rnd(U32Word::K12);
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
        .rnd(U32Word::K13);
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
        .rnd(U32Word::K14);
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
        .rnd(U32Word::K15);
    }

    pub fn block_16_31(&mut self, w: &mut [U32Word; 16]) {
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
        .rnd(U32Word::K16);
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
        .rnd(U32Word::K17);
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
        .rnd(U32Word::K18);
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
        .rnd(U32Word::K19);
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
        .rnd(U32Word::K20);
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
        .rnd(U32Word::K21);
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
        .rnd(U32Word::K22);
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
        .rnd(U32Word::K23);
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
        .rnd(U32Word::K24);
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
        .rnd(U32Word::K25);
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
        .rnd(U32Word::K26);
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
        .rnd(U32Word::K27);
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
        .rnd(U32Word::K28);
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
        .rnd(U32Word::K29);
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
        .rnd(U32Word::K30);
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
        .rnd(U32Word::K31);
    }

    pub fn block_32_47(&mut self, w: &mut [U32Word; 16]) {
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
        .rnd(U32Word::K32);
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
        .rnd(U32Word::K33);
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
        .rnd(U32Word::K34);
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
        .rnd(U32Word::K35);
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
        .rnd(U32Word::K36);
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
        .rnd(U32Word::K37);
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
        .rnd(U32Word::K38);
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
        .rnd(U32Word::K39);
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
        .rnd(U32Word::K40);
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
        .rnd(U32Word::K41);
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
        .rnd(U32Word::K42);
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
        .rnd(U32Word::K43);
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
        .rnd(U32Word::K44);
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
        .rnd(U32Word::K45);
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
        .rnd(U32Word::K46);
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
        .rnd(U32Word::K47);
    }

    pub fn block_48_63(&mut self, w: &mut [U32Word; 16]) {
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
        .rnd(U32Word::K48);
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
        .rnd(U32Word::K49);
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
        .rnd(U32Word::K50);
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
        .rnd(U32Word::K51);
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
        .rnd(U32Word::K52);
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
        .rnd(U32Word::K53);
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
        .rnd(U32Word::K54);
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
        .rnd(U32Word::K55);
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
        .rnd(U32Word::K56);
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
        .rnd(U32Word::K57);
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
        .rnd(U32Word::K58);
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
        .rnd(U32Word::K59);
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
        .rnd(U32Word::K60);
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
        .rnd(U32Word::K61);
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
        .rnd(U32Word::K62);
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
        .rnd(U32Word::K63);
    }
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
