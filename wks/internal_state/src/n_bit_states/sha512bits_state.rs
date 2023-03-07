use crate::rotors::sha512rotor::Sha512Rotor as Rotor;
use core::{
    hash::{Hash, Hasher},
    ops::AddAssign,
};
use n_bit_words_lib::U64Word;

#[derive(Clone)]
pub struct Sha512BitsState(
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
);

impl Sha512BitsState {
    pub fn block_00_15(&mut self, w: &[U64Word; 16]) {
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
        .rnd(U64Word::K00);
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
        .rnd(U64Word::K01);
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
        .rnd(U64Word::K02);
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
        .rnd(U64Word::K03);
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
        .rnd(U64Word::K04);
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
        .rnd(U64Word::K05);
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
        .rnd(U64Word::K06);
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
        .rnd(U64Word::K07);
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
        .rnd(U64Word::K08);
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
        .rnd(U64Word::K09);
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
        .rnd(U64Word::K10);
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
        .rnd(U64Word::K11);
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
        .rnd(U64Word::K12);
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
        .rnd(U64Word::K13);
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
        .rnd(U64Word::K14);
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
        .rnd(U64Word::K15);
    }

    pub fn block_16_31(&mut self, w: &mut [U64Word; 16]) {
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
        .rnd(U64Word::K16);
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
        .rnd(U64Word::K17);
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
        .rnd(U64Word::K18);
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
        .rnd(U64Word::K19);
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
        .rnd(U64Word::K20);
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
        .rnd(U64Word::K21);
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
        .rnd(U64Word::K22);
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
        .rnd(U64Word::K23);
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
        .rnd(U64Word::K24);
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
        .rnd(U64Word::K25);
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
        .rnd(U64Word::K26);
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
        .rnd(U64Word::K27);
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
        .rnd(U64Word::K28);
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
        .rnd(U64Word::K29);
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
        .rnd(U64Word::K30);
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
        .rnd(U64Word::K31);
    }

    pub fn block_32_47(&mut self, w: &mut [U64Word; 16]) {
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
        .rnd(U64Word::K32);
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
        .rnd(U64Word::K33);
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
        .rnd(U64Word::K34);
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
        .rnd(U64Word::K35);
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
        .rnd(U64Word::K36);
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
        .rnd(U64Word::K37);
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
        .rnd(U64Word::K38);
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
        .rnd(U64Word::K39);
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
        .rnd(U64Word::K40);
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
        .rnd(U64Word::K41);
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
        .rnd(U64Word::K42);
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
        .rnd(U64Word::K43);
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
        .rnd(U64Word::K44);
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
        .rnd(U64Word::K45);
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
        .rnd(U64Word::K46);
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
        .rnd(U64Word::K47);
    }

    pub fn block_48_63(&mut self, w: &mut [U64Word; 16]) {
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
        .rnd(U64Word::K48);
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
        .rnd(U64Word::K49);
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
        .rnd(U64Word::K50);
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
        .rnd(U64Word::K51);
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
        .rnd(U64Word::K52);
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
        .rnd(U64Word::K53);
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
        .rnd(U64Word::K54);
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
        .rnd(U64Word::K55);
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
        .rnd(U64Word::K56);
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
        .rnd(U64Word::K57);
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
        .rnd(U64Word::K58);
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
        .rnd(U64Word::K59);
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
        .rnd(U64Word::K60);
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
        .rnd(U64Word::K61);
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
        .rnd(U64Word::K62);
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
        .rnd(U64Word::K63);
    }

    pub fn block_64_79(&mut self, w: &mut [U64Word; 16]) {
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
        .rnd(U64Word::K64);
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
        .rnd(U64Word::K65);
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
        .rnd(U64Word::K66);
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
        .rnd(U64Word::K67);
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
        .rnd(U64Word::K68);
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
        .rnd(U64Word::K69);
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
        .rnd(U64Word::K70);
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
        .rnd(U64Word::K71);
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
        .rnd(U64Word::K72);
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
        .rnd(U64Word::K73);
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
        .rnd(U64Word::K74);
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
        .rnd(U64Word::K75);
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
        .rnd(U64Word::K76);
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
        .rnd(U64Word::K77);
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
        .rnd(U64Word::K78);
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
        .rnd(U64Word::K79);
    }
}

impl AddAssign for Sha512BitsState {
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

impl Hash for Sha512BitsState {
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
