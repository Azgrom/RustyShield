use crate::rotors::sha160rotor::Sha160Rotor as Rotor;
use core::{
    hash::{Hash, Hasher},
    ops::AddAssign,
};
use n_bit_words_lib::U32Word;

#[derive(Clone, Debug)]
pub struct Sha160BitsState(pub U32Word, pub U32Word, pub U32Word, pub U32Word, pub U32Word);

impl Sha160BitsState {
    pub fn block_00_15(&mut self, words: &[U32Word; 16]) {
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[0]).rounds_00_19();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[1]).rounds_00_19();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[2]).rounds_00_19();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[3]).rounds_00_19();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[4]).rounds_00_19();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[5]).rounds_00_19();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[6]).rounds_00_19();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[7]).rounds_00_19();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[8]).rounds_00_19();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[9]).rounds_00_19();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[10]).rounds_00_19();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[11]).rounds_00_19();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[12]).rounds_00_19();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[13]).rounds_00_19();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[14]).rounds_00_19();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[15]).rounds_00_19();
    }

    pub fn block_16_31(&mut self, words: &mut [U32Word; 16]) {
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

        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[0]).rounds_00_19();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[1]).rounds_00_19();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[2]).rounds_00_19();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[3]).rounds_00_19();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[4]).rounds_20_39();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[5]).rounds_20_39();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[6]).rounds_20_39();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[7]).rounds_20_39();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[8]).rounds_20_39();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[9]).rounds_20_39();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[10]).rounds_20_39();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[11]).rounds_20_39();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[12]).rounds_20_39();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[13]).rounds_20_39();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[14]).rounds_20_39();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[15]).rounds_20_39();
    }

    pub fn block_32_47(&mut self, words: &mut [U32Word; 16]) {
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

        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[0]).rounds_20_39();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[1]).rounds_20_39();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[2]).rounds_20_39();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[3]).rounds_20_39();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[4]).rounds_20_39();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[5]).rounds_20_39();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[6]).rounds_20_39();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[7]).rounds_20_39();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[8]).rounds_40_59();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[9]).rounds_40_59();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[10]).rounds_40_59();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[11]).rounds_40_59();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[12]).rounds_40_59();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[13]).rounds_40_59();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[14]).rounds_40_59();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[15]).rounds_40_59();
    }

    pub fn block_48_63(&mut self, words: &mut [U32Word; 16]) {
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

        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[0]).rounds_40_59();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[1]).rounds_40_59();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[2]).rounds_40_59();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[3]).rounds_40_59();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[4]).rounds_40_59();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[5]).rounds_40_59();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[6]).rounds_40_59();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[7]).rounds_40_59();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[8]).rounds_40_59();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[9]).rounds_40_59();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[10]).rounds_40_59();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[11]).rounds_40_59();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[12]).rounds_60_79();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[13]).rounds_60_79();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[14]).rounds_60_79();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[15]).rounds_60_79();
    }

    pub fn block_64_79(&mut self, words: &mut [U32Word; 16]) {
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

        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[0]).rounds_60_79();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[1]).rounds_60_79();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[2]).rounds_60_79();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[3]).rounds_60_79();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[4]).rounds_60_79();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[5]).rounds_60_79();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[6]).rounds_60_79();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[7]).rounds_60_79();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[8]).rounds_60_79();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[9]).rounds_60_79();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[10]).rounds_60_79();
        Rotor(self.0, &mut self.1, self.2, self.3, &mut self.4, words[11]).rounds_60_79();
        Rotor(self.4, &mut self.0, self.1, self.2, &mut self.3, words[12]).rounds_60_79();
        Rotor(self.3, &mut self.4, self.0, self.1, &mut self.2, words[13]).rounds_60_79();
        Rotor(self.2, &mut self.3, self.4, self.0, &mut self.1, words[14]).rounds_60_79();
        Rotor(self.1, &mut self.2, self.3, self.4, &mut self.0, words[15]).rounds_60_79();
    }
}

impl AddAssign for Sha160BitsState {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
    }
}

impl Hash for Sha160BitsState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2.hash(state);
        self.3.hash(state);
        self.4.hash(state);
    }
}

impl PartialEq for Sha160BitsState {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3 && self.4 == other.4
    }
}
