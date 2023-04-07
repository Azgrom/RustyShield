use crate::rotors::sha160rotor::Sha160Rotor as Rotor;
use crate::{DWords, NewGenericStateHasher};
use core::{
    hash::Hash,
};
use n_bit_words_lib::{NBitWord, TSize};

#[derive(Debug, Hash, PartialEq)]
pub struct Sha160BitsState(
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub DWords<u32>,
);

impl NewGenericStateHasher for Sha160BitsState {
    fn next_words(&mut self) {
        self.5[0] = (self.5[0] ^ self.5[2] ^ self.5[8] ^ self.5[13]).rotate_left(1.into());
        self.5[1] = (self.5[1] ^ self.5[3] ^ self.5[9] ^ self.5[14]).rotate_left(1.into());
        self.5[2] = (self.5[2] ^ self.5[4] ^ self.5[10] ^ self.5[15]).rotate_left(1.into());
        self.5[3] = (self.5[3] ^ self.5[5] ^ self.5[11] ^ self.5[0]).rotate_left(1.into());
        self.5[4] = (self.5[4] ^ self.5[6] ^ self.5[12] ^ self.5[1]).rotate_left(1.into());
        self.5[5] = (self.5[5] ^ self.5[7] ^ self.5[13] ^ self.5[2]).rotate_left(1.into());
        self.5[6] = (self.5[6] ^ self.5[8] ^ self.5[14] ^ self.5[3]).rotate_left(1.into());
        self.5[7] = (self.5[7] ^ self.5[9] ^ self.5[15] ^ self.5[4]).rotate_left(1.into());
        self.5[8] = (self.5[8] ^ self.5[10] ^ self.5[0] ^ self.5[5]).rotate_left(1.into());
        self.5[9] = (self.5[9] ^ self.5[11] ^ self.5[1] ^ self.5[6]).rotate_left(1.into());
        self.5[10] = (self.5[10] ^ self.5[12] ^ self.5[2] ^ self.5[7]).rotate_left(1.into());
        self.5[11] = (self.5[11] ^ self.5[13] ^ self.5[3] ^ self.5[8]).rotate_left(1.into());
        self.5[12] = (self.5[12] ^ self.5[14] ^ self.5[4] ^ self.5[9]).rotate_left(1.into());
        self.5[13] = (self.5[13] ^ self.5[15] ^ self.5[5] ^ self.5[10]).rotate_left(1.into());
        self.5[14] = (self.5[14] ^ self.5[0] ^ self.5[6] ^ self.5[11]).rotate_left(1.into());
        self.5[15] = (self.5[15] ^ self.5[1] ^ self.5[7] ^ self.5[12]).rotate_left(1.into());
    }

    fn block_00_15(&mut self) {
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[0]).rounds_00_19();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[1]).rounds_00_19();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[2]).rounds_00_19();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[3]).rounds_00_19();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[4]).rounds_00_19();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[5]).rounds_00_19();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[6]).rounds_00_19();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[7]).rounds_00_19();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[8]).rounds_00_19();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[9]).rounds_00_19();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[10]).rounds_00_19();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[11]).rounds_00_19();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[12]).rounds_00_19();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[13]).rounds_00_19();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[14]).rounds_00_19();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[15]).rounds_00_19();
    }

    fn block_16_31(&mut self) {
        self.next_words();

        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[0]).rounds_00_19();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[1]).rounds_00_19();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[2]).rounds_00_19();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[3]).rounds_00_19();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[4]).rounds_20_39();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[5]).rounds_20_39();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[6]).rounds_20_39();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[7]).rounds_20_39();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[8]).rounds_20_39();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[9]).rounds_20_39();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[10]).rounds_20_39();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[11]).rounds_20_39();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[12]).rounds_20_39();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[13]).rounds_20_39();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[14]).rounds_20_39();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[15]).rounds_20_39();
    }

    fn block_32_47(&mut self) {
        self.next_words();

        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[0]).rounds_20_39();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[1]).rounds_20_39();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[2]).rounds_20_39();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[3]).rounds_20_39();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[4]).rounds_20_39();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[5]).rounds_20_39();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[6]).rounds_20_39();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[7]).rounds_20_39();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[8]).rounds_40_59();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[9]).rounds_40_59();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[10]).rounds_40_59();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[11]).rounds_40_59();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[12]).rounds_40_59();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[13]).rounds_40_59();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[14]).rounds_40_59();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[15]).rounds_40_59();
    }

    fn block_48_63(&mut self) {
        self.next_words();

        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[0]).rounds_40_59();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[1]).rounds_40_59();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[2]).rounds_40_59();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[3]).rounds_40_59();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[4]).rounds_40_59();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[5]).rounds_40_59();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[6]).rounds_40_59();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[7]).rounds_40_59();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[8]).rounds_40_59();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[9]).rounds_40_59();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[10]).rounds_40_59();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[11]).rounds_40_59();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[12]).rounds_60_79();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[13]).rounds_60_79();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[14]).rounds_60_79();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[15]).rounds_60_79();
    }

    fn block_64_79(&mut self) {
        self.next_words();

        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[0]).rounds_60_79();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[1]).rounds_60_79();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[2]).rounds_60_79();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[3]).rounds_60_79();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[4]).rounds_60_79();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[5]).rounds_60_79();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[6]).rounds_60_79();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[7]).rounds_60_79();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[8]).rounds_60_79();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[9]).rounds_60_79();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[10]).rounds_60_79();
        Rotor(&self.0, &mut self.1, &self.2, &self.3, &mut self.4, &self.5[11]).rounds_60_79();
        Rotor(&self.4, &mut self.0, &self.1, &self.2, &mut self.3, &self.5[12]).rounds_60_79();
        Rotor(&self.3, &mut self.4, &self.0, &self.1, &mut self.2, &self.5[13]).rounds_60_79();
        Rotor(&self.2, &mut self.3, &self.4, &self.0, &mut self.1, &self.5[14]).rounds_60_79();
        Rotor(&self.1, &mut self.2, &self.3, &self.4, &mut self.0, &self.5[15]).rounds_60_79();
    }
}
