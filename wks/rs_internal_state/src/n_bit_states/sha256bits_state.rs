use crate::n_bit_states::GenericStateHasher;
use crate::DWords;
use core::{hash::Hash, ops::AddAssign};
use rs_n_bit_words::{NBitWord, TSize};

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Sha256BitsState(
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub DWords<u32>,
);

fn round<'a>(state: &'a mut Sha256BitsState, t: (usize, &u32)) -> &'a mut Sha256BitsState {
    let t0 = state.4.sigma1() + NBitWord::<u32>::ch(state.4, state.5, state.6) + state.7 + state.8[t.0] + *t.1;
    let t1 = state.0.sigma0() + NBitWord::<u32>::maj(state.0, state.1, state.2);
    state.7 = state.6;
    state.6 = state.5;
    state.5 = state.4;
    state.4 = state.3 + t0;
    state.3 = state.2;
    state.2 = state.1;
    state.1 = state.0;
    state.0 = t0 + t1;

    state
}

impl GenericStateHasher for Sha256BitsState {
    fn next_words(&mut self) {
        self.8[0] = self.8[0] + self.8[1].gamma0() + self.8[9] + self.8[14].gamma1();
        self.8[1] = self.8[1] + self.8[2].gamma0() + self.8[10] + self.8[15].gamma1();
        self.8[2] = self.8[2] + self.8[3].gamma0() + self.8[11] + self.8[0].gamma1();
        self.8[3] = self.8[3] + self.8[4].gamma0() + self.8[12] + self.8[1].gamma1();
        self.8[4] = self.8[4] + self.8[5].gamma0() + self.8[13] + self.8[2].gamma1();
        self.8[5] = self.8[5] + self.8[6].gamma0() + self.8[14] + self.8[3].gamma1();
        self.8[6] = self.8[6] + self.8[7].gamma0() + self.8[15] + self.8[4].gamma1();
        self.8[7] = self.8[7] + self.8[8].gamma0() + self.8[0] + self.8[5].gamma1();
        self.8[8] = self.8[8] + self.8[9].gamma0() + self.8[1] + self.8[6].gamma1();
        self.8[9] = self.8[9] + self.8[10].gamma0() + self.8[2] + self.8[7].gamma1();
        self.8[10] = self.8[10] + self.8[11].gamma0() + self.8[3] + self.8[8].gamma1();
        self.8[11] = self.8[11] + self.8[12].gamma0() + self.8[4] + self.8[9].gamma1();
        self.8[12] = self.8[12] + self.8[13].gamma0() + self.8[5] + self.8[10].gamma1();
        self.8[13] = self.8[13] + self.8[14].gamma0() + self.8[6] + self.8[11].gamma1();
        self.8[14] = self.8[14] + self.8[15].gamma0() + self.8[7] + self.8[12].gamma1();
        self.8[15] = self.8[15] + self.8[0].gamma0() + self.8[8] + self.8[13].gamma1();
    }

    fn block_00_15(&mut self) {
        Self::K_00_TO_15.iter().enumerate().fold(self, round);
    }

    fn block_16_31(&mut self) {
        self.next_words();
        Self::K_16_TO_31.iter().enumerate().fold(self, round);
    }

    fn block_32_47(&mut self) {
        self.next_words();
        Self::K_32_TO_47.iter().enumerate().fold(self, round);
    }

    fn block_48_63(&mut self) {
        self.next_words();
        Self::K_48_TO_63.iter().enumerate().fold(self, round);
    }

    fn block_64_79(&mut self) {}
}

impl Sha256BitsState {
    const K_00_TO_15: [u32; 16] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98,
        0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    ];
    const K_16_TO_31: [u32; 16] = [
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152,
        0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    ];
    const K_32_TO_47: [u32; 16] = [
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1,
        0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    ];
    const K_48_TO_63: [u32; 16] = [
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE,
        0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];
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
