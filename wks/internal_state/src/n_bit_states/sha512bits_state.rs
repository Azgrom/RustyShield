use crate::n_bit_states::GenericStateHasher;
use crate::DWords;
use n_bit_words_lib::{NBitWord, TSize};

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Sha512BitsState(
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub DWords<u64>,
);

fn round<'a>(state: &'a mut Sha512BitsState, t: (usize, &u64)) -> &'a mut Sha512BitsState {
    let t0 = state.4.sigma1() + NBitWord::<u64>::ch(state.4, state.5, state.6) + state.7 + state.8[t.0] + *t.1;
    let t1 = state.0.sigma0() + NBitWord::<u64>::maj(state.0, state.1, state.2);
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

impl GenericStateHasher for Sha512BitsState {
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

    fn block_64_79(&mut self) {
        self.next_words();
        Self::K_64_TO_79.iter().enumerate().fold(self, round);
    }
}

impl Sha512BitsState {
    // SHA-384, SHA-512, SHA-512/224, SHA-512/256 constants
    const K_64_TO_79: [u64; 16] = [
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    ];
    const K_00_TO_15: [u64; 16] = [
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
    ];
    const K_16_TO_31: [u64; 16] = [
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
    ];
    const K_32_TO_47: [u64; 16] = [
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
    ];
    const K_48_TO_63: [u64; 16] = [
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
    ];
}
