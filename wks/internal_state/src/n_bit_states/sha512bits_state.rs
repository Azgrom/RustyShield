use crate::n_bit_states::GenericStateHasher;
use crate::{rotors::sha512rotor::Sha512Rotor as Rotor, DWords};
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
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[0]).rnd(Self::K00);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[1]).rnd(Self::K01);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[2]).rnd(Self::K02);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[3]).rnd(Self::K03);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[4]).rnd(Self::K04);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[5]).rnd(Self::K05);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[6]).rnd(Self::K06);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[7]).rnd(Self::K07);
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[8]).rnd(Self::K08);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[9]).rnd(Self::K09);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[10]).rnd(Self::K10);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[11]).rnd(Self::K11);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[12]).rnd(Self::K12);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[13]).rnd(Self::K13);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[14]).rnd(Self::K14);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[15]).rnd(Self::K15);
    }

    fn block_16_31(&mut self) {
        self.next_words();

        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[0]).rnd(Self::K16);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[1]).rnd(Self::K17);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[2]).rnd(Self::K18);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[3]).rnd(Self::K19);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[4]).rnd(Self::K20);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[5]).rnd(Self::K21);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[6]).rnd(Self::K22);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[7]).rnd(Self::K23);
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[8]).rnd(Self::K24);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[9]).rnd(Self::K25);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[10]).rnd(Self::K26);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[11]).rnd(Self::K27);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[12]).rnd(Self::K28);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[13]).rnd(Self::K29);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[14]).rnd(Self::K30);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[15]).rnd(Self::K31);
    }

    fn block_32_47(&mut self) {
        self.next_words();

        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[0]).rnd(Self::K32);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[1]).rnd(Self::K33);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[2]).rnd(Self::K34);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[3]).rnd(Self::K35);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[4]).rnd(Self::K36);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[5]).rnd(Self::K37);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[6]).rnd(Self::K38);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[7]).rnd(Self::K39);
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[8]).rnd(Self::K40);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[9]).rnd(Self::K41);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[10]).rnd(Self::K42);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[11]).rnd(Self::K43);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[12]).rnd(Self::K44);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[13]).rnd(Self::K45);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[14]).rnd(Self::K46);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[15]).rnd(Self::K47);
    }

    fn block_48_63(&mut self) {
        self.next_words();

        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[0]).rnd(Self::K48);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[1]).rnd(Self::K49);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[2]).rnd(Self::K50);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[3]).rnd(Self::K51);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[4]).rnd(Self::K52);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[5]).rnd(Self::K53);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[6]).rnd(Self::K54);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[7]).rnd(Self::K55);
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[8]).rnd(Self::K56);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[9]).rnd(Self::K57);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[10]).rnd(Self::K58);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[11]).rnd(Self::K59);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[12]).rnd(Self::K60);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[13]).rnd(Self::K61);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[14]).rnd(Self::K62);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[15]).rnd(Self::K63);
    }

    fn block_64_79(&mut self) {
        self.next_words();

        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[0]).rnd(Self::K64);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[1]).rnd(Self::K65);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[2]).rnd(Self::K66);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[3]).rnd(Self::K67);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[4]).rnd(Self::K68);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[5]).rnd(Self::K69);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[6]).rnd(Self::K70);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[7]).rnd(Self::K71);
        Rotor(self.0, self.1, self.2, &mut self.3, self.4, self.5, self.6, &mut self.7, self.8[8]).rnd(Self::K72);
        Rotor(self.7, self.0, self.1, &mut self.2, self.3, self.4, self.5, &mut self.6, self.8[9]).rnd(Self::K73);
        Rotor(self.6, self.7, self.0, &mut self.1, self.2, self.3, self.4, &mut self.5, self.8[10]).rnd(Self::K74);
        Rotor(self.5, self.6, self.7, &mut self.0, self.1, self.2, self.3, &mut self.4, self.8[11]).rnd(Self::K75);
        Rotor(self.4, self.5, self.6, &mut self.7, self.0, self.1, self.2, &mut self.3, self.8[12]).rnd(Self::K76);
        Rotor(self.3, self.4, self.5, &mut self.6, self.7, self.0, self.1, &mut self.2, self.8[13]).rnd(Self::K77);
        Rotor(self.2, self.3, self.4, &mut self.5, self.6, self.7, self.0, &mut self.1, self.8[14]).rnd(Self::K78);
        Rotor(self.1, self.2, self.3, &mut self.4, self.5, self.6, self.7, &mut self.0, self.8[15]).rnd(Self::K79);
    }
}

impl Sha512BitsState {
    // SHA-384, SHA-512, SHA-512/224, SHA-512/256 constants
    pub const K00: u64 = 0x428A2F98D728AE22;
    pub const K01: u64 = 0x7137449123EF65CD;
    pub const K02: u64 = 0xB5C0FBCFEC4D3B2F;
    pub const K03: u64 = 0xE9B5DBA58189DBBC;
    pub const K04: u64 = 0x3956C25BF348B538;
    pub const K05: u64 = 0x59F111F1B605D019;
    pub const K06: u64 = 0x923F82A4AF194F9B;
    pub const K07: u64 = 0xAB1C5ED5DA6D8118;
    pub const K08: u64 = 0xD807AA98A3030242;
    pub const K09: u64 = 0x12835B0145706FBE;
    pub const K10: u64 = 0x243185BE4EE4B28C;
    pub const K11: u64 = 0x550C7DC3D5FFB4E2;
    pub const K12: u64 = 0x72BE5D74F27B896F;
    pub const K13: u64 = 0x80DEB1FE3B1696B1;
    pub const K14: u64 = 0x9BDC06A725C71235;
    pub const K15: u64 = 0xC19BF174CF692694;
    pub const K16: u64 = 0xE49B69C19EF14AD2;
    pub const K17: u64 = 0xEFBE4786384F25E3;
    pub const K18: u64 = 0x0FC19DC68B8CD5B5;
    pub const K19: u64 = 0x240CA1CC77AC9C65;
    pub const K20: u64 = 0x2DE92C6F592B0275;
    pub const K21: u64 = 0x4A7484AA6EA6E483;
    pub const K22: u64 = 0x5CB0A9DCBD41FBD4;
    pub const K23: u64 = 0x76F988DA831153B5;
    pub const K24: u64 = 0x983E5152EE66DFAB;
    pub const K25: u64 = 0xA831C66D2DB43210;
    pub const K26: u64 = 0xB00327C898FB213F;
    pub const K27: u64 = 0xBF597FC7BEEF0EE4;
    pub const K28: u64 = 0xC6E00BF33DA88FC2;
    pub const K29: u64 = 0xD5A79147930AA725;
    pub const K30: u64 = 0x06CA6351E003826F;
    pub const K31: u64 = 0x142929670A0E6E70;
    pub const K32: u64 = 0x27B70A8546D22FFC;
    pub const K33: u64 = 0x2E1B21385C26C926;
    pub const K34: u64 = 0x4D2C6DFC5AC42AED;
    pub const K35: u64 = 0x53380D139D95B3DF;
    pub const K36: u64 = 0x650A73548BAF63DE;
    pub const K37: u64 = 0x766A0ABB3C77B2A8;
    pub const K38: u64 = 0x81C2C92E47EDAEE6;
    pub const K39: u64 = 0x92722C851482353B;
    pub const K40: u64 = 0xA2BFE8A14CF10364;
    pub const K41: u64 = 0xA81A664BBC423001;
    pub const K42: u64 = 0xC24B8B70D0F89791;
    pub const K43: u64 = 0xC76C51A30654BE30;
    pub const K44: u64 = 0xD192E819D6EF5218;
    pub const K45: u64 = 0xD69906245565A910;
    pub const K46: u64 = 0xF40E35855771202A;
    pub const K47: u64 = 0x106AA07032BBD1B8;
    pub const K48: u64 = 0x19A4C116B8D2D0C8;
    pub const K49: u64 = 0x1E376C085141AB53;
    pub const K50: u64 = 0x2748774CDF8EEB99;
    pub const K51: u64 = 0x34B0BCB5E19B48A8;
    pub const K52: u64 = 0x391C0CB3C5C95A63;
    pub const K53: u64 = 0x4ED8AA4AE3418ACB;
    pub const K54: u64 = 0x5B9CCA4F7763E373;
    pub const K55: u64 = 0x682E6FF3D6B2B8A3;
    pub const K56: u64 = 0x748F82EE5DEFB2FC;
    pub const K57: u64 = 0x78A5636F43172F60;
    pub const K58: u64 = 0x84C87814A1F0AB72;
    pub const K59: u64 = 0x8CC702081A6439EC;
    pub const K60: u64 = 0x90BEFFFA23631E28;
    pub const K61: u64 = 0xA4506CEBDE82BDE9;
    pub const K62: u64 = 0xBEF9A3F7B2C67915;
    pub const K63: u64 = 0xC67178F2E372532B;
    pub const K64: u64 = 0xCA273ECEEA26619C;
    pub const K65: u64 = 0xD186B8C721C0C207;
    pub const K66: u64 = 0xEADA7DD6CDE0EB1E;
    pub const K67: u64 = 0xF57D4F7FEE6ED178;
    pub const K68: u64 = 0x06F067AA72176FBA;
    pub const K69: u64 = 0x0A637DC5A2C898A6;
    pub const K70: u64 = 0x113F9804BEF90DAE;
    pub const K71: u64 = 0x1B710B35131C471B;
    pub const K72: u64 = 0x28DB77F523047D84;
    pub const K73: u64 = 0x32CAAB7B40C72493;
    pub const K74: u64 = 0x3C9EBE0A15C9BEBC;
    pub const K75: u64 = 0x431D67C49C100D4C;
    pub const K76: u64 = 0x4CC5D4BECB3E42B6;
    pub const K77: u64 = 0x597F299CFC657E2A;
    pub const K78: u64 = 0x5FCB6FAB3AD6FAEC;
    pub const K79: u64 = 0x6C44198C4A475817;
}
