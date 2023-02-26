use crate::{
    sha256comp::Sha256Comp, sha256state::Sha256State, sha256words::Sha256Words,
    SHA256_PADDING_U8_WORDS_COUNT, SHA256_SCHEDULE_U32_WORDS_COUNT,
};
use alloc::{boxed::Box, format, string::String};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;

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

const SHA256_SCHEDULE_LAST_INDEX: u32 = SHA256_SCHEDULE_U32_WORDS_COUNT - 1;

#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha256State,
    pub(crate) words: Sha256Words,
}

impl Sha256Hasher {
    fn load_words(&self) -> [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] {
        let mut w: [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] =
            [U32Word::default(); SHA256_SCHEDULE_U32_WORDS_COUNT as usize];

        self.words
            .u32_chunks()
            .enumerate()
            .for_each(|(i, c)| w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into());

        w[16] =  w[0] + w[1].gamma0() + w[9] + w[14].gamma1();
        w[17] = w[1] + w[2].gamma0() + w[10] + w[15].gamma1();
        w[18] = w[2] + w[3].gamma0() + w[11] + w[16].gamma1();
        w[19] = w[3] + w[4].gamma0() + w[12] + w[17].gamma1();
        w[20] = w[4] + w[5].gamma0() + w[13] + w[18].gamma1();
        w[21] = w[5] + w[6].gamma0() + w[14] + w[19].gamma1();
        w[22] = w[6] + w[7].gamma0() + w[15] + w[20].gamma1();
        w[23] = w[7] + w[8].gamma0() + w[16] + w[21].gamma1();
        w[24] = w[8] + w[9].gamma0() + w[17] + w[22].gamma1();
        w[25] = w[9] + w[10].gamma0() + w[18] + w[23].gamma1();
        w[26] = w[10] + w[11].gamma0() + w[19] + w[24].gamma1();
        w[27] = w[11] + w[12].gamma0() + w[20] + w[25].gamma1();
        w[28] = w[12] + w[13].gamma0() + w[21] + w[26].gamma1();
        w[29] = w[13] + w[14].gamma0() + w[22] + w[27].gamma1();
        w[30] = w[14] + w[15].gamma0() + w[23] + w[28].gamma1();
        w[31] = w[15] + w[16].gamma0() + w[24] + w[29].gamma1();
        w[32] = w[16] + w[17].gamma0() + w[25] + w[30].gamma1();
        w[33] = w[17] + w[18].gamma0() + w[26] + w[31].gamma1();
        w[34] = w[18] + w[19].gamma0() + w[27] + w[32].gamma1();
        w[35] = w[19] + w[20].gamma0() + w[28] + w[33].gamma1();
        w[36] = w[20] + w[21].gamma0() + w[29] + w[34].gamma1();
        w[37] = w[21] + w[22].gamma0() + w[30] + w[35].gamma1();
        w[38] = w[22] + w[23].gamma0() + w[31] + w[36].gamma1();
        w[39] = w[23] + w[24].gamma0() + w[32] + w[37].gamma1();
        w[40] = w[24] + w[25].gamma0() + w[33] + w[38].gamma1();
        w[41] = w[25] + w[26].gamma0() + w[34] + w[39].gamma1();
        w[42] = w[26] + w[27].gamma0() + w[35] + w[40].gamma1();
        w[43] = w[27] + w[28].gamma0() + w[36] + w[41].gamma1();
        w[44] = w[28] + w[29].gamma0() + w[37] + w[42].gamma1();
        w[45] = w[29] + w[30].gamma0() + w[38] + w[43].gamma1();
        w[46] = w[30] + w[31].gamma0() + w[39] + w[44].gamma1();
        w[47] = w[31] + w[32].gamma0() + w[40] + w[45].gamma1();
        w[48] = w[32] + w[33].gamma0() + w[41] + w[46].gamma1();
        w[49] = w[33] + w[34].gamma0() + w[42] + w[47].gamma1();
        w[50] = w[34] + w[35].gamma0() + w[43] + w[48].gamma1();
        w[51] = w[35] + w[36].gamma0() + w[44] + w[49].gamma1();
        w[52] = w[36] + w[37].gamma0() + w[45] + w[50].gamma1();
        w[53] = w[37] + w[38].gamma0() + w[46] + w[51].gamma1();
        w[54] = w[38] + w[39].gamma0() + w[47] + w[52].gamma1();
        w[55] = w[39] + w[40].gamma0() + w[48] + w[53].gamma1();
        w[56] = w[40] + w[41].gamma0() + w[49] + w[54].gamma1();
        w[57] = w[41] + w[42].gamma0() + w[50] + w[55].gamma1();
        w[58] = w[42] + w[43].gamma0() + w[51] + w[56].gamma1();
        w[59] = w[43] + w[44].gamma0() + w[52] + w[57].gamma1();
        w[60] = w[44] + w[45].gamma0() + w[53] + w[58].gamma1();
        w[61] = w[45] + w[46].gamma0() + w[54] + w[59].gamma1();
        w[62] = w[46] + w[47].gamma0() + w[55] + w[60].gamma1();
        w[63] = w[47] + w[48].gamma0() + w[56] + w[61].gamma1();

        w
    }

    pub(crate) fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = Into::<[U32Word; 8]>::into(&self.state);
        let w = self.load_words();

        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[0], K00);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[1], K01);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[2], K02);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[3], K03);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[4], K04);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[5], K05);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[6], K06);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[7], K07);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[8], K08);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[9], K09);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[10], K10);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[11], K11);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[12], K12);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[13], K13);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[14], K14);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[15], K15);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[16], K16);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[17], K17);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[18], K18);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[19], K19);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[20], K20);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[21], K21);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[22], K22);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[23], K23);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[24], K24);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[25], K25);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[26], K26);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[27], K27);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[28], K28);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[29], K29);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[30], K30);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[31], K31);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[32], K32);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[33], K33);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[34], K34);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[35], K35);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[36], K36);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[37], K37);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[38], K38);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[39], K39);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[40], K40);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[41], K41);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[42], K42);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[43], K43);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[44], K44);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[45], K45);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[46], K46);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[47], K47);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[48], K48);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[49], K49);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[50], K50);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[51], K51);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[52], K52);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[53], K53);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[54], K54);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[55], K55);
        Sha256Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[56], K56);
        Sha256Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[57], K57);
        Sha256Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[58], K58);
        Sha256Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[59], K59);
        Sha256Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[60], K60);
        Sha256Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[61], K61);
        Sha256Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[62], K62);
        Sha256Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[63], K63);

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA256_SCHEDULE_LAST_INDEX as u64
            & (55u64.wrapping_sub(self.size & SHA256_SCHEDULE_LAST_INDEX as u64)))
            as usize
    }

    fn finish_with_len(&mut self, len: u64) -> u64 {
        let pad_len: [u8; 8] = (len * 8).to_be_bytes();
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] =
            [0u8; SHA256_SCHEDULE_U32_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&pad_len);

        Into::<u64>::into(self.state[0]) << 32 | Into::<u64>::into(self.state[1])
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha256State::default(),
            words: Sha256Words::default(),
        }
    }
}

impl Hash for Sha256Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha256Hasher {
    fn finish(&self) -> u64 {
        self.clone().finish_with_len(self.size)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA256_SCHEDULE_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA256_PADDING_U8_WORDS_COUNT as u8 - len_w) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)]
                .clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA256_SCHEDULE_LAST_INDEX as u8;

            if len_w != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        while bytes.len() >= SHA256_PADDING_U8_WORDS_COUNT as usize {
            self.words
                .clone_from_slice(&bytes[..(SHA256_PADDING_U8_WORDS_COUNT as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA256_PADDING_U8_WORDS_COUNT as usize)..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl HasherContext for Sha256Hasher {
    fn to_lower_hex(&self) -> String {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        format!("{:08x}", hasher.state)
    }

    fn to_upper_hex(&self) -> String {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        format!("{:08X}", hasher.state)
    }

    fn to_bytes_hash(&self) -> Box<[u8]> {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        Box::new(Into::<[u8; 32]>::into(hasher.state))
    }
}
