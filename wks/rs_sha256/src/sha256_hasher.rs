use crate::{
    sha256_state::Sha256State, sha256_words::Sha256Words, SHA256_PADDING_U8_WORDS_COUNT,
    SHA256_SCHEDULE_U32_WORDS_COUNT, SHA256_SCHEDULE_U8_WORDS_LAST_INDEX,
};
use core::hash::{Hash, Hasher};
use u32_word_lib::U32Word;

pub struct Sha256Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha256State,
    pub(crate) words: Sha256Words,
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
        todo!()
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA256_SCHEDULE_U8_WORDS_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA256_PADDING_U8_WORDS_COUNT - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)]
                .clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA256_SCHEDULE_U8_WORDS_LAST_INDEX as u8;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
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

impl Sha256Hasher {
    pub(crate) fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state.u32_states();
        let w = self.load_words();

        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[0], 0x428A2F98);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[1], 0x71374491);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[2], 0xB5C0FBCF);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[3], 0xE9B5DBA5);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[4], 0x3956C25B);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[5], 0x59F111F1);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[6], 0x923F82A4);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[7], 0xAB1C5ED5);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[8], 0xD807AA98);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[9], 0x12835B01);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[10], 0x243185BE);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[11], 0x550C7DC3);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[12], 0x72BE5D74);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[13], 0x80DEB1FE);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[14], 0x9BDC06A7);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[15], 0xC19BF174);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[16], 0xE49B69C1);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[17], 0xEFBE4786);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[18], 0x0FC19DC6);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[19], 0x240CA1CC);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[20], 0x2DE92C6F);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[21], 0x4A7484AA);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[22], 0x5CB0A9DC);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[23], 0x76F988DA);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[24], 0x983E5152);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[25], 0xA831C66D);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[26], 0xB00327C8);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[27], 0xBF597FC7);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[28], 0xC6E00BF3);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[29], 0xD5A79147);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[30], 0x06CA6351);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[31], 0x14292967);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[32], 0x27B70A85);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[33], 0x2E1B2138);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[34], 0x4D2C6DFC);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[35], 0x53380D13);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[36], 0x650A7354);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[37], 0x766A0ABB);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[38], 0x81C2C92E);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[39], 0x92722C85);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[40], 0xA2BFE8A1);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[41], 0xA81A664B);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[42], 0xC24B8B70);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[43], 0xC76C51A3);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[44], 0xD192E819);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[45], 0xD6990624);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[46], 0xF40E3585);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[47], 0x106AA070);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[48], 0x19A4C116);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[49], 0x1E376C08);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[50], 0x2748774C);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[51], 0x34B0BCB5);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[52], 0x391C0CB3);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[53], 0x4ED8AA4A);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[54], 0x5B9CCA4F);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[55], 0x682E6FF3);
        U32Word::rnd(a, b, c, &mut d, e, f, g, &mut h, w[56], 0x748F82EE);
        U32Word::rnd(h, a, b, &mut c, d, e, f, &mut g, w[57], 0x78A5636F);
        U32Word::rnd(g, h, a, &mut b, c, d, e, &mut f, w[58], 0x84C87814);
        U32Word::rnd(f, g, h, &mut a, b, c, d, &mut e, w[59], 0x8CC70208);
        U32Word::rnd(e, f, g, &mut h, a, b, c, &mut d, w[60], 0x90BEFFFA);
        U32Word::rnd(d, e, f, &mut g, h, a, b, &mut c, w[61], 0xA4506CEB);
        U32Word::rnd(c, d, e, &mut f, g, h, a, &mut b, w[62], 0xBEF9A3F7);
        U32Word::rnd(b, c, d, &mut e, f, g, h, &mut a, w[63], 0xC67178F2);

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    fn load_words(&self) -> [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] {
        let mut w: [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] =
            [U32Word::default(); SHA256_SCHEDULE_U32_WORDS_COUNT as usize];

        self.words
            .u32_chunks()
            .enumerate()
            .for_each(|(i, c)| w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into());

        w[16] = ((w[1] + w[0]).gamma0() + w[9] + w[14]).gamma1();
        w[17] = ((w[2] + w[1]).gamma0() + w[10] + w[15]).gamma1();
        w[18] = ((w[3] + w[2]).gamma0() + w[11] + w[16]).gamma1();
        w[19] = ((w[4] + w[3]).gamma0() + w[12] + w[17]).gamma1();
        w[20] = ((w[5] + w[6]).gamma0() + w[13] + w[18]).gamma1();
        w[21] = ((w[6] + w[7]).gamma0() + w[14] + w[19]).gamma1();
        w[22] = ((w[7] + w[8]).gamma0() + w[15] + w[20]).gamma1();
        w[23] = ((w[8] + w[9]).gamma0() + w[16] + w[21]).gamma1();
        w[24] = ((w[9] + w[10]).gamma0() + w[17] + w[22]).gamma1();
        w[25] = ((w[10] + w[11]).gamma0() + w[18] + w[23]).gamma1();
        w[26] = ((w[11] + w[12]).gamma0() + w[19] + w[24]).gamma1();
        w[27] = ((w[12] + w[13]).gamma0() + w[20] + w[25]).gamma1();
        w[28] = ((w[13] + w[14]).gamma0() + w[21] + w[26]).gamma1();
        w[29] = ((w[14] + w[15]).gamma0() + w[22] + w[27]).gamma1();
        w[30] = ((w[15] + w[16]).gamma0() + w[23] + w[28]).gamma1();
        w[31] = ((w[16] + w[17]).gamma0() + w[24] + w[29]).gamma1();
        w[32] = ((w[17] + w[18]).gamma0() + w[25] + w[30]).gamma1();
        w[33] = ((w[18] + w[19]).gamma0() + w[26] + w[31]).gamma1();
        w[34] = ((w[19] + w[20]).gamma0() + w[27] + w[32]).gamma1();
        w[35] = ((w[20] + w[21]).gamma0() + w[28] + w[33]).gamma1();
        w[36] = ((w[21] + w[22]).gamma0() + w[29] + w[34]).gamma1();
        w[37] = ((w[22] + w[23]).gamma0() + w[30] + w[35]).gamma1();
        w[38] = ((w[23] + w[24]).gamma0() + w[31] + w[36]).gamma1();
        w[39] = ((w[24] + w[25]).gamma0() + w[32] + w[37]).gamma1();
        w[40] = ((w[25] + w[26]).gamma0() + w[33] + w[38]).gamma1();
        w[41] = ((w[26] + w[27]).gamma0() + w[34] + w[39]).gamma1();
        w[42] = ((w[27] + w[28]).gamma0() + w[35] + w[40]).gamma1();
        w[43] = ((w[28] + w[29]).gamma0() + w[36] + w[41]).gamma1();
        w[44] = ((w[29] + w[30]).gamma0() + w[37] + w[42]).gamma1();
        w[45] = ((w[30] + w[31]).gamma0() + w[38] + w[43]).gamma1();
        w[46] = ((w[31] + w[32]).gamma0() + w[39] + w[44]).gamma1();
        w[47] = ((w[32] + w[33]).gamma0() + w[40] + w[45]).gamma1();
        w[48] = ((w[33] + w[34]).gamma0() + w[41] + w[46]).gamma1();
        w[49] = ((w[34] + w[35]).gamma0() + w[42] + w[47]).gamma1();
        w[50] = ((w[35] + w[36]).gamma0() + w[43] + w[48]).gamma1();
        w[51] = ((w[36] + w[37]).gamma0() + w[44] + w[49]).gamma1();
        w[52] = ((w[37] + w[38]).gamma0() + w[45] + w[50]).gamma1();
        w[53] = ((w[38] + w[39]).gamma0() + w[46] + w[51]).gamma1();
        w[54] = ((w[39] + w[40]).gamma0() + w[47] + w[52]).gamma1();
        w[55] = ((w[40] + w[41]).gamma0() + w[48] + w[53]).gamma1();
        w[56] = ((w[41] + w[42]).gamma0() + w[49] + w[54]).gamma1();
        w[57] = ((w[42] + w[43]).gamma0() + w[50] + w[55]).gamma1();
        w[58] = ((w[43] + w[44]).gamma0() + w[51] + w[56]).gamma1();
        w[59] = ((w[44] + w[45]).gamma0() + w[52] + w[57]).gamma1();
        w[60] = ((w[45] + w[46]).gamma0() + w[53] + w[58]).gamma1();
        w[61] = ((w[46] + w[47]).gamma0() + w[54] + w[59]).gamma1();
        w[62] = ((w[47] + w[48]).gamma0() + w[55] + w[60]).gamma1();
        w[63] = ((w[48] + w[49]).gamma0() + w[56] + w[61]).gamma1();

        w
    }
}
