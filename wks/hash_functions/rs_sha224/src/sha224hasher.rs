use alloc::{
    boxed::Box,
    format,
    string::String
};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;
use crate::{SHA224_PADDING_U8_WORDS_COUNT, SHA224_SCHEDULE_U32_WORDS_COUNT, sha224state::Sha224State, sha224words::Sha224Words};
use crate::sha224comp::Sha224Comp;

const SHA224_SCHEDULE_LAST_INDEX: u32 = SHA224_SCHEDULE_U32_WORDS_COUNT - 1;

#[derive(Clone)]
pub struct Sha224Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha224State,
    pub(crate) words: Sha224Words
}

impl Sha224Hasher {
    pub(crate) fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = Into::<[U32Word; 8]>::into(&self.state);
        let w = self.load_words();

        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[0], U32Word::K00);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[1], U32Word::K01);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[2], U32Word::K02);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[3], U32Word::K03);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[4], U32Word::K04);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[5], U32Word::K05);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[6], U32Word::K06);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[7], U32Word::K07);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[8], U32Word::K08);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[9], U32Word::K09);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[10], U32Word::K10);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[11], U32Word::K11);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[12], U32Word::K12);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[13], U32Word::K13);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[14], U32Word::K14);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[15], U32Word::K15);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[16], U32Word::K16);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[17], U32Word::K17);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[18], U32Word::K18);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[19], U32Word::K19);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[20], U32Word::K20);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[21], U32Word::K21);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[22], U32Word::K22);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[23], U32Word::K23);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[24], U32Word::K24);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[25], U32Word::K25);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[26], U32Word::K26);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[27], U32Word::K27);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[28], U32Word::K28);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[29], U32Word::K29);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[30], U32Word::K30);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[31], U32Word::K31);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[32], U32Word::K32);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[33], U32Word::K33);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[34], U32Word::K34);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[35], U32Word::K35);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[36], U32Word::K36);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[37], U32Word::K37);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[38], U32Word::K38);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[39], U32Word::K39);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[40], U32Word::K40);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[41], U32Word::K41);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[42], U32Word::K42);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[43], U32Word::K43);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[44], U32Word::K44);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[45], U32Word::K45);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[46], U32Word::K46);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[47], U32Word::K47);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[48], U32Word::K48);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[49], U32Word::K49);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[50], U32Word::K50);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[51], U32Word::K51);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[52], U32Word::K52);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[53], U32Word::K53);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[54], U32Word::K54);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[55], U32Word::K55);
        Sha224Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[56], U32Word::K56);
        Sha224Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[57], U32Word::K57);
        Sha224Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[58], U32Word::K58);
        Sha224Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[59], U32Word::K59);
        Sha224Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[60], U32Word::K60);
        Sha224Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[61], U32Word::K61);
        Sha224Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[62], U32Word::K62);
        Sha224Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[63], U32Word::K63);

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    fn load_words(&self) -> [U32Word; SHA224_SCHEDULE_U32_WORDS_COUNT as usize] {
        let mut w: [U32Word; SHA224_SCHEDULE_U32_WORDS_COUNT as usize] =
            [U32Word::default(); SHA224_SCHEDULE_U32_WORDS_COUNT as usize];

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

    fn zero_padding_length(&self) -> usize {
        1 + (SHA224_SCHEDULE_LAST_INDEX as u64
            & (55u64.wrapping_sub(self.size & SHA224_SCHEDULE_LAST_INDEX as u64)))
            as usize
    }

    fn finish_with_len(&mut self, len: u64) -> u64 {
        let pad_len: [u8; 8] = (len * 8).to_be_bytes();
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA224_SCHEDULE_U32_WORDS_COUNT as usize] =
            [0u8; SHA224_SCHEDULE_U32_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&pad_len);

        Into::<u64>::into(self.state[0]) << 32 | Into::<u64>::into(self.state[1])
    }
}

impl Default for Sha224Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha224State::default(),
            words: Sha224Words::default()
        }
    }
}

impl Hash for Sha224Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha224Hasher {
    fn finish(&self) -> u64 {
        self.clone().finish_with_len(self.size)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA224_SCHEDULE_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA224_PADDING_U8_WORDS_COUNT - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)]
                .clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA224_SCHEDULE_LAST_INDEX as u8;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes.len() >= SHA224_PADDING_U8_WORDS_COUNT as usize {
            self.words
                .clone_from_slice(&bytes[..(SHA224_PADDING_U8_WORDS_COUNT as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA224_PADDING_U8_WORDS_COUNT as usize)..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl HasherContext for Sha224Hasher {
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
        Box::new(Into::<[u8; 28]>::into(hasher.state))
    }
}
