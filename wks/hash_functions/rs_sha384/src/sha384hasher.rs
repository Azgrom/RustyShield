use alloc::{
    format,
    boxed::Box,
    string::String
};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U64Word;
use crate::{
    SHA384BLOCK_SIZE,
    SHA384PADDING_SIZE,
    sha384state::Sha384State,
    sha384words::Sha384Words,
    sha384comp::Sha384Comp
};

const SHA384MESSAGE_SCHEDULE_SIZE: usize = 80;
const SHA384BLOCK_LAST_INDEX: usize = 127;

#[derive(Clone)]
pub struct Sha384Hasher {
    pub(crate) size: u128,
    pub(crate) state: Sha384State,
    pub(crate) words: Sha384Words
}

impl Sha384Hasher {
    fn load_words(&self) -> [U64Word; SHA384MESSAGE_SCHEDULE_SIZE]{
        let mut w: [U64Word; SHA384MESSAGE_SCHEDULE_SIZE] =
            [U64Word::default(); SHA384MESSAGE_SCHEDULE_SIZE];

        self.words
            .u64_chunks()
            .enumerate()
            .for_each(|(i, c)| w[i] = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]).into());

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
        w[64] = w[48] + w[49].gamma0() + w[57] + w[62].gamma1();
        w[65] = w[49] + w[50].gamma0() + w[58] + w[63].gamma1();
        w[66] = w[50] + w[51].gamma0() + w[59] + w[64].gamma1();
        w[67] = w[51] + w[52].gamma0() + w[60] + w[65].gamma1();
        w[68] = w[52] + w[53].gamma0() + w[61] + w[66].gamma1();
        w[69] = w[53] + w[54].gamma0() + w[62] + w[67].gamma1();
        w[70] = w[54] + w[55].gamma0() + w[63] + w[68].gamma1();
        w[71] = w[55] + w[56].gamma0() + w[64] + w[69].gamma1();
        w[72] = w[56] + w[57].gamma0() + w[65] + w[70].gamma1();
        w[73] = w[57] + w[58].gamma0() + w[66] + w[71].gamma1();
        w[74] = w[58] + w[59].gamma0() + w[67] + w[72].gamma1();
        w[75] = w[59] + w[60].gamma0() + w[68] + w[73].gamma1();
        w[76] = w[60] + w[61].gamma0() + w[69] + w[74].gamma1();
        w[77] = w[61] + w[62].gamma0() + w[70] + w[75].gamma1();
        w[78] = w[62] + w[63].gamma0() + w[71] + w[76].gamma1();
        w[79] = w[63] + w[64].gamma0() + w[72] + w[77].gamma1();

        w
    }

    fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = Into::<[U64Word; 8]>::into(&self.state);
        let w = self.load_words();

        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[0], U64Word::K00);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[1], U64Word::K01);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[2], U64Word::K02);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[3], U64Word::K03);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[4], U64Word::K04);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[5], U64Word::K05);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[6], U64Word::K06);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[7], U64Word::K07);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[8], U64Word::K08);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[9], U64Word::K09);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[10], U64Word::K10);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[11], U64Word::K11);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[12], U64Word::K12);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[13], U64Word::K13);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[14], U64Word::K14);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[15], U64Word::K15);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[16], U64Word::K16);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[17], U64Word::K17);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[18], U64Word::K18);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[19], U64Word::K19);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[20], U64Word::K20);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[21], U64Word::K21);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[22], U64Word::K22);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[23], U64Word::K23);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[24], U64Word::K24);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[25], U64Word::K25);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[26], U64Word::K26);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[27], U64Word::K27);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[28], U64Word::K28);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[29], U64Word::K29);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[30], U64Word::K30);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[31], U64Word::K31);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[32], U64Word::K32);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[33], U64Word::K33);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[34], U64Word::K34);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[35], U64Word::K35);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[36], U64Word::K36);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[37], U64Word::K37);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[38], U64Word::K38);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[39], U64Word::K39);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[40], U64Word::K40);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[41], U64Word::K41);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[42], U64Word::K42);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[43], U64Word::K43);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[44], U64Word::K44);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[45], U64Word::K45);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[46], U64Word::K46);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[47], U64Word::K47);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[48], U64Word::K48);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[49], U64Word::K49);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[50], U64Word::K50);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[51], U64Word::K51);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[52], U64Word::K52);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[53], U64Word::K53);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[54], U64Word::K54);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[55], U64Word::K55);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[56], U64Word::K56);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[57], U64Word::K57);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[58], U64Word::K58);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[59], U64Word::K59);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[60], U64Word::K60);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[61], U64Word::K61);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[62], U64Word::K62);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[63], U64Word::K63);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[64], U64Word::K64);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[65], U64Word::K65);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[66], U64Word::K66);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[67], U64Word::K67);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[68], U64Word::K68);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[69], U64Word::K69);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[70], U64Word::K70);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[71], U64Word::K71);
        Sha384Comp(a, b, c, &mut d, e, f, g, &mut h).rnd(w[72], U64Word::K72);
        Sha384Comp(h, a, b, &mut c, d, e, f, &mut g).rnd(w[73], U64Word::K73);
        Sha384Comp(g, h, a, &mut b, c, d, e, &mut f).rnd(w[74], U64Word::K74);
        Sha384Comp(f, g, h, &mut a, b, c, d, &mut e).rnd(w[75], U64Word::K75);
        Sha384Comp(e, f, g, &mut h, a, b, c, &mut d).rnd(w[76], U64Word::K76);
        Sha384Comp(d, e, f, &mut g, h, a, b, &mut c).rnd(w[77], U64Word::K77);
        Sha384Comp(c, d, e, &mut f, g, h, a, &mut b).rnd(w[78], U64Word::K78);
        Sha384Comp(b, c, d, &mut e, f, g, h, &mut a).rnd(w[79], U64Word::K79);

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
        1 + (SHA384BLOCK_LAST_INDEX
            & (111usize.wrapping_sub((self.size & SHA384BLOCK_LAST_INDEX as u128) as usize)))
    }

    fn finish_with_len(&mut self, len: u128) -> u64 {
        let pad_len: [u8; 16] = (len * 8).to_be_bytes();
        let zero_padding_len = self.zero_padding_length();
        let mut offset_pad = [0u8; SHA384BLOCK_SIZE];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_len]);
        self.write(&pad_len);

        Into::<u64>::into(self.state[0]) << 32 | Into::<u64>::into(self.state[1])
    }
}

impl Default for Sha384Hasher {
    fn default() -> Self {
        Self{
            size: u128::MIN,
            state: Sha384State::default(),
            words: Sha384Words::default()
        }
    }
}

impl Hash for Sha384Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha384Hasher {
    fn finish(&self) -> u64 {
        self.clone().finish_with_len(self.size)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA384BLOCK_LAST_INDEX as u128) as u8;
        self.size += bytes.len() as u128;

        if len_w != 0 {
            let mut left = (SHA384BLOCK_SIZE as u8 - len_w) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[len_w..(len_w + left)].clone_from_slice(&bytes[..left as usize]);

            len_w = (len_w + left) & SHA384BLOCK_LAST_INDEX as u8;

            if len_w != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        while bytes.len() >= SHA384BLOCK_SIZE {
            self.words.clone_from_slice(&bytes[..SHA384BLOCK_SIZE]);
            self.hash_block();
            bytes = &bytes[SHA384BLOCK_SIZE..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl HasherContext for Sha384Hasher {
    fn to_lower_hex(&self) -> String {
        let mut sha384hasher = self.clone();
        sha384hasher.finish_with_len(sha384hasher.size);
        format!("{:016x}", sha384hasher.state)
    }

    fn to_upper_hex(&self) -> String {
        let mut sha384hasher = self.clone();
        sha384hasher.finish_with_len(sha384hasher.size);
        format!("{:016X}", sha384hasher.state)
    }

    fn to_bytes_hash(&self) -> Box<[u8]> {
        let mut sha384hasher = self.clone();
        sha384hasher.finish_with_len(sha384hasher.size);
        Box::new(Into::<[u8; SHA384PADDING_SIZE]>::into(sha384hasher.state))
    }
}
