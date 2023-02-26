use crate::{
    sha1state::Sha1State, sha1words::Sha1Words, SHA1_BLOCK_SIZE, SHA1_WORD_COUNT,
    SHA_CBLOCK_LAST_INDEX, SHA_OFFSET_PAD
};
use alloc::{boxed::Box, format, string::String};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;

const T_0_19: u32 = 0x5A827999;
const T_20_39: u32 = 0x6ED9EBA1;
const T_40_59: u32 = 0x8F1BBCDC;
const T_60_79: u32 = 0xCA62C1D6;

#[derive(Clone, Debug)]
pub struct Sha1Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha1State,
    pub(crate) words: Sha1Words,
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha1State::default(),
            words: Sha1Words::default(),
        }
    }
}

impl Hash for Sha1Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha1Hasher {
    fn finish(&self) -> u64 {
        self.clone().finish_with_len(self.size)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA1_BLOCK_SIZE - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[len_w..len_w + left]
                .clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA_CBLOCK_LAST_INDEX as u8;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes.len() >= SHA1_BLOCK_SIZE as usize {
            self.words
                .clone_from_slice(&bytes[..(SHA1_BLOCK_SIZE as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA1_BLOCK_SIZE as usize)..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl PartialEq for Sha1Hasher {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.state == other.state && self.words == other.words
    }
}

impl HasherContext for Sha1Hasher {
    fn to_lower_hex(&self) -> String {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        format!("{:08x}", hasher.state)
    }

    fn to_upper_hex(&self) -> String {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        format!("{:08x}", hasher.state)
    }

    fn to_bytes_hash(&self) -> Box<[u8]> {
        let mut hasher = self.clone();
        hasher.finish_with_len(self.size);
        hasher.state.bytes_hash()
    }
}

impl Sha1Hasher {
    pub(crate) fn zero_padding_length(&self) -> usize {
        1 + (SHA_CBLOCK_LAST_INDEX as u64
                & (55u64.wrapping_sub(self.size & SHA_CBLOCK_LAST_INDEX as u64)))
                as usize
    }

    pub(crate) fn u32_words_from_u8_pad(&self, d_words: &mut [U32Word; SHA1_WORD_COUNT as usize]) {
        d_words[0] =
            U32Word::from_be_bytes([self.words[0], self.words[1], self.words[2], self.words[3]]);
        d_words[1] =
            U32Word::from_be_bytes([self.words[4], self.words[5], self.words[6], self.words[7]]);
        d_words[2] =
            U32Word::from_be_bytes([self.words[8], self.words[9], self.words[10], self.words[11]]);
        d_words[3] = U32Word::from_be_bytes([
            self.words[12],
            self.words[13],
            self.words[14],
            self.words[15],
        ]);
        d_words[4] = U32Word::from_be_bytes([
            self.words[16],
            self.words[17],
            self.words[18],
            self.words[19],
        ]);
        d_words[5] = U32Word::from_be_bytes([
            self.words[20],
            self.words[21],
            self.words[22],
            self.words[23],
        ]);
        d_words[6] = U32Word::from_be_bytes([
            self.words[24],
            self.words[25],
            self.words[26],
            self.words[27],
        ]);
        d_words[7] = U32Word::from_be_bytes([
            self.words[28],
            self.words[29],
            self.words[30],
            self.words[31],
        ]);
        d_words[8] = U32Word::from_be_bytes([
            self.words[32],
            self.words[33],
            self.words[34],
            self.words[35],
        ]);
        d_words[9] = U32Word::from_be_bytes([
            self.words[36],
            self.words[37],
            self.words[38],
            self.words[39],
        ]);
        d_words[10] = U32Word::from_be_bytes([
            self.words[40],
            self.words[41],
            self.words[42],
            self.words[43],
        ]);
        d_words[11] = U32Word::from_be_bytes([
            self.words[44],
            self.words[45],
            self.words[46],
            self.words[47],
        ]);
        d_words[12] = U32Word::from_be_bytes([
            self.words[48],
            self.words[49],
            self.words[50],
            self.words[51],
        ]);
        d_words[13] = U32Word::from_be_bytes([
            self.words[52],
            self.words[53],
            self.words[54],
            self.words[55],
        ]);
        d_words[14] = U32Word::from_be_bytes([
            self.words[56],
            self.words[57],
            self.words[58],
            self.words[59],
        ]);
        d_words[15] = U32Word::from_be_bytes([
            self.words[60],
            self.words[61],
            self.words[62],
            self.words[63],
        ]);
    }

    #[inline(always)]
    pub(crate) fn rounds_00_15(
        a: U32Word,
        b: &mut U32Word,
        c: U32Word,
        d: U32Word,
        e: &mut U32Word,
        word: U32Word,
    ) {
        *e += word + T_0_19 + a.rotate_left(5) + U32Word::ch(*b, c, d);
        *b = b.rotate_right(2);
    }

    #[inline(always)]
    pub(crate) fn rounds_16_19(
        a: U32Word,
        b: &mut U32Word,
        c: U32Word,
        d: U32Word,
        e: &mut U32Word,
        word: U32Word,
    ) {
        *e += word + T_0_19 + a.rotate_left(5) + U32Word::ch(*b, c, d);
        *b = b.rotate_right(2);
    }

    #[inline(always)]
    pub(crate) fn rounds_20_39(
        a: U32Word,
        b: &mut U32Word,
        c: U32Word,
        d: U32Word,
        e: &mut U32Word,
        word: U32Word,
    ) {
        *e += word + T_20_39 + a.rotate_left(5) + U32Word::parity(*b, c, d);
        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn rounds_40_59(
        a: U32Word,
        b: &mut U32Word,
        c: U32Word,
        d: U32Word,
        e: &mut U32Word,
        word: U32Word,
    ) {
        *e += word + T_40_59 + a.rotate_left(5) + U32Word::maj(*b, c, d);
        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn rounds_60_79(
        a: U32Word,
        b: &mut U32Word,
        c: U32Word,
        d: U32Word,
        e: &mut U32Word,
        word: U32Word,
    ) {
        *e += word + T_60_79 + a.rotate_left(5) + U32Word::parity(*b, c, d);
        *b = b.rotate_right(2);
    }

    fn block_00_15(
        &self,
        a: &mut U32Word,
        b: &mut U32Word,
        c: &mut U32Word,
        d: &mut U32Word,
        e: &mut U32Word,
        d_words: &mut [U32Word; SHA1_WORD_COUNT as usize],
    ) {
        self.u32_words_from_u8_pad(d_words);

        Self::rounds_00_15(*a, b, *c, *d, e, d_words[0]);
        Self::rounds_00_15(*e, a, *b, *c, d, d_words[1]);
        Self::rounds_00_15(*d, e, *a, *b, c, d_words[2]);
        Self::rounds_00_15(*c, d, *e, *a, b, d_words[3]);
        Self::rounds_00_15(*b, c, *d, *e, a, d_words[4]);
        Self::rounds_00_15(*a, b, *c, *d, e, d_words[5]);
        Self::rounds_00_15(*e, a, *b, *c, d, d_words[6]);
        Self::rounds_00_15(*d, e, *a, *b, c, d_words[7]);
        Self::rounds_00_15(*c, d, *e, *a, b, d_words[8]);
        Self::rounds_00_15(*b, c, *d, *e, a, d_words[9]);
        Self::rounds_00_15(*a, b, *c, *d, e, d_words[10]);
        Self::rounds_00_15(*e, a, *b, *c, d, d_words[11]);
        Self::rounds_00_15(*d, e, *a, *b, c, d_words[12]);
        Self::rounds_00_15(*c, d, *e, *a, b, d_words[13]);
        Self::rounds_00_15(*b, c, *d, *e, a, d_words[14]);
        Self::rounds_00_15(*a, b, *c, *d, e, d_words[15]);
    }

    fn block_16_19(
        a: &mut U32Word,
        b: &mut U32Word,
        c: &mut U32Word,
        d: &mut U32Word,
        e: &mut U32Word,
        d_words: &mut [U32Word; SHA1_WORD_COUNT as usize],
    ) {
        d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
        d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
        d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
        d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);

        Self::rounds_16_19(*e, a, *b, *c, d, d_words[0]);
        Self::rounds_16_19(*d, e, *a, *b, c, d_words[1]);
        Self::rounds_16_19(*c, d, *e, *a, b, d_words[2]);
        Self::rounds_16_19(*b, c, *d, *e, a, d_words[3]);
    }

    fn block_20_39(
        a: &mut U32Word,
        b: &mut U32Word,
        c: &mut U32Word,
        d: &mut U32Word,
        e: &mut U32Word,
        d_words: &mut [U32Word; SHA1_WORD_COUNT as usize],
    ) {
        d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
        d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
        d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
        d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);
        let step_20th_word = d_words[4];
        let step_21th_word = d_words[5];
        let step_22th_word = d_words[6];
        let step_23th_word = d_words[7];
        d_words[8] = (d_words[8] ^ d_words[10] ^ d_words[0] ^ d_words[5]).rotate_left(1);
        d_words[9] = (d_words[9] ^ d_words[11] ^ d_words[1] ^ d_words[6]).rotate_left(1);
        d_words[10] = (d_words[10] ^ d_words[12] ^ d_words[2] ^ d_words[7]).rotate_left(1);
        d_words[11] = (d_words[11] ^ d_words[13] ^ d_words[3] ^ d_words[8]).rotate_left(1);
        d_words[12] = (d_words[12] ^ d_words[14] ^ d_words[4] ^ d_words[9]).rotate_left(1);
        d_words[13] = (d_words[13] ^ d_words[15] ^ d_words[5] ^ d_words[10]).rotate_left(1);
        d_words[14] = (d_words[14] ^ d_words[0] ^ d_words[6] ^ d_words[11]).rotate_left(1);
        d_words[15] = (d_words[15] ^ d_words[1] ^ d_words[7] ^ d_words[12]).rotate_left(1);
        d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
        d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
        d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
        d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);
        d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
        d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
        d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
        d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);

        Self::rounds_20_39(*a, b, *c, *d, e, step_20th_word);
        Self::rounds_20_39(*e, a, *b, *c, d, step_21th_word);
        Self::rounds_20_39(*d, e, *a, *b, c, step_22th_word);
        Self::rounds_20_39(*c, d, *e, *a, b, step_23th_word);
        Self::rounds_20_39(*b, c, *d, *e, a, d_words[8]);
        Self::rounds_20_39(*a, b, *c, *d, e, d_words[9]);
        Self::rounds_20_39(*e, a, *b, *c, d, d_words[10]);
        Self::rounds_20_39(*d, e, *a, *b, c, d_words[11]);
        Self::rounds_20_39(*c, d, *e, *a, b, d_words[12]);
        Self::rounds_20_39(*b, c, *d, *e, a, d_words[13]);
        Self::rounds_20_39(*a, b, *c, *d, e, d_words[14]);
        Self::rounds_20_39(*e, a, *b, *c, d, d_words[15]);
        Self::rounds_20_39(*d, e, *a, *b, c, d_words[0]);
        Self::rounds_20_39(*c, d, *e, *a, b, d_words[1]);
        Self::rounds_20_39(*b, c, *d, *e, a, d_words[2]);
        Self::rounds_20_39(*a, b, *c, *d, e, d_words[3]);
        Self::rounds_20_39(*e, a, *b, *c, d, d_words[4]);
        Self::rounds_20_39(*d, e, *a, *b, c, d_words[5]);
        Self::rounds_20_39(*c, d, *e, *a, b, d_words[6]);
        Self::rounds_20_39(*b, c, *d, *e, a, d_words[7]);
    }

    fn block_40_59(
        a: &mut U32Word,
        b: &mut U32Word,
        c: &mut U32Word,
        d: &mut U32Word,
        e: &mut U32Word,
        d_words: &mut [U32Word; SHA1_WORD_COUNT as usize],
    ) {
        d_words[8] = (d_words[8] ^ d_words[10] ^ d_words[0] ^ d_words[5]).rotate_left(1);
        d_words[9] = (d_words[9] ^ d_words[11] ^ d_words[1] ^ d_words[6]).rotate_left(1);
        d_words[10] = (d_words[10] ^ d_words[12] ^ d_words[2] ^ d_words[7]).rotate_left(1);
        d_words[11] = (d_words[11] ^ d_words[13] ^ d_words[3] ^ d_words[8]).rotate_left(1);
        let step_40th_word = d_words[8];
        let step_41th_word = d_words[9];
        let step_42th_word = d_words[10];
        let step_43th_word = d_words[11];
        d_words[12] = (d_words[12] ^ d_words[14] ^ d_words[4] ^ d_words[9]).rotate_left(1);
        d_words[13] = (d_words[13] ^ d_words[15] ^ d_words[5] ^ d_words[10]).rotate_left(1);
        d_words[14] = (d_words[14] ^ d_words[0] ^ d_words[6] ^ d_words[11]).rotate_left(1);
        d_words[15] = (d_words[15] ^ d_words[1] ^ d_words[7] ^ d_words[12]).rotate_left(1);
        d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
        d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
        d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
        d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);
        d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
        d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
        d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
        d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);
        d_words[8] = (d_words[8] ^ d_words[10] ^ d_words[0] ^ d_words[5]).rotate_left(1);
        d_words[9] = (d_words[9] ^ d_words[11] ^ d_words[1] ^ d_words[6]).rotate_left(1);
        d_words[10] = (d_words[10] ^ d_words[12] ^ d_words[2] ^ d_words[7]).rotate_left(1);
        d_words[11] = (d_words[11] ^ d_words[13] ^ d_words[3] ^ d_words[8]).rotate_left(1);

        Self::rounds_40_59(*a, b, *c, *d, e, step_40th_word);
        Self::rounds_40_59(*e, a, *b, *c, d, step_41th_word);
        Self::rounds_40_59(*d, e, *a, *b, c, step_42th_word);
        Self::rounds_40_59(*c, d, *e, *a, b, step_43th_word);
        Self::rounds_40_59(*b, c, *d, *e, a, d_words[12]);
        Self::rounds_40_59(*a, b, *c, *d, e, d_words[13]);
        Self::rounds_40_59(*e, a, *b, *c, d, d_words[14]);
        Self::rounds_40_59(*d, e, *a, *b, c, d_words[15]);
        Self::rounds_40_59(*c, d, *e, *a, b, d_words[0]);
        Self::rounds_40_59(*b, c, *d, *e, a, d_words[1]);
        Self::rounds_40_59(*a, b, *c, *d, e, d_words[2]);
        Self::rounds_40_59(*e, a, *b, *c, d, d_words[3]);
        Self::rounds_40_59(*d, e, *a, *b, c, d_words[4]);
        Self::rounds_40_59(*c, d, *e, *a, b, d_words[5]);
        Self::rounds_40_59(*b, c, *d, *e, a, d_words[6]);
        Self::rounds_40_59(*a, b, *c, *d, e, d_words[7]);
        Self::rounds_40_59(*e, a, *b, *c, d, d_words[8]);
        Self::rounds_40_59(*d, e, *a, *b, c, d_words[9]);
        Self::rounds_40_59(*c, d, *e, *a, b, d_words[10]);
        Self::rounds_40_59(*b, c, *d, *e, a, d_words[11]);
    }

    fn block_60_79(
        a: &mut U32Word,
        b: &mut U32Word,
        c: &mut U32Word,
        d: &mut U32Word,
        e: &mut U32Word,
        d_words: &mut [U32Word; SHA1_WORD_COUNT as usize],
    ) {
        d_words[12] = (d_words[12] ^ d_words[14] ^ d_words[4] ^ d_words[9]).rotate_left(1);
        d_words[13] = (d_words[13] ^ d_words[15] ^ d_words[5] ^ d_words[10]).rotate_left(1);
        d_words[14] = (d_words[14] ^ d_words[0] ^ d_words[6] ^ d_words[11]).rotate_left(1);
        d_words[15] = (d_words[15] ^ d_words[1] ^ d_words[7] ^ d_words[12]).rotate_left(1);
        let step_60th_word = d_words[12];
        let step_61th_word = d_words[13];
        let step_62th_word = d_words[14];
        let step_63th_word = d_words[15];
        d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
        d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
        d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
        d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);
        d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
        d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
        d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
        d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);
        d_words[8] = (d_words[8] ^ d_words[10] ^ d_words[0] ^ d_words[5]).rotate_left(1);
        d_words[9] = (d_words[9] ^ d_words[11] ^ d_words[1] ^ d_words[6]).rotate_left(1);
        d_words[10] = (d_words[10] ^ d_words[12] ^ d_words[2] ^ d_words[7]).rotate_left(1);
        d_words[11] = (d_words[11] ^ d_words[13] ^ d_words[3] ^ d_words[8]).rotate_left(1);
        d_words[12] = (d_words[12] ^ d_words[14] ^ d_words[4] ^ d_words[9]).rotate_left(1);
        d_words[13] = (d_words[13] ^ d_words[15] ^ d_words[5] ^ d_words[10]).rotate_left(1);
        d_words[14] = (d_words[14] ^ d_words[0] ^ d_words[6] ^ d_words[11]).rotate_left(1);
        d_words[15] = (d_words[15] ^ d_words[1] ^ d_words[7] ^ d_words[12]).rotate_left(1);

        Self::rounds_60_79(*a, b, *c, *d, e, step_60th_word);
        Self::rounds_60_79(*e, a, *b, *c, d, step_61th_word);
        Self::rounds_60_79(*d, e, *a, *b, c, step_62th_word);
        Self::rounds_60_79(*c, d, *e, *a, b, step_63th_word);
        Self::rounds_60_79(*b, c, *d, *e, a, d_words[0]);
        Self::rounds_60_79(*a, b, *c, *d, e, d_words[1]);
        Self::rounds_60_79(*e, a, *b, *c, d, d_words[2]);
        Self::rounds_60_79(*d, e, *a, *b, c, d_words[3]);
        Self::rounds_60_79(*c, d, *e, *a, b, d_words[4]);
        Self::rounds_60_79(*b, c, *d, *e, a, d_words[5]);
        Self::rounds_60_79(*a, b, *c, *d, e, d_words[6]);
        Self::rounds_60_79(*e, a, *b, *c, d, d_words[7]);
        Self::rounds_60_79(*d, e, *a, *b, c, d_words[8]);
        Self::rounds_60_79(*c, d, *e, *a, b, d_words[9]);
        Self::rounds_60_79(*b, c, *d, *e, a, d_words[10]);
        Self::rounds_60_79(*a, b, *c, *d, e, d_words[11]);
        Self::rounds_60_79(*e, a, *b, *c, d, d_words[12]);
        Self::rounds_60_79(*d, e, *a, *b, c, d_words[13]);
        Self::rounds_60_79(*c, d, *e, *a, b, d_words[14]);
        Self::rounds_60_79(*b, c, *d, *e, a, d_words[15]);
    }

    fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e] = *self.state.to_slice();
        let mut d_words: [U32Word; SHA1_WORD_COUNT as usize] = [U32Word::default(); 16];

        self.block_00_15(&mut a, &mut b, &mut c, &mut d, &mut e, &mut d_words);
        Self::block_16_19(&mut a, &mut b, &mut c, &mut d, &mut e, &mut d_words);
        Self::block_20_39(&mut a, &mut b, &mut c, &mut d, &mut e, &mut d_words);
        Self::block_40_59(&mut a, &mut b, &mut c, &mut d, &mut e, &mut d_words);
        Self::block_60_79(&mut a, &mut b, &mut c, &mut d, &mut e, &mut d_words);

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
    }

    fn finish_with_len(&mut self, len: u64) -> u64 {
        let pad_len: [u8; 8] = (len * 8).to_be_bytes();
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&pad_len);

        Into::<u64>::into(self.state[0]) << 32 | Into::<u64>::into(self.state[1])
    }
}
