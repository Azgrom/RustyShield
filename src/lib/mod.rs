use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

const U32_BYTES: usize = size_of::<u32>();

const SHA_WORD_BLOCKS: u32 = 16;
const SHA_CBLOCK: u32 = SHA_WORD_BLOCKS * U32_BYTES as u32;
const SHA_OFFSET_PAD: u32 = SHA_CBLOCK + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA_CBLOCK - 1;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

const T_0_19: u32 = 0x5A827999;
const T_20_39: u32 = 0x6ED9EBA1;
const T_40_59: u32 = 0x8F1BBCDC;
const T_60_79: u32 = 0xCA62C1D6;

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

#[inline(always)]
fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

struct HashValue {
    data: [u32; 5],
}

impl Default for HashValue {
    fn default() -> Self {
        Self {
            data: [H0, H1, H2, H3, H4],
        }
    }
}

impl HashValue {
    fn to_slice(&self) -> &[u32; 5] {
        &self.data
    }
}

#[derive(Clone, Debug)]
struct DWords {
    data: [u32; SHA_WORD_BLOCKS as usize],
}

impl Default for DWords {
    fn default() -> Self {
        Self {
            data: [u32::MIN; SHA_WORD_BLOCKS as usize],
        }
    }
}

impl Index<usize> for DWords {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index & 15]
    }
}

impl IndexMut<usize> for DWords {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index & 15]
    }
}

impl PartialEq<[u32; 16]> for DWords {
    fn eq(&self, other: &[u32; 16]) -> bool {
        self.data == *other
    }
}

impl DWords {
    fn u32_be(c: &[u8]) -> u32 {
        match c.len() {
            4 => u32::from_be_bytes(c.try_into().unwrap()),
            3 => u32::from_be_bytes([c[0], c[1], c[2], 0]),
            2 => u32::from_be_bytes([c[0], c[1], 0, 0]),
            1 => u32::from_be_bytes([c[0], 0, 0, 0]),
            _ => panic!("this can't possibly happen"),
        }
    }

    fn include_bytes_on_incomplete_word(&mut self, word: usize, b: &[u8]) {
        self[word] = match b.len() {
            4 => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            3 => self[word] | u32::from_be_bytes([0, b[0], b[1], b[2]]),
            2 => self[word] | u32::from_be_bytes([0, 0, b[0], b[1]]),
            1 => self[word] | u32::from_be_bytes([0, 0, 0, b[0]]),
            _ => panic!("This cannot possibly happen"),
        }
    }

    fn from(&mut self, be_bytes: &[u8]) {
        be_bytes
            .chunks(U32_BYTES)
            .enumerate()
            .for_each(|(i, word)| self[i] = Self::u32_be(word));
    }

    fn skippable_offset(&mut self, be_bytes: &[u8], skip: u8) {
        let remaining = skip % U32_BYTES as u8;
        let completed_words = ((skip / U32_BYTES as u8) & 15) as usize;

        if remaining == 0
            && self.data[..(U32_BYTES - (skip as usize % U32_BYTES))]
                .iter()
                .rev()
                .take_while(|&u| *u == 0)
                .count()
                > 0
        {
            be_bytes
                .chunks(U32_BYTES)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words] = Self::u32_be(word));
        } else {
            let bytes_to_skip = U32_BYTES - remaining as usize;
            let skipped_bytes = &be_bytes[..bytes_to_skip];

            self.include_bytes_on_incomplete_word(completed_words, skipped_bytes);

            be_bytes[bytes_to_skip..]
                .chunks(U32_BYTES)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words + 1] = Self::u32_be(word));
        }
    }

    #[inline(always)]
    fn mix(&mut self, i: usize) {
        self[i] = (self[i + 13] ^ self[i + 8] ^ self[i + 2] ^ self[i]).rotate_left(1);
    }
}

pub struct Sha1Context {
    size: u64,
    hashes: HashValue,
    words: DWords,
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            hashes: HashValue::default(),
            words: DWords::default(),
        }
    }
}

impl Sha1Context {
    fn zero_padding_length(&self) -> usize {
        1 + 8
            + (SHA_CBLOCK_LAST_INDEX as u64
                & (55u64.wrapping_sub(self.size & SHA_CBLOCK_LAST_INDEX as u64)))
                as usize
    }

    #[inline(always)]
    fn block_00_15(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, word: u32) {
        *e = e
            .wrapping_add(word)
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_16_19(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_20_39(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_20_39)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_40_59(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_40_59)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(maj(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_60_79(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_60_79)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e] = self.hashes.to_slice().clone();

        let mut d_words = self.words.clone();

        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[0]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[1]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[2]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[3]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[4]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[5]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[6]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[7]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[8]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[9]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[10]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[11]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[12]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[13]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[14]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[15]);

        Self::block_16_19(16, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_16_19(17, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_16_19(18, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_16_19(19, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_20_39(20, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(21, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(22, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(23, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(24, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(25, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(26, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(27, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(28, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(29, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(30, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(31, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(32, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(33, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(34, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(35, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(36, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(37, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(38, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(39, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_40_59(40, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(41, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(42, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(43, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(44, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(45, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(46, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(47, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(48, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(49, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(50, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(51, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(52, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(53, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(54, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(55, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(56, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(57, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(58, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(59, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_60_79(60, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(61, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(62, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(63, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(64, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(65, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(66, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(67, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(68, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(69, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(70, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(71, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(72, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(73, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(74, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(75, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(76, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(77, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(78, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(79, b, &mut c, d, e, &mut a, &mut d_words);

        self.hashes.data[0] = self.hashes.data[0].wrapping_add(a);
        self.hashes.data[1] = self.hashes.data[1].wrapping_add(b);
        self.hashes.data[2] = self.hashes.data[2].wrapping_add(c);
        self.hashes.data[3] = self.hashes.data[3].wrapping_add(d);
        self.hashes.data[4] = self.hashes.data[4].wrapping_add(e);
    }
}

impl Sha1Context {
    pub fn bytes_hash(&self) -> [u8; 20] {
        let hash_value = self.hashes.to_slice();
        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = hash_value[i].to_be_bytes()
        });

        hash
    }

    pub fn hex_hash(&self) -> String {
        self.hashes
            .to_slice()
            .iter()
            .map(|&b| format!("{:08x}", b))
            .collect::<String>()
    }

    pub fn finish(&mut self) {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        let pad_len: [u8; 8] = (self.size * 8).to_be_bytes();

        offset_pad[0] = 0x80;
        offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);

        self.write(&offset_pad[..zero_padding_length]);
    }

    pub fn finish_with_len(&mut self, len: u64) {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        let pad_len: [u8; 8] = (len * 8).to_be_bytes();

        offset_pad[0] = 0x80;
        offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);

        self.write(&offset_pad[..zero_padding_length]);
    }

    pub fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA_CBLOCK - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words
                .skippable_offset(&bytes[..(left as usize)], len_w);

            len_w = (len_w + left) & SHA_CBLOCK_LAST_INDEX as u8;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes.len() >= SHA_CBLOCK as usize {
            self.words.from(&bytes[..(SHA_CBLOCK as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA_CBLOCK as usize)..];
        }

        if bytes.len() != 0 {
            self.words.from(bytes)
        }
    }
}

#[cfg(test)]
mod use_cases {
    use crate::Sha1Context;

    #[test]
    fn test_commonly_known_sha1_phrases_with_their_hex_hashes() {
        let empty_str = "";
        let mut empty_str_sha1_ctx = Sha1Context::default();
        empty_str_sha1_ctx.write(empty_str.as_ref());
        empty_str_sha1_ctx.finish();
        let digest_result = empty_str_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let abc = "abc";
        let mut abc_sha1_ctx = Sha1Context::default();
        abc_sha1_ctx.write(abc.as_ref());
        abc_sha1_ctx.finish();
        let digest_result = abc_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "a9993e364706816aba3e25717850c26c9cd0d89d");

        let abcd = "abcd";
        let mut abcd_sha1_ctx = Sha1Context::default();
        abcd_sha1_ctx.write(abcd.as_ref());
        abcd_sha1_ctx.finish();
        let digest_result = abcd_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "81fe8bfe87576c3ecb22426f8e57847382917acf");

        let quick_fox = "The quick brown fox jumps over the lazy dog";

        let mut quick_fox_sha1_ctx = Sha1Context::default();
        quick_fox_sha1_ctx.write(quick_fox.as_ref());
        quick_fox_sha1_ctx.finish();
        let digest_result = quick_fox_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

        let lazy_cog = "The quick brown fox jumps over the lazy cog";
        let mut lazy_cog_sha1_ctx = Sha1Context::default();
        lazy_cog_sha1_ctx.write(lazy_cog.as_ref());
        lazy_cog_sha1_ctx.finish();
        let digest_result = lazy_cog_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    }

    #[test]
    fn test_phrases_with_their_bytes_sequences() {
        let random_big_string = "";
        let mut big_str_sha1_ctx = Sha1Context::default();
        big_str_sha1_ctx.write(random_big_string.as_ref());
        big_str_sha1_ctx.finish();
        let digest_result = big_str_sha1_ctx.bytes_hash();
        assert_eq!(
            digest_result,
            [
                0xdau8, 0x39u8, 0xa3u8, 0xeeu8, 0x5eu8, 0x6bu8, 0x4bu8, 0x0d, 0x32u8, 0x55u8,
                0xbfu8, 0xefu8, 0x95u8, 0x60u8, 0x18u8, 0x90u8, 0xafu8, 0xd8u8, 0x07u8, 0x09u8
            ]
        );
    }
}

#[cfg(test)]
mod hypothesis_and_coverage_assurance;

#[cfg(test)]
mod fips_pub_180_1_coverage;
