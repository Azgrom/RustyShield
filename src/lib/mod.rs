use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

const U32_BYTES: usize = size_of::<u32>();

const SHA_LBLOCK: u32 = 16;
const SHA_CBLOCK: u32 = SHA_LBLOCK * U32_BYTES as u32;
const SHA_OFFSET_PAD: u32 = SHA_CBLOCK + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA_CBLOCK - 1;

const H0: u32 = 0x67452301;
const H1: u32 = 0xefcdab89;
const H2: u32 = 0x98badcfe;
const H3: u32 = 0x10325476;
const H4: u32 = 0xc3d2e1f0;

const T_0_19: u32 = 0x5a827999;
const T_20_39: u32 = 0x6ed9eba1;
const T_40_59: u32 = 0x8f1bbcdc;
const T_60_79: u32 = 0xca62c1d6;

/// Represents `F_00_19` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
/// use lib::Sha1Context;
///
/// let ch1 = Sha1Context::ch(1, 2, 3);
/// assert_eq!(ch1, 2);
///
/// let ch2 = Sha1Context::ch(1000, 2001, 3002);
/// assert_eq!(ch2, 3026);
/// ```
#[inline]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

/// Represents `F_20_39` and `F_60_79` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
/// use lib::Sha1Context;
///
/// let parity1 = Sha1Context::parity(1, 2, 3);
/// assert_eq!(parity1, 0);
///
/// let parity2 = Sha1Context::parity(1000, 2001, 3002);
/// assert_eq!(parity2, 3971);
/// ```
#[inline]
pub fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Represents `F_40_59` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
/// use lib::Sha1Context;
///
/// let maj1 = Sha1Context::maj(1, 2, 3);
/// assert_eq!(maj1, 3);
///
/// let maj2 = Sha1Context::maj(1000, 2001, 3002);
/// assert_eq!(maj2, 1016);
/// ```
#[inline]
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

#[derive(Clone)]
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

impl Index<usize> for HashValue {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for HashValue {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

#[derive(Debug, Clone)]
struct DWords {
    data: [u32; SHA_LBLOCK as usize],
}

impl Default for DWords {
    fn default() -> Self {
        Self {
            data: [u32::MIN; SHA_LBLOCK as usize],
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
            3 => u32::from_be_bytes([c[0], c[1], c[2], 0].try_into().unwrap()),
            2 => ((c[0] as u32) << 24) | ((c[1] as u32) << 16),
            1 => (c[0] as u32) << 24,
            _ => panic!("this can't possibly happen"),
        }
    }

    fn include_bytes_on_incomplete_word(&mut self, word: usize, b: &[u8]) {
        self[word] = match b.len() {
            3 => self[word] | ((b[2] as u32) << 16) | ((b[1] as u32) << 8) | b[0] as u32,
            2 => self[word] | ((b[1] as u32) << 8) | b[0] as u32,
            1 => self[word] | (b[0] as u32),
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

        if remaining == 0 {
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

    #[inline]
    fn mix(&mut self, i: usize) {
        self[i] = (self[i+13] ^ self[i + 8] ^ self[i + 2] ^ self[i]).rotate_left(1);
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
    fn finish_arbitrary_length(&mut self, len: usize) {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        let pad_len: [u8; 8] = (len * 3).to_be_bytes();

        offset_pad[0] = 0x80;
        offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);

        self.write(&offset_pad[..zero_padding_length]);
    }

    fn zero_padding_length(&self) -> usize {
        1 + 8
            + (SHA_CBLOCK_LAST_INDEX as u64 & (55 - (self.size & SHA_CBLOCK_LAST_INDEX as u64)))
                as usize
    }

    #[inline]
    fn block_00_15(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, word: u32) {
        *e = e
            .wrapping_add(word)
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline]
    fn block_16_19(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline]
    fn block_20_39(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_20_39)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline]
    fn block_40_59(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_40_59)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(maj(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline]
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
        let [mut a, mut b, mut c, mut d, mut e] = self.hashes.clone().to_slice();

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

        self.hashes[0] = self.hashes[0].wrapping_add(a);
        self.hashes[1] = self.hashes[1].wrapping_add(b);
        self.hashes[2] = self.hashes[2].wrapping_add(c);
        self.hashes[3] = self.hashes[3].wrapping_add(d);
        self.hashes[4] = self.hashes[4].wrapping_add(e);
    }
}

impl Sha1Context {
    pub fn bytes_hash(&self) -> [u8; 20] {
        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self.hashes[i].to_be_bytes()
        });

        hash
    }

    pub fn hex_hash(&self) -> String {
        self.hashes
            .to_slice()
            .into_iter()
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

    pub fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w: u8 = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;
        let mut bytes_len = bytes.len();

        self.size += bytes_len as u64;

        if len_w != 0 {
            let mut left = (SHA_CBLOCK - len_w as u32) as u8;
            if bytes_len < left as usize {
                left = bytes_len as u8;
            }

            self.words
                .skippable_offset(&bytes[..(left as usize)], len_w);

            len_w = (len_w + left) & SHA_CBLOCK_LAST_INDEX as u8;
            bytes_len -= left as usize;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes_len >= SHA_CBLOCK as usize {
            self.words.from(&bytes[..(SHA_CBLOCK as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA_CBLOCK as usize)..];
            bytes_len -= 64;
        }

        if bytes_len != 0 {
            self.words.from(bytes)
        }
    }
}

#[cfg(test)]
mod use_cases {
    use crate::Sha1Context;

    #[test]
    fn test_commonly_known_sha1_phrases() {
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
}

#[cfg(test)]
mod hypothesis_and_coverage_assurance {
    use core::ops::{BitOr, Shl, Shr};
    use std::arch::x86_64::_mm_sha1msg1_epu32;

    use crate::{DWords, Sha1Context};

    #[test]
    fn fips180_rotate_right_and_left_are_consistent_with_core_rotate_methods() {
        let x: u32 = 5;
        let y: u32 = 2;

        let std_rotate_left = x.rotate_left(y);
        let cus_rotate_left = rotate_left(x, y);
        let std_rotate_right = x.rotate_right(y);
        let cus_rotate_right = rotate_right(x, y);

        assert_eq!(std_rotate_left, cus_rotate_left);
        assert_eq!(std_rotate_right, cus_rotate_right);
    }

    #[test]
    fn compare_fips180_hex_character_big_endianness() {
        let big_endian_zero = 0x0u8;
        let four_bit_str_be_zero = "0000";

        let big_endian_one = 0x1u8;
        let four_bit_str_be_one = "0001";

        let big_endian_two = 0x2u8;
        let four_bit_str_be_two = "0010";

        let big_endian_three = 0x3u8;
        let four_bit_str_be_three = "0011";

        let big_endian_four = 0x4u8;
        let four_bit_str_be_four = "0100";

        let big_endian_five = 0x5u8;
        let four_bit_str_be_five = "0101";

        let big_endian_six = 0x6u8;
        let four_bit_str_be_six = "0110";

        let big_endian_seven = 0x7u8;
        let four_bit_str_be_seven = "0111";

        let big_endian_eight = 0x8u8;
        let four_bit_str_be_eight = "1000";

        let big_endian_nine = 0x9u8;
        let four_bit_str_be_nine = "1001";

        let big_endian_a = 0xau8;
        let four_bit_str_be_a = "1010";

        let big_endian_b = 0xbu8;
        let four_bit_str_be_b = "1011";

        let big_endian_c = 0xcu8;
        let four_bit_str_be_c = "1100";

        let big_endian_d = 0xdu8;
        let four_bit_str_be_d = "1101";

        let big_endian_e = 0xeu8;
        let four_bit_str_be_e = "1110";

        let big_endian_f = 0xfu8;
        let four_bit_str_be_f = "1111";

        assert_eq!(format!("{:04b}", big_endian_zero), *four_bit_str_be_zero);
        assert_eq!(format!("{:04b}", big_endian_one), *four_bit_str_be_one);
        assert_eq!(format!("{:04b}", big_endian_two), *four_bit_str_be_two);
        assert_eq!(format!("{:04b}", big_endian_three), *four_bit_str_be_three);
        assert_eq!(format!("{:04b}", big_endian_four), *four_bit_str_be_four);
        assert_eq!(format!("{:04b}", big_endian_five), *four_bit_str_be_five);
        assert_eq!(format!("{:04b}", big_endian_six), *four_bit_str_be_six);
        assert_eq!(format!("{:04b}", big_endian_seven), *four_bit_str_be_seven);
        assert_eq!(format!("{:04b}", big_endian_eight), *four_bit_str_be_eight);
        assert_eq!(format!("{:04b}", big_endian_nine), *four_bit_str_be_nine);
        assert_eq!(format!("{:04b}", big_endian_a), *four_bit_str_be_a);
        assert_eq!(format!("{:04b}", big_endian_b), *four_bit_str_be_b);
        assert_eq!(format!("{:04b}", big_endian_c), *four_bit_str_be_c);
        assert_eq!(format!("{:04b}", big_endian_d), *four_bit_str_be_d);
        assert_eq!(format!("{:04b}", big_endian_e), *four_bit_str_be_e);
        assert_eq!(format!("{:04b}", big_endian_f), *four_bit_str_be_f);
    }

    #[test]
    fn assert_value_to_append_one_at_message_end() {
        let one_to_append: u8 = 0x80;
        let u4_half = "1000";
        let u4_zero = "0000";
        let mut u8_one_to_append = u4_half.to_string();
        u8_one_to_append.push_str(u4_zero);

        assert_eq!(format!("{:08b}", one_to_append), u8_one_to_append);
    }

    #[test]
    fn first_w_bit_word_in_fips180_documentation_conversion_test() {
        let w32_hex_str: u32 = 0xa103fe23;
        let four_w32_bit_str = [
            "1010", "0001", "0000", "0011", "1111", "1110", "0010", "0011",
        ];
        let w64_hex_str: u64 = 0xa103fe2332ef301a;
        let four_w64_bit_str = [
            "1010", "0001", "0000", "0011", "1111", "1110", "0010", "0011", "0011", "0010", "1110",
            "1111", "0011", "0000", "0001", "1010",
        ];

        let w32_ones_count = w32_hex_str.count_ones();
        let w32_zeros_count = w32_hex_str.count_zeros();
        let w32_bits_count = w32_ones_count + w32_zeros_count;
        let w32_binary_representation = binary_representation(&w32_hex_str.to_be_bytes());

        let w64_ones_count = w64_hex_str.count_ones();
        let w64_zeros_count = w64_hex_str.count_zeros();
        let w64_bits_count = w64_ones_count + w64_zeros_count;
        let w64_binary_representation = binary_representation(&w64_hex_str.to_be_bytes());

        assert_eq!(w32_ones_count, 15);
        assert_eq!(w32_zeros_count, 17);
        assert_eq!(w32_bits_count, u32::BITS);
        assert_eq!(w32_binary_representation, four_w32_bit_str);

        assert_eq!(w64_ones_count, w32_ones_count * 2);
        assert_eq!(w64_zeros_count, w32_zeros_count * 2);
        assert_eq!(w64_bits_count, u64::BITS);
        assert_eq!(w64_binary_representation, four_w64_bit_str);
    }

    #[test]
    fn convert_big_endian_bytes_to_u32() {
        const FIRST_U8: u8 = 0x12;
        const SECOND_U8: u8 = 0x58;
        const THIRD_U8: u8 = 0xfd;
        const FOURTH_U8: u8 = 0xd7;

        let one_byte_stream_vec: &[u8] = &[FIRST_U8];
        let two_byte_stream_vec: &[u8] = &[FIRST_U8, SECOND_U8];
        let three_byte_stream_vec: &[u8] = &[FIRST_U8, SECOND_U8, THIRD_U8];
        let complete_u32_vec: &[u8] = &[FIRST_U8, SECOND_U8, THIRD_U8, FOURTH_U8];

        let manually_computed_single_u8_to_u32 = be_byte_to_u32(one_byte_stream_vec);
        let manually_computed_single_u8_to_u32_hex_str =
            format!("{:x}", manually_computed_single_u8_to_u32);

        let manually_computed_two_u8_to_u32 = two_be_bytes_to_u32(two_byte_stream_vec);
        let manually_computed_two_u8_to_u32_hex_str =
            format!("{:x}", manually_computed_two_u8_to_u32);

        let manually_computed_three_u8_to_u32 = three_be_bytes_to_u32(three_byte_stream_vec);
        let manually_computed_three_u8_to_u32_hex_str =
            format!("{:x}", manually_computed_three_u8_to_u32);

        let manually_computed_complete_u32 = four_be_bytes_to_u32(complete_u32_vec);
        let manually_computed_complete_u32_hex_str =
            format!("{:x}", manually_computed_complete_u32);

        let zeroes_bytes: &[u8] = &[0; 3];
        let one_byte_u32_binding = [zeroes_bytes, one_byte_stream_vec].concat();
        let two_byte_u32_binding = [&zeroes_bytes[..2], two_byte_stream_vec].concat();
        let three_byte_u32_binding = [&zeroes_bytes[..1], three_byte_stream_vec].concat();

        let std_computed_single_u8_to_u32 =
            u32::from_be_bytes(one_byte_u32_binding.try_into().unwrap());
        let std_computed_single_u8_to_u32_hex_str = format!("{:x}", std_computed_single_u8_to_u32);
        let std_computed_two_u8_to_u32 =
            u32::from_be_bytes(two_byte_u32_binding.try_into().unwrap());
        let std_computed_two_u8_to_u32_hex_str = format!("{:x}", std_computed_two_u8_to_u32);
        let std_computed_three_u8_to_u32 =
            u32::from_be_bytes(three_byte_u32_binding.try_into().unwrap());
        let std_computed_three_u8_to_u32_hex_str = format!("{:x}", std_computed_three_u8_to_u32);
        let std_computed_complete_u8_pack_to_u32 =
            u32::from_be_bytes(complete_u32_vec.try_into().unwrap());
        let std_computed_complete_u8_to_u32_hex_str =
            format!("{:x}", std_computed_complete_u8_pack_to_u32);

        assert_eq!(
            std_computed_single_u8_to_u32,
            manually_computed_single_u8_to_u32
        );
        assert_eq!(
            std_computed_single_u8_to_u32_hex_str,
            manually_computed_single_u8_to_u32_hex_str
        );
        assert_eq!(std_computed_two_u8_to_u32, manually_computed_two_u8_to_u32);
        assert_eq!(
            std_computed_two_u8_to_u32_hex_str,
            manually_computed_two_u8_to_u32_hex_str
        );
        assert_eq!(
            std_computed_three_u8_to_u32,
            manually_computed_three_u8_to_u32
        );
        assert_eq!(
            std_computed_three_u8_to_u32_hex_str,
            manually_computed_three_u8_to_u32_hex_str
        );
        assert_eq!(
            std_computed_complete_u8_pack_to_u32,
            manually_computed_complete_u32
        );
        assert_eq!(
            std_computed_complete_u8_to_u32_hex_str,
            manually_computed_complete_u32_hex_str
        );
    }

    #[test]
    fn bit_shift_method_vs_explicit_operation() {
        let unsigned_integer: u32 = 1684234849;

        assert_eq!(unsigned_integer >> 24, unsigned_integer.shr(24));
        assert_eq!(unsigned_integer >> 16, unsigned_integer.shr(16));
        assert_eq!(unsigned_integer >> 8, unsigned_integer.shr(8));
        assert_eq!(unsigned_integer >> 0, unsigned_integer.shr(0));

        assert_eq!(unsigned_integer << 24, unsigned_integer.shl(24));
        assert_eq!(unsigned_integer << 16, unsigned_integer.shl(16));
        assert_eq!(unsigned_integer << 8, unsigned_integer.shl(8));
        assert_eq!(unsigned_integer << 0, unsigned_integer.shl(0));

        let max_u32_unsigned_integer: u32 = u32::MAX;
        assert_eq!(
            max_u32_unsigned_integer.shr(8),
            16_777_215u32,
            "Assert equality for u24::MAX"
        );
        assert_eq!(
            max_u32_unsigned_integer.shr(16),
            65_535u32,
            "Assert equality for u16::MAX"
        );
        assert_eq!(
            max_u32_unsigned_integer.shr(24),
            255_u32,
            "Assert equality for u8::MAX"
        );

        // Assert cast has logic for pointing the least significant bits, by the amount of the new
        // type size. It seems to make use of Copy, because it looses original information in case a
        // cast backwards to original size is immediately made
        assert_eq!(
            max_u32_unsigned_integer as u8,
            (max_u32_unsigned_integer.shl(24) as u32).shr(24) as u8
        );
        assert_eq!(max_u32_unsigned_integer as u8, u8::MAX);
        assert_eq!(max_u32_unsigned_integer.shr(0), u32::MAX);
        assert_eq!((max_u32_unsigned_integer as u8) as u32, u8::MAX as u32);
    }

    #[test]
    fn associative_wrapping_add_property() {
        let u8_max = u8::MAX;
        let half_u8_max = u8::MAX / 2;

        assert_eq!(half_u8_max.wrapping_add(u8_max), half_u8_max - 1);
        assert_eq!(u8_max.wrapping_add(half_u8_max), half_u8_max - 1);

        assert_eq!(
            u8_max.wrapping_add(u8_max).wrapping_add(half_u8_max),
            half_u8_max - 2
        );
        assert_eq!(
            u8_max.wrapping_add(half_u8_max.wrapping_add(u8_max)),
            half_u8_max - 2
        );
        assert_eq!(
            u8_max.wrapping_add(half_u8_max).wrapping_add(u8_max),
            half_u8_max - 2
        );
        assert_eq!(
            u8_max.wrapping_add(u8_max.wrapping_add(half_u8_max)),
            half_u8_max - 2
        );
    }

    #[test]
    fn bytes_padding_into_32bit_words() {
        let first_alphabet_letters: [char; 4] = ['a', 'b', 'c', 'd']; // [0x61, 0x62, 0x63, 0x64]
        let bytes_64_chunk: [u8; 64] = [
            first_alphabet_letters
                .iter()
                .map(|&c| c as u8)
                .collect::<Vec<u8>>(),
            [0; 60].to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap();

        let mut d_words = DWords::default();
        d_words.from(&bytes_64_chunk);

        assert_eq!(
            d_words,
            [0x61626364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    fn rotate<R>(x: R, l: R, r: R) -> R
    where
        R: Shl<Output = R> + Shr<Output = R> + BitOr<Output = R> + Copy + Sized,
    {
        (x << l) | (x >> r)
    }

    fn rotate_left(x: u32, n: u32) -> u32 {
        rotate(x, n, u32::BITS - n)
    }

    fn rotate_right(x: u32, n: u32) -> u32 {
        rotate(x, u32::BITS - n, n)
    }

    fn binary_representation(x: &[u8]) -> Vec<String> {
        let mut result = Vec::with_capacity(x.len() * 2);
        x.iter().for_each(|b| {
            let byte_bits = format!("{:08b}", *b);
            result.push(byte_bits[..4].to_string());
            result.push(byte_bits[4..].to_string());
        });

        result
    }

    // TODO: Later bench if inlining improves performance
    fn be_byte_to_u32(src: &[u8]) -> u32 {
        src[0] as u32
    }

    // TODO: Later bench if inlining improves performance
    fn two_be_bytes_to_u32(src: &[u8]) -> u32 {
        (be_byte_to_u32(src) << 8) | (src[1] as u32)
    }

    // TODO: Later bench if inlining improves performance
    fn three_be_bytes_to_u32(src: &[u8]) -> u32 {
        (two_be_bytes_to_u32(src) << 8) | (src[2] as u32)
    }

    // TODO: Later bench if inlining improves performance
    fn four_be_bytes_to_u32(src: &[u8]) -> u32 {
        (three_be_bytes_to_u32(src) << 8) | (src[3] as u32)
    }
}

// #[cfg(test)]
// mod competitors_tests {
//     use sha1::{Digest, Sha1};
//
//     #[test]
//     fn test() {
//         let mut sha1 = Sha1::new();
//         let abc = b"abc";
//         sha1.update(abc);
//
//         let digest_result = &sha1.finalize()[..]
//             .iter()
//             .map(|&b| format!("{:02x}", b))
//             .collect::<String>();
//         assert_eq!(digest_result, "a9993e364706816aba3e25717850c26c9cd0d89d");
//     }
// }
