use core::{
    mem::size_of,
    ops::{BitOr, Index, IndexMut, RangeFrom, RangeTo, Shl, Shr},
};

const U16_BYTES: usize = size_of::<u16>();
const U32_BYTES: usize = size_of::<u32>();

const ZEROS: [u8; 3] = [0; 3];
const SHA_LBLOCK: u32 = 16;
const SHA_CBLOCK: u32 = SHA_LBLOCK * U32_BYTES as u32;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA_CBLOCK - 1;
const SHA_LAST_BLOCK: u32 = SHA_CBLOCK - 8;

const SHA_1H0: u32 = 0x67452301;
const SHA_1H1: u32 = 0xefcdab89;
const SHA_1H2: u32 = 0x98badcfe;
const SHA_1H3: u32 = 0x10325476;
const SHA_1H4: u32 = 0xc3d2e1f0;

const T_0_15: u32 = 0x5a827999;
const T_16_19: u32 = T_0_15;
const T_20_39: u32 = 0x6ed9eba1;
const T_40_59: u32 = 0x8f1bbcdc;
const T_60_79: u32 = 0xca62c1d6;

#[derive(Clone)]
struct HashValue(u32, u32, u32, u32, u32);

impl Default for HashValue {
    fn default() -> Self {
        Self(SHA_1H0, SHA_1H1, SHA_1H2, SHA_1H3, SHA_1H4)
    }
}

impl Index<usize> for HashValue {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => &self.0,
            1 => &self.1,
            2 => &self.2,
            3 => &self.3,
            4 => &self.4,
            _ => panic!("Index out of bounds"),
        }
    }
}

#[derive(Debug, Clone)]
struct DWords(
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
);

impl Default for DWords {
    fn default() -> Self {
        Self(
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
            u32::MIN,
        )
    }
}

impl Index<usize> for DWords {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        match index & 15 {
            0 => &self.0,
            1 => &self.1,
            2 => &self.2,
            3 => &self.3,
            4 => &self.4,
            5 => &self.5,
            6 => &self.6,
            7 => &self.7,
            8 => &self.8,
            9 => &self.9,
            10 => &self.10,
            11 => &self.11,
            12 => &self.12,
            13 => &self.13,
            14 => &self.14,
            15 => &self.15,
            _ => panic!("This cannot possibly happen"),
        }
    }
}

impl IndexMut<usize> for DWords {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index & 15 {
            0 => &mut self.0,
            1 => &mut self.1,
            2 => &mut self.2,
            3 => &mut self.3,
            4 => &mut self.4,
            5 => &mut self.5,
            6 => &mut self.6,
            7 => &mut self.7,
            8 => &mut self.8,
            9 => &mut self.9,
            10 => &mut self.10,
            11 => &mut self.11,
            12 => &mut self.12,
            13 => &mut self.13,
            14 => &mut self.14,
            15 => &mut self.15,
            _ => panic!("This cannot possibly happen"),
        }
    }
}

impl PartialEq<DWords> for DWords {
    fn eq(&self, other: &DWords) -> bool {
        self.0 == other.0
            && self.1 == other.1
            && self.2 == other.2
            && self.3 == other.3
            && self.4 == other.4
            && self.5 == other.5
            && self.6 == other.6
            && self.7 == other.7
            && self.8 == other.8
            && self.9 == other.9
            && self.10 == other.10
            && self.11 == other.11
            && self.12 == other.12
            && self.13 == other.13
            && self.14 == other.14
            && self.15 == other.15
    }
}

impl DWords {
    fn from_be_bytes(to: u8, chunk: &[u8]) -> u32 {
        u32::from_be_bytes(
            [chunk, &ZEROS[..to as usize]]
                .concat()
                .try_into()
                .unwrap(),
        )
    }

    fn to_u32_be(chunk: &[u8]) -> u32 {
        match chunk.len() {
            4 => Self::from_be_bytes(0, chunk),
            3 => Self::from_be_bytes(1, chunk),
            2 => Self::from_be_bytes(2, chunk),
            1 => Self::from_be_bytes(3, chunk),
            _ => panic!("this can't possibly happen"),
        }
    }

    fn include_bytes_on_incomplete_word(&mut self, completed_words: usize, skipped_bytes: &[u8]) {
        match skipped_bytes.len() {
            3 => {
                self[completed_words] = self[completed_words]
                    | ((skipped_bytes[0] as u32) << 16)
                    | ((skipped_bytes[1] as u32) << 8)
                    | skipped_bytes[2] as u32
            }
            2 => {
                self[completed_words] = self[completed_words]
                    | ((skipped_bytes[0] as u32) << 8)
                    | skipped_bytes[1] as u32
            }
            1 => self[completed_words] = self[completed_words] | skipped_bytes[0] as u32,
            _ => panic!("This cannot possibly happen"),
        }
    }

    fn from(&mut self, be_bytes: &[u8]) {
        be_bytes
            .chunks(U32_BYTES)
            .map(Self::to_u32_be)
            .enumerate()
            .for_each(|(i, word)| self[i] = word);
    }

    fn from_skippable_offset(&mut self, mut be_bytes: &[u8], skip: u8) {
        let remaining = skip % U32_BYTES as u8;
        let completed_words = ((skip / U32_BYTES as u8) & 15) as usize;

        if remaining == 0 {
            be_bytes
                .chunks(U32_BYTES)
                .map(Self::to_u32_be)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words] = word);
        } else {
            let bytes_to_skip = U32_BYTES - remaining as usize;
            let skipped_bytes = &be_bytes[..bytes_to_skip];

            self.include_bytes_on_incomplete_word(completed_words, skipped_bytes);

            be_bytes = &be_bytes[bytes_to_skip..];

            be_bytes
                .chunks(U32_BYTES)
                .map(Self::to_u32_be)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words + 1] = word);
        }
    }
}

pub struct Sha1Context {
    size: u64,
    h: HashValue,
    w: DWords,
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            h: HashValue::default(),
            w: DWords::default(),
        }
    }
}

impl Sha1Context {
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
    /// use lib::ch;
    ///
    /// let ch1 = ch(1, 2, 3);
    /// assert_eq!(ch1, 2);
    ///
    /// let ch2 = ch(1000, 2001, 3002);
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
    /// use lib::parity;
    ///
    /// let parity1 = parity(1, 2, 3);
    /// assert_eq!(parity1, 0);
    ///
    /// let parity2 = parity(1000, 2001, 3002);
    /// assert_eq!(parity2, 3971);
    /// ```
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
    /// use lib::maj;
    ///
    /// let maj1 = maj(1, 2, 3);
    /// assert_eq!(maj1, 3);
    ///
    /// let maj2 = maj(1000, 2001, 3002);
    /// assert_eq!(maj2, 1016);
    /// ```
    pub fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((x | y) & z)
    }

    fn mix(i: usize, a: &mut u32, array: &mut DWords) -> u32 {
        let x = array[i];
        let y = array[i];
        let z = array[i];
        let t = array[i];

        *a = (x ^ y ^ z ^ t).rotate_left(1);
        array[i] = *a;
        array[i]
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA_CBLOCK_LAST_INDEX as u64 & (55 - (self.size & SHA_CBLOCK_LAST_INDEX as u64)))
            as usize
    }

    fn hex_hash(byte_hash: &[u8]) -> String {
        byte_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn block_00_15(a: u32, b: &mut u32, c: u32, d: u32, e: u32, f: &mut u32, xi: u32) {
        *f = xi
            .wrapping_add(e)
            .wrapping_add(T_0_15)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn block_16_19(
        i: u8,
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: u32,
        f: &mut u32,
        array: &mut DWords,
    ) {
        Self::mix(i as usize, f, array);
        *f = (*f)
            .wrapping_add(e)
            .wrapping_add(T_16_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn block_20_39(
        i: u8,
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: u32,
        f: &mut u32,
        array: &mut DWords,
    ) {
        Self::mix(i as usize, f, array);
        *f = (*f)
            .wrapping_add(e)
            .wrapping_add(T_20_39)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn block_40_59(
        i: u8,
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: u32,
        f: &mut u32,
        array: &mut DWords,
    ) {
        Self::mix(i as usize, f, array);
        *f = (*f)
            .wrapping_add(e)
            .wrapping_add(T_40_59)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::maj(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn block_60_79(
        i: u8,
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: u32,
        f: &mut u32,
        array: &mut DWords,
    ) {
        *f = array[i as usize]
            .wrapping_add(e)
            .wrapping_add(T_60_79)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn hash_block(&mut self) {
        let HashValue(mut a, mut b, mut c, mut d, mut e) = self.h.clone();

        let mut aux: u32 = 0;

        let mut d_words = self.w.clone();

        Self::block_00_15(a, &mut b, c, d, e, &mut aux, d_words[0]);
        Self::block_00_15(aux, &mut a, b, c, d, &mut e, d_words[1]);
        Self::block_00_15(e, &mut aux, a, b, c, &mut d, d_words[2]);
        Self::block_00_15(d, &mut e, aux, a, b, &mut c, d_words[3]);
        Self::block_00_15(c, &mut d, e, aux, a, &mut b, d_words[4]);
        Self::block_00_15(b, &mut c, d, e, aux, &mut a, d_words[5]);
        Self::block_00_15(a, &mut b, c, d, e, &mut aux, d_words[6]);
        Self::block_00_15(aux, &mut a, b, c, d, &mut e, d_words[7]);
        Self::block_00_15(e, &mut aux, a, b, c, &mut d, d_words[8]);
        Self::block_00_15(d, &mut e, aux, a, b, &mut c, d_words[9]);
        Self::block_00_15(c, &mut d, e, aux, a, &mut b, d_words[10]);
        Self::block_00_15(b, &mut c, d, e, aux, &mut a, d_words[11]);
        Self::block_00_15(a, &mut b, c, d, e, &mut aux, d_words[12]);
        Self::block_00_15(aux, &mut a, b, c, d, &mut e, d_words[13]);
        Self::block_00_15(e, &mut aux, a, b, c, &mut d, d_words[14]);
        Self::block_00_15(d, &mut e, aux, a, b, &mut c, d_words[15]);

        Self::block_16_19(16, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_16_19(17, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_16_19(18, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_16_19(19, aux, &mut a, b, c, d, &mut e, &mut d_words);

        Self::block_20_39(20, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_20_39(21, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_20_39(22, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_20_39(23, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_20_39(24, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_20_39(25, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_20_39(26, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_20_39(27, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_20_39(28, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_20_39(29, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_20_39(30, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_20_39(31, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_20_39(32, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_20_39(33, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_20_39(34, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_20_39(35, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_20_39(36, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_20_39(37, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_20_39(38, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_20_39(39, d, &mut e, aux, a, b, &mut c, &mut d_words);

        Self::block_40_59(40, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_40_59(41, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_40_59(42, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_40_59(43, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_40_59(44, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_40_59(45, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_40_59(46, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_40_59(47, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_40_59(48, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_40_59(49, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_40_59(50, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_40_59(51, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_40_59(52, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_40_59(53, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_40_59(54, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_40_59(55, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_40_59(56, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_40_59(57, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_40_59(58, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_40_59(59, b, &mut c, d, e, aux, &mut a, &mut d_words);

        Self::block_60_79(60, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_60_79(61, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_60_79(62, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_60_79(63, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_60_79(64, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_60_79(65, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_60_79(66, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_60_79(67, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_60_79(68, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_60_79(69, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_60_79(70, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_60_79(71, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_60_79(72, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_60_79(73, aux, &mut a, b, c, d, &mut e, &mut d_words);
        Self::block_60_79(74, e, &mut aux, a, b, c, &mut d, &mut d_words);
        Self::block_60_79(75, d, &mut e, aux, a, b, &mut c, &mut d_words);
        Self::block_60_79(76, c, &mut d, e, aux, a, &mut b, &mut d_words);
        Self::block_60_79(77, b, &mut c, d, e, aux, &mut a, &mut d_words);
        Self::block_60_79(78, a, &mut b, c, d, e, &mut aux, &mut d_words);
        Self::block_60_79(79, aux, &mut a, b, c, d, &mut e, &mut d_words);

        self.h.0 = (self.h.0.wrapping_add(e)) & 0xffffffffu32;
        self.h.1 = (self.h.1.wrapping_add(aux)) & 0xffffffffu32;
        self.h.2 = (self.h.2.wrapping_add(a)) & 0xffffffffu32;
        self.h.3 = (self.h.3.wrapping_add(b)) & 0xffffffffu32;
        self.h.4 = (self.h.4.wrapping_add(c)) & 0xffffffffu32;
    }
}

impl Sha1Context {
    fn finish(&mut self) -> [u8; 20] {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_CBLOCK as usize] = [0u8; SHA_CBLOCK as usize];
        let pad_len: [u8; 8] = self.size.to_be_bytes();
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&pad_len);

        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self.h[i].to_be_bytes()
        });

        hash
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut lenW: u8 = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;
        let mut bytes_len = bytes.len();

        self.size += bytes_len as u64;

        if lenW != 0 {
            let mut left = (SHA_CBLOCK - lenW as u32) as u8;
            if bytes_len < left as usize {
                left = bytes_len as u8;
            }

            self.w.from_skippable_offset(&bytes[..(left as usize)], lenW);

            lenW = (lenW + left) & SHA_CBLOCK_LAST_INDEX as u8;
            bytes_len -= left as usize;
            bytes = &bytes[(left as usize)..];

            if lenW != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes_len >= SHA_CBLOCK as usize {
            self.w.from(&bytes[..(SHA_CBLOCK as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA_CBLOCK as usize)..];
            bytes_len -= 64;
        }

        if bytes_len != 0 {
            self.w.from(bytes)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{DWords, Sha1Context};
    use core::{
        cmp::max,
        fmt::Binary,
        mem::size_of,
        ops::{BitOr, Shl, Shr},
    };

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
        let big_endian_zero = 0x0u8.to_be();
        let four_bit_str_be_zero = "0000";

        let big_endian_one = 0x1u8.to_be();
        let four_bit_str_be_one = "0001";

        let big_endian_two = 0x2u8.to_be();
        let four_bit_str_be_two = "0010";

        let big_endian_three = 0x3u8.to_be();
        let four_bit_str_be_three = "0011";

        let big_endian_four = 0x4u8.to_be();
        let four_bit_str_be_four = "0100";

        let big_endian_five = 0x5u8.to_be();
        let four_bit_str_be_five = "0101";

        let big_endian_six = 0x6u8.to_be();
        let four_bit_str_be_six = "0110";

        let big_endian_seven = 0x7u8.to_be();
        let four_bit_str_be_seven = "0111";

        let big_endian_eight = 0x8u8.to_be();
        let four_bit_str_be_eight = "1000";

        let big_endian_nine = 0x9u8.to_be();
        let four_bit_str_be_nine = "1001";

        let big_endian_a = 0xau8.to_be();
        let four_bit_str_be_a = "1010";

        let big_endian_b = 0xbu8.to_be();
        let four_bit_str_be_b = "1011";

        let big_endian_c = 0xcu8.to_be();
        let four_bit_str_be_c = "1100";

        let big_endian_d = 0xdu8.to_be();
        let four_bit_str_be_d = "1101";

        let big_endian_e = 0xeu8.to_be();
        let four_bit_str_be_e = "1110";

        let big_endian_f = 0xfu8.to_be();
        let four_bit_str_be_f = "1111";

        assert_eq!(format!("{:04b}", big_endian_zero), *four_bit_str_be_zero);
        assert_eq!(format!("{:04b}", big_endian_one), *four_bit_str_be_one);
        assert_eq!(format!("{:04b}", big_endian_two), *four_bit_str_be_two);
        assert_eq!(format!("{:04b}", big_endian_three), *four_bit_str_be_three);
        assert_eq!(format!("{:04b}", big_endian_four), *four_bit_str_be_four);
        assert_eq!(format!("{:04b}", big_endian_five), *four_bit_str_be_five);
        assert_eq!(format!("{:04b}", big_endian_two), *four_bit_str_be_two);
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
        let size_of_u32 = size_of::<u32>();
        let one_byte_u32_binding = [zeroes_bytes, one_byte_stream_vec].concat();
        let two_byte_u32_binding = [&zeroes_bytes[..=1], two_byte_stream_vec].concat();
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
    fn test_commonly_known_sha1_phrases() {
        let quick_fox: &str = "The quick brown fox jumps over the lazy dog";

        let quick_fox_bytes: &[u8] = quick_fox.as_ref();
        let mut quick_fox_sha1_ctx = Sha1Context::default();
        quick_fox_sha1_ctx.write(quick_fox.as_ref());
        let digest_result = Sha1Context::hex_hash(&quick_fox_sha1_ctx.finish());

        assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

        let cavs_message: &str = "7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe585db6a78ce40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d9979016204bfd921322fdd5222183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b7398364f652fafc734329aafa3dcd45d4f31e388e4fafd7fc6495f37ca5cbab7f54d586463da4bfeaa3bae09f7b8e9239d832b4f0a733aa609cc1f8d4";

        let mut cavs_message_sha1_ctx = Sha1Context::default();
        cavs_message_sha1_ctx.write(cavs_message.as_ref());
        let digest_result = Sha1Context::hex_hash(&cavs_message_sha1_ctx.finish());

        assert_eq!(digest_result, "d8fd6a91ef3b6ced05b98358a99107c1fac8c807");
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
            DWords(0x61626364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
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
