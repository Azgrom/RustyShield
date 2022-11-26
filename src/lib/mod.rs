extern crate core;

use core::{
    mem::size_of,
    ops::{BitOr, RangeFrom, RangeTo, Shl, Shr},
};

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
const U8_TO_U32: [u8; 4] = [0, 8, 16, 24];

struct ExtMethods;

trait EncapsulateExtensions<T> {
    fn modulus_16_element(index: T) -> usize;
    fn range_from(index: T) -> RangeFrom<usize>;
    fn range_to(index: T) -> RangeTo<usize>;
}

impl EncapsulateExtensions<u8> for ExtMethods {
    fn modulus_16_element(index: u8) -> usize {
        (index as usize) & 15
    }

    fn range_from(index: u8) -> RangeFrom<usize> {
        (index as usize)..
    }

    fn range_to(index: u8) -> RangeTo<usize> {
        ..(index as usize)
    }
}

impl EncapsulateExtensions<u64> for ExtMethods {
    fn modulus_16_element(index: u64) -> usize {
        (index as usize) & 15
    }

    fn range_from(index: u64) -> RangeFrom<usize> {
        (index as usize)..
    }

    fn range_to(index: u64) -> RangeTo<usize> {
        ..(index as usize)
    }
}

impl EncapsulateExtensions<usize> for ExtMethods {
    fn modulus_16_element(index: usize) -> usize {
        index & 15
    }

    fn range_from(index: usize) -> RangeFrom<usize> {
        index..
    }

    fn range_to(index: usize) -> RangeTo<usize> {
        ..index
    }
}

pub trait Sha1 {
    fn init() -> Self;
    fn update(&mut self, data_in: &[u8], len: u64);
    fn finalize(&mut self) -> [u8; 20];
}

trait MemoryCopy<D, S> {
    /// Copies n bytes from src to memory dest, using a reference receiving point in dest
    fn mem_cpy(dest: &mut [D], src: &[S]);
}

pub struct Sha1Context {
    size: u64,
    h: [u32; 5],
    w: [u32; 16],
}

impl MemoryCopy<u8, u8> for Sha1Context {
    fn mem_cpy(dest: &mut [u8], src: &[u8]) {
        dest[..src.len()].clone_from_slice(&src)
    }
}

impl MemoryCopy<u32, u8> for Sha1Context {
    fn mem_cpy(dest: &mut [u32], src: &[u8]) {
        let u32_src = src
            .chunks(4)
            .map(|c| match c.len() {
                4 => u32::from_be_bytes(c.try_into().unwrap()),
                3 => u32::from_be_bytes([&[0], c].concat().try_into().unwrap()),
                2 => u32::from_be_bytes([&[0, 0], c].concat().try_into().unwrap()),
                1 => u32::from_be_bytes([&[0, 0, 0], c].concat().try_into().unwrap()),
                _ => panic!("Chunks are modulo 4"),
            })
            .collect::<Vec<u32>>();

        let to = ExtMethods::range_to(u32_src.len());
        dest[to].clone_from_slice(&u32_src);
    }
}

impl MemoryCopy<u32, u32> for Sha1Context {
    fn mem_cpy(dest: &mut [u32], src: &[u32]) {
        dest[..src.len()].clone_from_slice(&src)
    }
}

impl Sha1Context {
    fn form_d_words_from_data_stream(&mut self, data_stream: &[u8], len_w: &mut u64, left: u64) {
        let dest_from = ExtMethods::range_from(ExtMethods::modulus_16_element(*len_w));
        Self::mem_cpy(&mut self.w[dest_from], data_stream);

        *len_w = (*len_w + left) & 63;
    }

    fn set_w(i: u8, val: u32, array: &mut [u32]) {
        array[ExtMethods::modulus_16_element(i)] = val;
    }

    fn src(vec: &[u8], i: usize) -> u32 {
        let stepped_size = (i * 4) & (vec.len() - 1);
        let offset = vec.len() - stepped_size;
        let vec_slice = &vec[stepped_size..];

        match offset {
            n if n > 3 => {
                let (u8_bytes, _) = vec_slice.split_at(size_of::<u32>());
                u32::from_be_bytes(u8_bytes.try_into().unwrap())
            }
            3 => u32::from_be_bytes([&[0], vec_slice].concat().try_into().unwrap()),
            2 => u32::from_be_bytes([&[0, 0], vec_slice].concat().try_into().unwrap()),
            1 => u32::from_be_bytes([&[0, 0, 0], vec_slice].concat().try_into().unwrap()),
            _ => panic!("This cannot possibly happen"),
        }
    }

    fn mix(i: u8, array: &[u32]) -> u32 {
        let x_i = ExtMethods::modulus_16_element(i + 13);
        let y_i = ExtMethods::modulus_16_element(i + 8);
        let z_i = ExtMethods::modulus_16_element(i + 2);
        let t_i = ExtMethods::modulus_16_element(i);

        let x = array[x_i];
        let y = array[y_i];
        let z = array[z_i];
        let t = array[t_i];

        (x ^ y ^ z ^ t).rotate_left(1)
    }

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x ^ z)
    }

    fn parity(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn to_byte_slice(&self) -> [u8; 20] {
        // Use flatten once it stabilizes
        let mut hash_out: [u8; 20] = [0; 20];
        self.h
            .iter()
            .zip((0..5).into_iter())
            .for_each(|(constant, k_index)| {
                let temp_mini_hash: [u8; 4] = constant.to_be_bytes();
                hash_out[0 + (k_index * 4)] = temp_mini_hash[0];
                hash_out[1 + (k_index * 4)] = temp_mini_hash[1];
                hash_out[2 + (k_index * 4)] = temp_mini_hash[2];
                hash_out[3 + (k_index * 4)] = temp_mini_hash[3];
            });

        hash_out
    }

    fn hex_hash(byte_hash: &[u8]) -> String {
        byte_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn t_0_15(
        t: u8,
        block: &[u8],
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: &mut u32,
        array: &mut [u32],
    ) {
        let temp = Self::src(block, t as usize);
        Self::set_w(t, temp, array);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::ch(*b, c, d))
            .wrapping_add(T_0_15);
        *b = (*b).rotate_right(2);
    }

    fn t_0_15_u32(&self, temp: u32, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(Self::ch(*b, c, d))
            .wrapping_add(T_0_15);
        *b = (*b).rotate_right(2);
    }

    fn t_16_19(t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        let f_16_19 = Self::ch(*b, c, d);
        let temp = Self::mix(t, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_16_19)
            .wrapping_add(T_16_19);
        *b = (*b).rotate_right(2);
    }

    fn t_20_39(t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        let f_20_39 = Self::parity(*b, c, d);
        let temp = Self::mix(t, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_20_39)
            .wrapping_add(T_20_39);
        *b = (*b).rotate_right(2);
    }

    fn t_40_59(t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        let f_40_59 = Self::maj(*b, c, d);
        let temp = Self::mix(t, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_40_59)
            .wrapping_add(T_40_59);
        *b = (*b).rotate_right(2);
    }

    fn t_60_79(t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        let f_60_79 = Self::parity(*b, c, d);
        let temp = Self::mix(t, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_60_79)
            .wrapping_add(T_60_79);
        *b = (*b).rotate_right(2);
    }

    fn iterations_from_mixing_array(
        a: &mut u32,
        b: &mut u32,
        c: &mut u32,
        d: &mut u32,
        e: &mut u32,
        array: &mut [u32; 16],
    ) {
        /* Round 1 - tail. Input from 512-bit mixing array */
        Self::t_16_19(16, array, *e, a, *b, *c, d);
        Self::t_16_19(17, array, *d, e, *a, *b, c);
        Self::t_16_19(18, array, *c, d, *e, *a, b);
        Self::t_16_19(19, array, *b, c, *d, *e, a);

        /* Round 2 */
        Self::t_20_39(20, array, *a, b, *c, *d, e);
        Self::t_20_39(21, array, *e, a, *b, *c, d);
        Self::t_20_39(22, array, *d, e, *a, *b, c);
        Self::t_20_39(23, array, *c, d, *e, *a, b);
        Self::t_20_39(24, array, *b, c, *d, *e, a);
        Self::t_20_39(25, array, *a, b, *c, *d, e);
        Self::t_20_39(26, array, *e, a, *b, *c, d);
        Self::t_20_39(27, array, *d, e, *a, *b, c);
        Self::t_20_39(28, array, *c, d, *e, *a, b);
        Self::t_20_39(29, array, *b, c, *d, *e, a);
        Self::t_20_39(30, array, *a, b, *c, *d, e);
        Self::t_20_39(31, array, *e, a, *b, *c, d);
        Self::t_20_39(32, array, *d, e, *a, *b, c);
        Self::t_20_39(33, array, *c, d, *e, *a, b);
        Self::t_20_39(34, array, *b, c, *d, *e, a);
        Self::t_20_39(35, array, *a, b, *c, *d, e);
        Self::t_20_39(36, array, *e, a, *b, *c, d);
        Self::t_20_39(37, array, *d, e, *a, *b, c);
        Self::t_20_39(38, array, *c, d, *e, *a, b);
        Self::t_20_39(39, array, *b, c, *d, *e, a);

        /* Round 3 */
        Self::t_40_59(40, array, *a, b, *c, *d, e);
        Self::t_40_59(41, array, *e, a, *b, *c, d);
        Self::t_40_59(42, array, *d, e, *a, *b, c);
        Self::t_40_59(43, array, *c, d, *e, *a, b);
        Self::t_40_59(44, array, *b, c, *d, *e, a);
        Self::t_40_59(45, array, *a, b, *c, *d, e);
        Self::t_40_59(46, array, *e, a, *b, *c, d);
        Self::t_40_59(47, array, *d, e, *a, *b, c);
        Self::t_40_59(48, array, *c, d, *e, *a, b);
        Self::t_40_59(49, array, *b, c, *d, *e, a);
        Self::t_40_59(50, array, *a, b, *c, *d, e);
        Self::t_40_59(51, array, *e, a, *b, *c, d);
        Self::t_40_59(52, array, *d, e, *a, *b, c);
        Self::t_40_59(53, array, *c, d, *e, *a, b);
        Self::t_40_59(54, array, *b, c, *d, *e, a);
        Self::t_40_59(55, array, *a, b, *c, *d, e);
        Self::t_40_59(56, array, *e, a, *b, *c, d);
        Self::t_40_59(57, array, *d, e, *a, *b, c);
        Self::t_40_59(58, array, *c, d, *e, *a, b);
        Self::t_40_59(59, array, *b, c, *d, *e, a);

        /* Round 4 */
        Self::t_60_79(60, array, *a, b, *c, *d, e);
        Self::t_60_79(61, array, *e, a, *b, *c, d);
        Self::t_60_79(62, array, *d, e, *a, *b, c);
        Self::t_60_79(63, array, *c, d, *e, *a, b);
        Self::t_60_79(64, array, *b, c, *d, *e, a);
        Self::t_60_79(65, array, *a, b, *c, *d, e);
        Self::t_60_79(66, array, *e, a, *b, *c, d);
        Self::t_60_79(67, array, *d, e, *a, *b, c);
        Self::t_60_79(68, array, *c, d, *e, *a, b);
        Self::t_60_79(69, array, *b, c, *d, *e, a);
        Self::t_60_79(70, array, *a, b, *c, *d, e);
        Self::t_60_79(71, array, *e, a, *b, *c, d);
        Self::t_60_79(72, array, *d, e, *a, *b, c);
        Self::t_60_79(73, array, *c, d, *e, *a, b);
        Self::t_60_79(74, array, *b, c, *d, *e, a);
        Self::t_60_79(75, array, *a, b, *c, *d, e);
        Self::t_60_79(76, array, *e, a, *b, *c, d);
        Self::t_60_79(77, array, *d, e, *a, *b, c);
        Self::t_60_79(78, array, *c, d, *e, *a, b);
        Self::t_60_79(79, array, *b, c, *d, *e, a);
    }

    fn block(h: &mut [u32; 5], block: &[u8]) {
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        let mut array: [u32; 16] = [0; 16];

        /* Round 1 - iterations 0-16 take their input from 'block' */
        Self::t_0_15(0, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(1, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(2, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(3, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(4, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(5, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(6, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(7, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(8, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(9, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(10, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(11, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(12, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(13, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(14, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(15, block, a, &mut b, c, d, &mut e, &mut array);

        Self::iterations_from_mixing_array(&mut a, &mut b, &mut c, &mut d, &mut e, &mut array);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    fn block_32_bit_word(&mut self) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        let mut array: [u32; 16] = self.w;

        /* Round 1 - iterations 0-16 take their input from 'block' */
        self.t_0_15_u32(array[0], a, &mut b, c, d, &mut e);
        self.t_0_15_u32(array[1], e, &mut a, b, c, &mut d);
        self.t_0_15_u32(array[2], d, &mut e, a, b, &mut c);
        self.t_0_15_u32(array[3], c, &mut d, e, a, &mut b);
        self.t_0_15_u32(array[4], b, &mut c, d, e, &mut a);
        self.t_0_15_u32(array[5], a, &mut b, c, d, &mut e);
        self.t_0_15_u32(array[6], e, &mut a, b, c, &mut d);
        self.t_0_15_u32(array[7], d, &mut e, a, b, &mut c);
        self.t_0_15_u32(array[8], c, &mut d, e, a, &mut b);
        self.t_0_15_u32(array[9], b, &mut c, d, e, &mut a);
        self.t_0_15_u32(array[10], a, &mut b, c, d, &mut e);
        self.t_0_15_u32(array[11], e, &mut a, b, c, &mut d);
        self.t_0_15_u32(array[12], d, &mut e, a, b, &mut c);
        self.t_0_15_u32(array[13], c, &mut d, e, a, &mut b);
        self.t_0_15_u32(array[14], b, &mut c, d, e, &mut a);
        self.t_0_15_u32(array[15], a, &mut b, c, d, &mut e);

        Self::iterations_from_mixing_array(&mut a, &mut b, &mut c, &mut d, &mut e, &mut array);

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

impl Sha1Context {
    pub fn digest(data: &[u8]) -> String {
        let mut ctx = Self::init();
        ctx.update(data, (data.len() * 4) as u64);

        Self::hex_hash(ctx.finalize().as_ref())
    }
}

impl Sha1 for Sha1Context {
    fn init() -> Self {
        Self {
            size: u64::MIN,
            /* Initialize H with the magic constants provided in FIPS180 */
            h: [SHA_1H0, SHA_1H1, SHA_1H2, SHA_1H3, SHA_1H4],
            w: [0; 16],
        }
    }

    fn update(&mut self, mut data_in: &[u8], mut len: u64) {
        let mut len_w = self.size & 63;

        self.size += len;

        if len_w != 0 {
            let mut left = 64 - len_w;
            if len < left {
                left = len;
            }

            let (data_stream_chunk, rest) = data_in.split_at(left as usize);
            self.form_d_words_from_data_stream(data_stream_chunk, &mut len_w, left);

            len -= left;
            data_in = rest;

            if len_w != 0 {
                return;
            }

            self.block_32_bit_word();
        }

        while len >= 64 {
            Self::block(&mut self.h, data_in);
            let from = ExtMethods::range_from(64 & data_in.len() - 1);
            data_in = &data_in[from];
            len -= 64;
        }

        if len != 0 {
            if len > data_in.len() as u64 {
                len = data_in.len() as u64
            }
            let to = ExtMethods::range_to(len);
            Self::mem_cpy(&mut self.w, &data_in[to]);
        }
    }

    fn finalize(&mut self) -> [u8; 20] {
        let mut pad: [u8; 64] = [0; 64];
        let mut pad_len: [u8; 8] = self.size.to_be_bytes();
        pad[0] = 0x80;

        let i = self.size & 63;
        self.update(&pad, 1 + (63 & (55 - i)));
        self.update(&pad_len, pad_len.len() as u64);

        self.to_byte_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::{MemoryCopy, Sha1, Sha1Context};
    use core::{
        cmp::max,
        fmt::Binary,
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
        let size_of_u32 = core::mem::size_of::<u32>();
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

        let digest_result = Sha1Context::digest(quick_fox.as_ref());

        assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

        let cavs_message: &str = "7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe585db6a78ce40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d9979016204bfd921322fdd5222183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b7398364f652fafc734329aafa3dcd45d4f31e388e4fafd7fc6495f37ca5cbab7f54d586463da4bfeaa3bae09f7b8e9239d832b4f0a733aa609cc1f8d4";
        let digest_result = Sha1Context::digest(cavs_message.as_ref());
        assert_eq!(digest_result, "d8fd6a91ef3b6ced05b98358a99107c1fac8c807");
    }

    #[test]
    fn copy_a_u8_vector_into_a_u8_vector() {
        let src: [u8; 5] = [1, 2, 3, 4, 5];
        let mut dest: [u8; 5] = [0; 5];

        Sha1Context::mem_cpy(&mut dest[3..], &src[..2]);
        assert_eq!(dest, [0, 0, 0, 1, 2]);

        Sha1Context::mem_cpy(&mut dest[0..], &src[3..]);
        assert_eq!(dest, [4, 5, 0, 1, 2]);

        Sha1Context::mem_cpy(&mut dest[1..], &src[1..4]);
        assert_eq!(dest, [4, 2, 3, 4, 2]);
    }

    #[test]
    fn copy_a_u8_vector_into_a_u32_vector() {
        let char_vec = ['a', 'b', 'c', 'd', 'e'];
        let mut dest: [u32; 5] = [0; 5];

        Sha1Context::mem_cpy(
            &mut dest[0..],
            &char_vec.into_iter().collect::<String>().as_bytes()[..5],
        );

        assert_eq!(
            dest,
            [0x61626364, 0x65, 0, 0, 0],
            "Asserts characters bytes were correctly copied into u32 integers"
        );
    }

    #[test]
    fn copy_a_u32_vector_into_a_u32_vector() {
        let src: [u32; 5] = [1, 2, 3, 4, 5];
        let mut dest: [u32; 5] = [0; 5];

        Sha1Context::mem_cpy(&mut dest[3..], &src[..2]);
        assert_eq!(dest, [0, 0, 0, 1, 2]);

        Sha1Context::mem_cpy(&mut dest[0..], &src[3..]);
        assert_eq!(dest, [4, 5, 0, 1, 2]);

        Sha1Context::mem_cpy(&mut dest[1..], &src[1..4]);
        assert_eq!(dest, [4, 2, 3, 4, 2]);
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
