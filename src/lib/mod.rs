extern crate core;

use core::ops::{BitOr, RangeFrom, RangeTo, Shl, Shr};

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

struct ExtensionMethods;

trait SixteenModulusIndex<T> {
    fn modulus_16_element(index: T) -> usize;
    fn range_from(index: T) -> RangeFrom<usize>;
    fn range_to(index: T) -> RangeTo<usize>;
}

impl SixteenModulusIndex<u8> for ExtensionMethods {
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

impl SixteenModulusIndex<u64> for ExtensionMethods {
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

impl SixteenModulusIndex<usize> for ExtensionMethods {
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

fn swab32(val: &u32) -> u32 {
    ((*val & 0xff000000) >> 24)
        | ((*val & 0x00ff0000) >> 8)
        | ((*val & 0x0000ff00) << 8)
        | ((*val & 0x000000ff) << 24)
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

pub trait Sha1 {
    fn init() -> Self;
    fn update(&mut self, data_in: &[u8], len: u64);
    fn finalize(&mut self) -> [u8; 20];
}

trait MemoryCopy<D, S> {
    /// Copies n bytes from src to memory dest, using a reference receiving point in dest
    fn mem_cpy(dest: &mut [D], src: &[S]);
}

trait ShaSource<T> {
    fn src(vec: &[T], i: usize) -> u32;
    fn t_0_15(
        t: u8,
        block: &[T],
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: &mut u32,
        array: &mut [u32],
    );
    fn block(h: &mut [u32; 5], block: &[T]);
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
                4 => four_be_bytes_to_u32(c),
                3 => three_be_bytes_to_u32(c),
                2 => two_be_bytes_to_u32(c),
                1 => be_byte_to_u32(c),
                _ => panic!("Chunks are modulo 4"),
            })
            .collect::<Vec<u32>>();

        dest[..u32_src.len()].clone_from_slice(&u32_src);
    }
}

impl MemoryCopy<u32, u32> for Sha1Context {
    fn mem_cpy(dest: &mut [u32], src: &[u32]) {
        dest[..src.len()].clone_from_slice(&src)
    }
}

impl ShaSource<u8> for Sha1Context {
    fn src(vec: &[u8], i: usize) -> u32 {
        let stepped_size = (i * 4) & (vec.len() - 1);
        let offset = vec.len() - stepped_size;
        let vec_slice = &vec[stepped_size..];

        match offset {
            n if n > 3 => four_be_bytes_to_u32(vec_slice),
            3 => three_be_bytes_to_u32(vec_slice),
            2 => two_be_bytes_to_u32(vec_slice),
            1 => be_byte_to_u32(vec_slice),
            _ => panic!("This cannot possibly happen"),
        }
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

        /* Round 1 - tail. Input from 512-bit mixing array */
        Self::t_16_19(16, &mut array, e, &mut a, b, c, &mut d);
        Self::t_16_19(17, &mut array, d, &mut e, a, b, &mut c);
        Self::t_16_19(18, &mut array, c, &mut d, e, a, &mut b);
        Self::t_16_19(19, &mut array, b, &mut c, d, e, &mut a);

        /* Round 2 */
        Self::t_20_39(20, &mut array, a, b, c, d, e);
        Self::t_20_39(21, &mut array, e, a, b, c, d);
        Self::t_20_39(22, &mut array, d, e, a, b, c);
        Self::t_20_39(23, &mut array, c, d, e, a, b);
        Self::t_20_39(24, &mut array, b, c, d, e, a);
        Self::t_20_39(25, &mut array, a, b, c, d, e);
        Self::t_20_39(26, &mut array, e, a, b, c, d);
        Self::t_20_39(27, &mut array, d, e, a, b, c);
        Self::t_20_39(28, &mut array, c, d, e, a, b);
        Self::t_20_39(29, &mut array, b, c, d, e, a);
        Self::t_20_39(30, &mut array, a, b, c, d, e);
        Self::t_20_39(31, &mut array, e, a, b, c, d);
        Self::t_20_39(32, &mut array, d, e, a, b, c);
        Self::t_20_39(33, &mut array, c, d, e, a, b);
        Self::t_20_39(34, &mut array, b, c, d, e, a);
        Self::t_20_39(35, &mut array, a, b, c, d, e);
        Self::t_20_39(36, &mut array, e, a, b, c, d);
        Self::t_20_39(37, &mut array, d, e, a, b, c);
        Self::t_20_39(38, &mut array, c, d, e, a, b);
        Self::t_20_39(39, &mut array, b, c, d, e, a);

        /* Round 3 */
        Self::t_40_59(40, &mut array, a, b, c, d, e);
        Self::t_40_59(41, &mut array, e, a, b, c, d);
        Self::t_40_59(42, &mut array, d, e, a, b, c);
        Self::t_40_59(43, &mut array, c, d, e, a, b);
        Self::t_40_59(44, &mut array, b, c, d, e, a);
        Self::t_40_59(45, &mut array, a, b, c, d, e);
        Self::t_40_59(46, &mut array, e, a, b, c, d);
        Self::t_40_59(47, &mut array, d, e, a, b, c);
        Self::t_40_59(48, &mut array, c, d, e, a, b);
        Self::t_40_59(49, &mut array, b, c, d, e, a);
        Self::t_40_59(50, &mut array, a, b, c, d, e);
        Self::t_40_59(51, &mut array, e, a, b, c, d);
        Self::t_40_59(52, &mut array, d, e, a, b, c);
        Self::t_40_59(53, &mut array, c, d, e, a, b);
        Self::t_40_59(54, &mut array, b, c, d, e, a);
        Self::t_40_59(55, &mut array, a, b, c, d, e);
        Self::t_40_59(56, &mut array, e, a, b, c, d);
        Self::t_40_59(57, &mut array, d, e, a, b, c);
        Self::t_40_59(58, &mut array, c, d, e, a, b);
        Self::t_40_59(59, &mut array, b, c, d, e, a);

        /* Round 4 */
        Self::t_60_79(60, &mut array, a, b, c, d, e);
        Self::t_60_79(61, &mut array, e, a, b, c, d);
        Self::t_60_79(62, &mut array, d, e, a, b, c);
        Self::t_60_79(63, &mut array, c, d, e, a, b);
        Self::t_60_79(64, &mut array, b, c, d, e, a);
        Self::t_60_79(65, &mut array, a, b, c, d, e);
        Self::t_60_79(66, &mut array, e, a, b, c, d);
        Self::t_60_79(67, &mut array, d, e, a, b, c);
        Self::t_60_79(68, &mut array, c, d, e, a, b);
        Self::t_60_79(69, &mut array, b, c, d, e, a);
        Self::t_60_79(70, &mut array, a, b, c, d, e);
        Self::t_60_79(71, &mut array, e, a, b, c, d);
        Self::t_60_79(72, &mut array, d, e, a, b, c);
        Self::t_60_79(73, &mut array, c, d, e, a, b);
        Self::t_60_79(74, &mut array, b, c, d, e, a);
        Self::t_60_79(75, &mut array, a, b, c, d, e);
        Self::t_60_79(76, &mut array, e, a, b, c, d);
        Self::t_60_79(77, &mut array, d, e, a, b, c);
        Self::t_60_79(78, &mut array, c, d, e, a, b);
        Self::t_60_79(79, &mut array, b, c, d, e, a);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
}

impl ShaSource<u32> for Sha1Context {
    fn src(vec: &[u32], i: usize) -> u32 {
        vec[i].to_be()
    }

    fn t_0_15(
        t: u8,
        block: &[u32],
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

    fn block(h: &mut [u32; 5], block: &[u32]) {
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

        /* Round 1 - tail. Input from 512-bit mixing array */
        Self::t_16_19(16, &mut array, e, &mut a, b, c, &mut d);
        Self::t_16_19(17, &mut array, d, &mut e, a, b, &mut c);
        Self::t_16_19(18, &mut array, c, &mut d, e, a, &mut b);
        Self::t_16_19(19, &mut array, b, &mut c, d, e, &mut a);

        /* Round 2 */
        Self::t_20_39(20, &mut array, a, b, c, d, e);
        Self::t_20_39(21, &mut array, e, a, b, c, d);
        Self::t_20_39(22, &mut array, d, e, a, b, c);
        Self::t_20_39(23, &mut array, c, d, e, a, b);
        Self::t_20_39(24, &mut array, b, c, d, e, a);
        Self::t_20_39(25, &mut array, a, b, c, d, e);
        Self::t_20_39(26, &mut array, e, a, b, c, d);
        Self::t_20_39(27, &mut array, d, e, a, b, c);
        Self::t_20_39(28, &mut array, c, d, e, a, b);
        Self::t_20_39(29, &mut array, b, c, d, e, a);
        Self::t_20_39(30, &mut array, a, b, c, d, e);
        Self::t_20_39(31, &mut array, e, a, b, c, d);
        Self::t_20_39(32, &mut array, d, e, a, b, c);
        Self::t_20_39(33, &mut array, c, d, e, a, b);
        Self::t_20_39(34, &mut array, b, c, d, e, a);
        Self::t_20_39(35, &mut array, a, b, c, d, e);
        Self::t_20_39(36, &mut array, e, a, b, c, d);
        Self::t_20_39(37, &mut array, d, e, a, b, c);
        Self::t_20_39(38, &mut array, c, d, e, a, b);
        Self::t_20_39(39, &mut array, b, c, d, e, a);

        /* Round 3 */
        Self::t_40_59(40, &mut array, a, b, c, d, e);
        Self::t_40_59(41, &mut array, e, a, b, c, d);
        Self::t_40_59(42, &mut array, d, e, a, b, c);
        Self::t_40_59(43, &mut array, c, d, e, a, b);
        Self::t_40_59(44, &mut array, b, c, d, e, a);
        Self::t_40_59(45, &mut array, a, b, c, d, e);
        Self::t_40_59(46, &mut array, e, a, b, c, d);
        Self::t_40_59(47, &mut array, d, e, a, b, c);
        Self::t_40_59(48, &mut array, c, d, e, a, b);
        Self::t_40_59(49, &mut array, b, c, d, e, a);
        Self::t_40_59(50, &mut array, a, b, c, d, e);
        Self::t_40_59(51, &mut array, e, a, b, c, d);
        Self::t_40_59(52, &mut array, d, e, a, b, c);
        Self::t_40_59(53, &mut array, c, d, e, a, b);
        Self::t_40_59(54, &mut array, b, c, d, e, a);
        Self::t_40_59(55, &mut array, a, b, c, d, e);
        Self::t_40_59(56, &mut array, e, a, b, c, d);
        Self::t_40_59(57, &mut array, d, e, a, b, c);
        Self::t_40_59(58, &mut array, c, d, e, a, b);
        Self::t_40_59(59, &mut array, b, c, d, e, a);

        /* Round 4 */
        Self::t_60_79(60, &mut array, a, b, c, d, e);
        Self::t_60_79(61, &mut array, e, a, b, c, d);
        Self::t_60_79(62, &mut array, d, e, a, b, c);
        Self::t_60_79(63, &mut array, c, d, e, a, b);
        Self::t_60_79(64, &mut array, b, c, d, e, a);
        Self::t_60_79(65, &mut array, a, b, c, d, e);
        Self::t_60_79(66, &mut array, e, a, b, c, d);
        Self::t_60_79(67, &mut array, d, e, a, b, c);
        Self::t_60_79(68, &mut array, c, d, e, a, b);
        Self::t_60_79(69, &mut array, b, c, d, e, a);
        Self::t_60_79(70, &mut array, a, b, c, d, e);
        Self::t_60_79(71, &mut array, e, a, b, c, d);
        Self::t_60_79(72, &mut array, d, e, a, b, c);
        Self::t_60_79(73, &mut array, c, d, e, a, b);
        Self::t_60_79(74, &mut array, b, c, d, e, a);
        Self::t_60_79(75, &mut array, a, b, c, d, e);
        Self::t_60_79(76, &mut array, e, a, b, c, d);
        Self::t_60_79(77, &mut array, d, e, a, b, c);
        Self::t_60_79(78, &mut array, c, d, e, a, b);
        Self::t_60_79(79, &mut array, b, c, d, e, a);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
}

impl Sha1Context {
    fn to_byte_slice(&self) -> [u8; 20] {
        // Use flatten once it stabilizes
        let mut hash_out: [u8; 20] = [0; 20];
        self.h
            .iter()
            .zip((0..5).into_iter())
            .for_each(|(constant, k_index)| {
                hash_out[0 + (k_index * 4)] = constant.shr(24) as u8;
                hash_out[1 + (k_index * 4)] = constant.shr(16) as u8;
                hash_out[2 + (k_index * 4)] = constant.shr(8) as u8;
                hash_out[3 + (k_index * 4)] = *constant as u8;
            });

        hash_out
    }

    fn hex_hash(byte_hash: &[u8]) -> String {
        byte_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn set_w(i: u8, val: u32, array: &mut [u32]) {
        array[ExtensionMethods::modulus_16_element(i)] = val;
    }

    fn mix(i: usize, array: &[u32]) -> u32 {
        let x_i = ExtensionMethods::modulus_16_element(i + 13);
        let x = array[x_i];
        let y_i = ExtensionMethods::modulus_16_element(i + 8);
        let y = array[y_i];
        let z_i = ExtensionMethods::modulus_16_element(i + 2);
        let z = array[z_i];
        let t_i = ExtensionMethods::modulus_16_element(i);
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

    fn block_32_bit_word(&mut self) {}

    fn t_16_19(t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        let f_n = Self::ch(*b, c, d);
        let temp = Self::mix(t as usize, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        *e = (*e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_n)
            .wrapping_add(T_16_19);
        *b = (*b).rotate_right(2);
    }

    fn t_20_39(t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        let f_n = Self::parity(b, c, d);
        let temp = Self::mix(t as usize, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        e = (e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_n)
            .wrapping_add(T_20_39);
        b = (b).rotate_right(2);
    }

    fn t_40_59(t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        let f_n = Self::maj(b, c, d);
        let temp = Self::mix(t as usize, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        e = (e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_n)
            .wrapping_add(T_40_59);
        b = (b).rotate_right(2);
    }

    fn t_60_79(t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        let f_n = Self::parity(b, c, d);
        let temp = Self::mix(t as usize, shamble_arr);
        Self::set_w(t, temp, shamble_arr);
        e = (e)
            .wrapping_add(temp)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(f_n)
            .wrapping_add(T_60_79);
        b = (b).rotate_right(2);
    }

    fn form_d_words_from_data_stream(&mut self, data_stream: &[u8], len_w: &mut u64, left: u64) {
        let dest_from = ExtensionMethods::range_from(ExtensionMethods::modulus_16_element(*len_w));
        Self::mem_cpy(&mut self.w[dest_from], data_stream);

        *len_w = (*len_w + left) & 63;
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

            Self::block(&mut self.h, &mut self.w);
        }

        while len >= 64 {
            Self::block(&mut self.h, data_in);
            data_in = &data_in[(64 & data_in.len() - 1)..];
            len -= 64;
        }

        if len != 0 {
            if len > data_in.len() as u64 {
                len = data_in.len() as u64
            }
            let to = ExtensionMethods::range_to(len);
            Self::mem_cpy(&mut self.w, &data_in[to]);
        }
    }

    fn finalize(&mut self) -> [u8; 20] {
        let mut pad: [u8; 64] = [0; 64];
        let mut pad_len = self.size.to_be_bytes();
        pad[0] = 0x80;

        let i = self.size & 63;
        self.update(&pad, 1 + (63 & (55 - i)));
        self.update(&pad_len, 8);

        self.to_byte_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        be_byte_to_u32, four_be_bytes_to_u32, three_be_bytes_to_u32, two_be_bytes_to_u32, MemoryCopy, Sha1,
        Sha1Context,
    };
    use core::cmp::max;
    use core::fmt::Binary;
    use core::ops::{Shl, Shr};
    use std::ops::BitOr;

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
        let manually_computed_complete_u32_hex_str = format!("{:x}", manually_computed_complete_u32);

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
            [1684234849, 101, 0, 0, 0],
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
}
