use crate::sha1::sha1_constants::{
    HashValues, Sha1Output, ShambleMatrix, H_0, H_1, H_2, H_3, H_4, R1, R2, R3, R4, SHA1_BLOCK_SIZE,
};
use std::iter::Cycle;
use std::ops::{Add, BitAnd, BitXor, Index, Range};
use std::slice::Iter;

mod sha1_constants;
mod sha1_padding;
#[cfg(test)]
mod sha1_padding_tests;
#[cfg(test)]
mod sha1_tests;

fn f_1<T>(b: &T, c: &T, d: &T) -> T
where
    T: BitAnd<Output = T> + BitXor<Output = T> + Copy,
{
    *d ^ (*b & (*c ^ *d))
}

fn f_2<T: BitXor<Output = T> + Copy>(b: &T, c: &T, d: &T) -> T {
    *b ^ *c ^ *d
}

fn f_3<T>(b: &T, c: &T, d: &T) -> T
where
    T: Add<Output = T> + BitAnd<Output = T> + BitXor<Output = T> + Copy,
{
    (*b & *c) + (*d & (*b ^ *c))
}

pub fn swab32(val: &u32) -> u32 {
    ((*val & 0xff000000) >> 24)
        | ((*val & 0x00ff0000) >> 8)
        | ((*val & 0x0000ff00) << 8)
        | ((*val & 0x000000ff) << 24)
}

trait ShaProcess {
    fn init() -> Self;

    fn update(&mut self, data: &mut Vec<u32>, len: usize) -> Self;

    fn finalize(&mut self) -> Sha1Output;
}

#[derive(Debug, Clone)]
struct SHA1 {
    hashes: HashValues,
    d_words_shambling: ShambleMatrix,
    size: usize,
}

impl SHA1 {
    fn rol(x: u32, n: u32) -> u32 {
        SHA1::rot(x, n, 32 - n)
    }

    // fn ror(x: u32, n: u32) -> u32 {
    //     SHA1::rot(x, 32 - n, n)
    // }

    fn rot(x: u32, l: u32, r: u32) -> u32 {
        (x << l) | (x >> r)
    }

    fn array_roller(index: usize, array: &ShambleMatrix) -> u32 {
        array[index & 15]
    }

    fn get_be32(block: &[u32]) -> u32 {
        let i1 = block[0] << 24;
        let i2 = block[1] << 16;
        let i3 = block[2] << 8;
        let i4 = block[3] << 0;
        i1 | i2 | i3 | i4
    }

    fn set_d_word(index: usize, value: u32, d_words_shambling: &mut ShambleMatrix) {
        d_words_shambling[index] = value;
    }

    fn source<T>(index: usize, block: &T) -> u32
    where
        T: Index<Range<usize>, Output = [u32]>,
    {
        let start = index * 4;
        let end = start + 5;
        SHA1::get_be32(&block[start..end][..]) as u32
    }

    fn mix(index: usize, array: &ShambleMatrix) -> u32 {
        //TODO - Check later how to converto it into a iterator
        let i1 = SHA1::array_roller(index + 13, array);
        let i2 = SHA1::array_roller(index + 8, array);
        let i3 = SHA1::array_roller(index + 2, array);
        let i4 = SHA1::array_roller(index + 1, array);
        //TODO - Check later if this rol function has same speed as {integer}::rotate_left
        SHA1::rol(i1 ^ i2 ^ i3 ^ i4, 1)
    }

    fn round(&mut self, input: u32, f: u32, constant: u32) {
        self.hashes[4] = input.wrapping_add(
            self.hashes[0]
                .rotate_left(5)
                .wrapping_add(f.wrapping_add(constant)),
        );
        self.hashes[1] = self.hashes[1].rotate_right(2);
    }
}

impl SHA1 {
    /// Round 1 - Iterations 0-16 take their input from block
    ///
    /// # Arguments
    ///
    /// * `array`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn t_0_15<T>(&mut self, f_n: u32, d_word_input: &mut T)
    where
        T: Index<usize, Output = u32> + Index<Range<usize>, Output = [u32]>,
    {
        let constant = R1;

        for index in 0..16 {
            let val = SHA1::source::<T>(index, d_word_input);

            SHA1::set_d_word(index, val, &mut self.d_words_shambling);
            self.round(val, f_n, constant);
            self.hashes.rotate_right(1);
        }
    }

    fn t_16_79(&mut self, f_n: u32, constant: u32, range: Range<usize>) {
        for x in range {
            let input = SHA1::mix(x, &mut self.d_words_shambling);

            SHA1::set_d_word(x, input, &mut self.d_words_shambling);
            self.round(input, f_n, constant);
            self.hashes.rotate_right(1);
        }
    }

    fn t_16_19(&mut self, f_n: u32) {
        let constant = R1;
        let range = 16..20;
        self.t_16_79(f_n, constant, range)
    }

    fn t_20_39(&mut self) {
        let constant = R2;
        let f2 = f_2(&self.hashes[1], &self.hashes[2], &self.hashes[3]);
        let range = 20..40;
        self.t_16_79(f2, constant, range);
    }

    fn t_40_59(&mut self) {
        let constant = R3;
        let f3 = f_3(&self.hashes[1], &self.hashes[2], &self.hashes[3]);
        let range = 40..60;
        self.t_16_79(f3, constant, range);
    }

    fn t_60_79(&mut self) {
        let constant = R4;
        let f4 = f_2(&self.hashes[1], &self.hashes[2], &self.hashes[3]);
        let range = 60..80;
        self.t_16_79(f4, constant, range);
    }

    fn hash_block<T>(&mut self, d_word_input: &mut T)
    where
        T: Index<usize, Output = u32> + Index<Range<usize>, Output = [u32]>,
    {
        let f_n = f_1(&self.hashes[1], &self.hashes[2], &self.hashes[3]);
        self.t_0_15::<T>(f_n, d_word_input);
        self.t_16_19(f_n);

        self.t_20_39();
        self.t_40_59();
        self.t_60_79();
    }
}

impl ShaProcess for SHA1 {
    fn init() -> Self {
        Self {
            hashes: [H_0, H_1, H_2, H_3, H_4],
            d_words_shambling: [0; 80],
            size: 0,
        }
    }

    fn update(&mut self, data: &mut Vec<u32>, mut len: usize) -> Self {
        let mut len_w = self.size & 63;
        self.size += len;

        if len_w != 0 {
            let mut left = (SHA1_BLOCK_SIZE as usize) - len_w;
            if len < left {
                left = len;
            }

            let mut temp = len_w;
            for i in 0..data.len() {
                self.d_words_shambling[temp] = data[i];
                temp += 1;
            }

            len_w = (len_w + left) & 63;
            len -= left;

            if len_w != 0 {
                return self.to_owned();
            }

            let mut struct_d_words = self.d_words_shambling.clone();
            self.hash_block::<[u32; 80]>(&mut struct_d_words);
        }

        while len >= SHA1_BLOCK_SIZE as usize {
            self.hash_block::<Vec<u32>>(data);
            len -= SHA1_BLOCK_SIZE as usize;
        }

        if len != 0 {
            for i in 0..len {
                self.d_words_shambling[i] = data[i];
            }
            //TODO - Maybe its beneficial to change to `clonefrom`
        }

        return self.to_owned();
    }

    fn finalize(&mut self) -> Sha1Output {
        let mut pad: [u32; SHA1_BLOCK_SIZE as usize] = [0; SHA1_BLOCK_SIZE as usize];
        let mut pad_len: [u32; 2] = [0; 2];
        pad[0] = 0x80;

        pad_len[0] = swab32(&((&self.size >> 29) as u32));
        pad_len[1] = swab32(&((&self.size << 3) as u32));

        let i = 1 + (63 & (55 - (self.size & 63)));
        self.update(&mut pad.to_vec(), i);
        self.update(&mut pad_len.to_vec(), 8);

        let mut u32_bytes: Cycle<Iter<u32>> = [24, 18, 12, 6, 0].iter().cycle();
        let mut hash: Sha1Output = [0; 20];

        hash[0] = (self.hashes[0] >> u32_bytes.next().unwrap()) as u8;
        hash[1] = (self.hashes[0] >> u32_bytes.next().unwrap()) as u8;
        hash[2] = (self.hashes[0] >> u32_bytes.next().unwrap()) as u8;
        hash[3] = (self.hashes[0] >> u32_bytes.next().unwrap()) as u8;
        hash[4] = (self.hashes[0] >> u32_bytes.next().unwrap()) as u8;

        hash[5] = (self.hashes[1] >> u32_bytes.next().unwrap()) as u8;
        hash[6] = (self.hashes[1] >> u32_bytes.next().unwrap()) as u8;
        hash[7] = (self.hashes[1] >> u32_bytes.next().unwrap()) as u8;
        hash[8] = (self.hashes[1] >> u32_bytes.next().unwrap()) as u8;
        hash[9] = (self.hashes[1] >> u32_bytes.next().unwrap()) as u8;

        hash[10] = (self.hashes[2] >> u32_bytes.next().unwrap()) as u8;
        hash[11] = (self.hashes[2] >> u32_bytes.next().unwrap()) as u8;
        hash[12] = (self.hashes[2] >> u32_bytes.next().unwrap()) as u8;
        hash[13] = (self.hashes[2] >> u32_bytes.next().unwrap()) as u8;
        hash[14] = (self.hashes[2] >> u32_bytes.next().unwrap()) as u8;

        hash[15] = (self.hashes[3] >> u32_bytes.next().unwrap()) as u8;
        hash[16] = (self.hashes[3] >> u32_bytes.next().unwrap()) as u8;
        hash[17] = (self.hashes[3] >> u32_bytes.next().unwrap()) as u8;
        hash[18] = (self.hashes[3] >> u32_bytes.next().unwrap()) as u8;
        hash[19] = (self.hashes[3] >> u32_bytes.next().unwrap()) as u8;

        return hash;
    }
}

// fn linear_interpolation(y: i16, hy: i16, ly: i16, hx: i16, lx: i16) -> u8 {
//     let mut i = (y - ly);
//     if i < 0 {
//         i *= -1;
//     }
//     (((hx - lx) * i / (hy - ly)) + lx) as u8
// }

/// Single byte characters are every character with index from 0 to 127 on ASCII table. This
/// function, though, will parse any single byte value integer outside the 48..=57 and 97..=122
/// intervals to a given value inside one of them. Which interval digit will the input be parsed
/// to will be calculated in function of the distance the input finds itself to the
/// nearest interval.
///
/// Since the upper limit of the lower case digits (97..=122) is closer to the upper limit of the
/// single byte characters on ASCII table (127), values between 0..=20 will be considered as closer
/// to 97..=122 interval to provide a equal probability of a letter or a number.
///
/// # Arguments
///
/// * `u8_shift_byte`:
///
/// returns: u8
///
/// # Examples
///
/// ```
///
/// ```
// fn to_single_byte_char(mut u8_shift_byte: u8) -> u8 {
//     if u8_shift_byte > 127 {
//         u8_shift_byte -= 128;
//     }
//     return u8_shift_byte;

// return match u8_shift_byte {
//     n @ 0..=20 => linear_interpolation(u8_shift_byte as i16, 20, 0, 122, 112),
//     n @ 21..=47 => linear_interpolation(u8_shift_byte as i16, 47, 21, 52, 48),
//     n @ 58..=76 => linear_interpolation(u8_shift_byte as i16, 76, 58, 57, 53),
//     n @ 77..=96 => linear_interpolation(u8_shift_byte as i16, 96, 77, 109, 97),
//     n @ 123..=127 => linear_interpolation(u8_shift_byte as i16, 127, 123, 111, 110),
//     _ => u8_shift_byte,
// };
// }

impl SHA1 {
    fn new() -> Self {
        SHA1::init()
    }

    fn hash_eq(&self, other: &Self) -> bool {
        self.hashes == other.hashes
    }

    fn d_words_eq(&self, other: &Self) -> bool {
        self.d_words_shambling == other.d_words_shambling
    }

    fn size_eq(&self, other: &Self) -> bool {
        self.size == other.size
    }

    fn hash_ne(&self, other: &Self) -> bool {
        !self.hash_eq(other)
    }

    fn d_words_ne(&self, other: &Self) -> bool {
        !self.d_words_eq(other)
    }

    fn size_ne(&self, other: &Self) -> bool {
        !self.size_eq(other)
    }

    pub fn unwrap_hashes(&self) -> HashValues {
        self.hashes
    }
}

impl PartialEq for SHA1 {
    fn eq(&self, other: &Self) -> bool {
        self.hash_eq(&other) && self.d_words_eq(&other) && self.size_eq(other)
    }

    fn ne(&self, other: &Self) -> bool {
        self.hash_ne(&other) && self.d_words_ne(&other) && self.size_ne(other)
    }
}
