use sha1_constants::{
    HashValues, Sha1Output, ShamblesMatrix, H_0, H_1, H_2, H_3, H_4, SHA1_BLOCK_SIZE,
};
use std::iter::{Cycle, Map};
use std::ops::Range;
use std::slice::Iter;

mod sha1_constants;

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

trait ShaProcess {
    fn init() -> Self;

    fn update(&mut self, len: usize, data: Box<[u8]>);

    fn finalize(&mut self) -> Sha1Output;
}

#[derive(Debug)]
struct SHA1 {
    h: HashValues,
    w: ShamblesMatrix,
    size: usize,
}

impl SHA1 {
    fn array_roller(i: usize, array: &[u32; 16]) -> u32 {
        array[i & 15]
    }

    fn rol(x: u32, n: u32) -> u32 {
        SHA1::rot(x, n, 32 - n)
    }

    fn ror(x: u32, n: u32) -> u32 {
        SHA1::rot(x, 32 - n, n)
    }

    fn rot(x: u32, l: u32, r: u32) -> u32 {
        (x << l) | (x >> r)
    }

    fn get_be32(block: &Vec<u32>) -> u8 {
        let i1 = (block[0] << 24) as u8;
        let i2 = (block[1] << 16) as u8;
        let i3 = (block[2] << 8) as u8;
        let i4 = (block[3] << 0) as u8;
        i1 | i2 | i3 | i4
    }

    fn setW(x: usize, val: u32, array: &mut DWords) {
        array[x] = val;
    }

    fn source(t: usize, block: &Vec<u32>) -> u32 {
        let start = t * 4;
        SHA1::get_be32(&block[start..].to_vec()) as u32
    }

    fn mix(t: usize, array: &[u32; 16]) -> u32 {
        let i1 = SHA1::array_roller(t + 13, array);
        let i2 = SHA1::array_roller(t + 8, array);
        let i3 = SHA1::array_roller(t + 2, array);
        let i4 = SHA1::array_roller(t + 1, array);
        SHA1::rol(i1 ^ i2 ^ i3 ^ i4, 1)
    }

    fn round(&mut self, t: usize, input: u32, f: u32, constant: u32, array: &mut DWords) {
        SHA1::setW(t, input, array);
        self.h[4] = input + SHA1::rol(self.h[0], 5) + f + constant;
        self.h[1] = SHA1::ror(self.h[1], 2);
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
    fn t_0_15(&mut self, f: u32, d_words: &mut DWords, block: &Vec<u32>) {
        let constant = R1;
        let i = SHA1::source;

        for x in 0..16 {
            let input = SHA1::source(x, block);

            self.round(x, input, f, constant, d_words);
            self.h.rotate_right(1);
        }
    }

    fn t_16_79(&mut self, f: u32, constant: u32, range: Range<usize>, d_words: &mut DWords) {
        for x in range {
            let input = SHA1::mix(x, d_words);

            self.round(x, input, f, constant, d_words);
            self.h.rotate_right(1);
        }
    }

    fn t_16_19(&mut self, f: u32, d_words: &mut DWords) {
        let constant = R1;

        let range = 16..20;
        self.t_16_79(f, constant, range, d_words, )
    }

    fn t_20_39(&mut self, f: u32, d_words: &mut DWords) {
        let constant = R2;
        let range = 20..40;
        self.t_16_79(f, constant, range, d_words);
    }

    fn t_40_59(&mut self, f: u32, d_words: &mut DWords) {
        let constant = R3;
        let range = 40..60;
        self.t_16_79(f, constant, range, d_words);
    }

    fn t_60_79(&mut self, f: u32, d_words: &mut DWords) {
        let constant = R4;
        let range = 60..80;
        self.t_16_79(f, constant, range, d_words);
    }
}

impl SHA1 {
    fn init() -> Self {
        Self {
            h: [H_0, H_1, H_2, H_3, H_4],
            w: [0; 80],
            size: 0,
        }
    }

    fn update(&mut self, mut len: usize, data: Box<[u8]>) {
        let mut lenW = self.size & (SHA1_BLOCK_SIZE - 1) as usize;
        let mut left = SHA1_BLOCK_SIZE as usize - lenW;
        let mut data_range = Range {
            start: 0,
            end: left,
        };

        self.size += len;

        if lenW != 0 {
            if len < left {
                left = len;
            }

            self.w[lenW..]
                .iter_mut()
                .zip(data[data_range.clone()].iter())
                .map(|(x, y)| *x = *y as u32);

            // let mut i = lenW;
            // for k in data_range {
            //     self.w[i] = data[k] as u32;
            //     i += 1;
            // }

            lenW = (lenW + left) & (SHA1_BLOCK_SIZE - 1) as usize;
            len -= left;
            data_range.start += left;
            data_range.end += left;

            if lenW != 0 {
                return;
            }

            self.hash_block();
        }

        while len >= SHA1_BLOCK_SIZE as usize {
            self.hash_block();
            data_range.start += SHA1_BLOCK_SIZE as usize;
            data_range.end += SHA1_BLOCK_SIZE as usize;
            len -= SHA1_BLOCK_SIZE as usize;
        }

        if len != 0 {
            // let x = &data[data_range].iter().map(|x| x as u32).collect();
            // self.w.clone_from_slice(x);
            self.w
                .iter_mut()
                .zip(data[len..].iter())
                .map(|(x, y)| *x = *y as u32);
        }
    }

    fn finalize(&mut self) -> Sha1Output {
        // let pad0x80: u8 = 0x80;
        // let pad0x00: u8 = 0x00;
        let mut bit_shifting: Cycle<Iter<u32>> = [24, 16, 8, 0].iter().cycle();
        let pad: [u8; 8] = [0; 8];
        let padding: [u8; 64] = [
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let mut pad = Box::new(pad);
        let mut padding = Box::new(padding);

        pad.map(|_| (self.size >> bit_shifting.next().unwrap()).swap_bytes());

        let i = self.size & 63;
        self.update(1 + (63 & (55 - i)), pad);
        self.update(8, padding);

        let mut h_value = self.h.iter().cycle();
        let mut hash_out: Sha1Output = [0; 20];
        for el in hash_out.iter_mut() {
            *el = (h_value.next().unwrap() >> bit_shifting.next().unwrap()) as u8;
        }

        return hash_out;
    }
}

impl PartialEq for SHA1 {
    fn eq(&self, other: &Self) -> bool {
        self.h == other.h && self.w == other.w && self.size == self.size
    }

    fn ne(&self, other: &Self) -> bool {
        self.h != other.h && self.w != other.w && self.size != self.size
    }
}

#[cfg(test)]
mod sha1_tests {
    use crate::sha1::SHA1;
    use crate::sha1::sha1_constants::{H_0, H_1, H_2, H_3, H_4};

    #[test]
    fn new_sha1_struct() {
        let expected_sha1 = SHA1 {
            h: [H_0, H_1, H_2, H_3, H_4],
            w: [0; 80],
            size: 0,
        };

        let resultant_sha1 = SHA1::new();

        assert_eq!(expected_sha1, resultant_sha1);
    }
}
