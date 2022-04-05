use sha1_constants::{
    HashValues, Sha1Output, ShambleMatrix, H_0, H_1, H_2, H_3, H_4, SHA1_BLOCK_SIZE,
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

fn swab32(val: &u32) -> u32 {
    ((*val & 0xff000000) >> 24)
        | ((*val & 0x00ff0000) >> 8)
        | ((*val & 0x0000ff00) << 8)
        | ((*val & 0x000000ff) << 24)
}

trait ShaProcess {
    fn init() -> Self;

    fn update(&mut self, data: &mut Vec<[u8]>, len: usize);

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

    fn ror(x: u32, n: u32) -> u32 {
        SHA1::rot(x, 32 - n, n)
    }

    fn rot(x: u32, l: u32, r: u32) -> u32 {
        (x << l) | (x >> r)
    }

    fn array_roller(index: usize, array: &ShambleMatrix) -> u32 {
        array[index & 15]
    }

    fn get_be32(block: &[u32]) -> u8 {
        let i1 = (block[0] << 24) as u8;
        let i2 = (block[1] << 16) as u8;
        let i3 = (block[2] << 8) as u8;
        let i4 = (block[3] << 0) as u8;
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
        //TODO - Check later if this rol function is the sabe as {integer}::rotate_left
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

impl SHA1 {
    fn init() -> Self {
        Self {
            hashes: [H_0, H_1, H_2, H_3, H_4],
            d_words_shambling: [0; 80],
            size: 0,
        }
    }

    fn new() -> Self {
        SHA1::init()
    }

    fn update(&mut self, data: &mut Vec<u32>, mut len: usize) {
        let mut len_w = self.size & 63;
        self.size += len;

        if len_w != 0 {
            let mut left = 64 - len_w;
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
                return;
            }

            let mut struct_d_words = self.d_words_shambling.clone();
            self.hash_block::<[u32; 80]>(&mut struct_d_words);
        }

        while len >= 64 {
            self.hash_block::<Vec<u32>>(data);
            len -= 64;
        }

        if len != 0 {
            for i in 0..len {
                self.d_words_shambling[i] = data[i];
            }
            //TODO - Maybe its beneficial to change to `clonefrom`
        }
    }

    fn update_chunked(&mut self, data: &mut Vec<u32>, mut len: &mut isize) {
        let mut total = 0;
        let mut nr = 0;
        let mut c_data = data.clone();

        while *len < 0 {
            nr = *len;

            if nr > SHA1_BLOCK_SIZE as isize {
                nr = SHA1_BLOCK_SIZE as isize;
            }

            self.update(&mut c_data, nr as usize);
            total += nr;
            *len -= nr;
        }
    }

    fn final_block(&mut self) -> [u8; 20] {
        let mut pad: [u32; 64] = [0; 64];
        let mut padlen: [u32; 2] = [0; 2];
        pad[0] = 0x80;

        padlen[0] = (self.size >> 29).swap_bytes() as u32;
        padlen[1] = (self.size << 3).swap_bytes() as u32;

        let i = 1 + (63 & (55 - (self.size & 63)));
        self.update(&mut pad.to_vec(), i);
        self.update(&mut padlen.to_vec(), 8);

        let hash_out: [u8; 20] = [
            (self.hashes[0] >> 24) as u8,
            (self.hashes[1] >> 16) as u8,
            (self.hashes[2] >> 8) as u8,
            (self.hashes[3] >> 0) as u8,
            (self.hashes[4] >> 16) as u8,
            (self.hashes[5] >> 8) as u8,
            (self.hashes[6] >> 0) as u8,
            (self.hashes[7] >> 16) as u8,
            (self.hashes[8] >> 8) as u8,
            (self.hashes[9] >> 0) as u8,
            (self.hashes[0] >> 24) as u8,
            (self.hashes[11] >> 8) as u8,
            (self.hashes[12] >> 0) as u8,
            (self.hashes[13] >> 16) as u8,
            (self.hashes[14] >> 8) as u8,
            (self.hashes[15] >> 0) as u8,
            (self.hashes[16] >> 24) as u8,
            (self.hashes[17] >> 24) as u8,
            (self.hashes[18] >> 24) as u8,
            (self.hashes[19] >> 24) as u8,
        ];

        return hash_out;
    }
}
//
// impl ShaProcess for SHA1 {
//     fn init() -> Self {
//         Self {
//             h: [H_0, H_1, H_2, H_3, H_4],
//             w: [0; 80],
//             size: 0,
//         }
//     }
//
//     fn update(&mut self, mut len: usize, data: &mut Box<[u8]>) {
//         let mut lenW = self.size & (SHA1_BLOCK_SIZE - 1) as usize;
//         let mut left = SHA1_BLOCK_SIZE as usize - lenW;
//         let mut data_range = Range {
//             start: 0,
//             end: left,
//         };
//
//         self.size += len;
//
//         if lenW != 0 {
//             if len < left {
//                 left = len;
//             }
//
//             self.w[lenW..]
//                 .iter_mut()
//                 .zip(data[data_range.clone()].iter())
//                 .map(|(x, y)| *x = *y as u32);
//
//             // let mut i = lenW;
//             // for k in data_range {
//             //     self.w[i] = data[k] as u32;
//             //     i += 1;
//             // }
//
//             lenW = (lenW + left) & (SHA1_BLOCK_SIZE - 1) as usize;
//             len -= left;
//             data_range.start += left;
//             data_range.end += left;
//
//             if lenW != 0 {
//                 return;
//             }
//
//             self.hash_block();
//         }
//
//         while len >= SHA1_BLOCK_SIZE as usize {
//             self.hash_block();
//             data_range.start += SHA1_BLOCK_SIZE as usize;
//             data_range.end += SHA1_BLOCK_SIZE as usize;
//             len -= SHA1_BLOCK_SIZE as usize;
//         }
//
//         if len != 0 {
//             // let x = &data[data_range].iter().map(|x| x as u32).collect();
//             // self.w.clone_from_slice(x);
//             self.w
//                 .iter_mut()
//                 .zip(data[len..].iter())
//                 .map(|(x, y)| *x = *y as u32);
//         }
//     }
//
//     fn finalize(&mut self) -> Sha1Output {
//         let mut pad: Box<[u8]> = [0; 8].to_vec().into_boxed_slice();
//         let mut padding: Box<[u8]> = SHA1_PADDING.to_vec().into_boxed_slice();
//         let mut bit_shifting: Cycle<Iter<u32>> = [24, 16, 8, 0].iter().cycle();
//
//         pad.iter_mut().map(|_| (self.size >> bit_shifting.next().unwrap()).swap_bytes() as u8);
//         // let x = pad.iter().map(|_| (self.size >> bit_shifting.next().unwrap()).swap_bytes()).collect();
//
//         let i = self.size & 63;
//         self.update(1 + (63 & (55 - i)), &mut pad);
//         self.update(8, &mut padding);
//
//         let mut h_value = self.h.iter().cycle();
//         let mut hash_out: Sha1Output = [0; 20];
//         for el in hash_out.iter_mut() {
//             *el = (h_value.next().unwrap() >> bit_shifting.next().unwrap()) as u8;
//         }
//
//         return hash_out;
//     }
// }

impl PartialEq for SHA1 {
    fn eq(&self, other: &Self) -> bool {
        self.hashes == other.hashes
            && self.d_words_shambling == other.d_words_shambling
            && self.size == self.size
    }

    fn ne(&self, other: &Self) -> bool {
        self.hashes != other.hashes
            && self.d_words_shambling != other.d_words_shambling
            && self.size != self.size
    }
}

#[cfg(test)]
mod sha1_tests {
    use super::*;

    #[test]
    fn new_sha1_struct() {
        let expected_sha1 = SHA1 {
            hashes: [H_0, H_1, H_2, H_3, H_4],
            d_words_shambling: [0; 80],
            size: 0,
        };

        let resultant_sha1 = SHA1::new();

        assert_eq!(expected_sha1, resultant_sha1);
    }

    #[test]
    fn update_sha1_struct() {
        let mut x = SHA1::new();
        let mut padding: Vec<u32> = SHA1_PADDING
            .to_vec()
            .iter()
            .map(|x| *x as u32)
            .collect::<Vec<u32>>();
        let mut pad: [u32; 2] = [
            swab32(&((x.size >> 29) as u32)),
            swab32(&((x.size << 3) as u32)),
        ];

        let i = 1 + (63 & (55 - (x.size & 63)));
        x.update(&mut padding, i);
        x.update(&mut pad.to_vec(), 8);

        println!("test");
    }

    // #[test]
    // fn finalize_sha1() {
    //
    // }
}
