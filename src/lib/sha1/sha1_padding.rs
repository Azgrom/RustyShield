use crate::sha1::sha1_constants::{ShaPadding, SHA1_PADDING};
use crate::SHA1_BLOCK_SIZE;
use std::borrow::{Borrow, BorrowMut};
use std::mem;
use std::ops::{Range, RangeFull};

#[derive(Debug)]
struct SHA1Padding(ShaPadding);

impl PartialEq for SHA1Padding {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

impl SHA1Padding {
    pub fn new(stream: String) -> Self {
        let byte_stream = stream.as_bytes();

        let mut last_index = 0;
        let mut padding: [u8; 64] = [0; 64];
        let mut wrapped_array = Vec::new();

        while last_index < byte_stream.len() - 1 {
            wrapped_array = byte_stream
                .iter()
                .enumerate()
                .zip(SHA1_PADDING.iter())
                .map(|(byte, pad)| {
                    last_index += 1;
                    return pad.wrapping_add(*byte.1);
                })
                .collect::<Vec<u8>>();
        }

        wrapped_array.push(0x80);

        for (index, i) in wrapped_array.iter().enumerate() {
            padding[index] = *i;
        }

        let bit_amount_of_byte_stream: usize = byte_stream.len() * 8;

        Self::push_stream_len(&mut padding, bit_amount_of_byte_stream);

        return Self(padding);
    }

    fn push_stream_len(mut padding: &mut [u8; 64], mut stream_len: usize) {
        let mut vec: Vec<u8> = Vec::new();

        let range = Range {
            start: 0,
            end: mem::size_of_val(&stream_len) * 7,
        }
        .step_by(8);

        vec = range
            .map(|r_shift| (stream_len >> r_shift) as u8)
            .collect::<Vec<u8>>();

        for (index, el) in vec.iter().enumerate() {
            let x_in = padding.len() - 1 - index;
            padding[x_in] += el;
        }
    }

    pub fn convert_padding_to_words(&self) -> [u32; 16] {
        let range = Range { start: 0, end: 16 };
        let mut x: [u32; 16] = [0; 16];

        for word in range {
            let y = word * 4;
            x[word] = ((self.0[0 + y] as u32) << 24)
                + ((self.0[1 + y] as u32) << 16)
                + ((self.0[2 + y] as u32) << 8)
                + self.0[3 + y] as u32;
        }

        return x;
    }

    pub fn copy_padded_word_to_eighty_chunk(t: [u32; 16]) -> [u32; 80] {
        let mut d_words: [u32; 80] = [0; 80];

        for (i, el) in t.iter().enumerate() {
            d_words[i] = *el;
        }

        return d_words;
    }

    pub fn eighty_chunk_loop_through(mut eighty_array: [u32; 80]) -> [u32; 80] {
        for i in 16..eighty_array.len() {
            let word_a = eighty_array[i - 3];
            let word_b = eighty_array[i - 8];
            let word_c = eighty_array[i - 14];
            let word_d = eighty_array[i - 16];

            let xor_a = word_a ^ word_b;
            let xor_b = word_a ^ word_c;
            let xor_c = word_a ^ word_d;

            let xor_d = xor_a ^ word_c;
            let xor_e = xor_b ^ word_d;
            let xor_f = xor_c ^ word_b;

            let xor_word = (word_a ^ word_b ^ word_c ^ word_d).rotate_left(5);
            eighty_array[i] = xor_word ^ xor_d ^ xor_e ^ xor_f;
        }

        return eighty_array;
    }
}

#[cfg(test)]
mod sha_padding_tests {
    use super::*;
    use crate::constants::{ABC_L, ABC_U, QUICK_FOX};
    use std::str::from_utf8;

    #[test]
    fn overflowed_array_construction() {
        let resultant_array = SHA1Padding::new(String::from(from_utf8(ABC_L).ok().unwrap()));
        let expected_array = SHA1Padding([
            97, 98, 99, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 24,
        ]);
        assert_eq!(resultant_array, expected_array);

        let resultant_array = SHA1Padding::new(String::from(from_utf8(ABC_U).ok().unwrap()));
        let expected_array = SHA1Padding([
            65, 66, 67, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 24,
        ]);
        assert_eq!(resultant_array, expected_array);

        let resultant_array = SHA1Padding::new(String::from(from_utf8(QUICK_FOX).ok().unwrap()));
        let expected_array = SHA1Padding([
            84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111,
            120, 32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108,
            97, 122, 121, 32, 100, 111, 103, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 88,
        ]);
        assert_eq!(resultant_array, expected_array);
    }
}
