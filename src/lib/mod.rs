use crate::lib::constants::{H_0, H_1, H_2, H_3, H_4};
use crate::ABC_L;
use std::ops::Range;
use std::str::from_utf8;
use sha1_ctx::disturbance_vectors_constants::DV_MASK_SIZE;

pub(crate) mod constants;
pub(crate) mod sha1_ctx;

const SHA_PADDING_LEN: usize = 64;

#[derive(Debug)]
pub struct SHAPadding([u8; SHA_PADDING_LEN]);

impl PartialEq for SHAPadding {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn ne(&self, other: &Self) -> bool {
        self.0 != other.0
    }
}

enum SHA {
    SHAPadding([u8; 64]),
    IDWords([u32; 16]),
    DWords([u32; 80]),
}

impl SHAPadding {
    pub fn new(stream: String) -> Self {
        let byte_stream = stream.as_bytes();
        let range = Range {
            start: 0,
            end: byte_stream.len(),
        };

        let mut byte = byte_stream.iter();
        let mut overflowed_array: Vec<u8> = vec![0; SHA_PADDING_LEN];

        for _ in range {
            for overflowed_byte in overflowed_array.iter_mut() {
                if let Some(x_i) = byte.next() {
                    *overflowed_byte = overflowed_byte.wrapping_add(*x_i);
                } else {
                    break;
                }
            }
        }

        let last_e = overflowed_array.len() - 1;
        overflowed_array[last_e] = 0x80;

        let bit_amount_of_byte_stream: usize = byte_stream.len() * 8;

        overflowed_array = SHAPadding::push_stream_len(overflowed_array, bit_amount_of_byte_stream);

        return SHAPadding(<[u8; SHA_PADDING_LEN]>::try_from(overflowed_array).unwrap());
    }

    fn push_stream_len(mut overflowed_array: Vec<u8>, mut stream_len: usize) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();

        if stream_len > u8::MAX as usize {
            while stream_len > u8::MAX as usize {
                vec.push(u8::MAX);
                stream_len -= u8::MAX as usize;
            }
            vec.push(stream_len as u8);
            vec.reverse();
        } else {
            vec.push(stream_len as u8);
        }

        for (index, el) in vec.iter().enumerate() {
            let x_in = overflowed_array.len() - 1 - index;
            overflowed_array[x_in] += el;
        }

        overflowed_array
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

    fn test() {
        let resultant_OArray = SHAPadding::new(String::from(from_utf8(ABC_L).ok().unwrap()));
        let d_words = resultant_OArray.convert_padding_to_words();
        let initial_eighty_array = SHAPadding::copy_padded_word_to_eighty_chunk(d_words);

        let h1 = H_1;
        let h2 = H_2;
        let h3 = H_3;
        let h4 = H_4;
    }
}

#[cfg(test)]
mod SHAPadding_tests {
    use crate::lib::constants::{ABC_L, ABC_U};
    use crate::lib::SHAPadding;
    use std::str::from_utf8;

    #[test]
    fn overflowed_array_construction() {
        let resultant_OArray = SHAPadding::new(String::from(from_utf8(ABC_L).ok().unwrap()));
        let expected_OArray = SHAPadding([
            97, 98, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 152,
        ]);
        assert_eq!(resultant_OArray, expected_OArray);

        let resultant_OArray = SHAPadding::new(String::from(from_utf8(ABC_U).ok().unwrap()));
        let expected_OArray = SHAPadding([
            65, 66, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 152,
        ]);
        assert_eq!(resultant_OArray, expected_OArray);
    }
}
