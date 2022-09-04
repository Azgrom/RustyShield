use crate::sha1::sha1_constants::{DWords, ShaPadding, SHA1_PADDING, SHA1_BLOCK_SIZE};
use std::mem;
use std::ops::{Deref, Range};
use crate::bit_length;

pub trait Padding {
    fn new(stream: &[u8]) -> Self;
    fn to_d_words(&self) -> DWords;
}

#[derive(Debug)]
pub struct SHA1Padding {
    data: [u8; SHA1_BLOCK_SIZE as usize]
}

impl Padding for SHA1Padding {
    fn new(stream: &[u8]) -> Self {
        let mut last_index = 0;
        let mut padding: ShaPadding = [0; 64];
        let mut wrapped_array = Vec::new();

        while last_index < stream.len() - 1 {
            wrapped_array = stream
                .iter()
                .enumerate()
                .zip(SHA1_PADDING.iter())
                .map(|(byte, pad)| {
                    last_index += 1;
                    return pad.wrapping_add(*byte.1);
                })
                .collect::<Vec<u8>>();
        }

        if wrapped_array.len() > 63 {
            wrapped_array[last_index % 64] = 0x80;
        } else {
            wrapped_array.push(0x80);
        }

        for (index, i) in wrapped_array.iter().enumerate() {
            padding[index] = *i;
        }

        let stream_len = bit_length(stream);
        let range = Range {
            start: 0,
            end: mem::size_of_val(&stream_len) * 7,
        }
            .step_by(8);

        let vec = range
            .map(|r_shift| (stream_len >> r_shift) as u8)
            .collect::<Vec<u8>>();

        for (index, el) in vec.iter().enumerate() {
            let x_in = padding.len() - 1 - index;
            padding[x_in] += el.to_be();
        }

        return Self { data: padding };
    }

    fn to_d_words(&self) -> DWords {
        let range = Range { start: 0, end: 16 };
        let mut x: DWords = [0; 16];

        for word in range {
            let y = word * 4;
            x[word] = ((self[0 + y] as u32) << 24)
                + ((self[1 + y] as u32) << 16)
                + ((self[2 + y] as u32) << 8)
                + self[3 + y] as u32;
        }

        return x;
    }
}

impl Deref for SHA1Padding {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl PartialEq for SHA1Padding {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl PartialEq<[u8; SHA1_BLOCK_SIZE as usize]> for SHA1Padding {
    fn eq(&self, other: &[u8; SHA1_BLOCK_SIZE as usize]) -> bool {
        self.data == *other
    }
}

#[cfg(test)]
mod partial_eq_padding_tests {
    use super::*;
    use crate::constants::HEIKE_MONOGATARI;

    #[test]
    fn padding_eq_test() {
        let x = SHA1Padding::new(HEIKE_MONOGATARI);
        let expected = [
            128, 104, 101, 32, 115, 111, 117, 110, 100, 32, 111, 102, 32, 116, 104, 101, 32, 71,
            105, 111, 110, 32, 83, 104, 197, 141, 106, 97, 32, 98, 101, 108, 108, 115, 32, 101, 99,
            104, 111, 101, 115, 32, 116, 104, 101, 32, 105, 109, 112, 101, 114, 109, 97, 110, 101,
            110, 99, 101, 32, 111, 102, 10, 107, 220,
        ];
        assert_eq!(x, expected);
    }

    #[test]
    fn padding_ne_test() {
        let x = SHA1Padding::new(HEIKE_MONOGATARI);
        let expected = [0; 64];
        assert_ne!(x, expected);
    }
}
