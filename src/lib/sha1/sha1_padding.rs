use crate::sha1::sha1_constants::{DWords, ShaPadding, SHA1_PADDING};
use std::mem;
use std::ops::Range;

#[derive(Debug)]
pub struct SHA1Padding(ShaPadding);

impl SHA1Padding {
    pub fn new(stream: String) -> Self {
        let byte_stream = stream.as_bytes();
        let byte_stream_len = byte_stream.len();

        let padding = Self::wrap_pad(byte_stream, byte_stream_len);
        let mut padding = Self::init(padding);

        let bit_amount_of_byte_stream: usize = byte_stream_len * mem::size_of_val(&byte_stream_len);
        padding.push_stream_len(bit_amount_of_byte_stream);

        return padding;
    }

    pub fn unwrap(&self) -> ShaPadding {
        self.0
    }

    pub fn convert_padding_to_words(&self) -> DWords {
        let range = Range { start: 0, end: 16 };
        let mut x: DWords = [0; 16];

        for word in range {
            let y = word * 4;
            x[word] = ((self.0[0 + y] as u32) << 24)
                + ((self.0[1 + y] as u32) << 16)
                + ((self.0[2 + y] as u32) << 8)
                + self.0[3 + y] as u32;
        }

        return x;
    }

    fn init(padding: ShaPadding) -> Self {
        Self(padding)
    }

    fn wrap_pad(byte_stream: &[u8], byte_stream_len: usize) -> ShaPadding {
        let mut last_index = 0;
        let mut padding: ShaPadding = [0; 64];
        let mut wrapped_array = Vec::new();

        while last_index < byte_stream_len - 1 {
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

        if wrapped_array.len() > 63 {
          wrapped_array[last_index % 64] = 0x80;
        } else {
            wrapped_array.push(0x80);
        }

        for (index, i) in wrapped_array.iter().enumerate() {
            padding[index] = *i;
        }
        padding
    }

    fn push_stream_len(&mut self, stream_len: usize) {
        let range = Range {
            start: 0,
            end: mem::size_of_val(&stream_len) * 7,
        }
        .step_by(8);

        let vec = range
            .map(|r_shift| (stream_len >> r_shift) as u8)
            .collect::<Vec<u8>>();

        for (index, el) in vec.iter().enumerate() {
            let x_in = self.0.len() - 1 - index;
            self.0[x_in] += el;
        }
    }
}

impl PartialEq for SHA1Padding {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

#[cfg(test)]
mod partial_eq_padding_tests {
    use super::*;
    use std::str::from_utf8;
    use crate::constants::HEIKE_MONOGATARI;

    #[test]
    fn padding_eq_test() {
        let x = SHA1Padding::new(String::from(from_utf8(HEIKE_MONOGATARI).ok().unwrap()));
        let expected = SHA1Padding([128, 104, 101, 32, 115, 111, 117, 110, 100, 32, 111, 102, 32, 116, 104, 101, 32, 71, 105,
            111, 110, 32, 83, 104, 197, 141, 106, 97, 32, 98, 101, 108, 108, 115, 32, 101, 99, 104,
            111, 101, 115, 32, 116, 104, 101, 32, 105, 109, 112, 101, 114, 109, 97, 110, 101, 110, 99,
            101, 32, 111, 102, 10, 107, 220,]);
        assert_eq!(x, expected);
    }

    #[test]
    fn padding_ne_test() {
        let x = SHA1Padding::new(String::from(from_utf8(HEIKE_MONOGATARI).ok().unwrap()));
        let expected = SHA1Padding([0; 64]);
        assert_ne!(x, expected);
    }
}
