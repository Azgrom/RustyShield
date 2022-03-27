use std::ops::Range;

const SHA_PADDING_LEN: usize = 4;

#[derive(Debug)]
struct SHAPadding([u8; SHA_PADDING_LEN]);

impl PartialEq for SHAPadding {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn ne(&self, other: &Self) -> bool {
        self.0 != other.0
    }
}

impl SHAPadding {
    fn new(stream: String) -> Self {
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

        let o = overflowed_array.len();
        overflowed_array[o - 1] = 128;

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
}

#[cfg(test)]
mod SHAPadding_tests {
    use crate::{ABC_L, ABC_U};
    use std::str::from_utf8;
    use crate::lib::SHAPadding;

    #[test]
    fn overflowed_array_construction() {
        let resultant_OArray = SHAPadding::new(String::from(from_utf8(ABC_L).ok().unwrap()));
        let expected_OArray = SHAPadding([97, 98, 99, 152]);
        assert_eq!(resultant_OArray, expected_OArray);

        let resultant_OArray = SHAPadding::new(String::from(from_utf8(ABC_U).ok().unwrap()));
        let expected_OArray = SHAPadding([65, 66, 67, 152]);
        assert_eq!(resultant_OArray, expected_OArray);
    }
}
