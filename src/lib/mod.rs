use crate::lib::constants::{H_0, H_1, H_2, H_3, H_4};
use crate::ABC_L;
use std::ops::Range;

pub(crate) mod constants;

fn memcpy<T>(dst: &mut Vec<T>, src: &mut Vec<T>, n: usize, src_len: &mut usize)
where
    T: Copy,
{
    if n < *src_len {
        for i in 0..n {
            dst[i] = src[i];
        }
    } else {
        for i in 0..*src_len {
            dst[i] = src[i];
        }
    }
}

pub fn copy_array<T>(dst: &mut Vec<T>, src: &mut Vec<T>, n: usize)
where
    T: Copy,
{
    let mut src_len = src.len() - 1;
    let mut dst_len = dst.len() - 1;

    if dst_len >= src_len {
        memcpy(dst, src, n, &mut src_len);
    } else {
        memcpy(dst, src, n, &mut dst_len);
    }
}

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
