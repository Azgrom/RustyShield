use std::mem;

mod constants;
mod sha1;

pub fn bit_length(byte_stream: &[u8]) -> usize {
    let byte_stream_len = byte_stream.len();
    byte_stream_len * mem::size_of_val(&byte_stream_len)
}

fn minimum_512_multiple(length: usize) -> usize {
    let mut k = 0;
    while (length + 1 + k + 64) % 512 != 0 {
        k += 1;
    }

    return k;
}

mod sha2 {
    const H_0: u32 = 0x6a09e667;
    const H_1: u32 = 0xbb67ae85;
    const H_2: u32 = 0x3c6ef372;
    const H_3: u32 = 0xa54ff53a;
    const H_4: u32 = 0x510e527f;
    const H_5: u32 = 0x9b05688c;
    const H_6: u32 = 0x1f83d9ab;
    const H_7: u32 = 0x5be0cd19;

    const SIXTY_FOURTH_PRIMES_CUBIC_ROOT_FRACTION_PART: [u16; 64] = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311,
    ];

    #[cfg(test)]
    mod sha2_tests {
        use crate::constants::HEIKE_MONOGATARI;
        use crate::{bit_length, minimum_512_multiple, wrapping_add_from_slice};
        use std::ops::Range;
        #[test]
        fn test() {
            let k: [u32; 64] = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2,
            ];

            let byte_message_stream = HEIKE_MONOGATARI;
            let byte_message_stream_len = byte_message_stream.len();

            let mut message_pad_chunk = byte_message_stream.chunks(64);
            let mut padding: &mut [u8; 64] = &mut [0u8; 64];

            for chunk in message_pad_chunk.next() {
                for (index, pad) in chunk.iter().enumerate() {
                    padding[index].wrapping_add(*pad);
                }
            }

            let message_bit_length = bit_length(byte_message_stream);
            let k = minimum_512_multiple(message_bit_length);

            println!("");
        }
    }

    // f32.cbrt(
    // f32.fract()
}

fn wrapping_add_from_slice(dst: &mut [u8], src: &[u8]) {
    for (i, x) in src.iter().enumerate() {
        dst[i].wrapping_add(*x);
    }
}