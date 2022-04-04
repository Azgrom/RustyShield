use sha1_constants::{
    HashValues, Sha1Output, ShamblesMatrix, H_0, H_1, H_2, H_3, H_4, SHA1_BLOCK_SIZE,
};
use std::iter::{Cycle, Map};
use std::ops::Range;
use std::slice::Iter;

pub(crate) mod sha1_constants;

trait ShaProcess {
    fn new() -> Self;

    fn update(&mut self, len: usize, data: Box<[u8]>);

    fn finalize(&mut self) -> Sha1Output;
}

struct SHA1 {
    h: HashValues,
    w: ShamblesMatrix,
    size: usize,
}

impl SHA1 {
    pub(crate) fn hash_block(&self) {
        todo!()
    }
}

impl ShaProcess for SHA1 {
    fn new() -> Self {
        Self {
            h: [H_0, H_1, H_2, H_3, H_4],
            w: [0; 80],
            size: 0,
        }
    }

    fn update(&mut self, mut len: usize, data: Box<[u8]>) {
        let mut lenW = self.size & 63;
        let mut left = 64 - lenW;
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

            lenW = (lenW + left) & 63;
            len -= left;
            data_range.start += left;
            data_range.end += left;

            if lenW != 0 {
                return;
            }

            self.hash_block();
        }

        while len >= 64 {
            self.hash_block();
            data_range.start += 64;
            data_range.end += 64;
            len -= 64;
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
