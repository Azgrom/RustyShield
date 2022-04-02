use sha1_constants::{
    HashValues, Sha1Output, ShamblesMatrix, H_0, H_1, H_2, H_3, H_4, SHA1_BLOCK_SIZE,
};

pub(crate) mod sha1_constants;

trait ShaProcess {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finalize(&self) -> Sha1Output;
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
            size: 0
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut i: usize = 0;
        let mut lenW = 0;

        while i < 80 as usize {
            self.w[lenW] <<= 8;
            self.w[lenW] |= data[i] as u32;

            if lenW % 64 == 0 {
                self.hash_block();
                lenW = 0;
            }
            lenW += 1;
            i += 1;
        }
    }

    fn finalize(&self) -> Sha1Output {
        let pad0x80: u8 = 0x80;
        let pad0x00: u8 = 0x00;
        let bit_shifting = [24, 16, 8, 0].iter().cycle();

        let mut pad: [u8; 8] = [0; 8];

        pad.map(|x| self.w.rotate_right())

        pad[]
    }
}
