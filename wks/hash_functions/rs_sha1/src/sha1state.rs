use crate::{sha1hasher::Sha1Hasher, sha1words::Sha1Words};
use alloc::boxed::Box;
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut},
};
use n_bit_words_lib::U32Word;

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

#[derive(Clone, Debug)]
pub struct Sha1State {
    pub(crate) data: [U32Word; 5],
}

impl BuildHasher for Sha1State {
    type Hasher = Sha1Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha1Hasher {
            size: u64::default(),
            state: Sha1State { data: self.data },
            words: Sha1Words::default(),
        }
    }
}

impl Default for Sha1State {
    fn default() -> Self {
        Self {
            data: [H0.into(), H1.into(), H2.into(), H3.into(), H4.into()],
        }
    }
}

impl Hash for Sha1State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self[0].hash(state);
        self[1].hash(state);
        self[2].hash(state);
        self[3].hash(state);
        self[4].hash(state);
    }
}

impl Index<usize> for Sha1State {
    type Output = U32Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha1State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl LowerHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let results = [
            LowerHex::fmt(&self[0], f),
            LowerHex::fmt(&self[1], f),
            LowerHex::fmt(&self[2], f),
            LowerHex::fmt(&self[3], f),
            LowerHex::fmt(&self[4], f),
        ];
        if results.iter().any(|&x| x.is_err()) {
            return Err(Error);
        }

        Ok(())
    }
}

impl PartialEq for Sha1State {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl UpperHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let results = [
            UpperHex::fmt(&self[0], f),
            UpperHex::fmt(&self[1], f),
            UpperHex::fmt(&self[2], f),
            UpperHex::fmt(&self[3], f),
            UpperHex::fmt(&self[4], f),
        ];
        if results.iter().any(|&x| x.is_err()) {
            return Err(Error);
        }

        Ok(())
    }
}

impl Sha1State {
    pub(crate) fn to_slice(&self) -> &[U32Word; 5] {
        &self.data
    }

    pub(crate) fn bytes_hash(&self) -> Box<[u8]> {
        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self.data[i].to_be_bytes()
        });

        Box::new(hash)
    }
}
