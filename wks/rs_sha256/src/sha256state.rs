use crate::{sha256hasher::Sha256Hasher, sha256words::Sha256Words};
use alloc::boxed::Box;
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut},
};
use u32_word_lib::U32Word;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

const SHA256_HASH_U32_WORDS_COUNT: u32 = 8;

#[derive(Clone, Debug)]
pub struct Sha256State {
    data: [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize],
}

impl Sha256State {
    pub(crate) fn u32_states(&self) -> [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize] {
        self.data
    }

    pub(crate) fn bytes_hash(&self) -> Box<[u8]> {
        let mut hash: [u8; 32] = [0; 32];
        for i in 0..8 {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self[i].to_be_bytes();
        }

        Box::new(hash)
    }
}

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha256Hasher {
            size: u64::MIN,
            state: Sha256State { data: self.data },
            words: Sha256Words::default(),
        }
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self {
            data: [
                H0.into(),
                H1.into(),
                H2.into(),
                H3.into(),
                H4.into(),
                H5.into(),
                H6.into(),
                H7.into(),
            ],
        }
    }
}

impl Index<usize> for Sha256State {
    type Output = U32Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha256State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Hash for Sha256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl LowerHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let results = [
            LowerHex::fmt(&self[0], f),
            LowerHex::fmt(&self[1], f),
            LowerHex::fmt(&self[2], f),
            LowerHex::fmt(&self[3], f),
            LowerHex::fmt(&self[4], f),
            LowerHex::fmt(&self[5], f),
            LowerHex::fmt(&self[6], f),
            LowerHex::fmt(&self[7], f),
        ];
        if results.iter().any(|&x| x.is_err()) {
            return Err(Error);
        }

        Ok(())
    }
}

impl UpperHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let result = [
            UpperHex::fmt(&self[0], f),
            UpperHex::fmt(&self[1], f),
            UpperHex::fmt(&self[2], f),
            UpperHex::fmt(&self[3], f),
            UpperHex::fmt(&self[4], f),
            UpperHex::fmt(&self[5], f),
            UpperHex::fmt(&self[6], f),
            UpperHex::fmt(&self[7], f),
        ];
        if result.iter().any(|&x| x.is_err()) {
            return Err(Error);
        }

        Ok(())
    }
}
