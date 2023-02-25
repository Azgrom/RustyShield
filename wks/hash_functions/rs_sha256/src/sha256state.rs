use crate::{sha256hasher::Sha256Hasher, sha256words::Sha256Words};
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
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

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha256Hasher {
            size: u64::MIN,
            state: self.clone(),
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

impl From<Sha256State> for [u8; 32] {
    // TODO: replace this for loop with flatten when it stabilizes
    fn from(value: Sha256State) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        for i in 0..8 {
            [
                bytes[i * 4],
                bytes[(i * 4) + 1],
                bytes[(i * 4) + 2],
                bytes[(i * 4) + 3],
            ] = value[i].to_be_bytes();
        }

        bytes
    }
}

impl From<&Sha256State> for [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize] {
    fn from(value: &Sha256State) -> Self {
        value.data
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
        self.data.hash(state)
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self[0], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[1], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[2], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[3], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[4], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[5], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[6], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[7], f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self[0], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[1], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[2], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[3], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[4], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[5], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[6], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[7], f)
    }
}
