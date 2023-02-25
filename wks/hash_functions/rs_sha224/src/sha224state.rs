use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut}
};
use u32_word_lib::U32Word;
use crate::sha224hasher::Sha224Hasher;
use crate::sha224words::Sha224Words;

const H0: u32 = 0xC1059ED8;
const H1: u32 = 0x367CD507;
const H2: u32 = 0x3070DD17;
const H3: u32 = 0xF70E5939;
const H4: u32 = 0xFFC00B31;
const H5: u32 = 0x68581511;
const H6: u32 = 0x64F98FA7;
const H7: u32 = 0xBEFA4FA4;

const SHA224_HASH_U32_WORDS_COUNT: u32 = 8;

#[derive(Clone)]
pub struct Sha224State {
    data: [U32Word; SHA224_HASH_U32_WORDS_COUNT as usize]
}

impl BuildHasher for Sha224State {
    type Hasher = Sha224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha224Hasher {
            size: u64::MIN,
            state: self.clone(),
            words: Sha224Words::default()
        }
    }
}

impl Default for Sha224State {
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
                H7.into()
            ]
        }
    }
}

impl From<Sha224State> for [u8; 28] {
    fn from(value: Sha224State) -> Self {
        let mut bytes: [u8; 28] = [0; 28];
        for i in 0..7 {
            [
                bytes[i * 4],
                bytes[(i * 4) + 1],
                bytes[(i * 4) + 2],
                bytes[(i * 4) + 3]
            ] = value[i].to_be_bytes();
        }

        bytes
    }
}

impl From<&Sha224State> for [U32Word; SHA224_HASH_U32_WORDS_COUNT as usize] {
    fn from(value: &Sha224State) -> Self {
        value.data
    }
}

impl Index<usize> for Sha224State {
    type Output = U32Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha224State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Hash for Sha224State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self[0], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[1], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[2], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[3], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[4], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[5], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[6], f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self[0], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[1], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[2], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[3], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[4], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[5], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[6], f)
    }
}
