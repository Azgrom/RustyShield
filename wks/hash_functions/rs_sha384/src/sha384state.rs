use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{Hash, Hasher},
    ops::{Index, IndexMut}
};
use core::hash::BuildHasher;
use n_bit_words_lib::U64Word;
use crate::{
    SHA384PADDING_SIZE,
    sha384hasher::Sha384Hasher,
    sha384words::Sha384Words
};

const H0: u64 = 0xCBBB9D5DC1059ED8;
const H1: u64 = 0x629A292A367CD507;
const H2: u64 = 0x9159015A3070DD17;
const H3: u64 = 0x152FECD8F70E5939;
const H4: u64 = 0x67332667FFC00B31;
const H5: u64 = 0x8EB44A8768581511;
const H6: u64 = 0xDB0C2E0D64F98FA7;
const H7: u64 = 0x47B5481DBEFA4fA4;

const SHA384STATE_CONSTANTS_COUNT: usize = 8;

#[derive(Clone)]
pub(crate) struct Sha384State {
    data: [U64Word; SHA384STATE_CONSTANTS_COUNT]
}

impl BuildHasher for Sha384State {
    type Hasher = Sha384Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha384Hasher {
            size: u128::MIN,
            state: self.clone(),
            words: Sha384Words::default()
        }
    }
}

impl Default for Sha384State {
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

impl From<Sha384State> for [u8; SHA384PADDING_SIZE] {
    fn from(value: Sha384State) -> Self {
        let mut bytes = [0; SHA384PADDING_SIZE];
        for i in 0..5 {
            [
                bytes[i * 4],
                bytes[(i * 4) + 1],
                bytes[(i * 4) + 2],
                bytes[(i * 4) + 3],
                bytes[(i * 4) + 4],
                bytes[(i * 4) + 5],
                bytes[(i * 4) + 6],
                bytes[(i * 4) + 7]
            ] = value[i].to_be_bytes();
        }

        bytes
    }
}

impl From<&Sha384State> for [U64Word; SHA384STATE_CONSTANTS_COUNT] {
    fn from(value: &Sha384State) -> Self {
        value.data
    }
}

impl Index<usize> for Sha384State {
    type Output = U64Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha384State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Hash for Sha384State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self[0].hash(state);
        self[1].hash(state);
        self[2].hash(state);
        self[3].hash(state);
        self[4].hash(state);
        self[5].hash(state);
        self[6].hash(state);
        self[7].hash(state);
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self[0], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[1], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[2], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[3], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[4], f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self[5], f)
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";

impl UpperHex for Sha384State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self[0], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[1], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[2], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[3], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[4], f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self[5], f)
    }
}
