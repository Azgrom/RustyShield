use crate::{
    sha256_hasher::Sha256Hasher, sha256_words::Sha256Words, H0, H1, H2, H3, H4, H5, H6, H7,
    SHA256_HASH_U32_WORDS_COUNT,
};
use core::{
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut},
};
use u32_word_lib::U32Word;

pub struct Sha256State {
    data: [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize],
}

impl Sha256State {
    pub(crate) fn u32_states(&self) -> [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize] {
        self.data
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
