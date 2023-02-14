use crate::{sha1_hasher::Sha1Hasher, sha1_words::Sha1Words, H0, H1, H2, H3, H4};
use core::{
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut},
};

#[derive(Clone)]
pub struct Sha1State {
    data: [u32; 5],
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
            data: [H0, H1, H2, H3, H4],
        }
    }
}

impl Index<usize> for Sha1State {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha1State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Sha1State {
    pub(crate) fn to_slice(&self) -> &[u32; 5] {
        &self.data
    }

    pub(crate) fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }

    pub(crate) fn bytes_hash(&self) -> [u8; 20] {
        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self.data[i].to_be_bytes()
        });

        hash
    }

    pub(crate) fn hex_hash(&self) -> String {
        self.data
            .iter()
            .map(|&b| format!("{:08x}", b))
            .collect::<String>()
    }
}
