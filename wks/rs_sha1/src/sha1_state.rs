use crate::{sha1_hasher::Sha1Hasher, sha1_words::Sha1Words, H0, H1, H2, H3, H4};
use alloc::boxed::Box;
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::{Index, IndexMut},
};
use u32_word_lib::U32Word;

#[derive(Clone, Debug)]
pub struct Sha1State {
    data: [U32Word; 5],
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

#[cfg(test)]
mod test_state_trait_impls {
    use crate::{Sha1Hasher, Sha1State, H0, H1, H2, H3, H4};
    use alloc::{format, string::String};
    use core::{
        any::{Any, TypeId},
        hash::{BuildHasher, Hash},
    };
    use u32_word_lib::U32Word;

    #[test]
    fn build_default_sha1_state_hasher() {
        let state = Sha1State::default();
        let hasher_default = BuildHasher::build_hasher(&state);

        assert_eq!(hasher_default.type_id(), TypeId::of::<Sha1Hasher>());

        let mut custom_hasher = BuildHasher::build_hasher(&state);
        String::new().hash(&mut custom_hasher);
        assert_eq!(custom_hasher.type_id(), TypeId::of::<Sha1Hasher>());
        assert_ne!(custom_hasher, hasher_default);
    }

    #[test]
    fn default_sha1_state() {
        let default_state = Sha1State::default();
        let expected_result = Sha1State {
            data: [
                U32Word::from(H0),
                U32Word::from(H1),
                U32Word::from(H2),
                U32Word::from(H3),
                U32Word::from(H4),
            ],
        };

        assert_eq!(default_state, expected_result);
        assert_eq!(default_state.type_id(), expected_result.type_id());
    }

    #[test]
    fn index_sha1_state() {
        let default_sha1_state = Sha1State::default();

        assert_eq!(default_sha1_state[0], U32Word::from(H0));
        assert_eq!(default_sha1_state[1], U32Word::from(H1));
        assert_eq!(default_sha1_state[2], U32Word::from(H2));
        assert_eq!(default_sha1_state[3], U32Word::from(H3));
        assert_eq!(default_sha1_state[4], U32Word::from(H4));
    }

    #[test]
    fn index_mut_sha1_state() {
        let mut default_sha1_state: Sha1State = Sha1State::default();

        assert_eq!(default_sha1_state[0], U32Word::from(H0));
        default_sha1_state[0] = U32Word::from(u32::MAX);
        assert_ne!(default_sha1_state[0], U32Word::from(H0));
    }

    #[test]
    fn lower_hex_format() {
        let state = Sha1State::default();
        let expected_result = "67452301efcdab8998badcfe10325476c3d2e1f0";
        assert_eq!(format!("{:08x}", state), expected_result);
    }

    #[test]
    fn upper_hex_format() {
        let state = Sha1State::default();
        let expected_result = "67452301EFCDAB8998BADCFE10325476C3D2E1F0";

        assert_eq!(format!("{:08X}", state), expected_result);
    }
}
