use crate::{Sha1Hasher, BYTES_LEN};
use core::{hash::BuildHasher, ops::AddAssign};
use rs_hasher_ctx::ByteArrayWrapper;
use rs_internal_hasher::{GenericPad, HashAlgorithm, U64Size};
use rs_internal_state::{BytesLen, DWords};
use rs_n_bit_words::{NBitWord, Rotate, TSize};

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

const T_00_19: u32 = 0x5A827999;
const T_20_39: u32 = 0x6ED9EBA1;
const T_40_59: u32 = 0x8F1BBCDC;
const T_60_79: u32 = 0xCA62C1D6;

const HX: [u32; 5] = [H0, H1, H2, H3, H4];

/// `Sha1State` represents the state of a SHA-1 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Sha1State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Sha1State` extracted from a `Sha1Hasher` should not be used with the expectation of
/// continuing the hashing operation from where it left off in the original `Sha1Hasher`. It is  a snapshot of a
/// particular point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA-1 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha1::{Sha1Hasher, Sha1State};
/// let hello = b"hello";
/// let world = b" world";
///
/// let mut default_sha1hasher = Sha1State::default().build_hasher();
/// default_sha1hasher.write(hello);
///
/// let intermediate_state: Sha1State = default_sha1hasher.clone().into();
///
/// default_sha1hasher.write(world);
///
/// let mut from_sha1state: Sha1Hasher = intermediate_state.into();
/// from_sha1state.write(world);
///
/// let default_hello_world_result = default_sha1hasher.finish();
/// let from_arbitrary_state_result = from_sha1state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal state are the same between `default_sha1hasher` and `from_sha1state`
/// before the `Hasher::finish` call, the results are different due to `from_sha1state` be instantiated with an empty
/// pad while the `default_sha1hasher`'s pad already is populated with `b"hello"`.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Sha1State(pub NBitWord<u32>, pub NBitWord<u32>, pub NBitWord<u32>, pub NBitWord<u32>, pub NBitWord<u32>);

impl Sha1State {
    pub(crate) fn next_words(words: &mut DWords<u32>) {
        words[0] = (words[0] ^ words[2] ^ words[8] ^ words[13]).rotate_left(1);
        words[1] = (words[1] ^ words[3] ^ words[9] ^ words[14]).rotate_left(1);
        words[2] = (words[2] ^ words[4] ^ words[10] ^ words[15]).rotate_left(1);
        words[3] = (words[3] ^ words[5] ^ words[11] ^ words[0]).rotate_left(1);
        words[4] = (words[4] ^ words[6] ^ words[12] ^ words[1]).rotate_left(1);
        words[5] = (words[5] ^ words[7] ^ words[13] ^ words[2]).rotate_left(1);
        words[6] = (words[6] ^ words[8] ^ words[14] ^ words[3]).rotate_left(1);
        words[7] = (words[7] ^ words[9] ^ words[15] ^ words[4]).rotate_left(1);
        words[8] = (words[8] ^ words[10] ^ words[0] ^ words[5]).rotate_left(1);
        words[9] = (words[9] ^ words[11] ^ words[1] ^ words[6]).rotate_left(1);
        words[10] = (words[10] ^ words[12] ^ words[2] ^ words[7]).rotate_left(1);
        words[11] = (words[11] ^ words[13] ^ words[3] ^ words[8]).rotate_left(1);
        words[12] = (words[12] ^ words[14] ^ words[4] ^ words[9]).rotate_left(1);
        words[13] = (words[13] ^ words[15] ^ words[5] ^ words[10]).rotate_left(1);
        words[14] = (words[14] ^ words[0] ^ words[6] ^ words[11]).rotate_left(1);
        words[15] = (words[15] ^ words[1] ^ words[7] ^ words[12]).rotate_left(1);
    }

    pub(crate) fn t_00_19_round<'a>(state: &'a mut Sha1State, word: &NBitWord<u32>) -> &'a mut Sha1State {
        let t = state.0.rotate_left(5) + NBitWord::<u32>::ch(state.1, state.2, state.3) + state.4 + *word + T_00_19;

        state.4 = state.3;
        state.3 = state.2;
        state.2 = state.1.rotate_right(2);
        state.1 = state.0;
        state.0 = t;

        state
    }

    pub(crate) fn t_20_39_round<'a>(state: &'a mut Sha1State, word: &NBitWord<u32>) -> &'a mut Sha1State {
        let t = state.0.rotate_left(5) + NBitWord::<u32>::parity(state.1, state.2, state.3) + state.4 + *word + T_20_39;

        state.4 = state.3;
        state.3 = state.2;
        state.2 = state.1.rotate_right(2);
        state.1 = state.0;
        state.0 = t;

        state
    }

    pub(crate) fn t_40_59_round<'a>(state: &'a mut Sha1State, word: &NBitWord<u32>) -> &'a mut Sha1State {
        let t = state.0.rotate_left(5) + NBitWord::<u32>::maj(state.1, state.2, state.3) + state.4 + *word + T_40_59;

        state.4 = state.3;
        state.3 = state.2;
        state.2 = state.1.rotate_right(2);
        state.1 = state.0;
        state.0 = t;

        state
    }

    pub(crate) fn t_60_79_round<'a>(state: &'a mut Sha1State, word: &NBitWord<u32>) -> &'a mut Sha1State {
        let t = state.0.rotate_left(5) + NBitWord::<u32>::parity(state.1, state.2, state.3) + state.4 + *word + T_60_79;

        state.4 = state.3;
        state.3 = state.2;
        state.2 = state.1.rotate_right(2);
        state.1 = state.0;
        state.0 = t;

        state
    }
}

impl AddAssign for Sha1State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
    }
}

impl BuildHasher for Sha1State {
    type Hasher = Sha1Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha1State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha1State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u8; BYTES_LEN]> for Sha1State {
    fn from(v: [u8; BYTES_LEN]) -> Self {
        Self(
            NBitWord::from(u32::from_ne_bytes([v[0], v[1], v[2], v[3]])),
            NBitWord::from(u32::from_ne_bytes([v[4], v[5], v[6], v[7]])),
            NBitWord::from(u32::from_ne_bytes([v[8], v[9], v[10], v[11]])),
            NBitWord::from(u32::from_ne_bytes([v[12], v[13], v[14], v[15]])),
            NBitWord::from(u32::from_ne_bytes([v[16], v[17], v[18], v[19]])),
        )
    }
}

impl From<[u32; 5]> for Sha1State {
    fn from(v: [u32; 5]) -> Self {
        Self(
            NBitWord::from(v[0]),
            NBitWord::from(v[1]),
            NBitWord::from(v[2]),
            NBitWord::from(v[3]),
            NBitWord::from(v[4]),
        )
    }
}

impl From<Sha1State> for ByteArrayWrapper<BYTES_LEN> {
    fn from(value: Sha1State) -> Self {
        let x = u32::to_be_bytes(value.0.into());
        let y = u32::to_be_bytes(value.1.into());
        let z = u32::to_be_bytes(value.2.into());
        let w = u32::to_be_bytes(value.3.into());
        let t = u32::to_be_bytes(value.4.into());

        [
            x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3], z[0], z[1], z[2], z[3], w[0], w[1], w[2], w[3], t[0], t[1],
            t[2], t[3],
        ]
        .into()
    }
}

impl HashAlgorithm for Sha1State {
    type Padding = GenericPad<U64Size, 64, 0x80>;
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut words = DWords::<u32>::from(<&[u8; 64]>::try_from(bytes).unwrap());
        let mut sha1state = self.clone();

        words.into_iter().fold(&mut sha1state, Self::t_00_19_round);

        Self::next_words(&mut words);
        words[..4].iter().fold(&mut sha1state, Self::t_00_19_round);
        words[4..].iter().fold(&mut sha1state, Self::t_20_39_round);

        Self::next_words(&mut words);
        words[..8].iter().fold(&mut sha1state, Self::t_20_39_round);
        words[8..].iter().fold(&mut sha1state, Self::t_40_59_round);

        Self::next_words(&mut words);
        words[..12].iter().fold(&mut sha1state, Self::t_40_59_round);
        words[12..].iter().fold(&mut sha1state, Self::t_60_79_round);

        Self::next_words(&mut words);
        words.into_iter().fold(&mut sha1state, Self::t_60_79_round);

        *self += sha1state;
    }

    fn state_to_u64(&self) -> u64 {
        Into::<u64>::into(self.0) << 32 | Into::<u64>::into(self.1)
    }
}
