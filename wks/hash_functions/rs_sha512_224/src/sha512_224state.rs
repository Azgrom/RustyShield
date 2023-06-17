use crate::{Sha512_224Hasher, BYTES_LEN};
use core::{hash::BuildHasher, ops::AddAssign};
use rs_hasher_ctx::ByteArrayWrapper;
use rs_internal_hasher::{GenericPad, HashAlgorithm, U128Size};
use rs_internal_state::{BytesLen, DWords, Sha512BitsState};
use rs_n_bit_words::{NBitWord, TSize};

const H0: u64 = 0x8C3D37C819544DA2;
const H1: u64 = 0x73E1996689DCD4D6;
const H2: u64 = 0x1DFAB7AE32FF9C82;
const H3: u64 = 0x679DD514582F9FCF;
const H4: u64 = 0x0F6D2B697BD44DA8;
const H5: u64 = 0x77E36F7304C48942;
const H6: u64 = 0x3F9D85A86A1D36C8;
const H7: u64 = 0x1112E6AD91D692A1;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

/// `Sha512_224State` represents the state of a SHA-512/224 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Sha512_224State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Sha512_224State` extracted from a `Sha512_224Hasher` should not be used with the expectation of
/// continuing the hashing operation from where it left off in the original `Sha512_224Hasher`. It is  a snapshot of a
/// particular point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA-512/224 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512_224::{Sha512_224Hasher, Sha512_224State};
/// let hello = b"hello";
/// let world = b" world";
///
/// let mut default_sha512_224hasher = Sha512_224State::default().build_hasher();
/// default_sha512_224hasher.write(hello);
///
/// let intermediate_state: Sha512_224State = default_sha512_224hasher.clone().into();
///
/// default_sha512_224hasher.write(world);
///
/// let mut from_sha512_224state: Sha512_224Hasher = intermediate_state.into();
/// from_sha512_224state.write(world);
///
/// let default_hello_world_result = default_sha512_224hasher.finish();
/// let from_arbitrary_state_result = from_sha512_224state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_sha512_224hasher` and `from_sha512_224state`
/// before the `Hasher::finish` call, the results are different. This is because `from_sha512_224state` is instantiated with an empty
/// pad, while the `default_sha512_224hasher`'s pad already has `b"hello"` populated in it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha512_224State(
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
);

impl Sha512_224State {
    fn round<'a>(state: &'a mut Self, t: (&NBitWord<u64>, &u64)) -> &'a mut Self {
        let t0 = state.4.sigma1() + NBitWord::<u64>::ch(state.4, state.5, state.6) + state.7 + *t.0 + *t.1;
        let t1 = state.0.sigma0() + NBitWord::<u64>::maj(state.0, state.1, state.2);
        state.7 = state.6;
        state.6 = state.5;
        state.5 = state.4;
        state.4 = state.3 + t0;
        state.3 = state.2;
        state.2 = state.1;
        state.1 = state.0;
        state.0 = t0 + t1;

        state
    }
}

impl AddAssign for Sha512_224State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
        self.5 += rhs.5;
        self.6 += rhs.6;
        self.7 += rhs.7;
    }
}

impl BuildHasher for Sha512_224State {
    type Hasher = Sha512_224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha512_224State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha512_224State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u8; BYTES_LEN]> for Sha512_224State {
    fn from(v: [u8; BYTES_LEN]) -> Self {
        Self(
            NBitWord::from(u64::from_ne_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])),
            NBitWord::from(u64::from_ne_bytes([v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]])),
            NBitWord::from(u64::from_ne_bytes([v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23]])),
            NBitWord::from(u64::from_ne_bytes([v[24], v[25], v[26], v[27], 0, 0, 0, 0])),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
        )
    }
}

impl From<[u64; 8]> for Sha512_224State {
    fn from(v: [u64; 8]) -> Self {
        Self(
            NBitWord::from(v[0]),
            NBitWord::from(v[1]),
            NBitWord::from(v[2]),
            NBitWord::from(v[3]),
            NBitWord::from(v[4]),
            NBitWord::from(v[5]),
            NBitWord::from(v[6]),
            NBitWord::from(v[7]),
        )
    }
}

impl From<Sha512_224State> for ByteArrayWrapper<BYTES_LEN> {
    fn from(value: Sha512_224State) -> Self {
        let a = u64::to_be_bytes(value.0.into());
        let b = u64::to_be_bytes(value.1.into());
        let c = u64::to_be_bytes(value.2.into());
        let d = u64::to_be_bytes(value.3.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3],
        ]
        .into()
    }
}

impl HashAlgorithm for Sha512_224State {
    type Padding = GenericPad<U128Size, 128, 0x80>;
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut sha512_224state = self.clone();
        let mut words = DWords::<u64>::from(<&[u8; 128]>::try_from(bytes).unwrap());

        words.into_iter().zip(Sha512BitsState::K_00_TO_15.iter()).fold(&mut sha512_224state, Self::round);

        Sha512BitsState::next_words(&mut words);
        words.into_iter().zip(Sha512BitsState::K_16_TO_31.iter()).fold(&mut sha512_224state, Self::round);

        Sha512BitsState::next_words(&mut words);
        words.into_iter().zip(Sha512BitsState::K_32_TO_47.iter()).fold(&mut sha512_224state, Self::round);

        Sha512BitsState::next_words(&mut words);
        words.into_iter().zip(Sha512BitsState::K_48_TO_63.iter()).fold(&mut sha512_224state, Self::round);

        Sha512BitsState::next_words(&mut words);
        words.into_iter().zip(Sha512BitsState::K_64_TO_79.iter()).fold(&mut sha512_224state, Self::round);

        *self += sha512_224state;
    }

    fn state_to_u64(&self) -> u64 {
        self.0.into()
    }
}
