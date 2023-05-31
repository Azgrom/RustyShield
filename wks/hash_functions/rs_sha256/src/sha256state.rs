use crate::{Sha256Hasher, BYTES_LEN};
use core::{hash::BuildHasher, ops::AddAssign};
use rs_internal_hasher::{GenericPad, HashAlgorithm, U64Size};
use rs_internal_state::{BytesLen, DWords, GenericStateHasher, Sha256BitsState};
use rs_n_bit_words::NBitWord;
use rs_hasher_ctx_lib::ByteArrayWrapper;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

const HX: [u32; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

/// `Sha256State` signifies the state of a SHA-256 hashing operation.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Sha256State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Sha256State` extracted from a `Sha256Hasher` should not be used with the expectation of
/// continuing the hashing operation from where it left off in the original `Sha256Hasher`. It is  a snapshot of a
/// particular point in the process, not a means to resume the process.
///
/// # Example
///
/// The following example demonstrates the persistence of a SHA-256 hashing operation's state:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha256::{Sha256Hasher, Sha256State};
/// let hello = b"hello";
/// let world = b" world";
///
/// let mut default_sha256hasher = Sha256State::default().build_hasher();
/// default_sha256hasher.write(hello);
///
/// let intermediate_state: Sha256State = default_sha256hasher.clone().into();
///
/// default_sha256hasher.write(world);
///
/// let mut from_sha256state: Sha256Hasher = intermediate_state.into();
/// from_sha256state.write(world);
///
/// let default_hello_world_result = default_sha256hasher.finish();
/// let from_arbitrary_state_result = from_sha256state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, despite the internal states of `default_sha256hasher` and `from_sha256state` being identical before
/// the `Hasher::finish` call, the results diverge due to `from_sha256state` being initiated with an empty pad while
/// `default_sha256hasher`'s pad is already filled with `b"hello"`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha256State(
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
);

impl AddAssign<Sha256BitsState> for Sha256State {
    fn add_assign(&mut self, rhs: Sha256BitsState) {
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

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha256State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u8; BYTES_LEN]> for Sha256State {
    fn from(v: [u8; BYTES_LEN]) -> Self {
        Self(
            NBitWord::from(u32::from_ne_bytes([v[0], v[1], v[2], v[3]])),
            NBitWord::from(u32::from_ne_bytes([v[4], v[5], v[6], v[7]])),
            NBitWord::from(u32::from_ne_bytes([v[8], v[9], v[10], v[11]])),
            NBitWord::from(u32::from_ne_bytes([v[12], v[13], v[14], v[15]])),
            NBitWord::from(u32::from_ne_bytes([v[16], v[17], v[18], v[19]])),
            NBitWord::from(u32::from_ne_bytes([v[20], v[21], v[22], v[23]])),
            NBitWord::from(u32::from_ne_bytes([v[24], v[25], v[26], v[27]])),
            NBitWord::from(u32::from_ne_bytes([v[28], v[29], v[30], v[31]])),
        )
    }
}

impl From<[u32; 8]> for Sha256State {
    fn from(v: [u32; 8]) -> Self {
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

impl From<Sha256State> for ByteArrayWrapper<BYTES_LEN> {
    fn from(value: Sha256State) -> Self {
        let a = u32::to_be_bytes(value.0.into());
        let b = u32::to_be_bytes(value.1.into());
        let c = u32::to_be_bytes(value.2.into());
        let d = u32::to_be_bytes(value.3.into());
        let e = u32::to_be_bytes(value.4.into());
        let f = u32::to_be_bytes(value.5.into());
        let g = u32::to_be_bytes(value.6.into());
        let h = u32::to_be_bytes(value.7.into());

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3], e[0], e[1],
            e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3], h[0], h[1], h[2], h[3],
        ]
        .into()
    }
}

impl HashAlgorithm for Sha256State {
    type Padding = GenericPad<U64Size, 64, 0x80>;
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut state = Sha256BitsState(
            self.0,
            self.1,
            self.2,
            self.3,
            self.4,
            self.5,
            self.6,
            self.7,
            DWords::<u32>::from(<&[u8; 64]>::try_from(bytes).unwrap()),
        );

        state.block_00_15();
        state.block_16_31();
        state.block_32_47();
        state.block_48_63();

        *self += state;
    }

    fn state_to_u64(&self) -> u64 {
        Into::<u64>::into(self.0) << 32 | Into::<u64>::into(self.1)
    }
}
