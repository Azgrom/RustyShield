use crate::{Sha512_256Hasher, BYTES_LEN};
use core::{hash::BuildHasher, ops::AddAssign};
use internal_hasher::{GenericPad, HashAlgorithm, U128Size};
use internal_state::{BytesLen, DWords, GenericStateHasher, Sha512BitsState};
use n_bit_words_lib::NBitWord;
use rs_hasher_ctx_lib::ByteArrayWrapper;

const H0: u64 = 0x22312194FC2BF72C;
const H1: u64 = 0x9F555FA3C84C64C2;
const H2: u64 = 0x2393B86B6F53B151;
const H3: u64 = 0x963877195940EABD;
const H4: u64 = 0x96283EE2A88EFFE3;
const H5: u64 = 0xBE5E1E2553863992;
const H6: u64 = 0x2B0199FC2C85B8AA;
const H7: u64 = 0x0EB72DDC81C52CA2;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

/// `Sha512_256State` represents the state of a SHA-512/256 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Sha512_256State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Sha512_256State` extracted from a `Sha512_256Hasher` should not be used with the expectation of
/// continuing the hashing operation from where it left off in the original `Sha512_256Hasher`. It is  a snapshot of a
/// particular point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA-512/256 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512_256::{Sha512_256Hasher, Sha512_256State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_sha512_256state = Sha512_256State::default();
///
/// let mut default_sha512_256hasher = default_sha512_256state.build_hasher();
/// default_sha512_256hasher.write(hello);
///
/// let intermediate_state: Sha512_256State = default_sha512_256hasher.clone().into();
///
/// default_sha512_256hasher.write(world);
///
/// let mut from_sha512_256state: Sha512_256Hasher = intermediate_state.into();
/// from_sha512_256state.write(world);
///
/// let default_hello_world_result = default_sha512_256hasher.finish();
/// let from_arbitrary_state_result = from_sha512_256state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, despite the internal states being identical between `default_sha512_256hasher` and `from_sha512_256state`
/// prior to the `Hasher::finish` call, the resultant hashes differ. This is because `from_sha512_256state` is instantiated
/// with an empty pad, whereas `default_sha512_256hasher`'s pad has already been populated with `b"hello"`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha512_256State(
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
);

impl AddAssign<Sha512BitsState> for Sha512_256State {
    fn add_assign(&mut self, rhs: Sha512BitsState) {
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

impl BuildHasher for Sha512_256State {
    type Hasher = Sha512_256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha512_256State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha512_256State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u8; BYTES_LEN]> for Sha512_256State {
    fn from(v: [u8; BYTES_LEN]) -> Self {
        Self(
            NBitWord::from(u64::from_ne_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])),
            NBitWord::from(u64::from_ne_bytes([v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]])),
            NBitWord::from(u64::from_ne_bytes([v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23]])),
            NBitWord::from(u64::from_ne_bytes([v[24], v[25], v[26], v[27], v[28], v[29], v[30], v[31]])),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
            NBitWord::from(u64::default()),
        )
    }
}

impl From<[u64; 8]> for Sha512_256State {
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

impl From<Sha512_256State> for ByteArrayWrapper<BYTES_LEN> {
    fn from(value: Sha512_256State) -> Self {
        let a = u64::to_be_bytes(value.0.into());
        let b = u64::to_be_bytes(value.1.into());
        let c = u64::to_be_bytes(value.2.into());
        let d = u64::to_be_bytes(value.3.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        ]
        .into()
    }
}

impl HashAlgorithm for Sha512_256State {
    type Padding = GenericPad<U128Size, 128, 0x80>;
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut state = Sha512BitsState(
            self.0,
            self.1,
            self.2,
            self.3,
            self.4,
            self.5,
            self.6,
            self.7,
            DWords::<u64>::from(<&[u8; 128]>::try_from(bytes).unwrap()),
        );

        state.block_00_15();
        state.block_16_31();
        state.block_32_47();
        state.block_48_63();
        state.block_64_79();

        *self += state;
    }

    fn state_to_u64(&self) -> u64 {
        Into::<u64>::into(self.0) << 32 | Into::<u64>::into(self.1)
    }
}
