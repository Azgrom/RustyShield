use crate::{Sha512Hasher, BYTES_LEN};
use core::{hash::BuildHasher, ops::AddAssign};
use hash_ctx_lib::ByteArrayWrapper;
use internal_hasher::{GenericPad, HashAlgorithm, U128Size};
use internal_state::{BytesLen, DWords, GenericStateHasher, Sha512BitsState};
use n_bit_words_lib::NBitWord;

const H0: u64 = 0x6A09E667F3BCC908;
const H1: u64 = 0xBB67AE8584CAA73B;
const H2: u64 = 0x3C6EF372FE94F82B;
const H3: u64 = 0xA54FF53A5F1D36F1;
const H4: u64 = 0x510E527FADE682D1;
const H5: u64 = 0x9B05688C2B3E6C1F;
const H6: u64 = 0x1F83D9ABFB41BD6B;
const H7: u64 = 0x5BE0CD19137E2179;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

/// `Sha512State` represents the state of a SHA-512 hashing process.
///
/// The state holds intermediate hash calculations, allowing you to pause and resume the hashing process. This is
/// particularly beneficial when working with large data or streaming inputs. With a `Sha512State`, hashing can be done
/// in chunks without having to hold all the data in memory.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA-512 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512::{Sha512Hasher, Sha512State};
/// let hello = b"hello";
/// let world = b" world";
///
/// let mut default_sha512hasher = Sha512State::default().build_hasher();
/// default_sha512hasher.write(hello);
///
/// let intermediate_state: Sha512State = default_sha512hasher.clone().into();
///
/// default_sha512hasher.write(world);
///
/// let mut from_sha512state: Sha512Hasher = intermediate_state.into();
/// from_sha512state.write(world);
///
/// let default_hello_world_result = default_sha512hasher.finish();
/// let from_arbitrary_state_result = from_sha512state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal state are the same between `default_sha512hasher` and `from_sha512state`
/// before the `Hasher::finish` call, the results are different due to `from_sha512state` be instantiated with an empty
/// pad while the `default_sha512hasher`'s pad already is populated with `b"hello"`.
#[derive(Clone, Debug)]
pub struct Sha512State(
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
    pub NBitWord<u64>,
);

impl AddAssign<Sha512BitsState> for Sha512State {
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

impl BuildHasher for Sha512State {
    type Hasher = Sha512Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl BytesLen for Sha512State {
    fn len() -> usize {
        BYTES_LEN
    }
}

impl Default for Sha512State {
    fn default() -> Self {
        Self::from(HX)
    }
}

impl From<[u8; BYTES_LEN]> for Sha512State {
    fn from(v: [u8; BYTES_LEN]) -> Self {
        Self(
            NBitWord::from(u64::from_ne_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])),
            NBitWord::from(u64::from_ne_bytes([v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]])),
            NBitWord::from(u64::from_ne_bytes([v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23]])),
            NBitWord::from(u64::from_ne_bytes([v[24], v[25], v[26], v[27], v[28], v[29], v[30], v[31]])),
            NBitWord::from(u64::from_ne_bytes([v[32], v[33], v[34], v[35], v[36], v[37], v[38], v[39]])),
            NBitWord::from(u64::from_ne_bytes([v[40], v[41], v[42], v[43], v[44], v[45], v[46], v[47]])),
            NBitWord::from(u64::from_ne_bytes([v[48], v[49], v[50], v[51], v[52], v[53], v[54], v[55]])),
            NBitWord::from(u64::from_ne_bytes([v[56], v[57], v[58], v[59], v[60], v[61], v[62], v[63]])),
        )
    }
}

impl From<[u64; 8]> for Sha512State {
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

impl From<Sha512State> for ByteArrayWrapper<BYTES_LEN> {
    fn from(value: Sha512State) -> Self {
        let a = u64::to_be_bytes(value.0.into());
        let b = u64::to_be_bytes(value.1.into());
        let c = u64::to_be_bytes(value.2.into());
        let d = u64::to_be_bytes(value.3.into());
        let e = u64::to_be_bytes(value.4.into());
        let f = u64::to_be_bytes(value.5.into());
        let g = u64::to_be_bytes(value.6.into());
        let h = u64::to_be_bytes(value.7.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], e[0], e[1], e[2], e[3],
            e[4], e[5], e[6], e[7], f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], g[0], g[1], g[2], g[3], g[4], g[5],
            g[6], g[7], h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        ]
        .into()
    }
}

impl HashAlgorithm for Sha512State {
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
