use crate::Sha512_256Hasher;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::BuildHasher,
    ops::AddAssign,
};
use internal_hasher::{HashAlgorithm, Sha1FamilyPad, U128Size};
use internal_state::{BytesLen, DWords, GenericStateHasher, Sha512BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};
use n_bit_words_lib::NBitWord;

const H0: u64 = 0x22312194FC2BF72C;
const H1: u64 = 0x9F555FA3C84C64C2;
const H2: u64 = 0x2393B86B6F53B151;
const H3: u64 = 0x963877195940EABD;
const H4: u64 = 0x96283EE2A88EFFE3;
const H5: u64 = 0xBE5E1E2553863992;
const H6: u64 = 0x2B0199FC2C85B8AA;
const H7: u64 = 0x0EB72DDC81C52CA2;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];
const BYTES_LEN: usize = 32;

#[derive(Clone, Debug)]
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

impl From<Sha512_256State> for [u8; BYTES_LEN] {
    fn from(value: Sha512_256State) -> Self {
        let a = u64::to_be_bytes(value.0.into());
        let b = u64::to_be_bytes(value.1.into());
        let c = u64::to_be_bytes(value.2.into());
        let d = u64::to_be_bytes(value.3.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        ]
    }
}

impl HashAlgorithm for Sha512_256State {
    type Padding = Sha1FamilyPad<U128Size, 128>;
    type Output = [u8; BYTES_LEN];

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

impl LowerHex for Sha512_256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f)
    }
}

impl UpperHex for Sha512_256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f)
    }
}
