use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::BuildHasher,
    ops::AddAssign
};
use hash_ctx_lib::GenericHasher;
use internal_hasher::{HashAlgorithm, U32Pad};
use internal_state::{DWords, LOWER_HEX_ERR, NewGenericStateHasher, Sha160BitsState, UPPER_HEX_ERR};
use n_bit_words_lib::NBitWord;

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

const HX: [u32; 5] = [H0, H1, H2, H3, H4];

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Sha1State(
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>,
    pub NBitWord<u32>
);

impl AddAssign<Sha160BitsState> for Sha1State {
    fn add_assign(&mut self, rhs: Sha160BitsState) {
        self.0 += rhs.0;
        self.1 += rhs.1;
        self.2 += rhs.2;
        self.3 += rhs.3;
        self.4 += rhs.4;
    }
}

impl BuildHasher for Sha1State {
    type Hasher = GenericHasher<Sha1State>;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::default()
    }
}

impl Default for Sha1State {
    fn default() -> Self {
        Self::from(HX)
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

impl From<Sha1State> for [u8; 20] {
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
    }
}

impl HashAlgorithm for Sha1State {
    type Padding = U32Pad;
    type Output = [u8; 20];

    fn hash_block(&mut self, bytes: &[u8]) {
        let mut state = Sha160BitsState(
            self.0,
            self.1,
            self.2,
            self.3,
            self.4,
            DWords::<u32>::from(<&[u8; 64]>::try_from(bytes).unwrap()),
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

impl LowerHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        LowerHex::fmt(&self.0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.4, f)
    }
}

impl UpperHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        UpperHex::fmt(&self.0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.4, f)
    }
}
