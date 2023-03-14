use crate::Sha1Hasher;
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::AddAssign,
};
use hash_ctx_lib::{BlockHasher, GenericStateHasher, HasherWords};
use internal_state::Sha160BitsState;

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

#[derive(Clone, Debug)]
pub struct Sha1State(pub(crate) Sha160BitsState);

impl GenericStateHasher<u32> for Sha1State {
    fn block_00_15(&mut self, words: &HasherWords<u32>) {
        self.0.block_00_15(words)
    }

    fn block_16_31(&mut self, words: &mut HasherWords<u32>) {
        self.0.block_16_31(words)
    }

    fn block_32_47(&mut self, words: &mut HasherWords<u32>) {
        self.0.block_32_47(words)
    }

    fn block_48_63(&mut self, words: &mut HasherWords<u32>) {
        self.0.block_48_63(words)
    }

    fn block_64_79(&mut self, words: &mut HasherWords<u32>) {
        self.0.block_64_79(words)
    }
}

impl AddAssign for Sha1State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Hash for Sha1State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Default for Sha1State {
    fn default() -> Self {
        Self(Sha160BitsState(H0.into(), H1.into(), H2.into(), H3.into(), H4.into()))
    }
}

impl BuildHasher for Sha1State {
    type Hasher = Sha1Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha1Hasher {
            size: u64::default(),
            state: self.clone(),
            padding: [0u8; Sha1Hasher::U8_PADDING_COUNT],
        }
    }
}

impl From<Sha1State> for [u8; 20] {
    fn from(value: Sha1State) -> Self {
        let x = u32::to_be_bytes(value.0 .0.into());
        let y = u32::to_be_bytes(value.0 .1.into());
        let z = u32::to_be_bytes(value.0 .2.into());
        let w = u32::to_be_bytes(value.0 .3.into());
        let t = u32::to_be_bytes(value.0 .4.into());

        [
            x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3], z[0], z[1], z[2], z[3], w[0], w[1], w[2], w[3], t[0], t[1],
            t[2], t[3],
        ]
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .4, f)
    }
}

impl PartialEq for Sha1State {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .4, f)
    }
}
