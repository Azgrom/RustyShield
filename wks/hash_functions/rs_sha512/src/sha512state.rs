use crate::Sha512Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{DWords, GenericStateHasher, LOWER_HEX_ERR, Sha512BitsState, UPPER_HEX_ERR};

const H0: u64 = 0x6A09E667F3BCC908;
const H1: u64 = 0xBB67AE8584CAA73B;
const H2: u64 = 0x3C6EF372FE94F82B;
const H3: u64 = 0xA54FF53A5F1D36F1;
const H4: u64 = 0x510E527FADE682D1;
const H5: u64 = 0x9B05688C2B3E6C1F;
const H6: u64 = 0x1F83D9ABFB41BD6B;
const H7: u64 = 0x5BE0CD19137E2179;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

#[derive(Clone, Debug)]
pub struct Sha512State(pub(crate) Sha512BitsState);
use core::ops::AddAssign;
impl AddAssign for Sha512State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}
use core::hash::BuildHasher;
impl BuildHasher for Sha512State {
    type Hasher = Sha512Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        use internal_hasher::BlockHasher;
        Sha512Hasher {
            size: u128::MIN,
            state: self.clone(),
            padding: [0u8; Sha512Hasher::U8_PAD_SIZE as usize],
        }
    }
}
impl Default for Sha512State {
    fn default() -> Self {
        Self::from(HX)
    }
}
impl From<[u64; 8]> for Sha512State {
    fn from(v: [u64; 8]) -> Self {
        Self(Sha512BitsState::from(v))
    }
}
impl GenericStateHasher<u64> for Sha512State {
    fn block_00_15(&mut self, w: &DWords<u64>) {
        self.0.block_00_15(w)
    }

    fn block_16_31(&mut self, w: &mut DWords<u64>) {
        self.0.block_16_31(w)
    }

    fn block_32_47(&mut self, w: &mut DWords<u64>) {
        self.0.block_32_47(w)
    }

    fn block_48_63(&mut self, w: &mut DWords<u64>) {
        self.0.block_48_63(w)
    }

    fn block_64_79(&mut self, w: &mut DWords<u64>) {
        self.0.block_64_79(w)
    }
}
use core::hash::{Hash, Hasher};

impl Hash for Sha512State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl LowerHex for Sha512State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .3, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .4, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .5, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .6, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .7, f)
    }
}
impl UpperHex for Sha512State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .4, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .5, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .6, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .7, f)
    }
}
