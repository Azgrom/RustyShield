use crate::Sha512_256Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{DWords, GenericStateHasher, LOWER_HEX_ERR, Sha512BitsState, UPPER_HEX_ERR};

const H0: u64 = 0x22312194FC2BF72C;
const H1: u64 = 0x9F555FA3C84C64C2;
const H2: u64 = 0x2393B86B6F53B151;
const H3: u64 = 0x963877195940EABD;
const H4: u64 = 0x96283EE2A88EFFE3;
const H5: u64 = 0xBE5E1E2553863992;
const H6: u64 = 0x2B0199FC2C85B8AA;
const H7: u64 = 0x0EB72DDC81C52CA2;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

#[derive(Clone, Debug)]
pub struct Sha512_256State(pub(crate) Sha512BitsState);
use core::ops::AddAssign;
impl AddAssign for Sha512_256State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}
use core::hash::BuildHasher;
impl BuildHasher for Sha512_256State {
    type Hasher = Sha512_256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        use internal_hasher::BlockHasher;
        Sha512_256Hasher {
            size: u128::MIN,
            state: self.clone(),
            padding: [0u8; Sha512_256Hasher::U8_PAD_SIZE as usize],
        }
    }
}
impl Default for Sha512_256State {
    fn default() -> Self {
        Self::from(HX)
    }
}
impl From<[u64; 8]> for Sha512_256State {
    fn from(v: [u64; 8]) -> Self {
        Self(Sha512BitsState::from(v))
    }
}
impl GenericStateHasher<u64> for Sha512_256State {
    fn block_00_15(&mut self, w: &DWords<u64>) {
        self.0.block_00_15(w)
    }

    fn block_16_31(&mut self, w: &mut DWords<u64>) {
        self.0.block_16_31(w)
    }

    fn block_32_47(&mut self, w: &mut DWords<u64>) {
        self.0. block_32_47(w)
    }

    fn block_48_63(&mut self, w: &mut DWords<u64>) {
        self.0.block_48_63(w)
    }

    fn block_64_79(&mut self, w: &mut DWords<u64>) {
        self.0.block_64_79(w)
    }
}
use core::hash::{Hash, Hasher};

impl Hash for Sha512_256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl LowerHex for Sha512_256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .3, f)
    }
}
impl UpperHex for Sha512_256State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f)
    }
}
