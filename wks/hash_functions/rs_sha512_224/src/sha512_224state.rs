use crate::Sha512_224Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{DWords, GenericStateHasher, LOWER_HEX_ERR, Sha512BitsState, UPPER_HEX_ERR};

const H0: u64 = 0x8C3D37C819544DA2;
const H1: u64 = 0x73E1996689DCD4D6;
const H2: u64 = 0x1DFAB7AE32FF9C82;
const H3: u64 = 0x679DD514582F9FCF;
const H4: u64 = 0x0F6D2B697BD44DA8;
const H5: u64 = 0x77E36F7304C48942;
const H6: u64 = 0x3F9D85A86A1D36C8;
const H7: u64 = 0x1112E6AD91D692A1;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

#[derive(Clone, Debug)]
pub struct Sha512_224State(pub(crate) Sha512BitsState);
use core::ops::AddAssign;
impl AddAssign for Sha512_224State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}
use core::hash::BuildHasher;
impl BuildHasher for Sha512_224State {
    type Hasher = Sha512_224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        use internal_hasher::BlockHasher;
        Sha512_224Hasher {
            size: u128::MIN,
            state: self.clone(),
            padding: [0u8; Sha512_224Hasher::U8_PAD_SIZE as usize],
        }
    }
}
impl Default for Sha512_224State {
    fn default() -> Self {
        Self::from(HX)
    }
}
impl From<[u64; 8]> for Sha512_224State {
    fn from(v: [u64; 8]) -> Self {
        Self(Sha512BitsState::from(v))
    }
}
impl GenericStateHasher<u64> for Sha512_224State {
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

impl Hash for Sha512_224State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<Sha512_224State> for [u8; 28] {
    fn from(value: Sha512_224State) -> Self {
        let a = u64::to_be_bytes(value.0 .0.into());
        let b = u64::to_be_bytes(value.0 .0.into());
        let c = u64::to_be_bytes(value.0 .0.into());
        let d = u64::to_be_bytes(value.0 .0.into());

        [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1],
            c[2], c[3], c[4], c[5], c[6], c[7], d[0], d[1], d[2], d[3],
        ]
    }
}

impl LowerHex for Sha512_224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .1, f).expect(LOWER_HEX_ERR);
        LowerHex::fmt(&self.0 .2, f).expect(LOWER_HEX_ERR);
        let i = (Into::<u32>::into(self.0 .3) as u64) << 32;
        LowerHex::fmt(&i, f)
    }
}
impl UpperHex for Sha512_224State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        let i = (Into::<u32>::into(self.0 .3) as u64) << 32;
        UpperHex::fmt(&i, f)
    }
}
