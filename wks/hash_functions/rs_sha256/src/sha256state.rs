use crate::Sha256Hasher;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::AddAssign,
};
use hash_ctx_lib::{BlockHasher, GenericStateHasher, HasherWords};
use internal_state::Sha256BitsState;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

#[derive(Clone, Debug)]
pub struct Sha256State(pub(crate) Sha256BitsState);

impl AddAssign for Sha256State {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha256Hasher {
            size: u64::MIN,
            state: self.clone(),
            padding: [0u8; Sha256Hasher::U8_PADDING_COUNT],
        }
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self(Sha256BitsState(
            H0.into(),
            H1.into(),
            H2.into(),
            H3.into(),
            H4.into(),
            H5.into(),
            H6.into(),
            H7.into(),
        ))
    }
}

impl From<Sha256State> for [u8; 32] {
    fn from(value: Sha256State) -> Self {
        let a = u32::to_be_bytes(value.0 .0.into());
        let b = u32::to_be_bytes(value.0 .1.into());
        let c = u32::to_be_bytes(value.0 .2.into());
        let d = u32::to_be_bytes(value.0 .3.into());
        let e = u32::to_be_bytes(value.0 .4.into());
        let f = u32::to_be_bytes(value.0 .5.into());
        let g = u32::to_be_bytes(value.0 .6.into());
        let h = u32::to_be_bytes(value.0 .7.into());

        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3], e[0], e[1],
            e[2], e[3], f[0], f[1], f[2], f[3], g[0], g[1], g[2], g[3], h[0], h[1], h[2], h[3],
        ]
    }
}

impl GenericStateHasher<u32> for Sha256State {
    fn block_00_15(&mut self, w: &HasherWords<u32>) {
        self.0.block_00_15(w)
    }

    fn block_16_31(&mut self, w: &mut HasherWords<u32>) {
        self.0.block_16_31(w)
    }

    fn block_32_47(&mut self, w: &mut HasherWords<u32>) {
        self.0.block_32_47(w)
    }

    fn block_48_63(&mut self, w: &mut HasherWords<u32>) {
        self.0.block_48_63(w)
    }

    fn block_64_79(&mut self, _w: &mut HasherWords<u32>) {}
}

impl Hash for Sha256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
impl LowerHex for Sha256State {
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

const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";
impl UpperHex for Sha256State {
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
