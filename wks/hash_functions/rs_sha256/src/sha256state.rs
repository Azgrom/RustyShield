use crate::Sha256Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{define_sha_state, Sha256BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

const HX: [u32; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

define_sha_state!(Sha256State, Sha256Hasher, Sha256BitsState);

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

impl PartialEq for Sha256State {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

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
