use crate::Sha1Hasher;
use core::{
    fmt::{Error, Formatter, LowerHex, UpperHex},
    hash::{BuildHasher, Hash, Hasher},
    ops::AddAssign,
};
use hash_ctx_lib::{BlockHasher, GenericStateHasher, HasherWords};
use internal_state::{Sha160BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR, define_sha_state};

pub(crate) const H0: u32 = 0x67452301;
pub(crate) const H1: u32 = 0xEFCDAB89;
pub(crate) const H2: u32 = 0x98BADCFE;
pub(crate) const H3: u32 = 0x10325476;
pub(crate) const H4: u32 = 0xC3D2E1F0;

const HX: [u32; 5] = [H0, H1, H2, H3, H4];

define_sha_state!(Sha1State, Sha1Hasher, Sha160BitsState);

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

impl UpperHex for Sha1State {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        UpperHex::fmt(&self.0 .0, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .1, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .2, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .3, f).expect(UPPER_HEX_ERR);
        UpperHex::fmt(&self.0 .4, f)
    }
}
