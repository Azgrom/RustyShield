use crate::Sha512Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{define_sha_state, Sha512BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};

const H0: u64 = 0x6A09E667F3BCC908;
const H1: u64 = 0xBB67AE8584CAA73B;
const H2: u64 = 0x3C6EF372FE94F82B;
const H3: u64 = 0xA54FF53A5F1D36F1;
const H4: u64 = 0x510E527FADE682D1;
const H5: u64 = 0x9B05688C2B3E6C1F;
const H6: u64 = 0x1F83D9ABFB41BD6B;
const H7: u64 = 0x5BE0CD19137E2179;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

define_sha_state!(Sha512State, Sha512Hasher, Sha512BitsState);

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
