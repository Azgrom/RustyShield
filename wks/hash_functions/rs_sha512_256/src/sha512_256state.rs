use crate::Sha512_256Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{define_sha_state, Sha512BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};

const H0: u64 = 0x22312194FC2BF72C;
const H1: u64 = 0x9F555FA3C84C64C2;
const H2: u64 = 0x2393B86B6F53B151;
const H3: u64 = 0x963877195940EABD;
const H4: u64 = 0x96283EE2A88EFFE3;
const H5: u64 = 0xBE5E1E2553863992;
const H6: u64 = 0x2B0199FC2C85B8AA;
const H7: u64 = 0x0EB72DDC81C52CA2;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

define_sha_state!(Sha512_256State, Sha512_256Hasher, Sha512BitsState);

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
