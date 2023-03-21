use crate::Sha512_224Hasher;
use core::fmt::{Formatter, LowerHex, UpperHex};
use internal_state::{define_sha_state, Sha512BitsState, LOWER_HEX_ERR, UPPER_HEX_ERR};

const H0: u64 = 0x8C3D37C819544DA2;
const H1: u64 = 0x73E1996689DCD4D6;
const H2: u64 = 0x1DFAB7AE32FF9C82;
const H3: u64 = 0x679DD514582F9FCF;
const H4: u64 = 0x0F6D2B697BD44DA8;
const H5: u64 = 0x77E36F7304C48942;
const H6: u64 = 0x3F9D85A86A1D36C8;
const H7: u64 = 0x1112E6AD91D692A1;

const HX: [u64; 8] = [H0, H1, H2, H3, H4, H5, H6, H7];

define_sha_state!(Sha512_224State, Sha512_224Hasher, Sha512BitsState);

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
