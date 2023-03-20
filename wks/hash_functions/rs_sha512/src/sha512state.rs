use crate::Sha512Hasher;
use internal_state::{define_sha_state, Sha512BitsState};

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
