use crate::Sha512_224Hasher;
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
