/// Length in bytes of SHA-1 value
const SHA1_RAW_SIZE: u8 = 20;

/// Length in bytes of SHA-1 value
const SHA1_HEX_SIZE: u8 = 2 * SHA1_RAW_SIZE;

/// Block size of SHA-1
pub const SHA1_BLOCK_SIZE: u8 = 64;

pub const R1: u32 = 0x5A827999;
pub const R2: u32 = 0x6ED9EBA1;
pub const R3: u32 = 0x8F1BBCDC;
pub const R4: u32 = 0xCA62C1D6;

pub const H_0: u32 = 0x67452301;
pub const H_1: u32 = 0xEFCDAB89;
pub const H_2: u32 = 0x98BADCFE;
pub const H_3: u32 = 0x10325476;
pub const H_4: u32 = 0xC3D2E1F0;

pub const SHA1_PADDING: [u8; SHA1_BLOCK_SIZE as usize] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub type Sha1Output = [u8; 20];
pub type ShaPadding = [u8; SHA1_BLOCK_SIZE as usize];
pub type HashValues = [u32; 5];
pub type DWords = [u32; 16];
pub type ShambleMatrix = [u32; 80];
