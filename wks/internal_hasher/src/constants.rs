pub const U8_PAD_FOR_U32_SIZE: usize = u64::BITS as usize;
pub const U8_PAD_FOR_U64_SIZE: usize = u128::BITS as usize;

pub const PAD_FOR_U32_WORDS: [u8; U8_PAD_FOR_U32_SIZE] = [0u8; U8_PAD_FOR_U32_SIZE];
pub const PAD_FOR_U64_WORDS: [u8; U8_PAD_FOR_U64_SIZE] = [0u8; U8_PAD_FOR_U64_SIZE];
