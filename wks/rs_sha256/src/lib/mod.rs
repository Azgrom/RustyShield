pub use sha256_state::Sha256State;
use u32_word_lib::U32Word;

mod sha256_words;
mod sha256_state;
mod sha256_hasher;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

const SHA256_SCHEDULE_U32_WORDS_COUNT: u32 = 64;
const SHA256_PADDING_U8_WORDS_COUNT: u32 = SHA256_SCHEDULE_U32_WORDS_COUNT;
const SHA256_SCHEDULE_U8_WORDS_LAST_INDEX: u32 = SHA256_PADDING_U8_WORDS_COUNT - 1;
const SHA256_HASH_U32_WORDS_COUNT: u32 = 8;

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
