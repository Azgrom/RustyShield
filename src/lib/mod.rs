use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

const U32_BYTES: usize = size_of::<u32>();

const SHA_LBLOCK: u32 = 16;
const SHA_CBLOCK: u32 = SHA_LBLOCK * U32_BYTES as u32;
const SHA_OFFSET_PAD: u32 = SHA_CBLOCK + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA_CBLOCK - 1;

const H0: u32 = 0x67452301;
const H1: u32 = 0xefcdab89;
const H2: u32 = 0x98badcfe;
const H3: u32 = 0x10325476;
const H4: u32 = 0xc3d2e1f0;

const T_0_19: u32 = 0x5a827999;
const T_20_39: u32 = 0x6ed9eba1;
const T_40_59: u32 = 0x8f1bbcdc;
const T_60_79: u32 = 0xca62c1d6;

/// Represents `F_00_19` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
/// use lib::ch;
///
/// let ch1 = ch(1, 2, 3);
/// assert_eq!(ch1, 2);
///
/// let ch2 = ch(1000, 2001, 3002);
/// assert_eq!(ch2, 3026);
/// ```
#[inline(always)]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

/// Represents `F_20_39` and `F_60_79` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
///
/// use lib::parity;
///
/// let parity1 = parity(1, 2, 3);
/// assert_eq!(parity1, 0);
///
/// let parity2 = parity(1000, 2001, 3002);
/// assert_eq!(parity2, 3971);
/// ```
#[inline(always)]
pub fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Represents `F_40_59` SHA steps
///
/// # Arguments
///
/// * `x`: u32
/// * `y`: u32
/// * `z`: u32
///
/// returns: u32
///
/// # Examples
///
/// ```
/// use lib::maj;
///
/// let maj1 = maj(1, 2, 3);
/// assert_eq!(maj1, 3);
///
/// let maj2 = maj(1000, 2001, 3002);
/// assert_eq!(maj2, 1016);
/// ```
#[inline(always)]
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

#[derive(Clone)]
struct HashValue {
    data: [u32; 5],
}

impl Default for HashValue {
    fn default() -> Self {
        Self {
            data: [H0, H1, H2, H3, H4],
        }
    }
}

impl HashValue {
    fn to_slice(&self) -> &[u32; 5] {
        &self.data
    }
}

impl Index<usize> for HashValue {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for HashValue {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

#[derive(Debug, Clone)]
struct DWords {
    data: [u32; SHA_LBLOCK as usize],
}

impl Default for DWords {
    fn default() -> Self {
        Self {
            data: [u32::MIN; SHA_LBLOCK as usize],
        }
    }
}

impl Index<usize> for DWords {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index & 15]
    }
}

impl IndexMut<usize> for DWords {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index & 15]
    }
}

impl PartialEq<[u32; 16]> for DWords {
    fn eq(&self, other: &[u32; 16]) -> bool {
        self.data == *other
    }
}

impl DWords {
    fn u32_be(c: &[u8]) -> u32 {
        match c.len() {
            4 => u32::from_be_bytes(c.try_into().unwrap()),
            3 => u32::from_be_bytes([c[0], c[1], c[2], 0].try_into().unwrap()),
            2 => ((c[0] as u32) << 24) | ((c[1] as u32) << 16),
            1 => (c[0] as u32) << 24,
            _ => panic!("this can't possibly happen"),
        }
    }

    fn include_bytes_on_incomplete_word(&mut self, word: usize, b: &[u8]) {
        self[word] = match b.len() {
            3 => self[word] | ((b[2] as u32) << 16) | ((b[1] as u32) << 8) | b[0] as u32,
            2 => self[word] | ((b[1] as u32) << 8) | b[0] as u32,
            1 => self[word] | (b[0] as u32),
            _ => panic!("This cannot possibly happen"),
        }
    }

    fn from(&mut self, be_bytes: &[u8]) {
        be_bytes
            .chunks(U32_BYTES)
            .enumerate()
            .for_each(|(i, word)| self[i] = Self::u32_be(word));
    }

    fn skippable_offset(&mut self, be_bytes: &[u8], skip: u8) {
        let remaining = skip % U32_BYTES as u8;
        let completed_words = ((skip / U32_BYTES as u8) & 15) as usize;

        if remaining == 0 {
            be_bytes
                .chunks(U32_BYTES)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words] = Self::u32_be(word));
        } else {
            let bytes_to_skip = U32_BYTES - remaining as usize;
            let skipped_bytes = &be_bytes[..bytes_to_skip];

            self.include_bytes_on_incomplete_word(completed_words, skipped_bytes);

            be_bytes[bytes_to_skip..]
                .chunks(U32_BYTES)
                .enumerate()
                .for_each(|(i, word)| self[i + completed_words + 1] = Self::u32_be(word));
        }
    }

    #[inline(always)]
    fn mix(&mut self, i: usize) {
        self[i] = (self[i + 13] ^ self[i + 8] ^ self[i + 2] ^ self[i]).rotate_left(1);
    }
}

pub struct Sha1Context {
    size: u64,
    hashes: HashValue,
    words: DWords,
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            hashes: HashValue::default(),
            words: DWords::default(),
        }
    }
}

impl Sha1Context {
    fn zero_padding_length(&self) -> usize {
        1 + 8
            + (SHA_CBLOCK_LAST_INDEX as u64 & (55 - (self.size & SHA_CBLOCK_LAST_INDEX as u64)))
                as usize
    }

    #[inline(always)]
    fn block_00_15(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, word: u32) {
        *e = e
            .wrapping_add(word)
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_16_19(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_0_19)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(ch(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_20_39(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_20_39)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_40_59(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_40_59)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(maj(*b, c, d));

        *b = b.rotate_right(2);
    }

    #[inline(always)]
    fn block_60_79(i: u8, a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, d_words: &mut DWords) {
        d_words.mix(i.into());

        *e = e
            .wrapping_add(d_words[i.into()])
            .wrapping_add(T_60_79)
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(parity(*b, c, d));

        *b = b.rotate_right(2);
    }

    fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e] = self.hashes.clone().to_slice();

        let mut d_words = self.words.clone();

        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[0]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[1]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[2]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[3]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[4]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[5]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[6]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[7]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[8]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[9]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[10]);
        Self::block_00_15(e, &mut a, b, c, &mut d, d_words[11]);
        Self::block_00_15(d, &mut e, a, b, &mut c, d_words[12]);
        Self::block_00_15(c, &mut d, e, a, &mut b, d_words[13]);
        Self::block_00_15(b, &mut c, d, e, &mut a, d_words[14]);
        Self::block_00_15(a, &mut b, c, d, &mut e, d_words[15]);

        Self::block_16_19(16, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_16_19(17, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_16_19(18, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_16_19(19, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_20_39(20, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(21, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(22, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(23, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(24, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(25, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(26, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(27, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(28, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(29, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(30, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(31, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(32, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(33, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(34, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_20_39(35, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_20_39(36, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_20_39(37, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_20_39(38, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_20_39(39, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_40_59(40, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(41, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(42, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(43, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(44, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(45, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(46, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(47, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(48, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(49, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(50, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(51, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(52, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(53, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(54, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_40_59(55, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_40_59(56, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_40_59(57, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_40_59(58, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_40_59(59, b, &mut c, d, e, &mut a, &mut d_words);

        Self::block_60_79(60, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(61, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(62, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(63, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(64, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(65, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(66, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(67, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(68, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(69, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(70, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(71, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(72, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(73, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(74, b, &mut c, d, e, &mut a, &mut d_words);
        Self::block_60_79(75, a, &mut b, c, d, &mut e, &mut d_words);
        Self::block_60_79(76, e, &mut a, b, c, &mut d, &mut d_words);
        Self::block_60_79(77, d, &mut e, a, b, &mut c, &mut d_words);
        Self::block_60_79(78, c, &mut d, e, a, &mut b, &mut d_words);
        Self::block_60_79(79, b, &mut c, d, e, &mut a, &mut d_words);

        self.hashes[0] = self.hashes[0].wrapping_add(a);
        self.hashes[1] = self.hashes[1].wrapping_add(b);
        self.hashes[2] = self.hashes[2].wrapping_add(c);
        self.hashes[3] = self.hashes[3].wrapping_add(d);
        self.hashes[4] = self.hashes[4].wrapping_add(e);
    }
}

impl Sha1Context {
    pub fn bytes_hash(&self) -> [u8; 20] {
        let mut hash: [u8; 20] = [0; 20];
        (0..5).for_each(|i| {
            [
                hash[i * 4],
                hash[(i * 4) + 1],
                hash[(i * 4) + 2],
                hash[(i * 4) + 3],
            ] = self.hashes[i].to_be_bytes()
        });

        hash
    }

    pub fn hex_hash(&self) -> String {
        self.hashes
            .to_slice()
            .into_iter()
            .map(|&b| format!("{:08x}", b))
            .collect::<String>()
    }

    pub fn finish(&mut self) {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        let pad_len: [u8; 8] = (self.size * 8).to_be_bytes();

        offset_pad[0] = 0x80;
        offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);

        self.write(&offset_pad[..zero_padding_length]);
    }

    pub fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w: u8 = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;
        let mut bytes_len = bytes.len();

        self.size += bytes_len as u64;

        if len_w != 0 {
            let mut left = (SHA_CBLOCK - len_w as u32) as u8;
            if bytes_len < left as usize {
                left = bytes_len as u8;
            }

            self.words
                .skippable_offset(&bytes[..(left as usize)], len_w);

            len_w = (len_w + left) & SHA_CBLOCK_LAST_INDEX as u8;
            bytes_len -= left as usize;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes_len >= SHA_CBLOCK as usize {
            self.words.from(&bytes[..(SHA_CBLOCK as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA_CBLOCK as usize)..];
            bytes_len -= 64;
        }

        if bytes_len != 0 {
            self.words.from(bytes)
        }
    }
}

#[cfg(test)]
mod use_cases {
    use crate::Sha1Context;

    #[test]
    fn test_commonly_known_sha1_phrases() {
        let empty_str = "";
        let mut empty_str_sha1_ctx = Sha1Context::default();
        empty_str_sha1_ctx.write(empty_str.as_ref());
        empty_str_sha1_ctx.finish();
        let digest_result = empty_str_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let abc = "abc";
        let mut abc_sha1_ctx = Sha1Context::default();
        abc_sha1_ctx.write(abc.as_ref());
        abc_sha1_ctx.finish();
        let digest_result = abc_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "a9993e364706816aba3e25717850c26c9cd0d89d");

        let abcd = "abcd";
        let mut abcd_sha1_ctx = Sha1Context::default();
        abcd_sha1_ctx.write(abcd.as_ref());
        abcd_sha1_ctx.finish();
        let digest_result = abcd_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "81fe8bfe87576c3ecb22426f8e57847382917acf");

        let quick_fox = "The quick brown fox jumps over the lazy dog";

        let mut quick_fox_sha1_ctx = Sha1Context::default();
        quick_fox_sha1_ctx.write(quick_fox.as_ref());
        quick_fox_sha1_ctx.finish();
        let digest_result = quick_fox_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

        let lazy_cog = "The quick brown fox jumps over the lazy cog";
        let mut lazy_cog_sha1_ctx = Sha1Context::default();
        lazy_cog_sha1_ctx.write(lazy_cog.as_ref());
        lazy_cog_sha1_ctx.finish();
        let digest_result = lazy_cog_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");

        let random_big_string = "3a14145dd1fa9e46c4562eed0b0da10d845ad84f43cdb16e29933699b8f7151925295133af3e36503079925bf2c9226bc3924ba24cb00a559eba2e6c0e83c50c43e7d4748dc44b2578463746a2683a46c9b738c3285954ab044f1ba182f7fea2bbd506e81292c30ec6458676c3f2d0e8be50097b80d075b982da65febb5aaa21b67b4f56e7b288533fffe5b2fe70cb97c9e62592fc1b57c741e4734c62b4b0d25b621888b42c803c0dfbbdc3fbe9159c1200f4d04344e01c69f4af521e0ef8fdd311c7442006951158c177726165953fc226defdfe53fa02219380da986f6aea4510c653d34aae1947da7985d8ec33c701e14be0d44e8cbf91484eaa77dfeee0dae87b7d7600b29d03cd2dc40a87d77ef6b7a3426e3f7e9ce29b828c64666c29ba205089b12e8be5b422faf99c3d69aaca324eeb732db8e13c148245070dcc0b0c40ab412bde2039806247ea3917d194a4dab4a38c2121d6c63cb7a007dbf6cff9d1f66b8d1759e192147e60871bf784ad363e326122a3c3a99a89640dd9d2bca85a98d07ee21e2410c006232e53c4c10dce525f993825ef0cb76158c00d491c4163f938a746574c23ef47fbd7c71e95eb2a5af3dd6b90a31819a546c9814135ee74816baf4bec9ff227a9b02a7eef466fd3bcb7d4c4ca27f54abff4cf3da351d516983040f9c566a6f39409ce801d1dc350e270274abcc3cad2152a7b4758b61ed0a650ff59cbe866d870d06cd591620c2932e97d064ebfbf3711b275a947acf22b13949672e46f5b60a5cbab86345d75e716e97ffe6962fe031953646b577d79ae47c1ad4cf941ac129bc33499ed562311f537d53cf3f5acbd97d4f093726fdae1aba2ebf0f3a78276ba7fae19a394412f369c26c8d6c0f4eef2fec22b7fcc3e4ca5fef965b8e905156bc9c20b4060f5c943e01aa8f80bfc1d9299823a65dacc789e9c7eb3324f5c7614671879ab02676883cb5ae6431eecd2df6dd8c90ee2adecff4523e34721b0221f22576accc2c1935e248e8a9d40ed9641416adf612b08302ec190fce1a6289ff2c227e78be728d33cb55e9af0bb27ef20dee38446ff06cd95d86c06e727ed77f70f32f7d0bbc6af8544702023d5c168e40de9c0a5a4cf4a9a52600a41ec263194d11da28384c3afa19a6f231ed7e386f594249c66638a2fa7f6130ed73dfc5633cf93f08c8b475bf97f01acc909b7d3bb3b3e1f72845f05238d2e1d9162976d3bd23aead318793cf3bbcec20cb262d69fccdc52af4f775276df583c57a21efe14a2ba97417381d9f8157f6dcf1b0f17070da93b060cfaa107b43a751147ba922507bc00bce388ba7156bcb5fa8de41f5cc84ae45f02107740d47bcfa79792b0d8c9e82b2db1b668c4462ca3754e097507c36a55a37adf5e8807c45301dbcfe094afe5227d26326a5bad783e28a6a7a16ec7af95b8bc92dd4714bd07075a98aac2825ced928825489c53488ffbdfe62cfb9bc1ab88104f7de6c40df5a25e1697c80af492561fb68bf100429cd740ed9d150949a2fabe3ec4cbdf5d25b82d702e0f0f561bb0350ebac17b116fa210e57c23d7ef7ff50d893c5f2d549d3210cff7ff59298f8710545d738d5b104698f5528fce5a4c6347556d0a759b67f94f5b7b00af16f7c5f9b1fd71fec985a92046a5c0b633112bb2cdde3581d98bf4323b417bdbc55a51384d21229602d8b5ef00001e5721d4359616174617b70f0a0198d2d6a3ddc013154f51ee1caf11504f4ae81178cd9f693d5ba0a700ddfd250399b47bd00732f3d8df153d5a773664864ce701e3de79afeec202be04f25c2c816771d02aeab6d9c827f677160351d8dd2f84565efd6beff073c4f5ea9f3506c329913f782f57ad2e4c7b0419fa69949c1b4878b2d27b118c976eb37c8b8f9d11089a2f847d1a5752792d4d2b0587800b37b9d0a704b3fd0a56885f805e72d8b32c1608147d09bf7cd492b813ccb28472ac61c4043c1b9bb2d79b63bfc2e79ff0bc8c31f1d62bcef48534ae9bf6f28818a1c8bd9321bad4cb432e26015df4da12e18514e331886a01b59b98892c4f74463f74241a5c988e9fc1ca100dd7a4715fc28818b136297ced8c4ddca615d23044aeef5f6294bdb2747af689add9fc4d20881da5258c15edfe31d4e4ba5a82a45a15c1d83372322993963af9a70b06549c5acc2305dc54a37dcdb8168da268b9d09c70f5549efed9443c1ec8c414c96f1d611efa1acdef88b2877fdce6968a55ed6d86208fbf29accf942b5ecc9d4d87e9c49a932c08ed83e488b39d8fddf261faad8bc0aa7dbc897bc7e824874d9b8249acc9540334567b5cf7dbc04e20a8c63f87053c6e82be5791fdde80bdcdba4a854131a666fa335a63fd80afec07b26a04217efea3733700595d93db35c4b2c5e5aa5cf21e028b073fc229d131391a3791a37d6d11fb2f6b1b10919eb8db8cddb110d29ef4f3666a386d5e8ee45fe8142d368bf17fc0af801f3e602f0eba4f79309a1914ad76cc6b9827a84ecf2022e822022ff2b76abe27ac0d86f8ff080380ab71bbba1432c6f2a5178d79b825d29db62ef1d87fa265480ca88d5f536db0dc6abc40faf0d05be7a96697776816ff1a32e2590ca010abcb8535fdced1935f74b5a42e3b08f79432ea3b4eb1a79ab247de48f0f4e25b989860dd5cac421f1830d4510fe4255077bbb1bf398d3c59f20c01853df90c2b3498e5c734616ebce1f80eea6a5f0f820f6b4519e074f1fcc751e4c4c883e82a88b15b1c0c551d10c4b4ad98c8138e366128f072cbcf8c2b39fed02b1afb3cfe9bcc0c036df017c3c84cf782b0686a1477dbf8f28304d68d51fb0be2bac7d14f75d23ea5de9a237ef5a835d1aac66ac3586da6c08f7d97cb1630dd1230516fc61fa93a29e7bb0be954b1aeac3e9558ec0cc4420577a0978c918690e30500dd0aa03b48b810bb95abec4dac3cf53dfa369cca14e8c4d79d79c8e36b7cc03be5c4006eaf7ae2028a6cc66575a85626184a0f656392fd89733ac531b506e96c4d9c482cb996e4f8b1d6e8e25219eab97ccf6d7f792baa1ddf769056b7a809fade397f5cac359f05d48f5caa8bb7375ced6ebeff9cda53fdaad52f3cb98ba74d6044ade6d17e9992b93f2aa768a9c77832cf0bcd15c781909c01acc902d64bcd9b64dab1709a5c05298f58bf3118227614995bd12c1bbb3e7c9f0ee7dcb27de257420fa7d1b070c8ec26f0dc2d2bcebc5b75b7f328fe8a6f145a5e7d8d47c6f45b8654af3be95b41caaef9e5a50b55b4cf0a261b5397758b2ad7a3725ebcad6b70d7afb1f86da7da8bcc7cc2e1df3fc53701b031f30f04fa87c1e5b0973abbaf5edd2a964e63dbfaf62a805b29d012565d015d1d518dbf25f3be2d1e80e87628ed41cc4486f38008d5700d98c50658d107b336c7b53a2f72357682a461ef683ee4ab9da4e7471d6eee462b61fca8989dfebe4217663edb4a1793ec2a8176195a0dc2a69ebb843a930952e39e18df5b220acc8af6aec04b165fba739829a610e22e2fee1b48d560dff03f3c375fd228c8f282144ad3e8083cd69520d6a1a7d540109a7d01d86015ba6ab33f141aaa87f7808aeafd1edf992644ccfacd31a0f0da7ba95c3ab14de48c3e56f31d908e00177a8c14f5d7cd863a7107096321b9ea1a370792ac1bc552bd35d2603b0ba71c90a92f981c46da58e224ed5681b81c49670b5a274160f0e9b517cc8e54d11c62cad51c8058b32c96852726e8103fee9828c04b24dfc7f530ddacef86512b165b2ec6fbd49365eec88a405bc8f6fe5a5cc71e81907097fcaf9bbbe04f1b61bd8d2243739ab4a546775b3834fc1d3d851fabeda573db192fef580e4af198bb38820f162cdca3bb5c2a5fd6588e6b449a683cf55ed60895b4777d6bd375b281b0c25e05cfa148ef5969fee47085ca5abfc0e2fe55c0df52b3cf709b23e250fa4cd375d904f28b8865bca02823ea21c91cae05cf3139489a55809b66e3405a6f353fbe5972d654d0a7acad6c1ac457d7dbba0d319b492bb3c1116593bb97b728928e9f4fc2558b0d48c08d76fc1b56cd216c62ec3bf970e6200a35ec52f0516d8c4682819b7718886f81a90e72f805f3194d6cc8b850ff7b9af4753751520f864bf1ceb9a645e389457567fe24624c90e8e4948dbb56c0ba56568c3d5fc6d9baf616ebbd8bc6d458f226300db96113edb9b94002eb149ceb7db8e2c625539753b63e4155f102d43c9d1c6d02dafd4253b255d9f0f191795536a2df9a4b013197b2f0384b8002c97f6fdd84a62e3fc208fb3fc81f74d64141aa9deb8078d890cf13b43866e1cd9d678ff3dfc15e2e7954bdff74571de9daf701306e4154e19a420012a96dbc6b363d25e6e41b11d25081201e446094d42ebf62e4d0a58823383aa293f329b8e57e485b3cfd7bf0342fd64b23a201809f23e1f5407974bca653fd20be7e627e425bd2577f91aaa25bff9a6796f5048950a3a4e4ccd1769773d1d4a31cb2dfb68ab72141360771d04fa6169b00a42f58f1955254104173c2919c075333f86a07c6797e42eac99622190e9210e8194b9589e0316f952f32e5089ade578eb6c919fd893182223ee13fc01d55edd6bb1fe8216e8a5de2047ca7e1b5a1d8b255c59537cf822866ce1cd04cbda95b52f275f7c026a4467f2919b023d397fd293e26237c32b95c3ee10d7cc6d5d482e526136d6ef0c951f504d1a9d6de09ef7ad8b46ad59d1d4833df7eec354d1f8916bfc2f033b43fa6cbff6c3a03bd3fd52d8a371349f5f711cc3135c8a10dd2996e254a28185a4f6e8981b10ab15881d8cabe76c5e1238fe2923dfab713fc35d974c173bf24cb41d1b8f169c2e8971720dadb3a29a40f2de10c6c976191049072b0f9055a60ed5df6dfb95c09b06248d4e5494be79aa11936c226d26f260c2a8baa36c7a4d2a9eb068640528812a15e1d716f71a6cbc29a0a3cd47589d7fd4c4debe1824284e8322835ee13e7153c9f2208b7740e4058fa8503dc4656aebd3ee0fa60fedf7e907b85752b66cdc21b540c31881bc8004c7fce9ea80e7fb235486b5f1d0321c68a0e44cd5f15e21f27c402754a2f7c1387720e959e94abeb4db216a37e59b066bf338fc6f2e6cf3746392d5a6679d182f01b6c7128a28362eec30b4dedc7356616328be64da23c0f61f9b46a42be70546ec111b8adfeaf1efec46fe5d11758cc765262b8d611d0b1614dc02d47c90191ebad24f59571d62766fd6df3920fc0a2c9dc3cc1f6fa34242c7d792add612b414e28cead47c3a0860fb62a00987816f0f618408b15261070acd106e96d4d966d7f78376a2dbcb742e037d1934a1901bce54e979d9c5e0b9ec79190f25d56eb1d65e586b3ae24c063c0c7883512bc2a107ec6687ff168cdb467043ece1744d257eab9e41132c266f299b0776d572738f3a9c7dcba7e0cffbd7373390401dff225f53a780b215f4ef65238c8c38223d46e4e9b1bd5aa1449bed326a81c85eef48e6fb26b29e4c32377d3a8a0bff978a68755884c58dc4652c16f65b49e0a3b7f9b3e67e4f3e1b68b7e04482aea25ee5548a6d798cb7e6cc3cd2f788513f88c3c524ba20cf281002e11cd5f8bcb6e4d8ab929d026b7f74c43ebfba64203b6aad3bd7eaa0aad2c68b63b1637eeeb3d5cece1c7ba1fa4afaf7b22bb3914f4ae5debe4bfc907ac4bb8c801c71679d0f8e424c866dfaa180e5c127a57772270476c2ccdf7452b7844b60f6dc845540409add976ef85f09d7c1db1fbb7a995fee9a140820c679d98812b3086010ca80fd67fb4f44bf518ba61b800aec3169427fcc2cc0be877869468ded6545ab29d77c9225d4960774bf825f6a69a64084871e8987b6e71bd0df56399a7e0bc815ac6485d7b7d1852b1dd309f4cc780c5d86616ebf2b591805b42d9224b310dbf0883bdfab6995ad071f3ea7b993e00966d8eec83dce82f0a970332426b4f37b5ce378fbfb8a30d37b4c2bc513606cdc32f70d327df0d33a1eac1d5c1af4320abd569267526a61bd0a1d10cebca27cd94459434a1a32e848e7c022c67be14b2e844a1eae4aba76be361a8430ffeaaea51d88275b7d1520c1974519efc41cad3b6446843d3edb0e5b81bcfca867a960b410fc300321182b289fb339347df6e6d5bfd44990b94c87196f8cf0718e5f318ad13de3bd90ac55e28383273114107672096c0545549f8f7c7202e648ce8caf8dd0b5b90766523f83c54d5a7220e9da94d3861dc77b4475f91ba7748ac2a22951920c366cfc9a4690e76a49542ef391b2a0ab199397cbd913dee2f1b3e5403d6a97a9c24aedf5197e6c728a6398ce1a5ff3537f46549627612e6e0440b0d75a3d4407134d94f316b0c6fe842ce8ca02f13e07b53c1c53ff45ac7112ddbfe81e4e49bc7fd18c04ccdc7956dd2cb987ba1af34061f17965bf45bbc4b3d76ce2e811fb228e735dbaba660613dbcf6577ce31b595fc12d64be5f5fea15dca3268563ceae1b5af64755dc1ffce26a1772aadd9f760e9fcbd8711bac7cf7722cae8c7038b629be25ac52594c8ee442f8900d7883b39c23bb997b128a987967d70d4d91a7f3d87b88b4ab032f3ec9ae605aae9a0e3990b4c450e42a436724246decd0af618cb3f9e80567c410351b151677942c893072b9ada5b54d1e107f0fb5f21bb0afaa3fa10c478e83369b61dfe390c7173cc0cb9c3f3ff56262bb139179c8387ed97506d9be232928ea9724738f4d50416f0f21c442c7ac51589266137f152fff27148f0ac4403f9a7451eb3be25536946a48ff997ee4e20248ba02fb9082061de1b0629de748d8c31cf23e9ea45181f77491ea83ba3fa05c795e6fb274b7c7be4e7008f8efe0fc8a2aa2a5049ce83a51d7126ceac080ed4935a433a1f35b7accb77d0885a4b2b4d7e588a9d593c3688cd9f50c36564ed2b1c2b4d82fd516252e64feeaabce66079296cdd17a518a138fc35f53cf4551567a69b7e6c3e192d2cc9d1c37d134a4fea48598a6599ee44342dd7ac71e5432818d72d5e3c7e074888eaaff76619f13a0f3fa12afdb4279018d6e6ef2894d995bd2253559a29b67505cd2ce2fc2d75bf5683d63746804f25458c0635c79f62ded31ca00cfbcd711311e5fb2ea5ca42505eb95b27d69adf7458b19808b5719973e93a85dce7d5f1a33bc97d23097ce19d9654c275344052fdb0ec2ed09897c7f56de0875dd4dfa2b5e1ec35788db1cde78bca8ec7d63d4431ec903d35e79e88b3efc327084946fecbb2d2a687b90571deadaf226832ce2da16a5235a108d2466fdd36e754bba870451cf162e901e477d38a57100ee09f79dcc886ca9a92ffab69b4d04acbb270a1c28edcdd04fedb4a769076fa04461da34475c24e9b1c6302421513b3e5b43c0db497098774065664285e7322e109c54468f079441aeba8f5796c65d53b37770eabb3ebf4becef24f7952c03d3d7212d7bad7304da2a72dff80296b0124c29e4f086418a73daf1b86e9fc02ab6235a2d7da886bbdbac58e8ae6ea87da4adc3e296b35f411892d5e84eae8aef017bae1bf1882a036dbdd37122e1e40b315eab338449822b619d017d3fc7729ad96885c182564622b8e44b44fb6332a4e0e84b9f615091917782df3febf46072687148e5d619c161e3a92827e2fc7a8ed9d209edd5d174bb81c9d5f5f73c3cc0d61e5d5095d985081794d3e37fb5a41245a44fe78ad213f1a8fb4d690ea8eecc4bf72dca689e795f7b2eb240799598784ce78453255e567b149fae61d63e5fdeee85201bf77185ae38fe2e0579a43f0815220ffa517a25a0ec3d60a6f708753ee74f9f0ae959913c758cb0fc26eb7f0ac9dd5aa4b43068aa595dcb001a0e19345fdd1060e65f85525b619eeb297141c58fa1cc18f68707df82885736e75734077eb8dce5988a49381204619b293f6e8290f4cd20c088ea8890456c1205ebac006b676c61a4e2c636c1fd62d4cf5bec89f361c582ba39f9ecaa1d725a1dd26b674f72279cb56fe29490d5085dc3cfa522e16d1c078ba41d55f997d1d7d61457845162745d713a8699a813ba00aca37f9582a23b77dbd13c09a43bf151d9ba5a9e9abebd6e804a9b8e313fe28332dd6429fd87889a54c63f51d4913a90cdcc5bfe510e69958ba707bb52e2e7affe873b277ba46c389c8d0f75b122155b5b5041ed9fdbe09b3a5ab4683483314cb8a8ecd7238250185b2e92bd6275e87b2b50f6b1acab8948346a88ddffaa282208495e811ea89a033aafb27110121cb9e4d361929f09ce6322df6d61dadf34f894717b6d939eb4c1e01a56d8e2821adb2ee26adaa07a16b6abc24a3eedabbd9807282ae3abed041af776663b014c49a9b384f9cfd988ca07781a06ba61952bc80776532a8e1cf4d624ccc9e294f810ed18c1f6bb6fba501f30ef8b1e5e26e6513c64de8b63b3eabc11236915c40fd96d08a149e48d9811c67c49c0b20be456fb50f9b44e523b509566832d1cb9180bf2292ddb9359ab75c304318dbd9159e38de83ebbbb853b8d29caf5fd3e9a9b0d44236c920ffb7ae5e06faeda89180df6d1af39dc19213b0940e67fc1c58f20492b9f6757a29c8ec7e366c98f5cc787f58d4af400b251c32ca2622c61f7c230266f45241392646d84959089957fc64f4a8a64770dcc3b5c5e16e501c61d58520cd7bcadac287aa185be96f6d23a3eed5b90a3c8edb0078d07661708d67e7c0f632dad0a0cac07b231261f182fd457e99267aff186a6dedf8f58a2487a6454ee9437bf4119663226ef94d4f8949738cc56d631fac2f5e8d95eb52bc99b15087705be9b5cbd9d248729d25c9deac90a1e0ea6d1e987e74c03dc445d941fdac1321f89e862de9b045c46a6610f17b3f465249f36c8bfc233e572cfddb0f0fba7a84a624f5c66a6fb2eaed98857059d1f2bff89099e51cfc408861c5625f4c0e160ef0f78513c073184c8337b7c9aceb2f7072cf174255628f382f56efc157198e274590a494806cde6fe7be286c090d652a4509751239f862ecc20cd3c3955f3b74308ae4d72eaf8dcb77b647e5e29b3c33ebca23d33f1";
        let mut big_str_sha1_ctx = Sha1Context::default();
        big_str_sha1_ctx.write(random_big_string.as_ref());
        big_str_sha1_ctx.finish();
        let digest_result = big_str_sha1_ctx.hex_hash();
        assert_eq!(digest_result, "3762f1bd705660861e9d1c4c07638f4f009704ed");
    }
}

#[cfg(test)]
mod hypothesis_and_coverage_assurance;
