use core::{
    hash::{BuildHasher, Hash, Hasher},
    ops::{Add, Index, IndexMut, Range, RangeTo},
    slice::Chunks,
};
use std::ops::AddAssign;

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

#[derive(Clone, Copy, Hash)]
struct U32Word(u32);

impl U32Word {
    fn gamma0(self) -> u32 {
        self.0.rotate_right(7) ^ self.0.rotate_right(18) ^ (self.0 >> 3)
    }

    fn gamma1(self) -> Self {
        (self.0.rotate_right(17) ^ self.0.rotate_right(19) ^ (self.0 >> 10)).into()
    }
}

impl Add for U32Word {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Add<u32> for U32Word {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Add<U32Word> for u32 {
    type Output = U32Word;

    fn add(self, rhs: U32Word) -> Self::Output {
        U32Word(self.wrapping_add(rhs.0))
    }
}

impl AddAssign for U32Word {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Default for U32Word {
    fn default() -> Self {
        Self(0)
    }
}

impl From<u32> for U32Word {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<U32Word> for u32 {
    fn from(value: U32Word) -> Self {
        value.0
    }
}

struct Sha256State {
    data: [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize],
}

impl Sha256State {
    fn u32_states(&self) -> [U32Word; SHA256_HASH_U32_WORDS_COUNT as usize] {
        self.data.clone()
    }
}

impl BuildHasher for Sha256State {
    type Hasher = Sha256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha256Hasher {
            size: u64::MIN,
            state: Sha256State { data: self.data },
            words: Sha256Words::default(),
        }
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self {
            data: [
                H0.into(),
                H1.into(),
                H2.into(),
                H3.into(),
                H4.into(),
                H5.into(),
                H6.into(),
                H7.into(),
            ],
        }
    }
}

impl Index<usize> for Sha256State {
    type Output = U32Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sha256State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Hash for Sha256State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

struct Sha256Words {
    data: [u8; SHA256_PADDING_U8_WORDS_COUNT as usize],
}

impl Sha256Words {
    fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }

    fn u32_chunks(&self) -> Chunks<'_, u8> {
        self.data.chunks(4)
    }
}

impl Default for Sha256Words {
    fn default() -> Self {
        Self {
            data: [0u8; SHA256_PADDING_U8_WORDS_COUNT as usize],
        }
    }
}

impl Hash for Sha256Words {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha256Words {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Sha256Words {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha256Words {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha256Words {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha256Words {
    fn index_mut(&mut self, range: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

struct Sha256Hasher {
    size: u64,
    state: Sha256State,
    words: Sha256Words,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha256State::default(),
            words: Sha256Words::default(),
        }
    }
}

impl Hash for Sha256Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha256Hasher {
    fn finish(&self) -> u64 {
        todo!()
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA256_SCHEDULE_U8_WORDS_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA256_PADDING_U8_WORDS_COUNT - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)]
                .clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA256_SCHEDULE_U8_WORDS_LAST_INDEX as u8;
            bytes = &bytes[(left as usize)..];

            if len_w != 0 {
                return;
            }

            self.hash_block();
        }

        while bytes.len() >= SHA256_PADDING_U8_WORDS_COUNT as usize {
            self.words
                .clone_from_slice(&bytes[..(SHA256_PADDING_U8_WORDS_COUNT as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA256_PADDING_U8_WORDS_COUNT as usize)..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl Sha256Hasher {
    pub(crate) fn hash_block(&mut self) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state.u32_states();
        let w = self.load_words();

        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[0], 0x428A2F98);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[1], 0x71374491);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[2], 0xB5C0FBCF);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[3], 0xE9B5DBA5);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[4], 0x3956C25B);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[5], 0x59F111F1);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[6], 0x923F82A4);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[7], 0xAB1C5ED5);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[8], 0xD807AA98);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[9], 0x12835B01);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[10], 0x243185BE);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[11], 0x550C7DC3);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[12], 0x72BE5D74);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[13], 0x80DEB1FE);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[14], 0x9BDC06A7);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[15], 0xC19BF174);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[16], 0xE49B69C1);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[17], 0xEFBE4786);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[18], 0x0FC19DC6);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[19], 0x240CA1CC);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[20], 0x2DE92C6F);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[21], 0x4A7484AA);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[22], 0x5CB0A9DC);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[23], 0x76F988DA);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[24], 0x983E5152);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[25], 0xA831C66D);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[26], 0xB00327C8);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[27], 0xBF597FC7);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[28], 0xC6E00BF3);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[29], 0xD5A79147);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[30], 0x06CA6351);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[31], 0x14292967);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[32], 0x27B70A85);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[33], 0x2E1B2138);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[34], 0x4D2C6DFC);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[35], 0x53380D13);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[36], 0x650A7354);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[37], 0x766A0ABB);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[38], 0x81C2C92E);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[39], 0x92722C85);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[40], 0xA2BFE8A1);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[41], 0xA81A664B);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[42], 0xC24B8B70);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[43], 0xC76C51A3);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[44], 0xD192E819);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[45], 0xD6990624);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[46], 0xF40E3585);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[47], 0x106AA070);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[48], 0x19A4C116);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[49], 0x1E376C08);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[50], 0x2748774C);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[51], 0x34B0BCB5);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[52], 0x391C0CB3);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[53], 0x4ED8AA4A);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[54], 0x5B9CCA4F);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[55], 0x682E6FF3);
        Self::rnd(a, b, c, &mut d, e, f, g, &mut h, w[56], 0x748F82EE);
        Self::rnd(h, a, b, &mut c, d, e, f, &mut g, w[57], 0x78A5636F);
        Self::rnd(g, h, a, &mut b, c, d, e, &mut f, w[58], 0x84C87814);
        Self::rnd(f, g, h, &mut a, b, c, d, &mut e, w[59], 0x8CC70208);
        Self::rnd(e, f, g, &mut h, a, b, c, &mut d, w[60], 0x90BEFFFA);
        Self::rnd(d, e, f, &mut g, h, a, b, &mut c, w[61], 0xA4506CEB);
        Self::rnd(c, d, e, &mut f, g, h, a, &mut b, w[62], 0xBEF9A3F7);
        Self::rnd(b, c, d, &mut e, f, g, h, &mut a, w[63], 0xC67178F2);

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.state[4] += e;
        self.state[5] += f;
        self.state[6] += g;
        self.state[7] += h;
    }

    fn load_words(&self) -> [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] {
        let mut w: [U32Word; SHA256_SCHEDULE_U32_WORDS_COUNT as usize] =
            [U32Word::default(); SHA256_SCHEDULE_U32_WORDS_COUNT as usize];

        self.words
            .u32_chunks()
            .enumerate()
            .for_each(|(i, c)| w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into());

        w[16] = ((w[1] + w[0]).gamma0() + w[9] + w[14]).gamma1();
        w[17] = ((w[2] + w[1]).gamma0() + w[10] + w[15]).gamma1();
        w[18] = ((w[3] + w[2]).gamma0() + w[11] + w[16]).gamma1();
        w[19] = ((w[4] + w[3]).gamma0() + w[12] + w[17]).gamma1();
        w[20] = ((w[5] + w[6]).gamma0() + w[13] + w[18]).gamma1();
        w[21] = ((w[6] + w[7]).gamma0() + w[14] + w[19]).gamma1();
        w[22] = ((w[7] + w[8]).gamma0() + w[15] + w[20]).gamma1();
        w[23] = ((w[8] + w[9]).gamma0() + w[16] + w[21]).gamma1();
        w[24] = ((w[9] + w[10]).gamma0() + w[17] + w[22]).gamma1();
        w[25] = ((w[10] + w[11]).gamma0() + w[18] + w[23]).gamma1();
        w[26] = ((w[11] + w[12]).gamma0() + w[19] + w[24]).gamma1();
        w[27] = ((w[12] + w[13]).gamma0() + w[20] + w[25]).gamma1();
        w[28] = ((w[13] + w[14]).gamma0() + w[21] + w[26]).gamma1();
        w[29] = ((w[14] + w[15]).gamma0() + w[22] + w[27]).gamma1();
        w[30] = ((w[15] + w[16]).gamma0() + w[23] + w[28]).gamma1();
        w[31] = ((w[16] + w[17]).gamma0() + w[24] + w[29]).gamma1();
        w[32] = ((w[17] + w[18]).gamma0() + w[25] + w[30]).gamma1();
        w[33] = ((w[18] + w[19]).gamma0() + w[26] + w[31]).gamma1();
        w[34] = ((w[19] + w[20]).gamma0() + w[27] + w[32]).gamma1();
        w[35] = ((w[20] + w[21]).gamma0() + w[28] + w[33]).gamma1();
        w[36] = ((w[21] + w[22]).gamma0() + w[29] + w[34]).gamma1();
        w[37] = ((w[22] + w[23]).gamma0() + w[30] + w[35]).gamma1();
        w[38] = ((w[23] + w[24]).gamma0() + w[31] + w[36]).gamma1();
        w[39] = ((w[24] + w[25]).gamma0() + w[32] + w[37]).gamma1();
        w[40] = ((w[25] + w[26]).gamma0() + w[33] + w[38]).gamma1();
        w[41] = ((w[26] + w[27]).gamma0() + w[34] + w[39]).gamma1();
        w[42] = ((w[27] + w[28]).gamma0() + w[35] + w[40]).gamma1();
        w[43] = ((w[28] + w[29]).gamma0() + w[36] + w[41]).gamma1();
        w[44] = ((w[29] + w[30]).gamma0() + w[37] + w[42]).gamma1();
        w[45] = ((w[30] + w[31]).gamma0() + w[38] + w[43]).gamma1();
        w[46] = ((w[31] + w[32]).gamma0() + w[39] + w[44]).gamma1();
        w[47] = ((w[32] + w[33]).gamma0() + w[40] + w[45]).gamma1();
        w[48] = ((w[33] + w[34]).gamma0() + w[41] + w[46]).gamma1();
        w[49] = ((w[34] + w[35]).gamma0() + w[42] + w[47]).gamma1();
        w[50] = ((w[35] + w[36]).gamma0() + w[43] + w[48]).gamma1();
        w[51] = ((w[36] + w[37]).gamma0() + w[44] + w[49]).gamma1();
        w[52] = ((w[37] + w[38]).gamma0() + w[45] + w[50]).gamma1();
        w[53] = ((w[38] + w[39]).gamma0() + w[46] + w[51]).gamma1();
        w[54] = ((w[39] + w[40]).gamma0() + w[47] + w[52]).gamma1();
        w[55] = ((w[40] + w[41]).gamma0() + w[48] + w[53]).gamma1();
        w[56] = ((w[41] + w[42]).gamma0() + w[49] + w[54]).gamma1();
        w[57] = ((w[42] + w[43]).gamma0() + w[50] + w[55]).gamma1();
        w[58] = ((w[43] + w[44]).gamma0() + w[51] + w[56]).gamma1();
        w[59] = ((w[44] + w[45]).gamma0() + w[52] + w[57]).gamma1();
        w[60] = ((w[45] + w[46]).gamma0() + w[53] + w[58]).gamma1();
        w[61] = ((w[46] + w[47]).gamma0() + w[54] + w[59]).gamma1();
        w[62] = ((w[47] + w[48]).gamma0() + w[55] + w[60]).gamma1();
        w[63] = ((w[48] + w[49]).gamma0() + w[56] + w[61]).gamma1();

        w
    }

    fn rnd(
        a: U32Word,
        b: U32Word,
        c: U32Word,
        d: &mut U32Word,
        e: U32Word,
        f: U32Word,
        g: U32Word,
        h: &mut U32Word,
        w: U32Word,
        k: u32,
    ) {
        let t0 = *h + sigma1(e.into()) + ch(e.into(), f.into(), g.into()) + k + w;
        *d += t0;
        *h = t0 + sigma0(a.into()) + maj(a.into(), b.into(), c.into());
    }
}
