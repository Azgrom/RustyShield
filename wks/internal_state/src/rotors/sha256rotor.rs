use n_bit_words_lib::{NBitWord, TSize};

type U32Word = NBitWord<u32>;

/// Process hashing steps of SHA-224 and SHA-256
pub(crate) struct Sha256Rotor<'a, 'b>(
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub &'a mut U32Word,
    pub U32Word,
    pub U32Word,
    pub U32Word,
    pub &'b mut U32Word,
    pub U32Word,
);

impl Sha256Rotor<'_, '_> {
    #[inline(always)]
    pub fn rnd(&mut self, k: u32) {
        let t0 = self.4.sigma1() + U32Word::ch(self.4, self.5, self.6) + *self.7 + self.8 + k;
        *self.3 += t0;
        *self.7 = t0 + self.0.sigma0() + U32Word::maj(self.0, self.1, self.2);
    }
}
